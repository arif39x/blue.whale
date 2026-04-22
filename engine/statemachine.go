package main

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type VulnerabilityMsg struct {
	Type     string `msgpack:"type"`
	ID       string `msgpack:"id"`
	Name     string `msgpack:"name"`
	Severity string `msgpack:"severity"`
	URL      string `msgpack:"url"`
	Param    string `msgpack:"param"`
	Payload  string `msgpack:"payload"`
	Evidence string `msgpack:"evidence"`
}

type StateMachine struct {
	templates []Template
	client    *RawClient
	
	seenSignatures sync.Map
	endpoints      sync.Map // url -> *Endpoint

	mu              sync.Mutex
	payloadRequests map[string]chan []string
}

type Endpoint struct {
	URL      string
	Params   []string
	Tech     []string
	Baseline *RawResponse
}

func NewStateMachine(templates []Template, client *RawClient) *StateMachine {
	return &StateMachine{
		templates:       templates,
		client:          client,
		payloadRequests: make(map[string]chan []string),
	}
}

func (sm *StateMachine) GetDynamicPayloads(param string) []string {
	ch := make(chan []string, 1)
	sm.mu.Lock()
	sm.payloadRequests[param] = ch
	sm.mu.Unlock()

	emit(PayloadRequestMsg{
		Type:  "payload_request",
		Param: param,
	})

	select {
	case payloads := <-ch:
		return payloads
	case <-time.After(5 * time.Second):
		sm.mu.Lock()
		delete(sm.payloadRequests, param)
		sm.mu.Unlock()
		return nil
	}
}

var numericIDRe = regexp.MustCompile(`\b\d{1,10}\b`)

func (sm *StateMachine) generateSignature(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	path := u.Path
	path = numericIDRe.ReplaceAllString(path, "{int}")

	query := u.Query()
	var keys []string
	for k := range query {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var queryParts []string
	for _, k := range keys {
		val := query.Get(k)
		if _, err := url.Parse(val); err == nil && strings.Contains(val, "/") {
			queryParts = append(queryParts, fmt.Sprintf("%s={url}", k))
		} else if _, err := regexp.MatchString(`^\d+$`, val); err == nil && val != "" {
			queryParts = append(queryParts, fmt.Sprintf("%s={int}", k))
		} else {
			queryParts = append(queryParts, fmt.Sprintf("%s={val}", k))
		}
	}

	sig := path
	if len(queryParts) > 0 {
		sig += "?" + strings.Join(queryParts, "&")
	}
	return sig
}

func (sm *StateMachine) ProcessNode(rawURL string, params []string, tech []string) {
	sig := sm.generateSignature(rawURL)
	
	actual, _ := sm.seenSignatures.LoadOrStore(sig, 0)
	count := actual.(int)
	if count >= 3 {
		return
	}
	sm.seenSignatures.Store(sig, count+1)

	// Capture baseline
	baseline, err := sm.client.Do("GET", rawURL, nil, nil)
	if err != nil {
		return
	}

	ep := &Endpoint{
		URL:      rawURL,
		Params:   params,
		Tech:     tech,
		Baseline: baseline,
	}
	sm.endpoints.Store(rawURL, ep)
}

func (sm *StateMachine) Scan() {
	count := 0
	total := 0
	sm.endpoints.Range(func(key, value any) bool {
		total++
		return true
	})

	sm.endpoints.Range(func(key, value any) bool {
		ep := value.(*Endpoint)
		count++
		
		pct := (count * 100) / total
		emit(StatusMsg{
			Type:     "status",
			Phase:    "SCANNING",
			Detail:   fmt.Sprintf("Fuzzing: %s", ep.URL),
			Progress: pct,
		})

		sm.Fuzz(ep)
		return true
	})
}

func (sm *StateMachine) Fuzz(ep *Endpoint) {
	for _, t := range sm.templates {
		// Filter by tech stack
		if len(t.Tech) > 0 {
			matched := false
			for _, tTech := range t.Tech {
				for _, epTech := range ep.Tech {
					if tTech == epTech {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				continue
			}
		}

		for _, req := range t.Requests {
			for _, param := range ep.Params {
				payloads := req.Payloads
				
				// Add dynamic payloads from Python
				dynamic := sm.GetDynamicPayloads(param)
				if len(dynamic) > 0 {
					payloads = append(payloads, dynamic...)
				}

				for _, payload := range payloads {
					var resp *RawResponse
					var err error

					if payload == "CL.TE" || payload == "TE.CL" {
						smuggled := []byte("GET /bw_smuggling_test HTTP/1.1\r\nHost: localhost\r\n\r\n")
						resp, err = sm.client.DoSmuggling(req.Method, ep.URL, payload, smuggled)
					} else {
						// Construct fuzz URL
						u, _ := url.Parse(ep.URL)
						q := u.Query()
						q.Set(param, payload)
						u.RawQuery = q.Encode()
						fuzzURL := u.String()

						resp, err = sm.client.Do(req.Method, fuzzURL, nil, nil)
					}

					if err != nil {
						continue
					}

					// Differential Analysis
					if ep.Baseline != nil {
						// 1. Status Code Change
						if resp.StatusCode != ep.Baseline.StatusCode {
							sm.ReportVulnerability(t, ep.URL, param, payload, fmt.Sprintf("Status code changed from %d to %d (Differential)", ep.Baseline.StatusCode, resp.StatusCode))
						}

						// 2. Response Size Change (Significant, e.g. > 30% difference)
						baseLen := float64(len(ep.Baseline.Body))
						currLen := float64(len(resp.Body))
						if baseLen > 0 {
							diff := (currLen - baseLen) / baseLen
							if diff > 0.3 || diff < -0.3 {
								sm.ReportVulnerability(t, ep.URL, param, payload, fmt.Sprintf("Response size changed significantly (%.1f%% difference) (Differential)", diff*100))
							}
						}
					}

					// Check matchers (Keyword Matching)
					body := string(resp.Body)
					for _, matcher := range req.Matchers {
						matched := false
						if matcher.Part == "body" {
							for _, word := range matcher.Words {
								if strings.Contains(body, word) {
									matched = true
									sm.ReportVulnerability(t, ep.URL, param, payload, word)
									break
								}
							}
						}
						if matched {
							break
						}
					}
				}
			}
		}
	}
}

func (sm *StateMachine) ReportVulnerability(t Template, targetURL, param, payload, evidence string) {
	// 1. Honey-Token / Honeypot Evasion
	// Check if this finding is "too good to be true" by sending a control request
	if strings.Contains(t.ID, "lfi") || strings.Contains(t.ID, "sqli") || strings.Contains(t.ID, "rce") {
		u, _ := url.Parse(targetURL)
		q := u.Query()
		// Send a request with a completely random payload that should NOT work
		randomPayload := "bw_honeypot_check_" + fmt.Sprintf("%d", time.Now().UnixNano())
		q.Set(param, randomPayload)
		u.RawQuery = q.Encode()
		
		resp, err := sm.client.Do("GET", u.String(), nil, nil)
		if err == nil {
			// If the "invalid" payload returns the same evidence or status code 200, it's likely a honeypot
			if strings.Contains(string(resp.Body), evidence) || (resp.StatusCode == 200 && strings.Contains(evidence, "Status code")) {
				return // Discard finding
			}
		}
	}

	// 2. Vulnerability Msg Emission
	emit(VulnerabilityMsg{
		Type:     "vulnerability",
		ID:       t.ID,
		Name:     t.Name,
		Severity: t.Severity,
		URL:      targetURL,
		Param:    param,
		Payload:  payload,
		Evidence: evidence,
	})

	// 3. Chain Reaction Logic
	if strings.Contains(t.ID, "ssrf") {
		// SSRF found -> Chain to local port scan
		internalPorts := []string{"22", "80", "443", "6379", "8080", "9000"}
		for _, port := range internalPorts {
			sm.ProcessNode("http://127.0.0.1:"+port+"/", nil, []string{"internal"})
		}
	} else if strings.Contains(t.ID, "lfi") || strings.Contains(t.ID, "path-traversal") {
		// LFI found -> Chain to sensitive file extraction
		sensitiveFiles := []string{"/proc/self/environ", "/etc/shadow", "/var/www/html/config.php"}
		for _, f := range sensitiveFiles {
			// This is a simplification; ideally we'd trigger a specific template
			u, _ := url.Parse(targetURL)
			q := u.Query()
			q.Set(param, f)
			u.RawQuery = q.Encode()
			// We just process it as a node so the fuzzer picks it up or we log it
			sm.ProcessNode(u.String(), nil, []string{"sensitive"})
		}
	}
}
