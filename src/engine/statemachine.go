package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	Body     string `msgpack:"body"`
	Baseline string `msgpack:"baseline"`
}

type StateMachine struct {
	templates []Template
	client    *RawClient
	headers   map[string]string

	seenSignatures sync.Map
	endpoints      sync.Map

	mu              sync.Mutex
	payloadRequests map[string]chan []string
}

type Endpoint struct {
	URL      string
	Params   []string
	Tech     []string
	Baseline *RawResponse
}

func NewStateMachine(templates []Template, client *RawClient, headers map[string]string) *StateMachine {
	return &StateMachine{
		templates:       templates,
		client:          client,
		headers:         headers,
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

func (sm *StateMachine) extractTokens(resp *RawResponse) {
	if resp == nil {
		return
	}

	authHeader := resp.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		sm.mu.Lock()
		sm.headers["Authorization"] = authHeader
		sm.mu.Unlock()
	}

	body := string(resp.Body)
	csrfPatterns := []string{`csrf-token`, `csrf_token`, `_csrf`, `authenticity_token`}
	for _, p := range csrfPatterns {
		re := regexp.MustCompile(fmt.Sprintf(`(?i)%s["']\s*[:=]\s*["']([^"']+)`, p))
		if matches := re.FindStringSubmatch(body); len(matches) > 1 {
			sm.mu.Lock()
			sm.headers["X-CSRF-Token"] = matches[1]
			sm.mu.Unlock()
			break
		}
	}
}

func (sm *StateMachine) ProcessNode(rawURL string, params []string, tech []string, baseline *RawResponse) {
	sig := sm.generateSignature(rawURL)

	val, _ := sm.seenSignatures.LoadOrStore(sig, new(int32))
	countPtr := val.(*int32)
	count := atomic.AddInt32(countPtr, 1)
	if count > 3 {
		return
	}

	if baseline == nil {
		var err error
		baseline, err = sm.client.Do("GET", rawURL, sm.headers, nil)
		if err != nil {
			return
		}
	}

	sm.extractTokens(baseline)

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

func (sm *StateMachine) isSafeURL(targetURL string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err == nil && len(ips) > 0 {
			ip = ips[0]
		}
	}

	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return false
		}
	}

	port := u.Port()
	if port != "" {
		if port == "22" || port == "25" || port == "3306" || port == "5432" || port == "6379" {
			return false
		}
	}

	return true
}

type FeedbackMsg struct {
	Type       string `msgpack:"type"`
	URL        string `msgpack:"url"`
	StatusCode int    `msgpack:"status_code"`
	Reason     string `msgpack:"reason"`
}

func (sm *StateMachine) Fuzz(ep *Endpoint) {
	for _, t := range sm.templates {
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
			var targetURLs []string
			if len(req.Path) > 0 {
				u, _ := url.Parse(ep.URL)
				for _, p := range req.Path {
					newU := *u
					if strings.HasPrefix(p, "/") {
						newU.Path = p
					} else {
						newU.Path = strings.TrimSuffix(u.Path, "/") + "/" + p
					}
					targetURLs = append(targetURLs, newU.String())
				}
			} else {
				targetURLs = []string{ep.URL}
			}

			for _, targetURL := range targetURLs {
				if !sm.isSafeURL(targetURL) {
					fmt.Fprintf(os.Stderr, "[SECURITY] SSRF protection blocked target: %s\n", targetURL)
					continue
				}

				paramsToFuzz := ep.Params
				if len(paramsToFuzz) == 0 {
					paramsToFuzz = []string{"fuzz"}
				}

				for _, param := range paramsToFuzz {
					payloads := req.Payloads

					dynamic := sm.GetDynamicPayloads(param)
					if len(dynamic) > 0 {
						payloads = append(payloads, dynamic...)
					}

					for _, payload := range payloads {
						var resp *RawResponse
						var err error

						if payload == "CL.TE" || payload == "TE.CL" {
							smuggled := []byte("GET /bw_smuggling_test HTTP/1.1\r\nHost: localhost\r\n\r\n")
							resp, err = sm.client.DoSmuggling(req.Method, targetURL, payload, smuggled)
						} else {
							u, _ := url.Parse(targetURL)
							q := u.Query()
							q.Set(param, payload)
							u.RawQuery = q.Encode()
							fuzzURL := u.String()

							resp, err = sm.client.Do(req.Method, fuzzURL, sm.headers, nil)
						}

						if err != nil {
							continue
						}

						if resp.StatusCode == 403 || resp.StatusCode == 429 {
							emit(FeedbackMsg{
								Type:       "feedback",
								URL:        targetURL,
								StatusCode: resp.StatusCode,
								Reason:     "WAF_BLOCK",
							})
						}

						if ep.Baseline != nil && resp.StatusCode != 405 {
							if resp.StatusCode != ep.Baseline.StatusCode {
								if (ep.Baseline.StatusCode < 400 && resp.StatusCode >= 500) ||
									(ep.Baseline.StatusCode >= 400 && resp.StatusCode < 300) {
									sm.ReportVulnerability(t, targetURL, param, payload, fmt.Sprintf("Status code changed from %d to %d (Significant)", ep.Baseline.StatusCode, resp.StatusCode), string(resp.Body), string(ep.Baseline.Body))
								}
							}

							baseLen := float64(len(ep.Baseline.Body))
							currLen := float64(len(resp.Body))
							if baseLen > 500 {
								diff := (currLen - baseLen) / baseLen
								if diff > 0.5 || diff < -0.5 {
									sm.ReportVulnerability(t, targetURL, param, payload, "Possible semantic change detected", string(resp.Body), string(ep.Baseline.Body))
								}
							}
						}
						body := string(resp.Body)
						for _, matcher := range req.Matchers {
							matched := false
							if matcher.Part == "body" {
								for _, word := range matcher.Words {
									if strings.Contains(body, word) {
										matched = true
										sm.ReportVulnerability(t, targetURL, param, payload, word, body, "")
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
}

func (sm *StateMachine) ReportVulnerability(t Template, targetURL, param, payload, evidence, body, baseline string) {

	if strings.Contains(t.ID, "lfi") || strings.Contains(t.ID, "sqli") || strings.Contains(t.ID, "rce") {
		u, _ := url.Parse(targetURL)
		q := u.Query()
		randomPayload := "bw_honeypot_check_" + fmt.Sprintf("%d", time.Now().UnixNano())
		q.Set(param, randomPayload)
		u.RawQuery = q.Encode()

		resp, err := sm.client.Do("GET", u.String(), sm.headers, nil)
		if err == nil {
			if resp.StatusCode == 403 || resp.StatusCode == 429 {

			} else if strings.Contains(string(resp.Body), evidence) || (resp.StatusCode == 200 && strings.Contains(evidence, "Status code")) {
				return
			}
		}
	}

	emit(VulnerabilityMsg{
		Type:     "vulnerability",
		ID:       t.ID,
		Name:     t.Name,
		Severity: t.Severity,
		URL:      targetURL,
		Param:    param,
		Payload:  payload,
		Evidence: evidence,
		Body:     body,
		Baseline: baseline,
	})

	if strings.Contains(t.ID, "ssrf") {
		internalPorts := []string{"22", "80", "443", "6379", "8080", "9000"}
		for _, port := range internalPorts {

			u, _ := url.Parse(targetURL)
			q := u.Query()
			q.Set(param, fmt.Sprintf("http://127.0.0.1:%s/", port))
			u.RawQuery = q.Encode()

			sm.ProcessNode(u.String(), nil, []string{"internal-pivot"}, nil)
		}
	}
}
