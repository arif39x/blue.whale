package main

import (
	"bytes"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"
)

type crawler struct {
	client  *RawClient
	cfg     ScanConfig
	sm      *StateMachine
	seen    sync.Map
	queue   chan crawlJob
	wg      sync.WaitGroup
	total   atomic.Int64
	crawled atomic.Int64
}

type crawlJob struct {
	rawURL string
	depth  int
}

func extractLinks(base *url.URL, body io.Reader) []string {
	var links []string
	doc, err := html.Parse(body)
	if err != nil {
		return links
	}

	seen := map[string]bool{}
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			var attr string
			switch n.Data {
			case "a", "link":
				attr = "href"
			case "form":
				attr = "action"
			case "script", "iframe", "img":
				attr = "src"
			}
			if attr != "" {
				for _, a := range n.Attr {
					if a.Key == attr && a.Val != "" {
						ref, err := url.Parse(strings.TrimSpace(a.Val))
						if err != nil {
							continue
						}
						abs := base.ResolveReference(ref)
						if abs.Host == base.Host && abs.Scheme != "" {
							abs.Fragment = ""
							key := abs.String()
							if !seen[key] {
								seen[key] = true
								links = append(links, key)
							}
						}
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return links
}

func (c *crawler) run(seeds []string) {
	workers := c.cfg.Workers
	if workers <= 0 {
		workers = 10
	}

	c.queue = make(chan crawlJob, 10000)

	var rateTicker <-chan time.Time
	if c.cfg.RPS > 0 {
		interval := time.Duration(float64(time.Second) / c.cfg.RPS)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		rateTicker = ticker.C
	}

	workerWg := sync.WaitGroup{}
	for i := 0; i < workers; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for job := range c.queue {
				// Initial seed fetch safety: limit rate for depth 0
				if job.depth == 0 {
					time.Sleep(100 * time.Millisecond) // Reduced wait for seeds but kept some throttle
				} else if rateTicker != nil {
					<-rateTicker
				}
				c.visit(job)
			}
		}()
	}

	for _, seed := range seeds {
		c.enqueue(crawlJob{rawURL: seed, depth: 0})
	}

	c.wg.Wait()
	close(c.queue)
	workerWg.Wait()
}

func (c *crawler) enqueue(job crawlJob) {
	if _, loaded := c.seen.LoadOrStore(job.rawURL, true); loaded {
		return
	}

	c.total.Add(1)
	c.wg.Add(1)
	go func() {
		c.queue <- job
	}()
}

func (c *crawler) visit(job crawlJob) {
	defer c.wg.Done()

	resp, err := c.client.Do("GET", job.rawURL, c.cfg.Headers, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to fetch %s: %v\n", job.rawURL, err)
		if job.depth == 0 {
			emit(ErrorMsg{
				Type:    "error",
				Message: fmt.Sprintf("Failed to fetch seed URL %s: %v", job.rawURL, err),
			})
		}
		return
	}

	if resp.StatusCode >= 400 {
		if job.depth == 0 {
			emit(ErrorMsg{
				Type:    "error",
				Message: fmt.Sprintf("Seed URL %s returned status %d", job.rawURL, resp.StatusCode),
			})
		}
	}

	c.crawled.Add(1)

	u, _ := url.Parse(job.rawURL)
	var params []string
	for k := range u.Query() {
		params = append(params, k)
	}

	// Fingerprint tech stack
	tech := Fingerprint(resp.Header, string(resp.Body))

	// Move logic to StateMachine - pass resp as baseline to avoid double requests
	c.sm.ProcessNode(job.rawURL, params, tech, resp)

	// Shadow API Excavator logic
	uLower := strings.ToLower(u.Path)
	if strings.Contains(uLower, "/api") || strings.Contains(uLower, "/v") {
		docs := []string{"/swagger-ui.html", "/v2/api-docs", "/v3/api-docs", "/openapi.json", "/swagger.json"}
		for _, d := range docs {
			docURL := *u
			docURL.Path = d
			docURL.RawQuery = ""
			c.enqueue(crawlJob{rawURL: docURL.String(), depth: job.depth})
		}

		re := regexp.MustCompile(`/v(\d+)/`)
		if matches := re.FindStringSubmatch(u.Path); len(matches) > 1 {
			currentVer := matches[1]
			for _, ver := range []string{"1", "2", "3"} {
				if ver == currentVer {
					continue
				}
				newPath := strings.Replace(u.Path, "/v"+currentVer+"/", "/v"+ver+"/", 1)
				newURL := *u
				newURL.Path = newPath
				c.enqueue(crawlJob{rawURL: newURL.String(), depth: job.depth})
			}
		}
	}

	// Emit periodic progress
	crawled := c.crawled.Load()
	total := c.total.Load()
	if crawled%5 == 0 || crawled == total {
		var pct int
		if total > 0 {
			pct = int(crawled * 100 / total)
		}
		emit(StatusMsg{
			Type:     "status",
			Phase:    "CRAWLING",
			Detail:   fmt.Sprintf("Progress: %d/%d URLs | Current: %s", crawled, total, job.rawURL),
			Progress: pct,
		})
	}

	maxDepth := c.cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}

	ct := resp.Header.Get("Content-Type")
	isHTML := strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")

	if job.depth < maxDepth && isHTML {

		base, err := url.Parse(job.rawURL)
		if err == nil {
			links := extractLinks(base, bytes.NewReader(resp.Body))
			for _, link := range links {
				c.enqueue(crawlJob{rawURL: link, depth: job.depth + 1})
			}
		}
	}
}
