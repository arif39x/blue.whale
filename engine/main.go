package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"
)

type InMessage struct {
	Type string `json:"type"`
	// scan_start
	Targets []string   `json:"targets,omitempty"`
	Config  ScanConfig `json:"config,omitempty"`
	// fuzz_job
	JobID   string `json:"job_id,omitempty"`
	URL     string `json:"url,omitempty"`
	Method  string `json:"method,omitempty"`
	Payload string `json:"payload,omitempty"`
	Param   string `json:"param,omitempty"`
}

type ScanConfig struct {
	Workers  int    `json:"workers"`
	MaxDepth int    `json:"max_depth"`
	UA       string `json:"ua"`
	RPS      int    `json:"rps"`
	Timeout  int    `json:"timeout_seconds"`
}

type NodeMsg struct {
	Type   string   `json:"type"`
	URL    string   `json:"url"`
	Params []string `json:"params"`
	Score  float64  `json:"score"`
	Depth  int      `json:"depth"`
}

type FuzzResultMsg struct {
	Type      string `json:"type"`
	JobID     string `json:"job_id"`
	Status    int    `json:"status"`
	BodyLen   int64  `json:"body_len"`
	TimingMs  int64  `json:"timing_ms"`
	Reflect   bool   `json:"reflect"`
	TimingHit bool   `json:"timing_hit"`
}

type StatusMsg struct {
	Type     string `json:"type"`
	Phase    string `json:"phase"`
	Progress int    `json:"progress"`
}

type ScanDoneMsg struct {
	Type       string `json:"type"`
	TotalNodes int64  `json:"total_nodes"`
}

type ErrorMsg struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type EngineInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

var outMu sync.Mutex
var outEnc = json.NewEncoder(os.Stdout)

func emit(v any) {
	outMu.Lock()
	defer outMu.Unlock()
	_ = outEnc.Encode(v)
}

func newClient(cfg ScanConfig) *http.Client {
	// Dynamic connection pooling based on worker count
	// This prevents TLS handshake thrashing by maintaining adequate keep-alive connections
	workers := cfg.Workers
	if workers <= 0 {
		workers = 10
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for scanning
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		// Scale connection pools with worker count to prevent connection exhaustion
		MaxIdleConns:        workers * 5,     // Global idle connection pool
		MaxIdleConnsPerHost: workers * 2,     // Per-host connection pool (handles high concurrency)
		IdleConnTimeout:     60 * time.Second, // Keep connections alive longer for reuse
		// Timeouts remain conservative to prevent hanging on slow endpoints
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		DisableCompression:    false, // HTTP/2 multiplexing remains enabled by default
	}
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
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
						// keep only same-host links
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

// extractParams pulls query-parameter names from a URL string.
func extractParams(rawURL string) []string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	var params []string
	for k := range u.Query() {
		params = append(params, k)
	}
	return params
}

// scoreEndpoint assigns a heuristic priority score (higher = fuzz first).
func scoreEndpoint(rawURL string, params []string) float64 {
	score := 1.0
	if len(params) > 0 {
		score += float64(len(params)) * 2.0
	}
	lower := strings.ToLower(rawURL)
	for _, kw := range []string{"search", "query", "id", "user", "admin", "login", "api", "file", "path", "cmd", "exec", "redirect", "url", "page", "item"} {
		if strings.Contains(lower, kw) {
			score += 1.5
		}
	}
	if strings.Contains(lower, ".php") || strings.Contains(lower, ".asp") {
		score += 1.0
	}
	return score
}

type crawler struct {
	client       *http.Client
	cfg          ScanConfig
	seen         sync.Map
	queue        chan crawlJob
	wg           sync.WaitGroup
	total        atomic.Int64
	crawled      atomic.Int64
	// Queue manager pattern: prevents goroutine explosion by batching enqueue operations
	pendingMu    sync.Mutex
	pendingJobs  []crawlJob
	queueManager chan struct{} // Signals queue manager to process pending jobs
}

type crawlJob struct {
	rawURL string
	depth  int
}

func (c *crawler) run(seeds []string) {
	workers := c.cfg.Workers
	if workers <= 0 {
		workers = 10
	}

	c.queue = make(chan crawlJob, workers*20)
	c.pendingJobs = make([]crawlJob, 0, workers*10)
	c.queueManager = make(chan struct{}, 1)

	// Rate limiter
	var rateTicker <-chan time.Time
	if c.cfg.RPS > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(c.cfg.RPS))
		defer ticker.Stop()
		rateTicker = ticker.C
	}

	// Start the Queue Manager goroutine
	// This prevents goroutine explosion by batching job enqueues through a mutex-protected slice
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for range c.queueManager {
			c.pendingMu.Lock()
			batch := c.pendingJobs
			c.pendingJobs = make([]crawlJob, 0, workers*10)
			c.pendingMu.Unlock()

			for _, job := range batch {
				if _, loaded := c.seen.LoadOrStore(job.rawURL, true); loaded {
					continue
				}
				c.total.Add(1)
				c.queue <- job
			}
		}
	}()

	// Launch workers
	for i := 0; i < workers; i++ {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			for job := range c.queue {
				if rateTicker != nil {
					<-rateTicker
				}
				c.visit(job)
			}
		}()
	}

	// Enqueue seeds
	maxDepth := c.cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}
	for _, seed := range seeds {
		c.enqueue(crawlJob{rawURL: seed, depth: 0})
	}

	// Drain: close queue once all pending work is done
	go func() {
		c.wg.Wait()
		close(c.queueManager)
		close(c.queue)
	}()

	// Block until close (the goroutine above closes it)
	// We need a separate mechanism: re-implement with a pending counter.
	// Simple approach: use wg and a separate done channel.
}

func (c *crawler) enqueue(job crawlJob) {
	// Queue Manager Pattern:
	// Instead of spawning a goroutine per job (causing goroutine explosion),
	// we append to a mutex-protected slice and signal a dedicated queue manager.
	// The manager batches inserts into the channel safely without blocking callers.
	c.pendingMu.Lock()
	c.pendingJobs = append(c.pendingJobs, job)
	c.pendingMu.Unlock()

	// Signal queue manager to process pending jobs (non-blocking)
	select {
	case c.queueManager <- struct{}{}:
	default:
	}
}

func (c *crawler) visit(job crawlJob) {
	defer c.wg.Done()

	ua := c.cfg.UA
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
	}

	req, err := http.NewRequest("GET", job.rawURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := c.client.Do(req)
	if err != nil {
		return
	}

	c.crawled.Add(1)

	params := extractParams(job.rawURL)
	score := scoreEndpoint(job.rawURL, params)

	emit(NodeMsg{
		Type:   "node",
		URL:    job.rawURL,
		Params: params,
		Score:  score,
		Depth:  job.depth,
	})

	// Emit periodic progress
	crawled := c.crawled.Load()
	if crawled%10 == 0 {
		total := c.total.Load()
		var pct int
		if total > 0 {
			pct = int(crawled * 100 / total)
		}
		emit(StatusMsg{Type: "status", Phase: "crawling", Progress: pct})
	}

	// Asynchronous HTML Parsing:
	// Free up the network worker immediately after downloading.
	// Read body into memory, close response, then spawn a detached goroutine for parsing.
	maxDepth := c.cfg.MaxDepth
	if maxDepth <= 0 {
		maxDepth = 3
	}
	if job.depth < maxDepth && isHTMLContent(resp) {
		// Read entire body into memory (bounded by 512KB to prevent OOM)
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close() // Close immediately to free connection back to pool

		if err == nil {
			// Spawn detached goroutine for parsing - doesn't block this worker
			c.wg.Add(1)
			go func() {
				defer c.wg.Done()
				base, err := url.Parse(job.rawURL)
				if err != nil {
					return
				}
				// Parse from in-memory buffer instead of blocking on network I/O
				links := extractLinks(base, bytes.NewReader(bodyBytes))
				for _, link := range links {
					c.enqueue(crawlJob{rawURL: link, depth: job.depth + 1})
				}
			}()
		}
	} else {
		resp.Body.Close() // Always close body for non-HTML responses
	}
}

func isHTMLContent(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml")
}

func handleFuzzJob(client *http.Client, msg InMessage) {
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

	targetURL := msg.URL
	// Inject payload into the named query param if given
	if msg.Param != "" && msg.Payload != "" {
		u, err := url.Parse(msg.URL)
		if err == nil {
			q := u.Query()
			q.Set(msg.Param, msg.Payload)
			u.RawQuery = q.Encode()
			targetURL = u.String()
		}
	}

	method := msg.Method
	if method == "" {
		method = "GET"
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		emit(ErrorMsg{Type: "error", Message: fmt.Sprintf("fuzz_job build error: %v", err)})
		return
	}
	req.Header.Set("User-Agent", ua)

	start := time.Now()
	resp, err := client.Do(req)
	timingMs := time.Since(start).Milliseconds()
	if err != nil {
		emit(ErrorMsg{Type: "error", Message: fmt.Sprintf("fuzz_job request error: %v", err)})
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024)) // max 512 KB
	bodyLen := int64(len(body))

	// Naive reflection check
	reflect := msg.Payload != "" && strings.Contains(string(body), msg.Payload)

	// Naive timing oracle: flag if response took significantly longer than baseline (5s threshold)
	timingHit := timingMs > 4500

	emit(FuzzResultMsg{
		Type:      "fuzz_result",
		JobID:     msg.JobID,
		Status:    resp.StatusCode,
		BodyLen:   bodyLen,
		TimingMs:  timingMs,
		Reflect:   reflect,
		TimingHit: timingHit,
	})
}

func serve() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	var (
		client     *http.Client
		fuzzWg     sync.WaitGroup
		fuzzSem    chan struct{} // concurrency limit for fuzz jobs
		crawlDone  chan struct{}
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var msg InMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			emit(ErrorMsg{Type: "error", Message: fmt.Sprintf("bad JSON: %v", err)})
			continue
		}

		switch msg.Type {
		case "scan_start":
			if len(msg.Targets) == 0 {
				emit(ErrorMsg{Type: "error", Message: "scan_start: no targets provided"})
				continue
			}
			cfg := msg.Config
			client = newClient(cfg)

			fuzzSem = make(chan struct{}, max(cfg.Workers, 10))

			emit(StatusMsg{Type: "status", Phase: "crawling", Progress: 0})

			// Run crawler in background so fuzzing can start immediately as nodes are discovered
			crawlDone = make(chan struct{})
			c := &crawler{client: client, cfg: cfg}
			go func() {
				c.run(msg.Targets)
				close(crawlDone)
				emit(ScanDoneMsg{
					Type:       "scan_done",
					TotalNodes: c.crawled.Load(),
				})
			}()

		case "fuzz_job":
			if client == nil {
				// Create a default client if no scan_start was received
				client = newClient(ScanConfig{Timeout: 30})
				fuzzSem = make(chan struct{}, 10)
			}
			fuzzWg.Add(1)
			fuzzSem <- struct{}{}
			go func(m InMessage) {
				defer fuzzWg.Done()
				defer func() { <-fuzzSem }()
				handleFuzzJob(client, m)
			}(msg)

		default:
			emit(ErrorMsg{Type: "error", Message: fmt.Sprintf("unknown message type: %s", msg.Type)})
		}
	}

	// Wait for all in-flight fuzz jobs to finish before exiting
	fuzzWg.Wait()
	// Drain crawler goroutine if still running
	if crawlDone != nil {
		<-crawlDone
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serve()

	case "info":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(EngineInfo{
			Name:    "whale-engine",
			Version: "2.0.0",
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
		})

	case "check":
		fmt.Printf("whale-engine ok - %s/%s\n", runtime.GOOS, runtime.GOARCH)

	default:
		fmt.Fprintf(os.Stderr, "Unknown sub-command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(strings.TrimSpace(`
Blue Whale Engine - Native goroutine-based scanner core.

Usage:
  whale-engine <sub-command>

Sub-commands:
  serve   Start the JSON-RPC daemon (reads from stdin, writes to stdout).
  info    Print engine metadata as JSON.
  check   Verify engine is operational.

Build:
  cd engine && go build -o ../bin/whale-engine .

IPC (serve mode):
  Send {"type":"scan_start","targets":[...],"config":{...}} to stdin.
  Read {"type":"node",...} and {"type":"scan_done",...} from stdout.
`))
}
