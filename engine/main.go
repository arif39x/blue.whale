package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/net/html"
)

type InMessage struct {
	Type string `msgpack:"type"`
	// scan_start
	Targets []string   `msgpack:"targets,omitempty"`
	Config  ScanConfig `msgpack:"config,omitempty"`
	// fuzz_job
	JobID   string `msgpack:"job_id,omitempty"`
	URL     string `msgpack:"url,omitempty"`
	Method  string `msgpack:"method,omitempty"`
	Payload string `msgpack:"payload,omitempty"`
	Param   string `msgpack:"param,omitempty"`
}

type ScanConfig struct {
	Workers  int    `msgpack:"workers"`
	MaxDepth int    `msgpack:"max_depth"`
	UA       string `msgpack:"ua"`
	RPS      int    `msgpack:"rps"`
	Timeout  int    `msgpack:"timeout_seconds"`
}

type NodeMsg struct {
	Type   string   `msgpack:"type"`
	URL    string   `msgpack:"url"`
	Params []string `msgpack:"params"`
	Score  float64  `msgpack:"score"`
	Depth  int      `msgpack:"depth"`
}

type FuzzResultMsg struct {
	Type      string `msgpack:"type"`
	JobID     string `msgpack:"job_id"`
	Status    int    `msgpack:"status"`
	BodyLen   int64  `msgpack:"body_len"`
	TimingMs  int64  `msgpack:"timing_ms"`
	Reflect   bool   `msgpack:"reflect"`
	TimingHit bool   `msgpack:"timing_hit"`
}

type StatusMsg struct {
	Type     string `msgpack:"type"`
	Phase    string `msgpack:"phase"`
	Detail   string `msgpack:"detail,omitempty"`
	Progress int    `msgpack:"progress"`
}

type ScanDoneMsg struct {
	Type       string `msgpack:"type"`
	TotalNodes int64  `msgpack:"total_nodes"`
}

type ErrorMsg struct {
	Type    string `msgpack:"type"`
	Message string `msgpack:"message"`
}

type EngineInfo struct {
	Name    string `msgpack:"name"`
	Version string `msgpack:"version"`
	OS      string `msgpack:"os"`
	Arch    string `msgpack:"arch"`
}

var outEnc *msgpack.Encoder
var outMu sync.Mutex

func emit(v any) {
	outMu.Lock()
	defer outMu.Unlock()
	if outEnc != nil {
		_ = outEnc.Encode(v)
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

type crawler struct {
	client       *RawClient
	cfg          ScanConfig
	seen         sync.Map
	queue        chan crawlJob
	wg           sync.WaitGroup
	total        atomic.Int64
	crawled      atomic.Int64
	pendingMu    sync.Mutex
	pendingJobs  []crawlJob
	queueManager chan struct{}
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

	var rateTicker <-chan time.Time
	if c.cfg.RPS > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(c.cfg.RPS))
		defer ticker.Stop()
		rateTicker = ticker.C
	}

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

	for _, seed := range seeds {
		c.enqueue(crawlJob{rawURL: seed, depth: 0})
	}

	go func() {
		c.wg.Wait()
		close(c.queueManager)
		close(c.queue)
	}()
}

func (c *crawler) enqueue(job crawlJob) {
	c.pendingMu.Lock()
	c.pendingJobs = append(c.pendingJobs, job)
	c.pendingMu.Unlock()
	select {
	case c.queueManager <- struct{}{}:
	default:
	}
}

func (c *crawler) visit(job crawlJob) {
	defer c.wg.Done()

	resp, err := c.client.Do("GET", job.rawURL, nil, nil)
	if err != nil {
		return
	}

	c.crawled.Add(1)

	u, _ := url.Parse(job.rawURL)
	var params []string
	for k := range u.Query() {
		params = append(params, k)
	}

	emit(NodeMsg{
		Type:   "node",
		URL:    job.rawURL,
		Params: params,
		Score:  1.0, // simplified score
		Depth:  job.depth,
	})
// Emit periodic progress
crawled := c.crawled.Load()
if crawled%5 == 0 {
	total := c.total.Load()
	var pct int
	if total > 0 {
		pct = int(crawled * 100 / total)
	}
	emit(StatusMsg{
		Type:     "status",
		Phase:    "CRAWLING",
		Detail:   fmt.Sprintf("Scanning: %s", job.rawURL),
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
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			base, err := url.Parse(job.rawURL)
			if err != nil {
				return
			}
			links := extractLinks(base, bytes.NewReader(resp.Body))
			for _, link := range links {
				c.enqueue(crawlJob{rawURL: link, depth: job.depth + 1})
			}
		}()
	}
}

func handleFuzzJob(client *RawClient, msg InMessage) {
	targetURL := msg.URL
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

	resp, err := client.Do(method, targetURL, nil, nil)
	if err != nil {
		emit(ErrorMsg{Type: "error", Message: fmt.Sprintf("fuzz_job request error: %v", err)})
		return
	}

	bodyStr := string(resp.Body)
	reflect := msg.Payload != "" && strings.Contains(bodyStr, msg.Payload)
	timingMs := resp.Timing.Milliseconds()
	timingHit := timingMs > 4500

	emit(FuzzResultMsg{
		Type:      "fuzz_result",
		JobID:     msg.JobID,
		Status:    resp.StatusCode,
		BodyLen:   int64(len(resp.Body)),
		TimingMs:  timingMs,
		Reflect:   reflect,
		TimingHit: timingHit,
	})
}

func serve(socketPath string) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to connect to socket: %v", err)
	}
	defer conn.Close()

	outMu.Lock()
	outEnc = msgpack.NewEncoder(conn)
	outMu.Unlock()

	dec := msgpack.NewDecoder(conn)

	var (
		client     *RawClient
		fuzzWg     sync.WaitGroup
		fuzzSem    chan struct{}
		crawlDone  chan struct{}
	)

	for {
		var msg InMessage
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				break
			}
			emit(ErrorMsg{Type: "error", Message: fmt.Sprintf("msgpack decode error: %v", err)})
			continue
		}

		switch msg.Type {
		case "scan_start":
			cfg := msg.Config
			client = &RawClient{
				Timeout:   time.Duration(cfg.Timeout) * time.Second,
				UserAgent: cfg.UA,
			}
			if client.Timeout == 0 {
				client.Timeout = 30 * time.Second
			}

			fuzzSem = make(chan struct{}, max(cfg.Workers, 10))
			emit(StatusMsg{Type: "status", Phase: "crawling", Progress: 0})

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
				client = &RawClient{Timeout: 30 * time.Second}
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
			emit(ErrorMsg{Type: "error", Message: fmt.Sprintf("unknown type: %s", msg.Type)})
		}
	}

	fuzzWg.Wait()
	if crawlDone != nil {
		<-crawlDone
	}
}

func main() {
	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	socketPath := serveCmd.String("socket", "", "Unix domain socket path")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serveCmd.Parse(os.Args[2:])
		if *socketPath == "" {
			fmt.Println("Error: --socket is required for serve")
			os.Exit(1)
		}
		serve(*socketPath)

	case "info":
		info := EngineInfo{
			Name:    "whale-engine",
			Version: "3.0.0-optimized",
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
		}
		b, _ := msgpack.Marshal(info)
		os.Stdout.Write(b)

	case "check":
		fmt.Printf("whale-engine-raw ok - %s/%s\n", runtime.GOOS, runtime.GOARCH)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Blue Whale Engine (Raw Protocol Mode)\nUsage: whale-engine <command> [args]")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
