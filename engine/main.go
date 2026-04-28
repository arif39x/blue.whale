package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
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
	// payload_response
	Param    string   `msgpack:"param,omitempty"`
	Payloads []string `msgpack:"payloads,omitempty"`
}

type ScanConfig struct {
	Workers         int               `msgpack:"workers"`
	MaxDepth        int               `msgpack:"max_depth"`
	UAs             []string          `msgpack:"user_agents"`
	Headers         map[string]string `msgpack:"headers"`
	RPS             float64           `msgpack:"rps"`
	Timeout         int               `msgpack:"timeout_seconds"`
	StealthMode     bool              `msgpack:"stealth_mode"`
	Jitter          bool              `msgpack:"jitter"`
	Proxies         []string          `msgpack:"proxies"`
	CooldownSeconds int               `msgpack:"cooldown_seconds"`
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

type PayloadRequestMsg struct {
	Type  string `msgpack:"type"`
	Param string `msgpack:"param"`
}

type PayloadResponseMsg struct {
	Type     string   `msgpack:"type"`
	Payloads []string `msgpack:"payloads"`
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
	sm           *StateMachine
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
					time.Sleep(500 * time.Millisecond) // Max 2 RPS for seeds
				} else if rateTicker != nil {
					<-rateTicker
				}
				c.visit(job)
			}
		}()
	}

	go func() {
		for range c.queueManager {
			c.pendingMu.Lock()
			batch := c.pendingJobs
			c.pendingJobs = make([]crawlJob, 0, workers*10)
			c.pendingMu.Unlock()

			for _, job := range batch {
				c.total.Add(1)
				c.queue <- job
			}
		}
	}()

	for _, seed := range seeds {
		c.enqueue(crawlJob{rawURL: seed, depth: 0})
	}

	c.wg.Wait()

	close(c.queue)
	workerWg.Wait()
	close(c.queueManager)
}

func (c *crawler) enqueue(job crawlJob) {
	if _, loaded := c.seen.LoadOrStore(job.rawURL, true); loaded {
		return
	}

	c.wg.Add(1) // Track the job immediately upon discovery

	c.pendingMu.Lock()
	c.pendingJobs = append(c.pendingJobs, job)
	c.pendingMu.Unlock()
	select {
	case c.queueManager <- struct{}{}:
	default:
	}
}

func (c *crawler) visit(job crawlJob) {
	defer c.wg.Done() // Signal job completion

	resp, err := c.client.Do("GET", job.rawURL, c.cfg.Headers, nil)
	if err != nil {
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

func serve(socketPath string) {
	// Check if engine/templates exists
	if _, err := os.Stat("engine/templates"); os.IsNotExist(err) {
		log.Printf("Error: engine/templates directory not found in current working directory (%s)", os.Getenv("PWD"))
	}

	templates, err := LoadTemplates("engine/templates")
	if err != nil {
		log.Printf("Warning: failed to load templates: %v", err)
	}

	var conn net.Conn
	for i := 0; i < 15; i++ {
		conn, err = net.Dial("unix", socketPath)
		if err == nil {
			break
		}
		log.Printf("Waiting for socket %s (attempt %d/15) error: %v", socketPath, i+1, err)
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		log.Fatalf("CRITICAL: Failed to connect to socket %s after 15 attempts: %v", socketPath, err)
	}
	defer conn.Close()

	outMu.Lock()
	outEnc = msgpack.NewEncoder(conn)
	outMu.Unlock()

	dec := msgpack.NewDecoder(conn)

	var (
		client    *RawClient
		sm        *StateMachine
		crawlDone chan struct{}
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
			rl := NewHostRateLimiter()
			rl.Jitter = cfg.Jitter

			jar, _ := cookiejar.New(nil)

			client = &RawClient{
				Timeout:          time.Duration(cfg.Timeout) * time.Second,
				UserAgents:       cfg.UAs,
				RateLimiter:      rl,
				RPS:              cfg.RPS,
				StealthMode:      cfg.StealthMode,
				Proxies:          cfg.Proxies,
				Jar:              jar,
				CooldownDuration: time.Duration(cfg.CooldownSeconds) * time.Second,
			}
			if client.Timeout == 0 {
				client.Timeout = 30 * time.Second
			}

			sm = NewStateMachine(templates, client, cfg.Headers)

			emit(StatusMsg{Type: "status", Phase: "crawling", Progress: 0})

			crawlDone = make(chan struct{})
			c := &crawler{client: client, cfg: cfg, sm: sm}
			go func() {
				c.run(msg.Targets)
				close(crawlDone)

				emit(StatusMsg{Type: "status", Phase: "SCANNING", Progress: 0, Detail: "Crawler finished. Starting scan phase..."})
				sm.Scan()

				emit(ScanDoneMsg{
					Type:       "scan_done",
					TotalNodes: c.crawled.Load(),
				})
			}()

		case "payload_response":
			if sm != nil {
				sm.mu.Lock()
				if ch, ok := sm.payloadRequests[msg.Param]; ok {
					ch <- msg.Payloads
					delete(sm.payloadRequests, msg.Param)
				}
				sm.mu.Unlock()
			}

		default:
			emit(ErrorMsg{Type: "error", Message: fmt.Sprintf("unknown type: %s", msg.Type)})
		}
	}

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
			Version: "4.0.0-template-based",
			OS:      runtime.GOOS,
			Arch:    runtime.GOARCH,
		}
		b, _ := msgpack.Marshal(info)
		os.Stdout.Write(b)

	case "check":
		fmt.Printf("whale-engine ok - %s/%s\n", runtime.GOOS, runtime.GOARCH)

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Blue Whale Engine (Autonomous Mode)\nUsage: whale-engine <command> [args]")
}
