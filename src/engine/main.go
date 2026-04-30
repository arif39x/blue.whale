package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http/cookiejar"
	"net/url"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

type InMessage struct {
	Type   string `msgpack:"type"`
	Action string `msgpack:"action,omitempty"`
	// scan_start
	Targets []string   `msgpack:"targets,omitempty"`
	Config  ScanConfig `msgpack:"config,omitempty"`
	// fuzz_only nodes
	Nodes []string `msgpack:"nodes,omitempty"`
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
	TorMode         bool              `msgpack:"tor_mode"`
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

func serve(socketPath string) {
	if _, err := os.Stat("src/engine/templates"); os.IsNotExist(err) {
		log.Printf("Error: src/engine/templates directory not found in current working directory (%s)", os.Getenv("PWD"))
	}

	templates, err := LoadTemplates("src/engine/templates")
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
				TorMode:          cfg.TorMode,
				StealthMode:      cfg.StealthMode,
				Proxies:          cfg.Proxies,
				Jar:              jar,
				CooldownDuration: time.Duration(cfg.CooldownSeconds) * time.Second,
			}
			if client.Timeout == 0 {
				client.Timeout = 30 * time.Second
			}

			sm = NewStateMachine(templates, client, cfg.Headers)

			action := msg.Action
			if action == "" {
				action = "both"
			}

			crawlDone = make(chan struct{})
			c := &crawler{client: client, cfg: cfg, sm: sm}

			go func() {
				defer close(crawlDone)

				if action == "crawl" || action == "both" {
					emit(StatusMsg{Type: "status", Phase: "crawling", Progress: 0})
					c.run(msg.Targets)
				}

				if action == "fuzz" {
					// Manually inject nodes if fuzzing only
					for _, rawURL := range msg.Nodes {
						u, _ := url.Parse(rawURL)
						var params []string
						if u != nil {
							for k := range u.Query() {
								params = append(params, k)
							}
						}
						sm.ProcessNode(rawURL, params, nil, nil)
					}
				}

				if action == "fuzz" || action == "both" {
					emit(StatusMsg{Type: "status", Phase: "SCANNING", Progress: 0, Detail: "Starting scan phase..."})
					sm.Scan()
				}

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
