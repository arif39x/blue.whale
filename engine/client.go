package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	Timeout   time.Duration
	UserAgent string
}

func (c *RawClient) Do(method, targetURL string, headers map[string]string, body []byte) (*RawResponse, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, err
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
	defer cancel()

	var conn net.Conn
	dialer := &net.Dialer{}
	
	conn, err = dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if u.Scheme == "https" {
		// Use utls for JA3 spoofing (Chrome 120 profile)
		uconn := utls.UClient(conn, &utls.Config{ServerName: u.Hostname(), InsecureSkipVerify: true}, utls.HelloChrome_120)
		if err := uconn.Handshake(); err != nil {
			return nil, err
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
	
	if c.UserAgent != "" {
		reqBuf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", c.UserAgent))
	}
	
	for k, v := range headers {
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
		return nil, err
	}

	// Parse response
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	timing := time.Since(start)

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return nil, err
	}

	return &RawResponse{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       respBody,
		Timing:     timing,
	}, nil
}

// SinglePacketAttack sends multiple requests' headers and releases the last byte simultaneously.
func (c *RawClient) SinglePacketAttack(targetURL string, payloads []string) ([]*RawResponse, error) {
	// Implementation for race condition testing (Phase 2.4)
	// Simplified version: just send sequentially for now, but placeholder for the real thing
	results := make([]*RawResponse, 0, len(payloads))
	for _, p := range payloads {
		res, err := c.Do("GET", targetURL+"?fuzz="+url.QueryEscape(p), nil, nil)
		if err == nil {
			results = append(results, res)
		}
	}
	return results, nil
}
