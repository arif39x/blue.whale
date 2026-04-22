package main

import (
	"sync"
	"time"
)

type HostRateLimiter struct {
	mu     sync.Mutex
	hosts  map[string]*rateLimit
	Jitter bool
}

type rateLimit struct {
	ticker     *time.Ticker
	duration   time.Duration
	lastUpdate time.Time
	blocked    bool
}

func NewHostRateLimiter() *HostRateLimiter {
	return &HostRateLimiter{
		hosts: make(map[string]*rateLimit),
	}
}

func (hrl *HostRateLimiter) Wait(host string, rps int) {
	hrl.mu.Lock()
	rl, ok := hrl.hosts[host]
	if !ok {
		d := time.Second / time.Duration(rps)
		rl = &rateLimit{
			ticker:   time.NewTicker(d),
			duration: d,
		}
		hrl.hosts[host] = rl
	}
	hrl.mu.Unlock()

	if hrl.Jitter {
		// Add random jitter between 50% and 150% of the duration
		jitter := time.Duration(float64(rl.duration) * (0.5 + 1.0*randFloat()))
		time.Sleep(jitter)
	} else {
		<-rl.ticker.C
	}
}

func randFloat() float64 {
	// Simple non-cryptographic random for jitter
	return float64(time.Now().UnixNano()%1000) / 1000.0
}

func (hrl *HostRateLimiter) Block(host string, duration time.Duration) {
	hrl.mu.Lock()
	rl, ok := hrl.hosts[host]
	if ok {
		rl.blocked = true
		rl.ticker.Stop()
		go func() {
			time.Sleep(duration)
			hrl.mu.Lock()
			rl.blocked = false
			rl.ticker = time.NewTicker(rl.duration)
			hrl.mu.Unlock()
		}()
	}
	hrl.mu.Unlock()
}
