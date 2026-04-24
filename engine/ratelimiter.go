package main

import (
	"math/rand"
	"sync"
	"time"
)

type HostRateLimiter struct {
	mu     sync.Mutex
	hosts  map[string]*rateLimit
	Jitter bool
}

type rateLimit struct {
	mu       sync.Mutex
	ticker   *time.Ticker
	duration time.Duration
	blocked  bool
	unblock  chan struct{}
}

func NewHostRateLimiter() *HostRateLimiter {
	return &HostRateLimiter{
		hosts: make(map[string]*rateLimit),
	}
}

func (hrl *HostRateLimiter) getRL(host string, rps int) *rateLimit {
	hrl.mu.Lock()
	defer hrl.mu.Unlock()

	rl, ok := hrl.hosts[host]
	if !ok {
		d := time.Second / time.Duration(rps)
		rl = &rateLimit{
			ticker:   time.NewTicker(d),
			duration: d,
			unblock:  make(chan struct{}),
		}
		hrl.hosts[host] = rl
	}
	return rl
}

func (hrl *HostRateLimiter) Wait(host string, rps int) {
	rl := hrl.getRL(host, rps)

	if hrl.Jitter {
		jitter := time.Duration(float64(rl.duration) * (0.5 + 1.0*rand.Float64()))
		time.Sleep(jitter)
		return
	}

	for {
		rl.mu.Lock()
		if !rl.blocked {
			tickerC := rl.ticker.C
			rl.mu.Unlock()
			<-tickerC
			return
		}
		unblock := rl.unblock
		rl.mu.Unlock()
		<-unblock
	}
}

func (hrl *HostRateLimiter) Block(host string, duration time.Duration) {
	hrl.mu.Lock()
	rl, ok := hrl.hosts[host]
	hrl.mu.Unlock()

	if ok {
		rl.mu.Lock()
		if rl.blocked {
			rl.mu.Unlock()
			return
		}
		rl.blocked = true
		rl.ticker.Stop()
		rl.unblock = make(chan struct{})
		rl.mu.Unlock()

		go func() {
			time.Sleep(duration)
			rl.mu.Lock()
			rl.blocked = false
			rl.ticker = time.NewTicker(rl.duration)
			close(rl.unblock)
			rl.mu.Unlock()
		}()
	}
}

