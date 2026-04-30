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
	mu            sync.Mutex
	baseRPS       float64
	currentRPS    float64
	ticker        *time.Ticker
	duration      time.Duration
	blocked       bool
	unblock       chan struct{}

	targetLatency time.Duration
	kp, ki, kd    float64
	integral      float64
	prevError     float64
	lastUpdate    time.Time
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
			baseRPS:       float64(rps),
			currentRPS:    float64(rps),
			ticker:        time.NewTicker(d),
			duration:      d,
			unblock:       make(chan struct{}),
			targetLatency: 300 * time.Millisecond,
			kp:            0.1,
			ki:            0.01,
			kd:            0.05,
			lastUpdate:    time.Now(),
		}
		hrl.hosts[host] = rl
	}
	return rl
}

func (hrl *HostRateLimiter) UpdateLatency(host string, latency time.Duration) {
	hrl.mu.Lock()
	rl, ok := hrl.hosts[host]
	hrl.mu.Unlock()

	if !ok {
		return
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	dt := now.Sub(rl.lastUpdate).Seconds()
	if dt <= 0 {
		return
	}

	err := rl.targetLatency.Seconds() - latency.Seconds()

	rl.integral += err * dt
	derivative := (err - rl.prevError) / dt

	output := (rl.kp * err) + (rl.ki * rl.integral) + (rl.kd * derivative)
	rl.prevError = err
	rl.lastUpdate = now

	newRPS := rl.currentRPS + output
	if newRPS < 1 {
		newRPS = 1
	} else if newRPS > rl.baseRPS*2 {
		newRPS = rl.baseRPS * 2
	}

	if newRPS != rl.currentRPS {
		rl.currentRPS = newRPS
		rl.duration = time.Duration(float64(time.Second) / newRPS)
		rl.ticker.Reset(rl.duration)
	}
}

func (hrl *HostRateLimiter) Wait(host string, rps int) {
	rl := hrl.getRL(host, rps)

	rl.mu.Lock()
	if rl.blocked {
		unblock := rl.unblock
		rl.mu.Unlock()
		<-unblock

		time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
	} else {
		tickerC := rl.ticker.C
		rl.mu.Unlock()
		<-tickerC
	}

	if hrl.Jitter {
		mu := float64(rl.duration)
		sigma := mu * 0.3
		jitter := mu + (sigma * rand.NormFloat64())
		if jitter < 0 {
			jitter = 0
		}
		time.Sleep(time.Duration(jitter))
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
