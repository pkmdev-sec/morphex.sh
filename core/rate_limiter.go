// rate_limiter.go -- Tier 3: Performance - API Rate Limiting
//
// Token bucket rate limiter for controlling API call rates during
// verification and blast radius analysis. Prevents overwhelming
// target services. Standard library only, no external deps.
package synapse

import (
	"context"
	"sync"
	"time"
)

// RateLimiter controls the rate of API calls during verification.
// Prevents overwhelming target services.
type RateLimiter struct {
	limiters map[string]*serviceLimiter
	mu       sync.RWMutex
	defaults RateLimitConfig
}

// RateLimitConfig configures rate limiting for a service.
type RateLimitConfig struct {
	RequestsPerSecond float64
	BurstSize         int
}

// serviceLimiter implements a token bucket for a single service.
type serviceLimiter struct {
	tokens    float64
	maxTokens float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// Per-service defaults matching API rate limits.
var defaultServiceLimits = map[string]RateLimitConfig{
	"github.com":       {RequestsPerSecond: 5, BurstSize: 10},
	"api.stripe.com":   {RequestsPerSecond: 25, BurstSize: 50},
	"slack.com":        {RequestsPerSecond: 1, BurstSize: 3},
	"api.sendgrid.com": {RequestsPerSecond: 3, BurstSize: 5},
	"gitlab.com":       {RequestsPerSecond: 10, BurstSize: 20},
}

// NewRateLimiter creates a new rate limiter with the given defaults.
func NewRateLimiter(defaults RateLimitConfig) *RateLimiter {
	if defaults.RequestsPerSecond <= 0 {
		defaults.RequestsPerSecond = 10
	}
	if defaults.BurstSize <= 0 {
		defaults.BurstSize = 20
	}
	return &RateLimiter{
		limiters: make(map[string]*serviceLimiter),
		defaults: defaults,
	}
}

// Wait blocks until a token is available for the given service, or the context is cancelled.
func (rl *RateLimiter) Wait(ctx context.Context, service string) error {
	for {
		if rl.TryAcquire(service) {
			return nil
		}

		// Calculate how long to wait for next token
		sl := rl.getLimiter(service)
		sl.mu.Lock()
		waitDur := time.Duration(float64(time.Second) / sl.refillRate)
		sl.mu.Unlock()

		// Cap minimum wait to avoid busy-spinning
		if waitDur < time.Millisecond {
			waitDur = time.Millisecond
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitDur):
			// retry
		}
	}
}

// TryAcquire attempts to acquire a token for the given service without blocking.
// Returns true if a token was acquired, false if rate limited.
func (rl *RateLimiter) TryAcquire(service string) bool {
	sl := rl.getLimiter(service)

	sl.mu.Lock()
	defer sl.mu.Unlock()

	// Refill tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(sl.lastRefill).Seconds()
	sl.tokens += elapsed * sl.refillRate
	if sl.tokens > sl.maxTokens {
		sl.tokens = sl.maxTokens
	}
	sl.lastRefill = now

	// Try to consume a token
	if sl.tokens >= 1.0 {
		sl.tokens -= 1.0
		return true
	}
	return false
}

// getLimiter returns or creates a service-specific limiter.
func (rl *RateLimiter) getLimiter(service string) *serviceLimiter {
	rl.mu.RLock()
	sl, ok := rl.limiters[service]
	rl.mu.RUnlock()
	if ok {
		return sl
	}

	// Create new limiter
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Double-check after acquiring write lock
	if sl, ok := rl.limiters[service]; ok {
		return sl
	}

	config := rl.defaults
	if svcConfig, ok := defaultServiceLimits[service]; ok {
		config = svcConfig
	}

	sl = &serviceLimiter{
		tokens:     float64(config.BurstSize), // start full
		maxTokens:  float64(config.BurstSize),
		refillRate: config.RequestsPerSecond,
		lastRefill: time.Now(),
	}
	rl.limiters[service] = sl
	return sl
}
