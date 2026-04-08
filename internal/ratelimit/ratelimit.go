// Package ratelimit implements in-memory token bucket rate limiting.
package ratelimit

import (
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// Result is the outcome of a rate limit check.
type Result struct {
	Exceeded bool
	Rule     *policy.RateLimit
	Message  string
}

// Checker is the interface for rate limit backends (in-memory or Redis).
type Checker interface {
	Check(toolName, agentIdentity string) Result
}

// Limiter evaluates rate limits for tool calls using in-memory token buckets.
type Limiter struct {
	rules   []policy.RateLimit
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens    float64
	capacity  float64
	rate      float64 // tokens per second
	lastCheck time.Time
}

// NewLimiter creates a rate limiter from policy config.
func NewLimiter(rules []policy.RateLimit) *Limiter {
	return &Limiter{
		rules:   rules,
		buckets: make(map[string]*bucket),
	}
}

// Check evaluates all rate limits for a tool call.
// Returns the first exceeded limit, or a non-exceeded result.
func (l *Limiter) Check(toolName, agentIdentity string) Result {
	if len(l.rules) == 0 {
		return Result{}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	for i := range l.rules {
		rule := &l.rules[i]
		if !matchTools(rule.Match.Tools, toolName) {
			continue
		}

		key := bucketKey(rule, toolName, agentIdentity)
		b := l.getOrCreateBucket(key, rule, now)

		// Refill tokens
		elapsed := now.Sub(b.lastCheck).Seconds()
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.lastCheck = now

		// Try to consume
		if b.tokens < 1 {
			msg := rule.DenyMessage
			if msg == "" {
				msg = fmt.Sprintf("Rate limit exceeded: %d requests per %s",
					rule.Limit.Requests, rule.Limit.Window.Duration)
			}
			return Result{Exceeded: true, Rule: rule, Message: msg}
		}
		b.tokens--
	}

	return Result{}
}

func (l *Limiter) getOrCreateBucket(key string, rule *policy.RateLimit, now time.Time) *bucket {
	b, ok := l.buckets[key]
	if !ok {
		capacity := float64(rule.Limit.Requests)
		rate := capacity / rule.Limit.Window.Duration.Seconds()
		b = &bucket{
			tokens:    capacity,
			capacity:  capacity,
			rate:      rate,
			lastCheck: now,
		}
		l.buckets[key] = b
	}
	return b
}

func bucketKey(rule *policy.RateLimit, toolName, agentIdentity string) string {
	switch rule.Key {
	case "tool":
		return rule.Name + ":" + toolName
	case "global":
		return rule.Name + ":global"
	default: // "agent" or empty
		return rule.Name + ":" + agentIdentity
	}
}

func matchTools(patterns []string, toolName string) bool {
	for _, p := range patterns {
		if matched, _ := path.Match(p, toolName); matched {
			return true
		}
	}
	return false
}
