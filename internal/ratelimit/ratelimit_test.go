package ratelimit

import (
	"testing"
	"time"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

func dur(s string) policy.Duration {
	var d policy.Duration
	switch s {
	case "1s":
		d.Duration = time.Second
	case "10s":
		d.Duration = 10 * time.Second
	case "60s":
		d.Duration = 60 * time.Second
	}
	return d
}

func TestLimiter_AllowWithinLimit(t *testing.T) {
	l := NewLimiter([]policy.RateLimit{
		{
			Name:  "test",
			Match: policy.RateLimitMatch{Tools: []string{"*"}},
			Limit: policy.RateLimitSpec{Requests: 5, Window: dur("60s")},
			Key:   "agent",
		},
	})

	for i := 0; i < 5; i++ {
		r := l.Check("echo", "agent-1")
		if r.Exceeded {
			t.Fatalf("request %d should not be rate limited", i+1)
		}
	}
}

func TestLimiter_DenyOnExceed(t *testing.T) {
	l := NewLimiter([]policy.RateLimit{
		{
			Name:  "test",
			Match: policy.RateLimitMatch{Tools: []string{"*"}},
			Limit: policy.RateLimitSpec{Requests: 3, Window: dur("60s")},
			Key:   "agent",
		},
	})

	for i := 0; i < 3; i++ {
		l.Check("echo", "agent-1")
	}

	r := l.Check("echo", "agent-1")
	if !r.Exceeded {
		t.Error("4th request should be rate limited")
	}
	if r.Rule.Name != "test" {
		t.Errorf("Rule.Name = %q, want %q", r.Rule.Name, "test")
	}
}

func TestLimiter_PerAgentIsolation(t *testing.T) {
	l := NewLimiter([]policy.RateLimit{
		{
			Name:  "test",
			Match: policy.RateLimitMatch{Tools: []string{"*"}},
			Limit: policy.RateLimitSpec{Requests: 2, Window: dur("60s")},
			Key:   "agent",
		},
	})

	// Exhaust agent-1's limit
	l.Check("echo", "agent-1")
	l.Check("echo", "agent-1")
	r := l.Check("echo", "agent-1")
	if !r.Exceeded {
		t.Error("agent-1 should be rate limited")
	}

	// agent-2 should still have capacity
	r = l.Check("echo", "agent-2")
	if r.Exceeded {
		t.Error("agent-2 should NOT be rate limited")
	}
}

func TestLimiter_ToolGlobMatch(t *testing.T) {
	l := NewLimiter([]policy.RateLimit{
		{
			Name:  "db-limit",
			Match: policy.RateLimitMatch{Tools: []string{"database.*"}},
			Limit: policy.RateLimitSpec{Requests: 1, Window: dur("60s")},
			Key:   "agent",
		},
	})

	// database.query should match
	l.Check("database.query", "agent-1")
	r := l.Check("database.query", "agent-1")
	if !r.Exceeded {
		t.Error("database.query should be rate limited")
	}

	// echo should not match the rule
	r = l.Check("echo", "agent-1")
	if r.Exceeded {
		t.Error("echo should NOT be rate limited by database.* rule")
	}
}

func TestLimiter_GlobalKey(t *testing.T) {
	l := NewLimiter([]policy.RateLimit{
		{
			Name:  "global",
			Match: policy.RateLimitMatch{Tools: []string{"*"}},
			Limit: policy.RateLimitSpec{Requests: 2, Window: dur("60s")},
			Key:   "global",
		},
	})

	l.Check("echo", "agent-1")
	l.Check("echo", "agent-2")
	r := l.Check("echo", "agent-3")
	if !r.Exceeded {
		t.Error("global limit should be shared across agents")
	}
}

func TestLimiter_NoRules(t *testing.T) {
	l := NewLimiter(nil)
	r := l.Check("anything", "anyone")
	if r.Exceeded {
		t.Error("no rules should mean no rate limiting")
	}
}

func TestLimiter_CustomDenyMessage(t *testing.T) {
	l := NewLimiter([]policy.RateLimit{
		{
			Name:        "test",
			Match:       policy.RateLimitMatch{Tools: []string{"*"}},
			Limit:       policy.RateLimitSpec{Requests: 1, Window: dur("60s")},
			Key:         "agent",
			DenyMessage: "custom message",
		},
	})

	l.Check("echo", "agent")
	r := l.Check("echo", "agent")
	if r.Message != "custom message" {
		t.Errorf("Message = %q, want %q", r.Message, "custom message")
	}
}
