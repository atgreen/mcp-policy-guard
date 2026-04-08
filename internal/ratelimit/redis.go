package ratelimit

import (
	"context"
	"fmt"
	"path"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// RedisLimiter uses Redis for shared rate limit counters across instances.
type RedisLimiter struct {
	rules  []policy.RateLimit
	client *redis.Client
}

// NewRedisLimiter creates a Redis-backed rate limiter.
func NewRedisLimiter(rules []policy.RateLimit, redisURL string) (*RedisLimiter, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing Redis URL: %w", err)
	}
	client := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("connecting to Redis: %w", err)
	}

	return &RedisLimiter{rules: rules, client: client}, nil
}

// Check evaluates rate limits using Redis atomic counters.
func (l *RedisLimiter) Check(toolName, agentIdentity string) Result {
	if len(l.rules) == 0 {
		return Result{}
	}

	ctx := context.Background()

	for i := range l.rules {
		rule := &l.rules[i]
		if !matchRedisTools(rule.Match.Tools, toolName) {
			continue
		}

		key := "mcp-policy-guard:rl:" + redisBucketKey(rule, toolName, agentIdentity)
		window := rule.Limit.Window.Duration

		// Atomic increment with expiry
		count, err := l.client.Incr(ctx, key).Result()
		if err != nil {
			continue // fail open on Redis errors
		}

		// Set TTL on first increment
		if count == 1 {
			l.client.Expire(ctx, key, window)
		}

		if count > int64(rule.Limit.Requests) {
			msg := rule.DenyMessage
			if msg == "" {
				msg = fmt.Sprintf("Rate limit exceeded: %d requests per %s",
					rule.Limit.Requests, rule.Limit.Window.Duration)
			}
			return Result{Exceeded: true, Rule: rule, Message: msg}
		}
	}

	return Result{}
}

// Close closes the Redis connection.
func (l *RedisLimiter) Close() error {
	return l.client.Close()
}

func redisBucketKey(rule *policy.RateLimit, toolName, agentIdentity string) string {
	switch rule.Key {
	case "tool":
		return rule.Name + ":" + toolName
	case "global":
		return rule.Name + ":global"
	default:
		return rule.Name + ":" + agentIdentity
	}
}

func matchRedisTools(patterns []string, toolName string) bool {
	for _, p := range patterns {
		if matched, _ := path.Match(p, toolName); matched {
			return true
		}
	}
	return false
}
