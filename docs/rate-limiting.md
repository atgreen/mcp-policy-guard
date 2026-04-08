# Rate Limiting

Rate limits are evaluated before policy rules. If a rate limit is exceeded, the tool call is rejected immediately with a JSON-RPC error.

## Configuration

```yaml
rate_limits:
  - name: "global-limit"
    match:
      tools: ["*"]              # Glob patterns
    limit:
      requests: 100
      window: 60s               # Duration: ms, s, m, h
    key: agent                  # agent | tool | global
    on_exceed: deny             # deny | escalate
    deny_message: "Rate limit exceeded"
    escalate:                   # Optional. Fire on exceed.
      channel: oncall
      trigger_name: "rate-limit-exceeded"
```

## Keys

| Key | Behavior |
|---|---|
| `agent` | Per-agent counters. Each agent identity has its own budget. (Default) |
| `tool` | Per-tool counters. Each tool name has its own budget, shared across agents. |
| `global` | Single counter shared across all agents and tools matching the rule. |

## Backends

### In-memory (default)

Token bucket counters in process memory. No external dependencies. Suitable for single-instance deployments.

```bash
mcp-policy-guard --policy policy.yaml -- mcp-server
```

### Redis

Shared counters via Redis for multi-instance deployments (e.g., multiple sidecars sharing a global limit).

```bash
mcp-policy-guard \
  --policy policy.yaml \
  --listen :8081 \
  --upstream http://mcp-gateway:8080/mcp \
  --redis redis://redis:6379
```

The `--redis` flag switches all rate limit counters to Redis. The Redis URL supports standard `redis://` and `rediss://` (TLS) schemes.

Counters use atomic `INCR` with key expiry matching the window duration. On Redis errors, rate limiting fails open (allows the request).

## Escalation on exceed

When a rate limit is exceeded and `escalate` is configured, a fire-and-forget webhook is sent to the named escalation channel:

```yaml
rate_limits:
  - name: "burst-protection"
    match:
      tools: ["payments.*"]
    limit:
      requests: 5
      window: 10s
    on_exceed: deny
    escalate:
      channel: oncall
      trigger_name: "payment-burst"
```
