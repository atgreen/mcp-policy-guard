# mcp-policy-guard: Product Requirements Document

## Problem

The [FINOS Agent Card](https://github.com/finos/ai-reference-architecture-library/tree/main/Library/reference-architecture/agent-card) specification defines 18 governance policies for AI agents in regulated environments. Our [policy enforcement analysis](../adr/docs/policy-enforcement-options.md) found that 10 of these policies are best enforced at the MCP gateway layer -- but no MCP gateway implements the most critical ones today:

1. **Human-in-the-loop checkpoint hold** -- the A1/A2 oversight models require tool calls to be held pending human approval. No gateway supports this.
2. **Agent-card-driven policy** -- gateways support tool-level ACLs, but loading those ACLs from an agent card is manual. Operators configure the gateway separately from the card, creating drift.
3. **Escalation trigger evaluation** -- the card declares semantic conditions ("amount > $1M") on tool call content. No gateway evaluates expressions over tool arguments.
4. **Content filtering / DLP** -- PII detection and prompt injection scanning on MCP traffic.

These gaps exist because MCP gateways (including [Kuadrant's mcp-gateway](https://github.com/Kuadrant/mcp-gateway)) are infrastructure components focused on routing, authentication, and federation. They are not agent-card-aware policy engines.

## Proposal

**mcp-policy-guard** is a lightweight, protocol-aware policy middleware for MCP. It sits between any MCP client and server (or gateway) and enforces governance policies defined in a YAML policy file -- which can be derived directly from a FINOS Agent Card.

It is not a gateway. It does not do routing, federation, or authentication. It does one thing: **intercept MCP JSON-RPC tool calls and apply policy**.

```
MCP Client ── tools/call ──> mcp-policy-guard ── tools/call ──> MCP Server
                                    |                            (or gateway)
                              +-----------+
                              | Policy    |
                              | - approve?|
                              | - allow?  |
                              | - log?    |
                              | - redact? |
                              +-----------+
```

## Design principles

1. **Transport-level interception, not application-level.** mcp-policy-guard operates on MCP JSON-RPC messages. It does not need to understand what the tools do -- only their names and arguments.

2. **Works everywhere MCP works.** Two deployment modes:
   - **stdio proxy**: wraps an MCP server command. The client's MCP config just changes the command.
   - **HTTP reverse proxy**: sits in front of any streamable HTTP MCP endpoint.

   Same policy file, same enforcement, whether you're running Claude Code on a laptop or an agent fleet in OpenShift.

3. **The agent card is the policy source.** When pointed at a FINOS Agent Card, mcp-policy-guard derives rules automatically. The card's `approvedActionList` becomes a tool allowlist. The card's `humanOversightModel` sets approval requirements. The card's `escalationContacts` become webhook targets. Explicit rules in the policy file override card-derived rules.

4. **Composable, not monolithic.** mcp-policy-guard complements existing gateways. In Kubernetes, it runs as a sidecar alongside mcp-gateway. On a laptop, it wraps a local MCP server. It does not replace the gateway's auth, routing, or federation.

5. **Single static binary.** Go. No runtime dependencies. Easy to distribute, easy to audit.

## Deployment modes

### stdio proxy (developer / CLI)

The user changes their MCP client configuration to run tools through mcp-policy-guard:

```json
{
  "mcpServers": {
    "database": {
      "command": "mcp-policy-guard",
      "args": [
        "--policy", "policy.yaml",
        "--", "mcp-server-postgres", "--db", "prod"
      ]
    }
  }
}
```

mcp-policy-guard spawns the real server as a child process, relays stdio, and intercepts JSON-RPC messages in both directions. The MCP client is unaware of the middleware.

In this mode, human-in-the-loop approval uses `/dev/tty` to reach the controlling terminal -- the same technique `sudo` and `ssh` use when their stdin/stdout are pipes. Because stdin and stdout carry MCP JSON-RPC, the approval prompt cannot use either. Instead, mcp-policy-guard opens `/dev/tty` directly for both reading and writing:

```
 APPROVAL REQUIRED
 Tool:  database.execute_query
 Args:  {"sql": "DELETE FROM accounts WHERE status = 'inactive'"}
 Rule:  destructive-db-ops

 [a]pprove  [r]eject  [v]iew full args  >
```

**Limitations of terminal approval:**
- Unix only (Linux, macOS). No `/dev/tty` equivalent on Windows.
- Requires a controlling terminal. Fails in CI/CD, containers without a tty, and background processes.
- When `/dev/tty` is unavailable, falls back to the next configured approval channel (e.g., webhook). If no fallback is configured, the tool call is rejected.

This makes terminal approval a "developer at a workstation" feature, not a general-purpose mechanism. For headless and production environments, webhook or Slack approval channels are required.

### HTTP reverse proxy (gateway / Kubernetes)

mcp-policy-guard listens on an HTTP port and forwards to an upstream MCP endpoint:

```
mcp-policy-guard \
  --policy policy.yaml \
  --listen :8081 \
  --upstream http://mcp-gateway:8080/mcp
```

In Kubernetes, this runs as a sidecar container in the agent pod, or as a separate Deployment in front of mcp-gateway. The agent pod's egress points at the sidecar, and the sidecar forwards to the gateway.

In this mode, human-in-the-loop approval uses webhooks. When a tool call requires approval:

1. mcp-policy-guard POSTs the pending request to the configured approval endpoint
2. The proxy holds the HTTP response to the MCP client open (the SSE stream stays connected but no data events are sent) while waiting for approval
3. The approval service POSTs back to `mcp-policy-guard/approval/{request_id}` with the decision
4. On approval, the tool call is forwarded and the response relayed normally
5. On rejection or timeout, a JSON-RPC error is returned on the held connection

This works because MCP over streamable HTTP uses SSE for server-to-client messages. The SSE connection tolerates idle periods -- the proxy sends SSE keep-alive comments (`: keepalive\n\n`) during the hold to prevent intermediary timeouts. The MCP spec does not define a "pending" state for tool calls, so no protocol extension is needed -- from the client's perspective, the tool call simply takes longer to return.

### Kubernetes sidecar (with mcp-gateway)

```yaml
# Agent pod spec (abbreviated)
containers:
  - name: agent
    # Agent's MCP client points at localhost:8081 (the sidecar)
    env:
      - name: MCP_ENDPOINT
        value: "http://localhost:8081/mcp"

  - name: policy-guard
    image: ghcr.io/mcp-policy-guard:latest
    args:
      - --policy=/etc/policy/policy.yaml
      - --listen=:8081
      - --upstream=http://mcp-gateway.mcp-system:8080/mcp
    volumeMounts:
      - name: policy
        mountPath: /etc/policy

volumes:
  - name: policy
    configMap:
      name: agent-policy    # Generated from agent card
```

## Capabilities

### P0: Must have (v0.1)

#### 1. MCP JSON-RPC interception

Parse and intercept MCP JSON-RPC 2.0 messages over stdio and streamable HTTP transports. Specifically:

- `tools/call` requests: the primary policy enforcement point
- Pass through all other MCP methods (`initialize`, `tools/list`, `resources/*`, `prompts/*`, `ping`) unmodified

Note: `tools/list` filtering (hiding denied tools from the agent) is deferred to P2. In v0.1, the agent sees all tools but denied calls return an error. This keeps the transport adapter simple and avoids changing the observed tool set, which aids debugging.

Must handle:
- JSON-RPC batched requests (array of requests)
- Streaming responses (SSE)
- Request/response correlation by JSON-RPC `id`

#### 2. Tool allowlist

Match `tools/call` requests against an ordered list of rules. Each rule matches on tool name (glob pattern). First match wins. Actions: `allow`, `deny`.

When `defaults.action` is `deny`, only tools matching an explicit `allow` rule are forwarded. This implements the FINOS card's `governance.approvedActionList`.

Denied calls return a JSON-RPC error response to the client:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32600,
    "message": "Tool call denied by policy: database.drop_table",
    "data": {
      "rule": "default-deny",
      "policy_guard": true
    }
  }
}
```

#### 3. Human-in-the-loop approval

Rules with `action: require_approval` hold the tool call pending human review. Two approval channel types:

**Terminal (stdio mode, Unix only):**
- Opens `/dev/tty` directly -- stdin/stdout are reserved for JSON-RPC and cannot be used
- Display tool name, arguments (optionally truncated), and rule name
- Accept single-keystroke input: approve, reject, view full args
- Configurable timeout with auto-reject
- Falls back to next approval channel if `/dev/tty` is unavailable (no tty, container, CI)

**Webhook (HTTP mode):**
- POST pending request to configured endpoint (tool name, arguments, agent identity, request ID, rule name)
- Hold the client's SSE connection open during the approval wait, sending SSE keep-alive comments (`: keepalive\n\n`) to prevent intermediary timeouts
- Wait for callback POST to `/approval/{request_id}` with `{"decision": "approve"}` or `{"decision": "reject", "reason": "..."}`
- Alternatively, poll the approval endpoint (`callback_mode: poll`) if the approval service cannot make outbound callbacks
- Configurable timeout with reject or escalate on expiry
- Log approval decision, approver identity, and latency in audit trail

While held, the upstream MCP connection is not established. The tool call is only forwarded after approval. From the MCP client's perspective, the tool call simply takes longer to return -- no protocol extension is needed.

#### 4. Audit logging

Every intercepted `tools/call` (matching `audit: true`, which defaults to on) emits a structured audit record:

```json
{
  "timestamp": "2026-04-08T14:30:00Z",
  "request_id": "uuid",
  "agent": "trading-agent-1",
  "tool": "payments.submit",
  "arguments": { "amount": 50000, "currency": "USD" },
  "decision": "allow",
  "rule": "default-allow",
  "latency_ms": 12,
  "response_size_bytes": 1024
}
```

Output targets (configurable, multiple simultaneous):
- stdout (JSON or text)
- JSONL file with rotation
- Webhook (batched POST)

Redaction rules strip sensitive fields (password, token, ssn, etc.) from audit records before output.

#### 5. Policy file loading

Load policy from a YAML file. Validate against the machine-readable JSON Schema in `policy-schema.json` (JSON Schema Draft 2020-12). The schema is versioned with each release -- it defines exactly the fields the current binary supports. Unknown fields are rejected via `additionalProperties: false`. Support:
- Environment variable interpolation (`${VAR}` syntax) for secrets
- File watching with hot-reload on change (no restart required)
- Validation on load with clear error messages referencing schema constraints
- Either `rules` or `agent_card` (or both) must be present. When only `agent_card` is set, all rules are derived from the card

#### 6. Agent card derivation

When `agent_card.path` or `agent_card.url` is set, derive baseline rules from the FINOS Agent Card:

| Card field | Derived rule |
|---|---|
| `governance.approvedActionList` | Allow rule per listed action; default deny |
| `governance.humanOversightModel` = A1 | All tools require approval |
| `governance.humanOversightModel` = A2 | Tools with `requiresHumanApproval` require approval |
| `governance.escalationContacts` | Escalation channels from contact emails/triggers |
| `agentSecurity.rateLimiting.enabled` | Enable global rate limit (details from policy file) |

Explicit rules in the policy file take precedence over card-derived rules.

### P1: Should have (v0.2)

#### 7. CEL expression evaluation

Rules can include a `cel` field that evaluates a [Common Expression Language](https://github.com/google/cel-spec) expression over the tool call arguments. The expression receives:

- `args` -- the tool call arguments as a JSON object
- `tool` -- the tool name as a string
- `agent` -- the agent identity as a string

Examples:
- `double(args.amount) > 1000000.0` -- high-value transaction
- `args.sql.matches('(?i)(DELETE|DROP)')` -- destructive SQL
- `tool.startsWith("admin.")` -- admin tool namespace

CEL is chosen over JSONPath or Rego because it is:
- Designed for exactly this use case (policy evaluation over structured data)
- Side-effect-free and sandboxed (safe to evaluate on every request)
- Well-supported in Go via `google/cel-go`
- Already used in Kubernetes (ValidatingAdmissionPolicy, Gateway API)

This implements the FINOS card's `escalationContacts[].escalationTriggers` when triggers are expressed as CEL.

#### 8. Escalation webhooks

When a rule's CEL condition matches (or a rate limit is exceeded), fire an escalation:
- POST to configured webhook endpoint
- Payload from template with variable substitution
- Support Alertmanager, PagerDuty, and generic webhook formats
- Escalation is fire-and-forget -- it does not block the tool call (unless the rule action is also `deny` or `require_approval`)

#### 9. Rate limiting

Per-tool and per-agent token bucket rate limiting. Applied before rule matching.

- Key options: per-agent, per-tool, per-agent-per-tool, global
- On exceed: deny (return JSON-RPC error), or escalate
- In-memory counters (single instance). No external dependencies for v0.2.

#### 10. Content filters

Pattern-based inspection of tool arguments (request direction) and tool responses (response direction):
- Regex pattern matching for PII (SSN, credit card, email)
- Configurable action: block (return error), redact (replace matched content), flag (audit only)
- Applied after rule matching, before forwarding

#### 11. Kubernetes ConfigMap watching

When running in Kubernetes, watch a ConfigMap for policy changes. This enables a controller (built separately) to generate policy from agent cards and apply it as a ConfigMap, which mcp-policy-guard picks up automatically.

### P2: Nice to have (v0.3+)

#### 12. Argument mutation

Rules with `action: mutate` modify tool call arguments before forwarding. Uses JSON Patch (RFC 6902) with optional CEL expressions for computed values. Use cases:
- Redact PII from arguments before they reach the MCP server
- Inject context (agent identity, trace ID) into arguments
- Clamp numeric values to policy limits

#### 13. Time-window rules

Rules with `time_window.active_cron` are only active during the specified time window. Uses standard cron expressions with timezone support. Use case: change freeze enforcement.

#### 14. tools/list filtering

Intercept `tools/list` responses and remove tools the agent is not allowed to call. This prevents the agent from even discovering restricted tools, reducing prompt pollution and attack surface.

#### 15. Redis-backed rate limiting

Shared rate limit counters via Redis for multi-instance deployments (multiple sidecars sharing a limit).

#### 16. OpenTelemetry audit output

Emit audit records as OpenTelemetry span events, integrated with the agent's existing trace context. Propagate `traceparent` headers through the proxy.

#### 17. Slack approval channel

Interactive Slack messages with approve/reject buttons for human-in-the-loop in team environments. Uses Slack Block Kit for rich tool call display.

#### 18. Approval delegation rules

Route approval requests to different channels based on tool name, agent identity, or CEL conditions. Example: payments approvals go to the finance Slack channel; infrastructure approvals go to the ops terminal.

## Non-goals

- **Authentication.** mcp-policy-guard does not authenticate agents. That's the gateway's job (Kuadrant AuthPolicy, OAuth 2.1). The middleware trusts the identity provided by the upstream transport (JWT claim, header, client cert).

- **Routing and federation.** mcp-policy-guard does not route to multiple MCP servers or aggregate tool lists. That's mcp-gateway's job. The middleware has exactly one upstream.

- **MCP server implementation.** mcp-policy-guard does not serve tools. It is a transparent proxy that happens to understand MCP JSON-RPC well enough to apply policy.

- **Agent card hosting.** mcp-policy-guard reads agent cards. It does not serve them at `/.well-known/agent-card.json`.

- **OPA / Rego.** CEL is sufficient for per-request policy evaluation. OPA adds deployment complexity (sidecar or remote service) without meaningful benefit for this use case. If a user needs OPA, they can use an escalation webhook to call an OPA endpoint.

## Architecture

```
                       mcp-policy-guard
                    ┌───────────────────────────────────────┐
                    │                                       │
 MCP Client ──────>│  Transport   ──>  Policy    ──>  Transport  ──────> MCP Server
 (stdio or HTTP)   │  Adapter          Engine         Adapter           (or gateway)
                    │  (decode)         │    │         (encode)
                    │                   │    │
                    │              ┌────┘    └────┐
                    │              ▼              ▼
                    │         Approval       Audit Emitter
                    │         Handler        (stdout, file,
                    │         (terminal,      webhook, otel)
                    │          webhook,
                    │          slack)
                    └───────────────────────────────────────┘
```

**Components:**

| Component | Responsibility |
|---|---|
| **Transport Adapter (inbound)** | Accept MCP traffic (stdio pipe or HTTP listener). Decode JSON-RPC messages. Identify `tools/call` and `tools/list` methods. Pass others through unmodified. |
| **Policy Engine** | Load policy file. Match tool calls against rules (ordered, first match). Evaluate CEL expressions. Apply rate limits. Run content filters. Return decision: allow, deny, hold, mutate. |
| **Approval Handler** | For `hold` decisions: serialize pending request, notify approval channel, block until decision or timeout. Return approved/rejected to policy engine. |
| **Audit Emitter** | For every intercepted tool call: build audit record, apply redaction, emit to configured outputs. Non-blocking (buffered channel). |
| **Transport Adapter (outbound)** | Forward allowed/approved/mutated tool calls to upstream. Relay responses back to inbound adapter. For HTTP: maintain connection while held. |

**Data flow for a `require_approval` rule:**

```
1. Client sends tools/call {"method": "tools/call", "params": {"name": "db.delete", ...}}
2. Inbound adapter decodes JSON-RPC, extracts tool name and arguments
3. Policy engine matches rule "destructive-db-ops", decision = hold
4. Approval handler:
   a. Generates request_id
   b. Sends notification to approval channel (terminal prompt or webhook POST)
   c. Blocks (waits on channel/callback)
5. Human approves (keystroke or webhook callback)
6. Approval handler returns "approved" with approver metadata
7. Policy engine returns "allow"
8. Outbound adapter forwards original tools/call to upstream
9. Upstream returns response
10. Inbound adapter relays response to client
11. Audit emitter logs: tool=db.delete, decision=approved, approver=jane@..., latency=12400ms
```

## Success criteria

| Metric | Target |
|---|---|
| Overhead per tool call (no approval) | < 5ms p99 |
| Policy file reload | < 100ms |
| Audit record emission | Non-blocking (< 1ms on hot path) |
| stdio proxy startup | < 50ms |
| Binary size | < 20MB |
| Zero external dependencies | No database, no Redis, no external service required for P0 |

## Compatibility

- MCP protocol versions: 2024-11-05, 2025-03-26, and later
- Transports: stdio, streamable HTTP (SSE)
- Tested with: Claude Code (CLI), Claude Desktop, mcp-gateway, any MCP-compliant client/server
- Platforms: Linux (amd64, arm64), macOS (amd64, arm64), Windows (amd64)

## Resolved design decisions

1. **tools/list filtering is P2, not P0.** In v0.1, the agent sees all tools but denied calls return errors. This avoids changing the observed tool set (which complicates debugging) and keeps the transport adapter simple.

2. **HTTP approval holds the SSE connection open.** No "pending" protocol extension needed. The proxy sends SSE keep-alive comments during the hold to prevent intermediary timeouts. From the client's perspective, the tool call simply takes longer. This works because MCP over streamable HTTP uses SSE, which tolerates idle periods.

3. **The policy schema is JSON Schema (Draft 2020-12)**, not the annotated YAML example. The schema (`policy-schema.json`) validates exactly the fields the current binary supports -- it ships with each release and is updated as features are added. The example file (`examples/policy-full.yaml`) is documentation that previews future fields; it is not a validation artifact. Unknown fields in a policy file are rejected by the schema's `additionalProperties: false` constraints.

## Open questions

1. **Multi-agent identity in stdio mode.** When wrapping a server used by a single client, identity is static. But if the proxy is shared (HTTP mode, multiple agents), identity must come from the transport (header, JWT). Should stdio mode support multiplexed identity via a custom MCP extension?

2. **Policy file distribution.** In Kubernetes, the natural pattern is: controller generates policy ConfigMap from agent card CR, mcp-policy-guard watches the ConfigMap. Should this controller be part of mcp-policy-guard, or a separate project? (Recommendation: separate. The guard is a data-plane component; the controller is control-plane.)

3. **Interaction with mcp-gateway's own tool filtering.** If both mcp-gateway (`x-authorized-tools`) and mcp-policy-guard (policy rules) filter tools, which takes precedence? (Recommendation: both enforce independently -- defense in depth. The guard runs closer to the agent; the gateway runs closer to the server.)
