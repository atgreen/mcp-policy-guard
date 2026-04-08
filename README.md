# mcp-policy-guard

**Experimental** — MCP protocol-aware policy middleware for AI agent governance.

mcp-policy-guard sits between an MCP client and server, intercepting JSON-RPC tool calls and enforcing policies defined in a YAML file. It is designed to close the gap between the [FINOS Agent Card](https://github.com/finos/ai-reference-architecture-library/tree/main/Library/reference-architecture/agent-card) governance model and what MCP gateways enforce today.

It is not a gateway. It does not do routing, federation, or authentication. It does one thing: **intercept MCP tool calls and apply policy**.

```
MCP Client ── tools/call ──▶ mcp-policy-guard ──▶ MCP Server
                                    │
                              ┌─────┴─────┐
                              │  approve?  │
                              │  allow?    │
                              │  log?      │
                              │  redact?   │
                              └───────────┘
```

## Features

**Core (v0.1)**
- **Tool allowlist** — glob matching on tool names, first-match-wins rules, default deny
- **Human-in-the-loop approval** — interactive `/dev/tty` prompt (Unix) with webhook fallback
- **Audit logging** — structured JSON to stderr, JSONL file with rotation, batched webhook POST
- **Redaction** — field-name and regex-based redaction of sensitive data in audit records
- **Agent card derivation** — reads a FINOS Agent Card and derives rules from `approvedActionList` and `humanOversightModel`
- **Policy validation** — YAML with `${VAR}` expansion, validated against JSON Schema on load

**Policy intelligence (v0.2)**
- **CEL expressions** — match rules on tool call arguments (e.g., `double(args.amount) > 1000000.0`, `args.sql.matches('(?i)DROP')`)
- **Rate limiting** — in-memory token bucket, per-agent/per-tool/global keys, configurable deny messages
- **Content filters** — regex-based PII detection and prompt injection scanning on request/response, with block/redact/flag actions
- **Escalation webhooks** — fire-and-forget notifications to Alertmanager, PagerDuty, or generic webhooks on rule match, rate limit exceed, or content filter hit

**Advanced controls (v0.3)**
- **Argument mutation** — JSON Patch (RFC 6902) with optional CEL-computed values to modify tool arguments before forwarding (redact PII, inject context, clamp values)
- **Time-window rules** — cron-based activation windows with timezone support for change freezes and scheduled restrictions
- **tools/list filtering** — denied tools are hidden from the agent's tool discovery, reducing prompt pollution and attack surface
- **Slack approval** — interactive Slack messages with approve/reject buttons for team-based human-in-the-loop workflows
- **OTel audit output** — emit audit records as OpenTelemetry spans via OTLP gRPC or HTTP

## Quick start

```bash
go install github.com/atgreen/mcp-policy-guard@latest
```

Create a policy file (`policy.yaml`):

```yaml
version: 1

defaults:
  action: deny
  audit: true

identity:
  sources:
    - type: static
      value: "my-agent"

audit:
  outputs:
    - type: stdout
      format: json

rules:
  - name: "allow-read"
    match:
      tools: ["read_*", "search_*", "list_*"]
    action: allow

  - name: "approve-writes"
    match:
      tools: ["write_*", "delete_*"]
    action: require_approval
    approval:
      channel: terminal
      timeout: 120s
      on_timeout: reject
      message: "Write operation detected. Approve?"

approval:
  channels:
    - name: terminal
      type: terminal
      fallback: webhook
    - name: webhook
      type: webhook
      endpoint: https://approvals.internal/api/review
```

Wrap an MCP server:

```bash
mcp-policy-guard --policy policy.yaml -- mcp-server-postgres --db prod
```

Or in your MCP client config (e.g., Claude Code):

```json
{
  "mcpServers": {
    "database": {
      "command": "mcp-policy-guard",
      "args": ["--policy", "policy.yaml", "--", "mcp-server-postgres", "--db", "prod"]
    }
  }
}
```

## How it works

mcp-policy-guard spawns the MCP server as a child process and relays stdio. It parses each line as JSON-RPC 2.0, and for `tools/call` requests:

1. Checks **rate limits** — rejects if the agent/tool has exceeded its budget
2. Runs **content filters** — blocks if PII or injection patterns are detected in arguments
3. Matches the tool name (and optionally CEL expressions on arguments) against **policy rules** (first match wins)
4. **allow** — forwards to the server
5. **deny** — returns a JSON-RPC error to the client
6. **require_approval** — prompts via `/dev/tty` or webhook, then forwards or rejects
7. Fires **escalation webhooks** if the matched rule, rate limit, or content filter is configured to escalate
8. Emits a structured **audit record** for every intercepted call

All other MCP methods (`initialize`, `tools/list`, `resources/*`, `prompts/*`, `ping`) pass through unmodified.

## Agent card integration

Point mcp-policy-guard at a [FINOS Agent Card](https://github.com/finos/ai-reference-architecture-library/tree/main/Library/reference-architecture/agent-card) to derive rules automatically:

```yaml
version: 1
agent_card:
  path: ./agent-card.json
  watch: true
defaults:
  action: deny
audit:
  outputs:
    - type: stdout
```

The card's `governance.approvedActionList` becomes a tool allowlist. If `humanOversightModel` is `human-approves-every-action` (A1), all tools require approval. Explicit rules in the policy file override card-derived rules.

## Policy schema

The policy file is validated against `policy-schema.json` (JSON Schema Draft 2020-12) on load. See `examples/policy-full.yaml` for an annotated reference and `examples/policy-minimal.yaml` for a card-only configuration.

## Complements, does not replace, your MCP gateway

mcp-policy-guard is designed to work alongside [Kuadrant's mcp-gateway](https://github.com/Kuadrant/mcp-gateway) or any other MCP gateway. The gateway handles routing, federation, and authentication. The guard handles agent-card-specific governance that gateways don't cover yet — tool allowlists derived from the card, human-in-the-loop approval, and semantic audit trails.

In Kubernetes, run it as a sidecar:

```yaml
containers:
  - name: agent
    env:
      - name: MCP_ENDPOINT
        value: "http://localhost:8081/mcp"
  - name: policy-guard
    image: ghcr.io/atgreen/mcp-policy-guard:latest
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
      name: agent-policy
```

## Roadmap

- **v0.4** — HTTP reverse proxy transport, Redis-backed rate limiting, approval delegation rules, Kubernetes ConfigMap watching

See [PRD.md](PRD.md) for the full product requirements.

## License

MIT — see [LICENSE](LICENSE).

## Status

**Experimental.** The API, policy schema, and CLI flags may change without notice. Not recommended for production use without thorough testing in your environment.
