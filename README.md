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

## Features (v0.1)

- **Tool allowlist** — glob matching on tool names, first-match-wins rules, default deny
- **Human-in-the-loop approval** — interactive `/dev/tty` prompt (Unix) with webhook fallback
- **Audit logging** — structured JSON to stderr, JSONL file with rotation, batched webhook POST
- **Redaction** — field-name and regex-based redaction of sensitive data in audit records
- **Agent card derivation** — reads a FINOS Agent Card and derives rules from `approvedActionList` and `humanOversightModel`
- **Policy validation** — YAML with `${VAR}` expansion, validated against JSON Schema on load

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

1. Matches the tool name against policy rules (glob patterns, first match wins)
2. **allow** — forwards to the server
3. **deny** — returns a JSON-RPC error to the client
4. **require_approval** — prompts via `/dev/tty` or webhook, then forwards or rejects
5. Emits a structured audit record for every intercepted call

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

- **v0.2** — CEL expressions on tool arguments, escalation webhooks, rate limiting, content filters (PII/DLP)
- **v0.3** — argument mutation, time-window rules, Slack approval, OTel audit output, `tools/list` filtering

See [PRD.md](PRD.md) for the full product requirements.

## License

MIT — see [LICENSE](LICENSE).

## Status

**Experimental.** The API, policy schema, and CLI flags may change without notice. Not recommended for production use without thorough testing in your environment.
