# mcp-policy-guard

**Experimental** -- MCP protocol-aware policy middleware for AI agent governance.

mcp-policy-guard sits between an MCP client and server, intercepting JSON-RPC tool calls and enforcing policies defined in a YAML file. It is designed to close the gap between the [FINOS Agent Card](https://github.com/finos/ai-reference-architecture-library/tree/main/Library/reference-architecture/agent-card) governance model and what MCP gateways enforce today.

It is not a gateway. It does not do routing, federation, or authentication. It does one thing: **intercept MCP tool calls and apply policy**.

```
MCP Client -- tools/call --> mcp-policy-guard --> MCP Server
                                    |              (or gateway)
                              +-----+-----+
                              |  approve?  |
                              |  allow?    |
                              |  log?      |
                              |  redact?   |
                              +-----------+
```

## Features

- **Tool allowlist** -- glob matching on tool names, first-match-wins ordered rules, default deny
- **CEL expressions** -- match rules on tool call arguments (e.g., `double(args.amount) > 1000000.0`)
- **Human-in-the-loop approval** -- interactive terminal prompt, webhook, or Slack channels with fallback chains
- **Argument mutation** -- JSON Patch (RFC 6902) with optional CEL-computed values
- **Rate limiting** -- in-memory or Redis-backed token bucket, per-agent/per-tool/global keys
- **Content filters** -- regex-based PII detection and prompt injection scanning with block/redact/flag actions
- **Escalation webhooks** -- fire-and-forget notifications to Alertmanager, PagerDuty, or generic endpoints
- **Time-window rules** -- cron-based activation windows with timezone support
- **tools/list filtering** -- denied tools hidden from agent discovery
- **Audit logging** -- structured JSON, JSONL files, webhook, or OpenTelemetry spans
- **Redaction** -- field-name and regex-based redaction of sensitive data in audit records
- **Agent card derivation** -- reads a FINOS Agent Card and derives rules automatically
- **Approval delegation** -- route approvals to different channels based on tool or agent patterns
- **Policy hot-reload** -- file watcher reloads on change, works with Kubernetes ConfigMap mounts
- **mTLS** -- client certificates for mutual TLS to upstream endpoints

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

audit:
  outputs:
    - type: stdout
      format: json

rules:
  - name: "allow-read"
    match:
      tools: ["read_*", "search_*"]
    action: allow

  - name: "approve-writes"
    match:
      tools: ["write_*", "delete_*"]
    action: require_approval
    approval:
      channel: terminal
      timeout: 120s
      on_timeout: reject

approval:
  channels:
    - name: terminal
      type: terminal
```

Wrap an MCP server:

```bash
mcp-policy-guard --policy policy.yaml -- mcp-server-postgres --db prod
```

See the [documentation](docs/) for detailed guides on all deployment modes, policy configuration, and features.

## Deployment modes

| Mode | Command | Use case |
|---|---|---|
| **stdio** | `--policy p.yaml -- <cmd>` | Wrap a local MCP server process |
| **stdio-to-HTTP** | `--policy p.yaml --upstream <url>` | MCP client speaks stdio, server is remote |
| **HTTP proxy** | `--policy p.yaml --listen :8081 --upstream <url>` | Kubernetes sidecar or standalone proxy |

All three modes use the same policy engine and enforce the same rules. See [Deployment Modes](docs/deployment-modes.md) for details.

## Documentation

- [Deployment Modes](docs/deployment-modes.md) -- stdio, stdio-to-HTTP bridge, HTTP reverse proxy
- [Policy Reference](docs/policy-reference.md) -- complete policy file format with all fields
- [Rules and Matching](docs/rules.md) -- tool globs, CEL expressions, time windows, first-match-wins
- [Approval](docs/approval.md) -- terminal, webhook, and Slack channels, delegation, fallback chains
- [Rate Limiting](docs/rate-limiting.md) -- in-memory and Redis backends, per-agent/per-tool/global keys
- [Content Filters](docs/content-filters.md) -- PII detection, prompt injection scanning, block/redact/flag
- [Audit Trail](docs/audit.md) -- outputs, redaction, OpenTelemetry integration
- [Agent Card Integration](docs/agent-card.md) -- deriving policy from FINOS Agent Cards
- [Hot-Reload](docs/hot-reload.md) -- live policy updates, Kubernetes ConfigMap support
- [TLS and mTLS](docs/tls.md) -- client certificates, custom CA, upstream TLS configuration

## Complements your MCP gateway

mcp-policy-guard works alongside [Kuadrant's mcp-gateway](https://github.com/Kuadrant/mcp-gateway) or any other MCP gateway. The gateway handles routing, federation, and authentication. The guard handles agent-card-specific governance -- tool allowlists, human-in-the-loop approval, content filtering, and semantic audit trails.

## License

MIT -- see [LICENSE](LICENSE).

## Status

**Experimental.** The API, policy schema, and CLI flags may change without notice.
