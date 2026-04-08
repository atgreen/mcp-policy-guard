# Deployment Modes

mcp-policy-guard supports three deployment modes. All use the same policy engine and enforce the same rules.

## stdio mode

Wraps a local MCP server process. The MCP client spawns mcp-policy-guard, which spawns the real server and relays stdio with policy enforcement in between.

```bash
mcp-policy-guard --policy policy.yaml -- mcp-server-postgres --db prod
```

In your MCP client config (Claude Code, Claude Desktop, etc.):

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

In this mode, human-in-the-loop approval uses `/dev/tty` for interactive terminal prompts (Unix only). If no terminal is available, it falls back to the next configured approval channel.

## stdio-to-HTTP bridge

The MCP client speaks stdio (spawns mcp-policy-guard as a command), but the actual MCP server is a remote HTTP endpoint. Policy enforcement happens locally before forwarding.

```bash
mcp-policy-guard \
  --policy policy.yaml \
  --upstream https://mcp-gateway.internal:8443/mcp
```

In your MCP client config:

```json
{
  "mcpServers": {
    "remote-db": {
      "command": "mcp-policy-guard",
      "args": [
        "--policy", "policy.yaml",
        "--upstream", "https://mcp-gateway.internal:8443/mcp",
        "--tls-cert", "/etc/certs/client.pem",
        "--tls-key", "/etc/certs/client-key.pem"
      ]
    }
  }
}
```

This is useful when:
- Your MCP servers are behind an MCP gateway (like Kuadrant's mcp-gateway) and accessible only via HTTP
- You want policy enforcement at the client side, before traffic leaves the machine
- The upstream requires mTLS authentication

## HTTP reverse proxy

Runs as a standalone HTTP server that forwards to an upstream MCP endpoint. For Kubernetes sidecar deployments or standalone proxy use.

```bash
mcp-policy-guard \
  --policy policy.yaml \
  --listen :8081 \
  --upstream http://mcp-gateway:8080/mcp
```

The agent pod points at the proxy instead of the gateway directly:

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

For multi-instance deployments, use Redis-backed rate limiting so all sidecars share counters:

```bash
mcp-policy-guard \
  --policy policy.yaml \
  --listen :8081 \
  --upstream http://mcp-gateway:8080/mcp \
  --redis redis://redis:6379
```

## CLI reference

```
Usage:
  stdio:          mcp-policy-guard --policy <path> [options] -- <command> [args...]
  stdio-to-HTTP:  mcp-policy-guard --policy <path> --upstream <url> [options]
  HTTP proxy:     mcp-policy-guard --policy <path> --listen <addr> --upstream <url> [options]

Options:
  --policy <path>          Policy YAML file (required)
  --listen <addr>          HTTP listen address (e.g., :8081)
  --upstream <url>         Upstream MCP endpoint URL
  --agent-identity <id>    Static agent identity
  --redis <url>            Redis URL for shared rate limiting
  --tls-cert <path>        Client certificate PEM for mTLS
  --tls-key <path>         Client private key PEM for mTLS
  --tls-ca <path>          CA certificate PEM to verify upstream
  --tls-insecure           Skip upstream TLS verification
  --log-level <level>      debug, info, warn, error (default: info)
```
