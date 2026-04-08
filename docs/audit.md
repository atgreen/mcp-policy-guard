# Audit Trail

Every intercepted `tools/call` emits a structured audit record. Records can be sent to multiple outputs simultaneously.

## Configuration

```yaml
audit:
  outputs:
    - type: stdout
      format: json             # json | text

    - type: file
      path: /var/log/mcp-policy-guard/audit.jsonl
      format: jsonl
      rotate:
        max_size_mb: 100
        max_files: 10

    - type: webhook
      endpoint: https://logging.internal/ingest
      method: POST
      headers:
        Authorization: "Bearer ${LOG_TOKEN}"
      batch:
        max_size: 100
        flush_interval: 5s

    - type: otel
      endpoint: localhost:4317
      protocol: grpc           # grpc | http

  include:
    tool_name: true
    tool_arguments: true
    tool_response: true
    agent_identity: true
    timestamp: true
    request_id: true
    policy_decision: true
    approval_metadata: true
    latency: true

  redaction:
    fields:
      - password
      - secret
      - api_key
      - token
    patterns:
      - name: credit_card
        regex: '\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
        replacement: "[REDACTED:credit_card]"
      - name: ssn
        regex: '\b\d{3}-\d{2}-\d{4}\b'
        replacement: "[REDACTED:ssn]"
```

## Output types

### stdout

Writes to stderr (in stdio mode, stdout carries JSON-RPC). Format: `json` (structured, one record per line) or `text` (human-readable).

### file

JSONL format with size-based rotation. Old files are renamed with numeric suffixes (`.1`, `.2`, etc.). The directory is created automatically.

### webhook

Batched HTTP POST. Records accumulate up to `max_size` or `flush_interval`, whichever comes first, then POST as a JSON array.

### otel

Emits each audit record as an OpenTelemetry span with tool call metadata as span attributes. Connects to an OTLP collector via gRPC or HTTP.

Span attributes include: `mcp.tool`, `mcp.agent`, `mcp.decision`, `mcp.rule`, `mcp.request_id`, `mcp.latency_ms`, `mcp.arguments`, `mcp.approver`.

## Audit record format

```json
{
  "timestamp": "2026-04-08T14:30:00Z",
  "request_id": "uuid",
  "agent": "trading-agent-1",
  "tool": "payments.submit",
  "arguments": {"amount": 50000, "currency": "USD"},
  "decision": "allow",
  "rule": "allow-payments",
  "latency_ms": 12,
  "approver": "",
  "approval_latency_ms": 0
}
```

The `decision` field values: `allow`, `deny`, `approved`, `rejected`, `rate_limited`, `content_blocked`, `mutated`, `audit_only`.

## Redaction

Redaction is applied to the `arguments` field before any audit output.

**Field redaction** replaces the value of named JSON fields (case-insensitive, recursive) with `[REDACTED]`.

**Pattern redaction** applies regex replacements to all string values in the arguments JSON.

Both can be used together. Redaction does not affect the tool call itself -- only the audit record.

## Non-blocking emission

Audit records are sent to a buffered channel (256 deep) and emitted asynchronously. If the buffer is full, records are dropped to avoid blocking the request path. The pipeline flushes on shutdown.
