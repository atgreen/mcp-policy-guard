# Content Filters

Content filters inspect tool call arguments (request direction) and server responses (response direction) for sensitive patterns. They run after rate limiting and before policy rule evaluation.

## Configuration

```yaml
content_filters:
  - name: "pii-detection"
    description: "Block PII in outbound tool arguments"
    direction: request           # request | response | both
    match:
      tools: ["*"]               # Glob patterns
    patterns:
      - name: ssn
        regex: '\b\d{3}-\d{2}-\d{4}\b'
      - name: credit_card
        regex: '\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
      - name: email
        regex: '(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    action: block                # block | redact | flag
    block_message: "PII detected in tool arguments"
    escalate:
      channel: oncall
      trigger_name: "pii-leak"
```

## Actions

| Action | Behavior |
|---|---|
| `block` | Reject the tool call with a JSON-RPC error. The call never reaches the server. |
| `redact` | Replace matched content with `[REDACTED:pattern_name]` and forward. |
| `flag` | Forward unchanged but mark in the audit record. |

## Direction

| Direction | What is scanned |
|---|---|
| `request` | Tool call arguments (before forwarding to server) |
| `response` | Server response (before returning to client) |
| `both` | Both directions |

## Pattern matching

Patterns are standard regular expressions applied to all string values in the JSON content. Nested objects and arrays are traversed recursively -- every string value is checked.

## Prompt injection scanning

Detect prompt injection attempts in MCP server responses:

```yaml
content_filters:
  - name: "prompt-injection"
    direction: response
    match:
      tools: ["*"]
    patterns:
      - name: role_override
        regex: '(?i)(ignore previous|you are now|system prompt)'
      - name: instruction_injection
        regex: '(?i)(disregard|override instructions)'
    action: flag
    audit: true
```

Using `flag` (rather than `block`) is recommended for prompt injection detection, since regex-based detection has false positives. The flag appears in the audit trail for post-hoc review.

## Escalation

Any content filter can fire an escalation when it matches:

```yaml
content_filters:
  - name: "pii-block"
    direction: request
    match:
      tools: ["*"]
    patterns:
      - name: ssn
        regex: '\b\d{3}-\d{2}-\d{4}\b'
    action: block
    escalate:
      channel: oncall
      trigger_name: "pii-leak-attempt"
```
