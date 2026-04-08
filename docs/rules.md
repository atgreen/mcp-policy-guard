# Rules and Matching

Rules are an ordered list evaluated top-to-bottom. The first matching rule wins. If no rule matches, `defaults.action` applies.

## Rule structure

```yaml
rules:
  - name: "rule-name"                # Unique name (used in audit and errors)
    description: "..."               # Optional
    match:
      tools: ["glob_pattern*"]       # Required. Glob patterns on tool names.
      agent:                         # Optional. Restrict to specific agents.
        identity: "pattern*"
      arguments:                     # Optional. CEL expression on arguments.
        cel: "double(args.amount) > 1000000.0"
      time_window:                   # Optional. When this rule is active.
        active_cron: "0 9-17 * * 1-5"
        timezone: "America/New_York"
    action: allow                    # allow | deny | require_approval | audit_only | mutate
    deny_message: "..."              # Custom error message (deny action)
    audit: true                      # Override default audit setting
    approval: { ... }               # Required for require_approval
    escalate: { ... }               # Optional. Fire escalation on match.
    mutate: { ... }                 # Required for mutate action
```

## Actions

| Action | Behavior |
|---|---|
| `allow` | Forward the tool call to the server |
| `deny` | Return a JSON-RPC error to the client |
| `require_approval` | Hold for human approval, then forward or reject |
| `audit_only` | Forward but flag in audit log |
| `mutate` | Modify arguments via JSON Patch, then forward |

## Tool name matching

Tool names are matched with glob patterns using `*` (any characters) and `?` (single character):

```yaml
match:
  tools:
    - "database.*"          # All tools in the database namespace
    - "payments.submit"     # Exact match
    - "read_*"              # Anything starting with read_
    - "*"                   # Catch-all
```

## Agent identity matching

Restrict a rule to specific agents:

```yaml
match:
  agent:
    identity: "intern-*"   # Glob pattern
  tools: ["*"]
```

## CEL expressions

Match on tool call argument content using [Common Expression Language](https://github.com/google/cel-spec):

```yaml
match:
  tools: ["payments.*"]
  arguments:
    cel: "double(args.amount) > 1000000.0"
```

Available variables:
- `args` -- tool call arguments as a map
- `tool` -- tool name as a string
- `agent` -- agent identity as a string

Examples:
- `double(args.amount) > 1000000.0` -- high-value transaction
- `args.sql.matches('(?i)(DELETE|DROP)')` -- destructive SQL
- `tool.startsWith("admin.")` -- admin namespace
- `args.config.dangerous == true` -- nested field access

CEL expressions are compiled once and cached. They are side-effect-free and sandboxed.

## Time windows

Restrict when a rule is active using cron expressions:

```yaml
match:
  tools: ["deploy.*"]
  time_window:
    active_cron: "0 0 * * 5-0"       # Active Friday through Sunday
    timezone: "America/New_York"      # IANA timezone (optional)
```

The cron format is: `minute hour day-of-month month day-of-week`. The rule only matches during minutes that match the cron schedule.

## Argument mutation

Rules with `action: mutate` modify tool call arguments before forwarding using JSON Patch (RFC 6902):

```yaml
- name: "inject-trace-id"
  match:
    tools: ["*"]
  action: mutate
  mutate:
    arguments:
      - op: add
        path: "/trace_id"
        value: "static-value"
      - op: remove
        path: "/secret"
      - op: replace
        path: "/amount"
        cel: "int(args.amount) * 100"    # CEL-computed value
```

Operations: `add`, `remove`, `replace`. The `cel` field computes the value dynamically. Operations are applied sequentially.

## Escalation

Any rule can fire an escalation webhook independently of its action:

```yaml
- name: "high-value-alert"
  match:
    tools: ["payments.*"]
    arguments:
      cel: "double(args.amount) > 1000000.0"
  action: allow                          # Still allows the call
  escalate:
    channel: oncall                      # References escalation.channels[].name
    trigger_name: "high-value-payment"
```

Escalation channels are defined in the top-level `escalation` block:

```yaml
escalation:
  channels:
    - name: oncall
      type: webhook
      endpoint: https://alertmanager.internal/api/v2/alerts
      method: POST
      headers:
        Authorization: "Bearer ${ALERTMANAGER_TOKEN}"
      payload_template: |
        [{"labels":{"alertname":"AgentEscalation","trigger":"${trigger_name}"}}]

    - name: pagerduty
      type: pagerduty
      routing_key: "${PD_ROUTING_KEY}"
      severity: critical
```

Channel types: `webhook` (generic HTTP), `pagerduty`, `email`.

Escalation is fire-and-forget -- it does not block the tool call.
