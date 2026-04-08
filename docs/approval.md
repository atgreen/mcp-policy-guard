# Approval

Rules with `action: require_approval` hold tool calls pending human review before forwarding to the server.

## Channels

Define approval channels in the `approval` block. Rules reference them by name.

### Terminal

Interactive prompt via `/dev/tty` (Unix only). Works in stdio mode when the operator has a controlling terminal.

```yaml
approval:
  channels:
    - name: terminal
      type: terminal
      show_args: true          # Show tool arguments in prompt
      fallback: webhook        # Fall back if no tty available
```

The prompt looks like:

```
 APPROVAL REQUIRED
 Tool:  database.execute_query
 Args:  {"sql": "DELETE FROM accounts WHERE status = 'inactive'"}
 Rule:  destructive-db-ops

 [a]pprove  [r]eject  [v]iew full args  >
```

Limitations: Unix only (opens `/dev/tty`), requires a controlling terminal. Fails in CI/CD, containers without a tty, and background processes. When unavailable, falls back to the named `fallback` channel.

### Webhook

POST the pending request to an HTTP endpoint, then wait for a callback or poll for a decision.

```yaml
approval:
  channels:
    - name: webhook
      type: webhook
      endpoint: https://approvals.internal/api/review
      method: POST
      headers:
        Authorization: "Bearer ${APPROVAL_TOKEN}"
      callback_mode: callback    # callback | poll
      poll_interval: 5s          # For poll mode
```

In **callback** mode, mcp-policy-guard waits for a POST to `/approval/{request_id}` with:

```json
{"decision": "approve"}
```

or:

```json
{"decision": "reject", "reason": "..."}
```

In **poll** mode, it GETs `{endpoint}/{request_id}` at the configured interval until a decision is returned.

### Slack

Interactive Slack messages with approve/reject buttons.

```yaml
approval:
  channels:
    - name: slack
      type: slack
      webhook_url: "${SLACK_WEBHOOK_URL}"
      channel: "#agent-approvals"
      callback_url: https://policy-guard.internal/slack/callback
```

Posts a rich message with tool call details and action buttons. Polls the callback URL for the decision.

## Timeout and escalation

```yaml
approval:
  timeout: 300s              # Default max wait for all channels
  on_timeout: reject         # reject | escalate | allow
  escalate_on_timeout_to: oncall   # Escalation channel (when on_timeout: escalate)
```

Per-rule timeout overrides:

```yaml
rules:
  - name: "approve-delete"
    match:
      tools: ["database.delete_*"]
    action: require_approval
    approval:
      channel: terminal
      timeout: 60s
      on_timeout: reject
      message: "Confirm deletion before proceeding."
```

## Delegation

Route approval requests to different channels based on tool or agent patterns:

```yaml
approval:
  channels:
    - name: terminal
      type: terminal
    - name: finance-slack
      type: slack
      webhook_url: "${FINANCE_SLACK_WEBHOOK}"
    - name: ops-webhook
      type: webhook
      endpoint: https://ops.internal/approve

  delegation_rules:
    - name: payments-to-finance
      tools: ["payments.*"]
      channel: finance-slack
    - name: deploy-to-ops
      tools: ["deploy.*", "k8s.*"]
      channel: ops-webhook
    - name: interns-to-manager
      agents: ["intern-*"]
      channel: ops-webhook
```

Delegation rules are checked first. If a delegation rule matches, its channel is used instead of the one specified on the policy rule. If no delegation rule matches, the rule's own channel is used.

Both `tools` and `agents` support glob patterns. When both are specified, both must match.
