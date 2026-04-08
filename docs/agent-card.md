# Agent Card Integration

mcp-policy-guard can derive policy rules automatically from a [FINOS Agent Card](https://github.com/finos/ai-reference-architecture-library/tree/main/Library/reference-architecture/agent-card).

## Configuration

```yaml
agent_card:
  path: ./agent-card.json
  watch: true
```

Source options (exactly one required):
- `path` -- local file path
- `url` -- HTTP URL to fetch the card
- `configmap` -- Kubernetes ConfigMap reference as `namespace/name`

When `watch: true`, the file is monitored for changes and rules are re-derived on update.

## Rule derivation

| Card field | Derived behavior |
|---|---|
| `governance.approvedActionList` | One `allow` rule per listed action. Implies `defaults.action: deny`. |
| `governance.humanOversightModel` = `human-approves-every-action` (A1) | All derived rules become `require_approval` instead of `allow`. |
| `governance.humanOversightModel` = `human-reviews-at-checkpoints` (A2) | Logged. Per-skill `requiresHumanApproval` requires explicit rules. |
| `governance.escalationContacts` | Logged at startup. Escalation webhook targets for future use. |
| `agentSecurity.rateLimiting.enabled` | Logged. Rate limit details come from the policy file. |

## Precedence

Explicit rules in the policy file always take precedence over card-derived rules. The merge order is:

1. Explicit rules (from the `rules` block in the policy file)
2. Card-derived rules (appended after explicit rules)

Since rules are evaluated first-match-wins, explicit rules match before card-derived ones.

## Minimal card-only policy

When only `agent_card` is set (no explicit rules), all policy comes from the card:

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

## Example agent card

```json
{
  "governance": {
    "approvedActionList": ["echo", "search.*", "read_file"],
    "humanOversightModel": "human-approves-every-action",
    "escalationContacts": [
      {
        "name": "Jane Doe",
        "email": "jane@example.com",
        "role": "Oncall",
        "escalationTriggers": ["high-value"]
      }
    ]
  }
}
```

With this card and the A1 oversight model, mcp-policy-guard generates three `require_approval` rules for `echo`, `search.*`, and `read_file`, with all other tools denied by default.
