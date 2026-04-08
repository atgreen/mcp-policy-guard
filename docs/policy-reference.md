# Policy Reference

Policy files are YAML, validated against `policy-schema.json` (JSON Schema Draft 2020-12) on load. Environment variables are expanded using `${VAR}` syntax before parsing.

## Top-level structure

```yaml
version: 1                    # Required. Must be 1.
agent_card: { ... }           # Optional. Derive rules from a FINOS Agent Card.
defaults: { ... }             # Optional. Default action for unmatched tool calls.
identity: { ... }             # Optional. How to identify the calling agent.
approval: { ... }             # Optional. Approval channels and settings.
escalation: { ... }           # Optional. Escalation webhook channels.
audit: { ... }                # Optional. Audit trail configuration.
rules: [ ... ]                # Required (unless agent_card is set). Ordered policy rules.
rate_limits: [ ... ]          # Optional. Rate limiting rules.
content_filters: [ ... ]      # Optional. Content inspection rules.
```

Either `rules` or `agent_card` (or both) must be present.

## agent_card

Derive baseline rules from a [FINOS Agent Card](https://github.com/finos/ai-reference-architecture-library/tree/main/Library/reference-architecture/agent-card). Exactly one of `path`, `url`, or `configmap` must be set.

```yaml
agent_card:
  path: ./agent-card.json           # Local file path
  # url: https://agent/.well-known/agent-card.json
  # configmap: namespace/configmap-name
  watch: true                        # Re-read on change
```

See [Agent Card Integration](agent-card.md) for details on rule derivation.

## defaults

```yaml
defaults:
  action: deny                       # deny | allow | audit_only
  audit: true                        # Log every tool call
  deny_message: "Not permitted"      # Error message for denied calls
```

## identity

Ordered list of identity sources. First match wins. Used for per-agent rate limiting, audit attribution, and approval routing.

```yaml
identity:
  sources:
    - type: jwt_claim               # Extract from Authorization: Bearer <jwt>
      claim: sub
      header: Authorization
    - type: header                   # Extract from custom header
      header: X-Agent-Id
    - type: client_cert              # Extract from mTLS client certificate
      field: cn                      # cn | san_dns | san_uri
    - type: static                   # Fallback
      value: "local-agent"
```

## rules

See [Rules and Matching](rules.md).

## approval

See [Approval](approval.md).

## escalation

See the escalation section in [Rules and Matching](rules.md#escalation).

## rate_limits

See [Rate Limiting](rate-limiting.md).

## content_filters

See [Content Filters](content-filters.md).

## audit

See [Audit Trail](audit.md).
