// Package policy defines the configuration types for mcp-policy-guard policies.
package policy

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Policy is the top-level policy configuration.
type Policy struct {
	Version        int               `yaml:"version"`
	AgentCard      *AgentCardConfig  `yaml:"agent_card,omitempty"`
	Defaults       *Defaults         `yaml:"defaults,omitempty"`
	Identity       *Identity         `yaml:"identity,omitempty"`
	Approval       *ApprovalConfig   `yaml:"approval,omitempty"`
	Escalation     *EscalationConfig `yaml:"escalation,omitempty"`
	Audit          *AuditConfig      `yaml:"audit,omitempty"`
	Rules          []Rule            `yaml:"rules,omitempty"`
	RateLimits     []RateLimit       `yaml:"rate_limits,omitempty"`
	ContentFilters []ContentFilter   `yaml:"content_filters,omitempty"`
}

// AgentCardConfig specifies how to load a FINOS Agent Card.
type AgentCardConfig struct {
	Path      string `yaml:"path,omitempty"`
	URL       string `yaml:"url,omitempty"`
	ConfigMap string `yaml:"configmap,omitempty"`
	Watch     bool   `yaml:"watch,omitempty"`
}

// Defaults specifies the default action for unmatched tool calls.
type Defaults struct {
	Action      string `yaml:"action,omitempty"`      // deny | allow | audit_only
	Audit       *bool  `yaml:"audit,omitempty"`        // default true
	DenyMessage string `yaml:"deny_message,omitempty"` // default "Tool call not permitted by policy"
}

// Identity specifies how to identify the calling agent.
type Identity struct {
	Sources []IdentitySource `yaml:"sources"`
}

// IdentitySource is one method of extracting agent identity.
type IdentitySource struct {
	Type   string `yaml:"type"`             // jwt_claim | header | client_cert | static
	Claim  string `yaml:"claim,omitempty"`  // for jwt_claim
	Header string `yaml:"header,omitempty"` // for jwt_claim, header
	Field  string `yaml:"field,omitempty"`  // for client_cert: cn | san_dns | san_uri
	Value  string `yaml:"value,omitempty"`  // for static
}

// ApprovalConfig defines approval channels and global settings.
type ApprovalConfig struct {
	Channels           []ApprovalChannel  `yaml:"channels"`
	Timeout            Duration           `yaml:"timeout,omitempty"`
	OnTimeout          string             `yaml:"on_timeout,omitempty"`            // reject | escalate | allow
	EscalateOnTimeoutTo string            `yaml:"escalate_on_timeout_to,omitempty"` // escalation channel name
	DelegationRules    []DelegationRule   `yaml:"delegation_rules,omitempty"`
}

// DelegationRule routes approval requests to channels based on tool/agent patterns.
type DelegationRule struct {
	Name    string   `yaml:"name"`
	Tools   []string `yaml:"tools,omitempty"`
	Agents  []string `yaml:"agents,omitempty"`
	Channel string   `yaml:"channel"`
}

// ApprovalChannel defines a named approval mechanism.
type ApprovalChannel struct {
	Name         string            `yaml:"name"`
	Type         string            `yaml:"type"` // terminal | webhook | slack
	ShowArgs     *bool             `yaml:"show_args,omitempty"`
	ShowContext  *bool             `yaml:"show_context,omitempty"`
	Fallback     string            `yaml:"fallback,omitempty"`
	Endpoint     string            `yaml:"endpoint,omitempty"`
	Method       string            `yaml:"method,omitempty"`
	Headers      map[string]string `yaml:"headers,omitempty"`
	CallbackMode string            `yaml:"callback_mode,omitempty"` // callback | poll
	PollInterval Duration          `yaml:"poll_interval,omitempty"`
	WebhookURL   string            `yaml:"webhook_url,omitempty"`   // slack
	Channel      string            `yaml:"channel,omitempty"`       // slack
	CallbackURL  string            `yaml:"callback_url,omitempty"`  // slack
}

// AuditConfig defines audit trail settings.
type AuditConfig struct {
	Outputs   []AuditOutput  `yaml:"outputs"`
	Include   *AuditInclude  `yaml:"include,omitempty"`
	Redaction *AuditRedaction `yaml:"redaction,omitempty"`
}

// AuditOutput defines where audit records are sent.
type AuditOutput struct {
	Type     string            `yaml:"type"` // stdout | file | webhook | otel
	Format   string            `yaml:"format,omitempty"`
	Path     string            `yaml:"path,omitempty"`
	Rotate   *AuditRotate      `yaml:"rotate,omitempty"`
	Endpoint string            `yaml:"endpoint,omitempty"`
	Method   string            `yaml:"method,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Batch    *AuditBatch       `yaml:"batch,omitempty"`
	Protocol string            `yaml:"protocol,omitempty"` // otel: grpc | http
}

// AuditRotate configures file rotation.
type AuditRotate struct {
	MaxSizeMB int `yaml:"max_size_mb,omitempty"`
	MaxFiles  int `yaml:"max_files,omitempty"`
}

// AuditBatch configures webhook batching.
type AuditBatch struct {
	MaxSize       int      `yaml:"max_size,omitempty"`
	FlushInterval Duration `yaml:"flush_interval,omitempty"`
}

// AuditInclude controls which fields appear in audit records.
type AuditInclude struct {
	ToolName         *bool `yaml:"tool_name,omitempty"`
	ToolArguments    *bool `yaml:"tool_arguments,omitempty"`
	ToolResponse     *bool `yaml:"tool_response,omitempty"`
	AgentIdentity    *bool `yaml:"agent_identity,omitempty"`
	Timestamp        *bool `yaml:"timestamp,omitempty"`
	RequestID        *bool `yaml:"request_id,omitempty"`
	PolicyDecision   *bool `yaml:"policy_decision,omitempty"`
	ApprovalMetadata *bool `yaml:"approval_metadata,omitempty"`
	Latency          *bool `yaml:"latency,omitempty"`
}

// AuditRedaction defines what to redact from audit records.
type AuditRedaction struct {
	Fields   []string          `yaml:"fields,omitempty"`
	Patterns []RedactionPattern `yaml:"patterns,omitempty"`
}

// RedactionPattern is a named regex replacement for redaction.
type RedactionPattern struct {
	Name        string `yaml:"name"`
	Regex       string `yaml:"regex"`
	Replacement string `yaml:"replacement"`
}

// Rule is a single policy rule.
type Rule struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description,omitempty"`
	Match       RuleMatch       `yaml:"match"`
	Action      string          `yaml:"action"` // allow | deny | require_approval | audit_only | mutate
	DenyMessage string          `yaml:"deny_message,omitempty"`
	Audit       *bool           `yaml:"audit,omitempty"`
	Approval    *RuleApproval   `yaml:"approval,omitempty"`
	Escalate    *RuleEscalation `yaml:"escalate,omitempty"`
	Mutate      *RuleMutate     `yaml:"mutate,omitempty"`
}

// RuleMutate defines argument mutations for mutate rules.
type RuleMutate struct {
	Arguments []MutateOp `yaml:"arguments"`
}

// MutateOp is a single argument mutation operation.
type MutateOp struct {
	Op    string      `yaml:"op"`              // add | remove | replace
	Path  string      `yaml:"path"`            // JSON Pointer (RFC 6901)
	Value interface{} `yaml:"value,omitempty"`  // static value
	CEL   string      `yaml:"cel,omitempty"`   // CEL expression for computed value
}

// RuleMatch defines the conditions for a rule to fire.
type RuleMatch struct {
	Tools      []string       `yaml:"tools"`
	Agent      *AgentMatch    `yaml:"agent,omitempty"`
	Arguments  *ArgumentMatch `yaml:"arguments,omitempty"`
	TimeWindow *TimeWindow    `yaml:"time_window,omitempty"`
}

// ArgumentMatch defines a CEL expression to match on tool call arguments.
type ArgumentMatch struct {
	CEL string `yaml:"cel"`
}

// TimeWindow restricts when a rule is active.
type TimeWindow struct {
	ActiveCron string `yaml:"active_cron"`
	Timezone   string `yaml:"timezone,omitempty"`
}

// AgentMatch restricts a rule to a specific agent identity.
type AgentMatch struct {
	Identity string `yaml:"identity"`
}

// RuleApproval configures approval for a require_approval rule.
type RuleApproval struct {
	Channel   string   `yaml:"channel"`
	Timeout   Duration `yaml:"timeout,omitempty"`
	OnTimeout string   `yaml:"on_timeout,omitempty"` // reject | escalate | allow
	Message   string   `yaml:"message,omitempty"`
}

// RuleEscalation fires an escalation when a rule matches.
type RuleEscalation struct {
	Channel     string `yaml:"channel"`
	TriggerName string `yaml:"trigger_name"`
}

// EscalationConfig defines escalation channels.
type EscalationConfig struct {
	Channels []EscalationChannel `yaml:"channels"`
}

// EscalationChannel defines a named escalation target.
type EscalationChannel struct {
	Name            string            `yaml:"name"`
	Type            string            `yaml:"type"` // webhook | email | pagerduty
	Endpoint        string            `yaml:"endpoint,omitempty"`
	Method          string            `yaml:"method,omitempty"`
	Headers         map[string]string `yaml:"headers,omitempty"`
	PayloadTemplate string            `yaml:"payload_template,omitempty"`
	SMTPHost        string            `yaml:"smtp_host,omitempty"`
	SMTPPort        int               `yaml:"smtp_port,omitempty"`
	From            string            `yaml:"from,omitempty"`
	To              []string          `yaml:"to,omitempty"`
	RoutingKey      string            `yaml:"routing_key,omitempty"`
	Severity        string            `yaml:"severity,omitempty"`
}

// RateLimit defines a rate limiting rule.
type RateLimit struct {
	Name       string          `yaml:"name"`
	Match      RateLimitMatch  `yaml:"match"`
	Limit      RateLimitSpec   `yaml:"limit"`
	Key        string          `yaml:"key,omitempty"`          // agent | tool | global
	OnExceed   string          `yaml:"on_exceed,omitempty"`    // deny | escalate
	DenyMessage string         `yaml:"deny_message,omitempty"`
	Escalate   *RuleEscalation `yaml:"escalate,omitempty"`
}

// RateLimitMatch defines which tools a rate limit applies to.
type RateLimitMatch struct {
	Tools []string `yaml:"tools"`
}

// RateLimitSpec defines the rate limit parameters.
type RateLimitSpec struct {
	Requests int      `yaml:"requests"`
	Window   Duration `yaml:"window"`
}

// ContentFilter defines a content inspection rule.
type ContentFilter struct {
	Name         string              `yaml:"name"`
	Description  string              `yaml:"description,omitempty"`
	Direction    string              `yaml:"direction"` // request | response | both
	Match        ContentFilterMatch  `yaml:"match"`
	Patterns     []ContentPattern    `yaml:"patterns"`
	Action       string              `yaml:"action"` // block | redact | flag
	BlockMessage string              `yaml:"block_message,omitempty"`
	Audit        *bool               `yaml:"audit,omitempty"`
	Escalate     *RuleEscalation     `yaml:"escalate,omitempty"`
}

// ContentFilterMatch defines which tools a content filter applies to.
type ContentFilterMatch struct {
	Tools []string `yaml:"tools"`
}

// ContentPattern is a named regex pattern for content detection.
type ContentPattern struct {
	Name  string `yaml:"name"`
	Regex string `yaml:"regex"`
}

// Duration is a time.Duration that unmarshals from strings like "300s", "5m".
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	return d.parse(s)
}

func (d *Duration) parse(s string) error {
	// Parse format: digits + unit (ms|s|m|h)
	var numStr, unit string
	for i, c := range s {
		if c < '0' || c > '9' {
			numStr = s[:i]
			unit = s[i:]
			break
		}
	}
	if numStr == "" {
		return fmt.Errorf("invalid duration: %q", s)
	}
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid duration number: %q", s)
	}
	switch strings.ToLower(unit) {
	case "ms":
		d.Duration = time.Duration(n) * time.Millisecond
	case "s":
		d.Duration = time.Duration(n) * time.Second
	case "m":
		d.Duration = time.Duration(n) * time.Minute
	case "h":
		d.Duration = time.Duration(n) * time.Hour
	default:
		return fmt.Errorf("invalid duration unit %q in %q", unit, s)
	}
	return nil
}

// EffectiveDefaults returns the defaults with zero-values filled in.
func (p *Policy) EffectiveDefaults() Defaults {
	d := Defaults{
		Action:      "deny",
		DenyMessage: "Tool call not permitted by policy",
	}
	audit := true
	d.Audit = &audit

	if p.Defaults != nil {
		if p.Defaults.Action != "" {
			d.Action = p.Defaults.Action
		}
		if p.Defaults.Audit != nil {
			d.Audit = p.Defaults.Audit
		}
		if p.Defaults.DenyMessage != "" {
			d.DenyMessage = p.Defaults.DenyMessage
		}
	}
	return d
}
