// Package engine implements the policy evaluation engine.
package engine

import (
	"encoding/json"
	"log/slog"
	"path"
	"sync"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// Decision represents the policy engine's verdict on a tool call.
type Decision int

const (
	Allow          Decision = iota
	Deny
	RequireApproval
	AuditOnly
	Mutate
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case RequireApproval:
		return "require_approval"
	case AuditOnly:
		return "audit_only"
	case Mutate:
		return "mutate"
	default:
		return "unknown"
	}
}

// EvalResult is the outcome of evaluating a tool call against the policy.
type EvalResult struct {
	Decision    Decision
	Rule        *policy.Rule // nil if default action applied
	DenyMessage string
	Audit       bool // whether to emit an audit record
}

// Engine evaluates tool calls against a policy. Safe for concurrent use.
type Engine struct {
	mu       sync.RWMutex
	pol      *policy.Policy
	defaults policy.Defaults
	cel      *CELEvaluator
}

// New creates an engine from a loaded policy.
func New(pol *policy.Policy) *Engine {
	celEval, err := NewCELEvaluator()
	if err != nil {
		slog.Warn("failed to create CEL evaluator, CEL expressions will not work", "error", err)
	}
	return &Engine{
		pol:      pol,
		defaults: pol.EffectiveDefaults(),
		cel:      celEval,
	}
}

// Reload swaps the policy atomically.
func (e *Engine) Reload(pol *policy.Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pol = pol
	e.defaults = pol.EffectiveDefaults()
}

// Evaluate checks a tool call against the policy rules.
// Returns the decision, matched rule, and whether to audit.
// arguments is the raw JSON arguments for CEL evaluation (may be nil).
func (e *Engine) Evaluate(toolName, agentIdentity string, arguments ...json.RawMessage) EvalResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var args json.RawMessage
	if len(arguments) > 0 {
		args = arguments[0]
	}

	for i := range e.pol.Rules {
		rule := &e.pol.Rules[i]
		if e.matchRule(rule, toolName, agentIdentity, args) {
			return resultFromRule(rule, e.defaults)
		}
	}

	// No rule matched — apply defaults
	return resultFromDefaults(e.defaults)
}

// Policy returns the current policy (for reading approval config, etc.).
func (e *Engine) Policy() *policy.Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.pol
}

// CEL returns the CEL evaluator for use by mutation.
func (e *Engine) CEL() *CELEvaluator {
	return e.cel
}

func (e *Engine) matchRule(rule *policy.Rule, toolName, agentIdentity string, args json.RawMessage) bool {
	// Check agent identity if specified
	if rule.Match.Agent != nil && rule.Match.Agent.Identity != "" {
		if !globMatch(rule.Match.Agent.Identity, agentIdentity) {
			return false
		}
	}

	// Check tool name against any pattern
	toolMatched := false
	for _, pattern := range rule.Match.Tools {
		if globMatch(pattern, toolName) {
			toolMatched = true
			break
		}
	}
	if !toolMatched {
		return false
	}

	// Check time window if specified
	if rule.Match.TimeWindow != nil {
		if !isInTimeWindow(rule.Match.TimeWindow) {
			return false
		}
	}

	// Check CEL expression if specified
	if rule.Match.Arguments != nil && rule.Match.Arguments.CEL != "" {
		if e.cel == nil {
			slog.Warn("CEL expression in rule but evaluator unavailable", "rule", rule.Name)
			return false
		}
		matched, err := e.cel.Evaluate(rule.Match.Arguments.CEL, toolName, agentIdentity, args)
		if err != nil {
			slog.Warn("CEL evaluation error", "rule", rule.Name, "error", err)
			return false
		}
		return matched
	}

	return true
}

// globMatch matches a tool name against a glob pattern.
// Uses path.Match which supports * and ? wildcards.
// Tool names use "." as separator (e.g., "database.drop_table"),
// which path.Match treats as a literal character (not a separator).
func globMatch(pattern, name string) bool {
	matched, err := path.Match(pattern, name)
	if err != nil {
		return false
	}
	return matched
}

func resultFromRule(rule *policy.Rule, defaults policy.Defaults) EvalResult {
	result := EvalResult{
		Rule: rule,
	}

	switch rule.Action {
	case "allow":
		result.Decision = Allow
	case "deny":
		result.Decision = Deny
		result.DenyMessage = rule.DenyMessage
		if result.DenyMessage == "" {
			result.DenyMessage = defaults.DenyMessage
		}
	case "require_approval":
		result.Decision = RequireApproval
	case "audit_only":
		result.Decision = AuditOnly
	case "mutate":
		result.Decision = Mutate
	default:
		result.Decision = Deny
		result.DenyMessage = "unknown action: " + rule.Action
	}

	// Determine audit: rule override > default
	if rule.Audit != nil {
		result.Audit = *rule.Audit
	} else if defaults.Audit != nil {
		result.Audit = *defaults.Audit
	} else {
		result.Audit = true
	}

	return result
}

func resultFromDefaults(defaults policy.Defaults) EvalResult {
	result := EvalResult{}

	switch defaults.Action {
	case "allow":
		result.Decision = Allow
	case "audit_only":
		result.Decision = AuditOnly
	case "mutate":
		result.Decision = Mutate
	default:
		result.Decision = Deny
		result.DenyMessage = defaults.DenyMessage
	}

	if defaults.Audit != nil {
		result.Audit = *defaults.Audit
	} else {
		result.Audit = true
	}

	return result
}
