// Package engine implements the policy evaluation engine.
package engine

import (
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
}

// New creates an engine from a loaded policy.
func New(pol *policy.Policy) *Engine {
	return &Engine{
		pol:      pol,
		defaults: pol.EffectiveDefaults(),
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
func (e *Engine) Evaluate(toolName, agentIdentity string) EvalResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := range e.pol.Rules {
		rule := &e.pol.Rules[i]
		if matchRule(rule, toolName, agentIdentity) {
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

func matchRule(rule *policy.Rule, toolName, agentIdentity string) bool {
	// Check agent identity if specified
	if rule.Match.Agent != nil && rule.Match.Agent.Identity != "" {
		if !globMatch(rule.Match.Agent.Identity, agentIdentity) {
			return false
		}
	}

	// Check tool name against any pattern
	for _, pattern := range rule.Match.Tools {
		if globMatch(pattern, toolName) {
			return true
		}
	}
	return false
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
