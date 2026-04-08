package approval

import (
	"log/slog"
	"path"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// Delegator resolves which approval channel to use based on delegation rules.
type Delegator struct {
	rules []policy.DelegationRule
}

// NewDelegator creates a delegator from config.
func NewDelegator(rules []policy.DelegationRule) *Delegator {
	if len(rules) == 0 {
		return nil
	}
	return &Delegator{rules: rules}
}

// Resolve returns the approval channel name for a given request.
// Returns empty string if no delegation rule matches.
func (d *Delegator) Resolve(req Request) string {
	if d == nil || len(d.rules) == 0 {
		return ""
	}

	for _, rule := range d.rules {
		if matchesDelegation(rule, req) {
			slog.Debug("approval delegation matched", "rule", rule.Name, "channel", rule.Channel, "tool", req.ToolName)
			return rule.Channel
		}
	}
	return ""
}

func matchesDelegation(rule policy.DelegationRule, req Request) bool {
	if len(rule.Tools) > 0 {
		matched := false
		for _, pattern := range rule.Tools {
			if m, _ := path.Match(pattern, req.ToolName); m {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if len(rule.Agents) > 0 {
		matched := false
		for _, pattern := range rule.Agents {
			if m, _ := path.Match(pattern, req.Agent); m {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// ResolveChannel determines the approval channel: delegation override > rule default.
func ResolveChannel(delegator *Delegator, req Request, ruleChannel string) string {
	if delegator != nil {
		if ch := delegator.Resolve(req); ch != "" {
			return ch
		}
	}
	return ruleChannel
}
