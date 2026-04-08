package agentcard

import (
	"log/slog"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// DeriveRules generates policy rules from an agent card.
func DeriveRules(card *Card) []policy.Rule {
	var rules []policy.Rule

	// If the card has an approved action list, create allow rules for each
	if len(card.Governance.ApprovedActionList) > 0 {
		for _, action := range card.Governance.ApprovedActionList {
			rules = append(rules, policy.Rule{
				Name:        "card-approved:" + action,
				Description: "Derived from agent card approvedActionList",
				Match: policy.RuleMatch{
					Tools: []string{action},
				},
				Action: "allow",
			})
		}
	}

	// Human oversight model
	switch card.Governance.HumanOversightModel {
	case "human-approves-every-action":
		// A1: wrap all tools in require_approval
		rules = wrapWithApproval(rules)
	case "human-reviews-at-checkpoints":
		// A2: would need per-skill requiresHumanApproval flags
		// For now, log and leave rules as-is
		slog.Info("A2 oversight model detected; per-skill approval requires explicit rules")
	case "human-executes-all-actions":
		// A0: human does everything, agent is advisory. No tool calls expected.
		slog.Info("A0 oversight model: agent is advisory only")
	case "human-reviews-at-milestones", "human-receives-exception-alerts-only":
		// A3/A4: audit-focused, no per-call approval needed
		slog.Info("oversight model", "level", card.Governance.HumanOversightModel)
	}

	// Log escalation contacts for visibility (enforcement is P1)
	for _, contact := range card.Governance.EscalationContacts {
		slog.Info("escalation contact from card",
			"name", contact.Name,
			"email", contact.Email,
			"triggers", contact.EscalationTriggers)
	}

	return rules
}

// wrapWithApproval changes all allow rules to require_approval.
func wrapWithApproval(rules []policy.Rule) []policy.Rule {
	for i := range rules {
		if rules[i].Action == "allow" {
			rules[i].Action = "require_approval"
			rules[i].Approval = &policy.RuleApproval{
				Channel: "terminal", // default; overridden by explicit policy
			}
		}
	}
	return rules
}

// MergeRules combines explicit rules (higher priority) with card-derived rules.
// Explicit rules come first in the list, so they match before card rules.
func MergeRules(explicitRules, cardRules []policy.Rule) []policy.Rule {
	merged := make([]policy.Rule, 0, len(explicitRules)+len(cardRules))
	merged = append(merged, explicitRules...)
	merged = append(merged, cardRules...)
	return merged
}
