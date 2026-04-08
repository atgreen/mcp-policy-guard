package engine

import (
	"testing"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

func boolPtr(b bool) *bool { return &b }

func newTestPolicy(rules []policy.Rule, defaultAction string) *policy.Policy {
	return &policy.Policy{
		Version: 1,
		Defaults: &policy.Defaults{
			Action:      defaultAction,
			Audit:       boolPtr(true),
			DenyMessage: "default deny",
		},
		Rules: rules,
	}
}

func TestEvaluate_AllowRule(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{Name: "allow-echo", Match: policy.RuleMatch{Tools: []string{"echo"}}, Action: "allow"},
	}, "deny")

	eng := New(pol)
	result := eng.Evaluate("echo", "agent-1")

	if result.Decision != Allow {
		t.Errorf("Decision = %v, want Allow", result.Decision)
	}
	if result.Rule == nil || result.Rule.Name != "allow-echo" {
		t.Error("expected rule 'allow-echo'")
	}
}

func TestEvaluate_DenyRule(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{Name: "deny-drop", Match: policy.RuleMatch{Tools: []string{"database.drop_*"}}, Action: "deny", DenyMessage: "no drops"},
	}, "allow")

	eng := New(pol)
	result := eng.Evaluate("database.drop_table", "agent-1")

	if result.Decision != Deny {
		t.Errorf("Decision = %v, want Deny", result.Decision)
	}
	if result.DenyMessage != "no drops" {
		t.Errorf("DenyMessage = %q, want %q", result.DenyMessage, "no drops")
	}
}

func TestEvaluate_DefaultDeny(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{Name: "allow-echo", Match: policy.RuleMatch{Tools: []string{"echo"}}, Action: "allow"},
	}, "deny")

	eng := New(pol)
	result := eng.Evaluate("unknown_tool", "agent-1")

	if result.Decision != Deny {
		t.Errorf("Decision = %v, want Deny", result.Decision)
	}
	if result.Rule != nil {
		t.Error("expected no matched rule for default action")
	}
}

func TestEvaluate_DefaultAllow(t *testing.T) {
	pol := newTestPolicy(nil, "allow")
	eng := New(pol)
	result := eng.Evaluate("anything", "agent-1")

	if result.Decision != Allow {
		t.Errorf("Decision = %v, want Allow", result.Decision)
	}
}

func TestEvaluate_FirstMatchWins(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{Name: "deny-all-db", Match: policy.RuleMatch{Tools: []string{"database.*"}}, Action: "deny"},
		{Name: "allow-all", Match: policy.RuleMatch{Tools: []string{"*"}}, Action: "allow"},
	}, "deny")

	eng := New(pol)

	// database.query should match deny-all-db first
	result := eng.Evaluate("database.query", "agent-1")
	if result.Decision != Deny {
		t.Errorf("database.query: Decision = %v, want Deny", result.Decision)
	}

	// echo should match allow-all
	result = eng.Evaluate("echo", "agent-1")
	if result.Decision != Allow {
		t.Errorf("echo: Decision = %v, want Allow", result.Decision)
	}
}

func TestEvaluate_AgentMatch(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{
			Name:   "deny-intern",
			Match:  policy.RuleMatch{Tools: []string{"*"}, Agent: &policy.AgentMatch{Identity: "intern-*"}},
			Action: "deny",
		},
		{Name: "allow-all", Match: policy.RuleMatch{Tools: []string{"*"}}, Action: "allow"},
	}, "deny")

	eng := New(pol)

	// intern-agent should match deny rule
	result := eng.Evaluate("echo", "intern-agent")
	if result.Decision != Deny {
		t.Errorf("intern-agent: Decision = %v, want Deny", result.Decision)
	}

	// senior-agent should skip deny rule, match allow-all
	result = eng.Evaluate("echo", "senior-agent")
	if result.Decision != Allow {
		t.Errorf("senior-agent: Decision = %v, want Allow", result.Decision)
	}
}

func TestEvaluate_RequireApproval(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{
			Name:   "approve-delete",
			Match:  policy.RuleMatch{Tools: []string{"database.delete_*"}},
			Action: "require_approval",
			Approval: &policy.RuleApproval{
				Channel: "terminal",
				Message: "Confirm deletion",
			},
		},
	}, "deny")

	eng := New(pol)
	result := eng.Evaluate("database.delete_users", "agent-1")

	if result.Decision != RequireApproval {
		t.Errorf("Decision = %v, want RequireApproval", result.Decision)
	}
}

func TestEvaluate_AuditOnly(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{Name: "audit-read", Match: policy.RuleMatch{Tools: []string{"read_*"}}, Action: "audit_only"},
	}, "deny")

	eng := New(pol)
	result := eng.Evaluate("read_file", "agent-1")

	if result.Decision != AuditOnly {
		t.Errorf("Decision = %v, want AuditOnly", result.Decision)
	}
}

func TestEvaluate_GlobPatterns(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{Name: "match-question", Match: policy.RuleMatch{Tools: []string{"db.get_?"}}, Action: "allow"},
	}, "deny")

	eng := New(pol)

	// ? matches single char
	if r := eng.Evaluate("db.get_x", "a"); r.Decision != Allow {
		t.Error("db.get_x should match db.get_?")
	}
	// ? does not match multiple chars
	if r := eng.Evaluate("db.get_xy", "a"); r.Decision != Deny {
		t.Error("db.get_xy should NOT match db.get_?")
	}
}

func TestEvaluate_AuditOverride(t *testing.T) {
	noAudit := false
	pol := newTestPolicy([]policy.Rule{
		{Name: "no-audit", Match: policy.RuleMatch{Tools: []string{"silent"}}, Action: "allow", Audit: &noAudit},
	}, "deny")

	eng := New(pol)
	result := eng.Evaluate("silent", "a")

	if result.Audit {
		t.Error("expected audit=false for rule with audit override")
	}
}

func TestReload(t *testing.T) {
	pol1 := newTestPolicy([]policy.Rule{
		{Name: "allow-echo", Match: policy.RuleMatch{Tools: []string{"echo"}}, Action: "allow"},
	}, "deny")

	eng := New(pol1)
	if r := eng.Evaluate("echo", "a"); r.Decision != Allow {
		t.Fatal("echo should be allowed before reload")
	}

	pol2 := newTestPolicy([]policy.Rule{
		{Name: "deny-echo", Match: policy.RuleMatch{Tools: []string{"echo"}}, Action: "deny"},
	}, "deny")

	eng.Reload(pol2)
	if r := eng.Evaluate("echo", "a"); r.Decision != Deny {
		t.Error("echo should be denied after reload")
	}
}

func TestDecisionString(t *testing.T) {
	tests := []struct {
		d    Decision
		want string
	}{
		{Allow, "allow"},
		{Deny, "deny"},
		{RequireApproval, "require_approval"},
		{AuditOnly, "audit_only"},
		{Decision(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.d.String(); got != tt.want {
			t.Errorf("Decision(%d).String() = %q, want %q", tt.d, got, tt.want)
		}
	}
}
