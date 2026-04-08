package approval

import (
	"testing"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

func TestDelegator_ToolMatch(t *testing.T) {
	d := NewDelegator([]policy.DelegationRule{
		{Name: "payments-to-finance", Tools: []string{"payments.*"}, Channel: "finance-slack"},
		{Name: "infra-to-ops", Tools: []string{"deploy.*", "k8s.*"}, Channel: "ops-terminal"},
	})

	req := Request{ToolName: "payments.submit", Agent: "agent-1"}
	ch := d.Resolve(req)
	if ch != "finance-slack" {
		t.Errorf("got %q, want %q", ch, "finance-slack")
	}

	req = Request{ToolName: "deploy.rollout", Agent: "agent-1"}
	ch = d.Resolve(req)
	if ch != "ops-terminal" {
		t.Errorf("got %q, want %q", ch, "ops-terminal")
	}

	req = Request{ToolName: "echo", Agent: "agent-1"}
	ch = d.Resolve(req)
	if ch != "" {
		t.Errorf("got %q, want empty (no match)", ch)
	}
}

func TestDelegator_AgentMatch(t *testing.T) {
	d := NewDelegator([]policy.DelegationRule{
		{Name: "intern-approval", Agents: []string{"intern-*"}, Channel: "manager-webhook"},
	})

	req := Request{ToolName: "anything", Agent: "intern-alice"}
	if ch := d.Resolve(req); ch != "manager-webhook" {
		t.Errorf("got %q, want %q", ch, "manager-webhook")
	}

	req = Request{ToolName: "anything", Agent: "senior-bob"}
	if ch := d.Resolve(req); ch != "" {
		t.Errorf("got %q, want empty", ch)
	}
}

func TestDelegator_ToolAndAgentMatch(t *testing.T) {
	d := NewDelegator([]policy.DelegationRule{
		{Name: "specific", Tools: []string{"database.*"}, Agents: []string{"intern-*"}, Channel: "supervisor"},
	})

	// Both match
	req := Request{ToolName: "database.query", Agent: "intern-alice"}
	if ch := d.Resolve(req); ch != "supervisor" {
		t.Errorf("both match: got %q, want %q", ch, "supervisor")
	}

	// Tool matches but agent doesn't
	req = Request{ToolName: "database.query", Agent: "senior-bob"}
	if ch := d.Resolve(req); ch != "" {
		t.Errorf("agent mismatch: got %q, want empty", ch)
	}
}

func TestDelegator_Nil(t *testing.T) {
	d := NewDelegator(nil)
	if d != nil {
		t.Error("nil rules should produce nil delegator")
	}

	// ResolveChannel with nil delegator should return rule default
	ch := ResolveChannel(nil, Request{ToolName: "x"}, "default-channel")
	if ch != "default-channel" {
		t.Errorf("got %q, want %q", ch, "default-channel")
	}
}

func TestResolveChannel_DelegationOverride(t *testing.T) {
	d := NewDelegator([]policy.DelegationRule{
		{Name: "override", Tools: []string{"payments.*"}, Channel: "finance"},
	})

	req := Request{ToolName: "payments.submit"}
	ch := ResolveChannel(d, req, "default-terminal")
	if ch != "finance" {
		t.Errorf("got %q, want %q", ch, "finance")
	}

	req = Request{ToolName: "echo"}
	ch = ResolveChannel(d, req, "default-terminal")
	if ch != "default-terminal" {
		t.Errorf("got %q, want %q", ch, "default-terminal")
	}
}
