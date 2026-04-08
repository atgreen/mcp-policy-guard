package agentcard

import (
	"testing"
)

const sampleCard = `{
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
	},
	"agentSecurity": {
		"rateLimiting": {
			"enabled": true
		}
	}
}`

func TestParse(t *testing.T) {
	card, err := Parse([]byte(sampleCard))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(card.Governance.ApprovedActionList) != 3 {
		t.Errorf("ApprovedActionList = %d, want 3", len(card.Governance.ApprovedActionList))
	}
	if card.Governance.HumanOversightModel != "human-approves-every-action" {
		t.Errorf("HumanOversightModel = %q", card.Governance.HumanOversightModel)
	}
	if len(card.Governance.EscalationContacts) != 1 {
		t.Errorf("EscalationContacts = %d, want 1", len(card.Governance.EscalationContacts))
	}
	if !card.AgentSecurity.RateLimiting.Enabled {
		t.Error("RateLimiting.Enabled should be true")
	}
}

func TestParse_Invalid(t *testing.T) {
	_, err := Parse([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParse_Empty(t *testing.T) {
	card, err := Parse([]byte(`{}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(card.Governance.ApprovedActionList) != 0 {
		t.Error("empty card should have no approved actions")
	}
}

func TestDeriveRules_ApprovedActionList(t *testing.T) {
	card := &Card{
		Governance: Governance{
			ApprovedActionList: []string{"echo", "search.*"},
		},
	}
	rules := DeriveRules(card)

	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}
	if rules[0].Match.Tools[0] != "echo" {
		t.Errorf("rules[0].Tools[0] = %q, want %q", rules[0].Match.Tools[0], "echo")
	}
	if rules[0].Action != "allow" {
		t.Errorf("rules[0].Action = %q, want %q", rules[0].Action, "allow")
	}
}

func TestDeriveRules_A1_AllApproval(t *testing.T) {
	card := &Card{
		Governance: Governance{
			ApprovedActionList:  []string{"echo", "read_file"},
			HumanOversightModel: "human-approves-every-action",
		},
	}
	rules := DeriveRules(card)

	for _, r := range rules {
		if r.Action != "require_approval" {
			t.Errorf("rule %q: Action = %q, want require_approval (A1 model)", r.Name, r.Action)
		}
		if r.Approval == nil {
			t.Errorf("rule %q: Approval should not be nil for A1", r.Name)
		}
	}
}

func TestDeriveRules_NoOversight(t *testing.T) {
	card := &Card{
		Governance: Governance{
			ApprovedActionList:  []string{"echo"},
			HumanOversightModel: "human-receives-exception-alerts-only",
		},
	}
	rules := DeriveRules(card)

	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Action != "allow" {
		t.Errorf("A4 oversight should leave rules as allow, got %q", rules[0].Action)
	}
}

func TestDeriveRules_EmptyCard(t *testing.T) {
	card := &Card{}
	rules := DeriveRules(card)
	if len(rules) != 0 {
		t.Errorf("empty card should produce 0 rules, got %d", len(rules))
	}
}

func TestMergeRules_Order(t *testing.T) {
	explicitRules := DeriveRules(&Card{
		Governance: Governance{ApprovedActionList: []string{"explicit_tool"}},
	})
	cardRules := DeriveRules(&Card{
		Governance: Governance{ApprovedActionList: []string{"card_tool"}},
	})

	merged := MergeRules(explicitRules, cardRules)
	if len(merged) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(merged))
	}
	// Explicit rules should come first
	if merged[0].Match.Tools[0] != "explicit_tool" {
		t.Errorf("first rule should match explicit_tool, got %q", merged[0].Match.Tools[0])
	}
	if merged[1].Match.Tools[0] != "card_tool" {
		t.Errorf("second rule should match card_tool, got %q", merged[1].Match.Tools[0])
	}
}
