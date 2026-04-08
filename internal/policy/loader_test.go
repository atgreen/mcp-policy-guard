package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func setupSchema(t *testing.T) {
	t.Helper()
	// Load the real schema from the project root
	schemaPath := filepath.Join("..", "..", "policy-schema.json")
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("failed to read schema: %v", err)
	}
	SetSchema(data)
}

func TestLoad_ValidPolicy(t *testing.T) {
	setupSchema(t)

	policyPath := filepath.Join("..", "..", "testdata", "test-policy.yaml")
	pol, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if pol.Version != 1 {
		t.Errorf("Version = %d, want 1", pol.Version)
	}
	if len(pol.Rules) != 2 {
		t.Errorf("Rules count = %d, want 2", len(pol.Rules))
	}
	if pol.Rules[0].Name != "allow-echo" {
		t.Errorf("Rules[0].Name = %q, want %q", pol.Rules[0].Name, "allow-echo")
	}
	if pol.Rules[1].Action != "deny" {
		t.Errorf("Rules[1].Action = %q, want %q", pol.Rules[1].Action, "deny")
	}
}

func TestLoad_MinimalPolicy(t *testing.T) {
	setupSchema(t)

	policyPath := filepath.Join("..", "..", "examples", "policy-minimal.yaml")
	pol, err := Load(policyPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if pol.AgentCard == nil {
		t.Fatal("AgentCard should not be nil")
	}
	if pol.AgentCard.Path != "./agent-card.json" {
		t.Errorf("AgentCard.Path = %q", pol.AgentCard.Path)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	setupSchema(t)

	tmp := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(tmp, []byte(`{{{not yaml`), 0o644)

	_, err := Load(tmp)
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoad_SchemaViolation_MissingRulesAndCard(t *testing.T) {
	setupSchema(t)

	tmp := filepath.Join(t.TempDir(), "no-rules.yaml")
	os.WriteFile(tmp, []byte("version: 1\ndefaults:\n  action: deny\n"), 0o644)

	_, err := Load(tmp)
	if err == nil {
		t.Error("expected error when neither rules nor agent_card is present")
	}
}

func TestLoad_SchemaViolation_UnknownField(t *testing.T) {
	setupSchema(t)

	// Unknown top-level fields should be rejected
	tmp := filepath.Join(t.TempDir(), "unknown.yaml")
	os.WriteFile(tmp, []byte("version: 1\nrules:\n  - name: x\n    match:\n      tools: ['*']\n    action: allow\nfuture_field: true\n"), 0o644)

	_, err := Load(tmp)
	if err == nil {
		t.Error("expected error for unknown top-level field")
	}
}

func TestLoad_RateLimits_Accepted(t *testing.T) {
	setupSchema(t)

	yaml := `
version: 1
rules:
  - name: allow-all
    match:
      tools: ['*']
    action: allow
rate_limits:
  - name: global
    match:
      tools: ['*']
    limit:
      requests: 100
      window: 60s
    key: agent
    on_exceed: deny
`
	tmp := filepath.Join(t.TempDir(), "rl.yaml")
	os.WriteFile(tmp, []byte(yaml), 0o644)

	pol, err := Load(tmp)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(pol.RateLimits) != 1 {
		t.Errorf("RateLimits = %d, want 1", len(pol.RateLimits))
	}
}

func TestLoad_SemanticValidation_BadApprovalChannel(t *testing.T) {
	setupSchema(t)

	yaml := `
version: 1
approval:
  channels:
    - name: terminal
      type: terminal
rules:
  - name: test
    match:
      tools: ['*']
    action: require_approval
    approval:
      channel: nonexistent
`
	tmp := filepath.Join(t.TempDir(), "bad-channel.yaml")
	os.WriteFile(tmp, []byte(yaml), 0o644)

	_, err := Load(tmp)
	if err == nil {
		t.Error("expected error for nonexistent approval channel reference")
	}
}

func TestLoad_EnvVarExpansion(t *testing.T) {
	setupSchema(t)

	os.Setenv("TEST_TOOL_NAME", "expanded_tool")
	defer os.Unsetenv("TEST_TOOL_NAME")

	yaml := `
version: 1
rules:
  - name: env-test
    match:
      tools: ['${TEST_TOOL_NAME}']
    action: allow
`
	tmp := filepath.Join(t.TempDir(), "env.yaml")
	os.WriteFile(tmp, []byte(yaml), 0o644)

	pol, err := Load(tmp)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if pol.Rules[0].Match.Tools[0] != "expanded_tool" {
		t.Errorf("tool = %q, want %q", pol.Rules[0].Match.Tools[0], "expanded_tool")
	}
}

func TestDuration_UnmarshalYAML(t *testing.T) {
	tests := []struct {
		input string
		ms    int64
	}{
		{"100ms", 100},
		{"5s", 5000},
		{"2m", 120000},
		{"1h", 3600000},
	}
	for _, tt := range tests {
		var d Duration
		err := d.parse(tt.input)
		if err != nil {
			t.Errorf("parse(%q) error = %v", tt.input, err)
			continue
		}
		if d.Milliseconds() != tt.ms {
			t.Errorf("parse(%q) = %dms, want %dms", tt.input, d.Milliseconds(), tt.ms)
		}
	}
}

func TestDuration_Invalid(t *testing.T) {
	invalids := []string{"", "abc", "5x", "5"}
	for _, s := range invalids {
		var d Duration
		if err := d.parse(s); err == nil {
			t.Errorf("parse(%q) should fail", s)
		}
	}
}

func TestEffectiveDefaults(t *testing.T) {
	// Nil defaults
	pol := &Policy{Version: 1}
	d := pol.EffectiveDefaults()
	if d.Action != "deny" {
		t.Errorf("Action = %q, want %q", d.Action, "deny")
	}
	if d.DenyMessage != "Tool call not permitted by policy" {
		t.Errorf("DenyMessage = %q", d.DenyMessage)
	}

	// Custom defaults
	pol2 := &Policy{
		Version:  1,
		Defaults: &Defaults{Action: "allow", DenyMessage: "custom"},
	}
	d2 := pol2.EffectiveDefaults()
	if d2.Action != "allow" {
		t.Errorf("Action = %q, want %q", d2.Action, "allow")
	}
	if d2.DenyMessage != "custom" {
		t.Errorf("DenyMessage = %q, want %q", d2.DenyMessage, "custom")
	}
}
