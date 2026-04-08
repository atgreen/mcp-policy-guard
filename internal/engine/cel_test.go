package engine

import (
	"encoding/json"
	"testing"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

func TestCELEvaluator_BasicExpressions(t *testing.T) {
	eval, err := NewCELEvaluator()
	if err != nil {
		t.Fatalf("NewCELEvaluator() error = %v", err)
	}

	tests := []struct {
		name   string
		expr   string
		tool   string
		agent  string
		args   string
		want   bool
	}{
		{
			name: "amount threshold",
			expr: "double(args.amount) > 1000000.0",
			args: `{"amount": 2000000}`,
			want: true,
		},
		{
			name: "amount below threshold",
			expr: "double(args.amount) > 1000000.0",
			args: `{"amount": 500}`,
			want: false,
		},
		{
			name: "string match",
			expr: `args.sql.matches('(?i)(DELETE|DROP)')`,
			args: `{"sql": "DELETE FROM users"}`,
			want: true,
		},
		{
			name: "string no match",
			expr: `args.sql.matches('(?i)(DELETE|DROP)')`,
			args: `{"sql": "SELECT * FROM users"}`,
			want: false,
		},
		{
			name: "tool name check",
			expr: `tool.startsWith("admin.")`,
			tool: "admin.reset",
			want: true,
		},
		{
			name: "tool name no match",
			expr: `tool.startsWith("admin.")`,
			tool: "user.read",
			want: false,
		},
		{
			name: "agent identity check",
			expr: `agent == "trusted-agent"`,
			agent: "trusted-agent",
			want:  true,
		},
		{
			name: "boolean literal true",
			expr: "true",
			want: true,
		},
		{
			name: "boolean literal false",
			expr: "false",
			want: false,
		},
		{
			name: "nested field access",
			expr: `args.config.dangerous == true`,
			args: `{"config": {"dangerous": true}}`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var args json.RawMessage
			if tt.args != "" {
				args = json.RawMessage(tt.args)
			}
			got, err := eval.Evaluate(tt.expr, tt.tool, tt.agent, args)
			if err != nil {
				t.Fatalf("Evaluate() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Evaluate(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestCELEvaluator_CompileError(t *testing.T) {
	eval, _ := NewCELEvaluator()
	_, err := eval.Evaluate("invalid syntax !!!", "tool", "agent", nil)
	if err == nil {
		t.Error("expected compile error for invalid CEL")
	}
}

func TestCELEvaluator_NilArgs(t *testing.T) {
	eval, _ := NewCELEvaluator()
	// Expression that doesn't use args should work with nil args
	got, err := eval.Evaluate(`tool == "echo"`, "echo", "agent", nil)
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if !got {
		t.Error("expected true")
	}
}

func TestCELEvaluator_Caching(t *testing.T) {
	eval, _ := NewCELEvaluator()

	// Evaluate same expression twice — second should use cache
	expr := `args.x == "hello"`
	args := json.RawMessage(`{"x": "hello"}`)

	got1, _ := eval.Evaluate(expr, "", "", args)
	got2, _ := eval.Evaluate(expr, "", "", args)
	if got1 != got2 {
		t.Error("cached result should match")
	}
}

func TestEngine_WithCEL(t *testing.T) {
	pol := newTestPolicy([]policy.Rule{
		{
			Name: "high-value",
			Match: policy.RuleMatch{
				Tools:     []string{"payments.*"},
				Arguments: &policy.ArgumentMatch{CEL: "double(args.amount) > 1000000.0"},
			},
			Action: "deny",
			DenyMessage: "High-value transaction blocked",
		},
		{
			Name:  "allow-payments",
			Match: policy.RuleMatch{Tools: []string{"payments.*"}},
			Action: "allow",
		},
	}, "deny")

	eng := New(pol)

	// High value should be denied
	r := eng.Evaluate("payments.submit", "agent", json.RawMessage(`{"amount": 5000000}`))
	if r.Decision != Deny {
		t.Errorf("high-value: got %v, want Deny", r.Decision)
	}

	// Low value should be allowed (CEL doesn't match, falls through to next rule)
	r = eng.Evaluate("payments.submit", "agent", json.RawMessage(`{"amount": 100}`))
	if r.Decision != Allow {
		t.Errorf("low-value: got %v, want Allow", r.Decision)
	}
}
