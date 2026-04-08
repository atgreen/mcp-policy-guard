package mutate

import (
	"encoding/json"
	"testing"

	"github.com/atgreen/mcp-policy-guard/internal/engine"
	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

func TestApply_StaticReplace(t *testing.T) {
	ops := []policy.MutateOp{
		{Op: "replace", Path: "/name", Value: "redacted"},
	}
	args := json.RawMessage(`{"name":"secret","value":42}`)
	result, err := Apply(ops, args, nil, "tool", "agent")
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(result, &m)
	if m["name"] != "redacted" {
		t.Errorf("name = %v, want %q", m["name"], "redacted")
	}
	if m["value"] != float64(42) {
		t.Errorf("value should be unchanged, got %v", m["value"])
	}
}

func TestApply_Remove(t *testing.T) {
	ops := []policy.MutateOp{
		{Op: "remove", Path: "/secret"},
	}
	args := json.RawMessage(`{"name":"test","secret":"hidden"}`)
	result, err := Apply(ops, args, nil, "tool", "agent")
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(result, &m)
	if _, exists := m["secret"]; exists {
		t.Error("secret field should be removed")
	}
	if m["name"] != "test" {
		t.Error("name should be unchanged")
	}
}

func TestApply_Add(t *testing.T) {
	ops := []policy.MutateOp{
		{Op: "add", Path: "/trace_id", Value: "abc-123"},
	}
	args := json.RawMessage(`{"name":"test"}`)
	result, err := Apply(ops, args, nil, "tool", "agent")
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(result, &m)
	if m["trace_id"] != "abc-123" {
		t.Errorf("trace_id = %v, want %q", m["trace_id"], "abc-123")
	}
}

func TestApply_WithCEL(t *testing.T) {
	celEval, _ := engine.NewCELEvaluator()
	ops := []policy.MutateOp{
		{Op: "replace", Path: "/amount", CEL: "int(args.amount) * 100"},
	}
	args := json.RawMessage(`{"amount":42}`)
	result, err := Apply(ops, args, celEval, "tool", "agent")
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(result, &m)
	// CEL returns int64, JSON marshal/unmarshal converts to float64
	if m["amount"] != float64(4200) {
		t.Errorf("amount = %v, want 4200", m["amount"])
	}
}

func TestApply_MultipleOps(t *testing.T) {
	ops := []policy.MutateOp{
		{Op: "add", Path: "/injected", Value: true},
		{Op: "remove", Path: "/secret"},
	}
	args := json.RawMessage(`{"name":"test","secret":"hidden"}`)
	result, err := Apply(ops, args, nil, "tool", "agent")
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(result, &m)
	if m["injected"] != true {
		t.Error("injected should be true")
	}
	if _, exists := m["secret"]; exists {
		t.Error("secret should be removed")
	}
}

func TestApply_EmptyOps(t *testing.T) {
	args := json.RawMessage(`{"name":"test"}`)
	result, err := Apply(nil, args, nil, "tool", "agent")
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if string(result) != string(args) {
		t.Error("empty ops should return unchanged args")
	}
}
