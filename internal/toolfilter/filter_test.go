package toolfilter

import (
	"encoding/json"
	"testing"

	"github.com/atgreen/mcp-policy-guard/internal/engine"
	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

func boolPtr(b bool) *bool { return &b }

func TestFilterToolsList_RemovesDenied(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Defaults: &policy.Defaults{Action: "deny", Audit: boolPtr(true)},
		Rules: []policy.Rule{
			{Name: "allow-echo", Match: policy.RuleMatch{Tools: []string{"echo"}}, Action: "allow"},
			// database.drop_table has no allow rule → default deny
		},
	}
	eng := engine.New(pol)

	input := json.RawMessage(`{"tools":[{"name":"echo","description":"Echo"},{"name":"database.drop_table","description":"Drop"}]}`)
	output := FilterToolsList(input, eng, "agent")

	var result struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	json.Unmarshal(output, &result)

	if len(result.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(result.Tools))
	}
	if result.Tools[0].Name != "echo" {
		t.Errorf("expected echo, got %q", result.Tools[0].Name)
	}
}

func TestFilterToolsList_KeepsAllowed(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Defaults: &policy.Defaults{Action: "allow", Audit: boolPtr(true)},
	}
	eng := engine.New(pol)

	input := json.RawMessage(`{"tools":[{"name":"a"},{"name":"b"},{"name":"c"}]}`)
	output := FilterToolsList(input, eng, "agent")

	var result struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	json.Unmarshal(output, &result)

	if len(result.Tools) != 3 {
		t.Errorf("expected 3 tools, got %d", len(result.Tools))
	}
}

func TestFilterToolsList_EmptyResult(t *testing.T) {
	output := FilterToolsList(nil, nil, "")
	if output != nil {
		t.Error("nil input should return nil")
	}
}

func TestFilterToolsList_PreservesCursor(t *testing.T) {
	pol := &policy.Policy{
		Version: 1,
		Defaults: &policy.Defaults{Action: "allow", Audit: boolPtr(true)},
	}
	eng := engine.New(pol)

	input := json.RawMessage(`{"tools":[{"name":"a"}],"cursor":"next-page"}`)
	output := FilterToolsList(input, eng, "agent")

	var result struct {
		Cursor string `json:"cursor"`
	}
	json.Unmarshal(output, &result)

	if result.Cursor != "next-page" {
		t.Errorf("cursor = %q, want %q", result.Cursor, "next-page")
	}
}
