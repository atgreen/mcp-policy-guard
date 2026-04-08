package audit

import (
	"encoding/json"
	"testing"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

func TestRedactor_Fields(t *testing.T) {
	r := NewRedactor(&policy.AuditRedaction{
		Fields: []string{"password", "token"},
	})

	rec := Record{
		Arguments: json.RawMessage(`{"user":"alice","password":"secret123","token":"abc"}`),
	}
	redacted := r.Redact(rec)

	var args map[string]interface{}
	json.Unmarshal(redacted.Arguments, &args)

	if args["user"] != "alice" {
		t.Errorf("user should not be redacted, got %v", args["user"])
	}
	if args["password"] != "[REDACTED]" {
		t.Errorf("password should be redacted, got %v", args["password"])
	}
	if args["token"] != "[REDACTED]" {
		t.Errorf("token should be redacted, got %v", args["token"])
	}
}

func TestRedactor_Patterns(t *testing.T) {
	r := NewRedactor(&policy.AuditRedaction{
		Patterns: []policy.RedactionPattern{
			{Name: "ssn", Regex: `\b\d{3}-\d{2}-\d{4}\b`, Replacement: "[REDACTED:ssn]"},
		},
	})

	rec := Record{
		Arguments: json.RawMessage(`{"query":"SELECT * WHERE ssn='123-45-6789'"}`),
	}
	redacted := r.Redact(rec)

	var args map[string]interface{}
	json.Unmarshal(redacted.Arguments, &args)

	expected := "SELECT * WHERE ssn='[REDACTED:ssn]'"
	if args["query"] != expected {
		t.Errorf("query = %q, want %q", args["query"], expected)
	}
}

func TestRedactor_NestedFields(t *testing.T) {
	r := NewRedactor(&policy.AuditRedaction{
		Fields: []string{"secret"},
	})

	rec := Record{
		Arguments: json.RawMessage(`{"config":{"secret":"hidden","name":"test"}}`),
	}
	redacted := r.Redact(rec)

	var args map[string]interface{}
	json.Unmarshal(redacted.Arguments, &args)

	config := args["config"].(map[string]interface{})
	if config["secret"] != "[REDACTED]" {
		t.Errorf("nested secret should be redacted, got %v", config["secret"])
	}
	if config["name"] != "test" {
		t.Errorf("name should not be redacted, got %v", config["name"])
	}
}

func TestRedactor_CaseInsensitiveFields(t *testing.T) {
	r := NewRedactor(&policy.AuditRedaction{
		Fields: []string{"Password"},
	})

	rec := Record{
		Arguments: json.RawMessage(`{"password":"secret"}`),
	}
	redacted := r.Redact(rec)

	var args map[string]interface{}
	json.Unmarshal(redacted.Arguments, &args)

	if args["password"] != "[REDACTED]" {
		t.Errorf("field matching should be case-insensitive, got %v", args["password"])
	}
}

func TestRedactor_EmptyArguments(t *testing.T) {
	r := NewRedactor(&policy.AuditRedaction{Fields: []string{"secret"}})
	rec := Record{}
	redacted := r.Redact(rec)
	if len(redacted.Arguments) != 0 {
		t.Error("empty arguments should stay empty")
	}
}

func TestRedactor_Nil(t *testing.T) {
	r := NewRedactor(nil)
	rec := Record{Arguments: json.RawMessage(`{"password":"secret"}`)}
	redacted := r.Redact(rec)
	// No redaction configured — should pass through unchanged
	if string(redacted.Arguments) != `{"password":"secret"}` {
		t.Errorf("nil redactor should not modify arguments")
	}
}

func TestRedactor_ArrayValues(t *testing.T) {
	r := NewRedactor(&policy.AuditRedaction{
		Patterns: []policy.RedactionPattern{
			{Name: "cc", Regex: `\b\d{4}-\d{4}-\d{4}-\d{4}\b`, Replacement: "[REDACTED:cc]"},
		},
	})

	rec := Record{
		Arguments: json.RawMessage(`{"cards":["1234-5678-9012-3456","other"]}`),
	}
	redacted := r.Redact(rec)

	var args map[string]interface{}
	json.Unmarshal(redacted.Arguments, &args)

	cards := args["cards"].([]interface{})
	if cards[0] != "[REDACTED:cc]" {
		t.Errorf("card should be redacted, got %v", cards[0])
	}
	if cards[1] != "other" {
		t.Errorf("other should be unchanged, got %v", cards[1])
	}
}
