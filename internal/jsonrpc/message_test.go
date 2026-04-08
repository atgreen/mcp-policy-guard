package jsonrpc

import (
	"encoding/json"
	"testing"
)

func TestIsRequest(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"valid request", `{"jsonrpc":"2.0","method":"tools/call","id":1}`, true},
		{"response", `{"jsonrpc":"2.0","result":{},"id":1}`, false},
		{"empty object", `{}`, false},
		{"invalid json", `not json`, false},
		{"notification", `{"jsonrpc":"2.0","method":"ping"}`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsRequest([]byte(tt.data)); got != tt.want {
				t.Errorf("IsRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsBatch(t *testing.T) {
	tests := []struct {
		name string
		data string
		want bool
	}{
		{"single object", `{"jsonrpc":"2.0"}`, false},
		{"array", `[{"jsonrpc":"2.0"},{"jsonrpc":"2.0"}]`, true},
		{"empty array", `[]`, true},
		{"whitespace then array", `  [{}]`, true},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsBatch([]byte(tt.data)); got != tt.want {
				t.Errorf("IsBatch() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseRequest(t *testing.T) {
	data := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}},"id":42}`
	req, err := ParseRequest([]byte(data))
	if err != nil {
		t.Fatalf("ParseRequest() error = %v", err)
	}
	if req.Method != "tools/call" {
		t.Errorf("Method = %q, want %q", req.Method, "tools/call")
	}
	if req.Jsonrpc != "2.0" {
		t.Errorf("Jsonrpc = %q, want %q", req.Jsonrpc, "2.0")
	}
}

func TestParseRequest_Invalid(t *testing.T) {
	_, err := ParseRequest([]byte(`not json`))
	if err == nil {
		t.Error("ParseRequest() expected error for invalid JSON")
	}
}

func TestParseToolCallParams(t *testing.T) {
	params := json.RawMessage(`{"name":"database.drop_table","arguments":{"table":"users"}}`)
	tcp, err := ParseToolCallParams(params)
	if err != nil {
		t.Fatalf("ParseToolCallParams() error = %v", err)
	}
	if tcp.Name != "database.drop_table" {
		t.Errorf("Name = %q, want %q", tcp.Name, "database.drop_table")
	}
	if string(tcp.Arguments) != `{"table":"users"}` {
		t.Errorf("Arguments = %s, want %s", tcp.Arguments, `{"table":"users"}`)
	}
}

func TestMakeErrorResponse(t *testing.T) {
	id := json.RawMessage(`42`)
	resp := MakeErrorResponse(id, PolicyDeniedCode, "denied", map[string]interface{}{"rule": "test"})

	var parsed Response
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("failed to parse error response: %v", err)
	}
	if parsed.Jsonrpc != "2.0" {
		t.Errorf("Jsonrpc = %q, want %q", parsed.Jsonrpc, "2.0")
	}
	if string(parsed.ID) != "42" {
		t.Errorf("ID = %s, want 42", parsed.ID)
	}
	if parsed.Error == nil {
		t.Fatal("Error is nil")
	}
	if parsed.Error.Code != PolicyDeniedCode {
		t.Errorf("Error.Code = %d, want %d", parsed.Error.Code, PolicyDeniedCode)
	}
	if parsed.Error.Message != "denied" {
		t.Errorf("Error.Message = %q, want %q", parsed.Error.Message, "denied")
	}
}

func TestMakeErrorResponse_NilData(t *testing.T) {
	resp := MakeErrorResponse(json.RawMessage(`1`), -32600, "err", nil)
	var parsed Response
	if err := json.Unmarshal(resp, &parsed); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if parsed.Error.Data != nil {
		t.Errorf("Error.Data should be nil, got %s", parsed.Error.Data)
	}
}
