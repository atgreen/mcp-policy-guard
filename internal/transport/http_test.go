package transport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/atgreen/mcp-policy-guard/internal/audit"
	"github.com/atgreen/mcp-policy-guard/internal/contentfilter"
	"github.com/atgreen/mcp-policy-guard/internal/engine"
	"github.com/atgreen/mcp-policy-guard/internal/escalation"
	"github.com/atgreen/mcp-policy-guard/internal/policy"
	"github.com/atgreen/mcp-policy-guard/internal/ratelimit"
)

func boolPtr(b bool) *bool { return &b }

func setupHTTPProxy(t *testing.T, rules []policy.Rule, defaultAction string, upstream *httptest.Server) *HTTPProxy {
	t.Helper()
	pol := &policy.Policy{
		Version:  1,
		Defaults: &policy.Defaults{Action: defaultAction, Audit: boolPtr(true)},
		Rules:    rules,
	}
	eng := engine.New(pol)
	pipeline := audit.NewPipeline(nil)
	t.Cleanup(func() { pipeline.Close() })

	return NewHTTPProxy(eng, pipeline, nil, nil, nil,
		ratelimit.NewLimiter(nil), contentfilter.NewEngine(nil),
		escalation.NewDispatcher(nil), upstream.URL, ":0",
		func(r *http.Request) string { return "test-agent" })
}

func TestHTTPProxy_AllowToolCall(t *testing.T) {
	// Upstream echo server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct{ ID json.RawMessage `json:"id"` }
		json.Unmarshal(body, &req)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":{"content":[{"type":"text","text":"ok"}]}}`))
	}))
	defer upstream.Close()

	proxy := setupHTTPProxy(t, []policy.Rule{
		{Name: "allow-echo", Match: policy.RuleMatch{Tools: []string{"echo"}}, Action: "allow"},
	}, "deny", upstream)

	// Make a request
	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo","arguments":{}},"id":1}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	proxy.handleRequest(w, req)

	resp := w.Result()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{}       `json:"error"`
	}
	json.Unmarshal(respBody, &rpcResp)
	if rpcResp.Error != nil {
		t.Errorf("expected no error, got one")
	}
	if rpcResp.Result == nil {
		t.Errorf("expected result, got nil")
	}
}

func TestHTTPProxy_DenyToolCall(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called for denied requests")
	}))
	defer upstream.Close()

	proxy := setupHTTPProxy(t, []policy.Rule{
		{Name: "deny-drop", Match: policy.RuleMatch{Tools: []string{"database.drop_*"}}, Action: "deny"},
	}, "deny", upstream)

	body := `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"database.drop_table","arguments":{}},"id":1}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	proxy.handleRequest(w, req)

	respBody, _ := io.ReadAll(w.Result().Body)
	var rpcResp struct {
		Error *struct{ Code int } `json:"error"`
	}
	json.Unmarshal(respBody, &rpcResp)
	if rpcResp.Error == nil {
		t.Fatal("expected error response")
	}
	if rpcResp.Error.Code != -32600 {
		t.Errorf("error code = %d, want -32600", rpcResp.Error.Code)
	}
}

func TestHTTPProxy_PassthroughNonToolCall(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`))
	}))
	defer upstream.Close()

	proxy := setupHTTPProxy(t, nil, "deny", upstream)

	body := `{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	proxy.handleRequest(w, req)

	if w.Result().StatusCode != 200 {
		t.Errorf("status = %d, want 200 (passthrough)", w.Result().StatusCode)
	}
}

func TestHTTPProxy_ToolsListFiltering(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"echo"},{"name":"database.drop_table"}]}}`))
	}))
	defer upstream.Close()

	proxy := setupHTTPProxy(t, []policy.Rule{
		{Name: "allow-echo", Match: policy.RuleMatch{Tools: []string{"echo"}}, Action: "allow"},
	}, "deny", upstream)

	body := `{"jsonrpc":"2.0","method":"tools/list","id":1}`
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	w := httptest.NewRecorder()

	proxy.handleRequest(w, req)

	respBody, _ := io.ReadAll(w.Result().Body)
	var rpcResp struct {
		Result struct {
			Tools []struct{ Name string } `json:"tools"`
		} `json:"result"`
	}
	json.Unmarshal(respBody, &rpcResp)

	if len(rpcResp.Result.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(rpcResp.Result.Tools))
	}
	if rpcResp.Result.Tools[0].Name != "echo" {
		t.Errorf("expected echo, got %q", rpcResp.Result.Tools[0].Name)
	}
}

func TestHTTPProxy_Run(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer upstream.Close()

	proxy := setupHTTPProxy(t, nil, "allow", upstream)
	proxy.listenAddr = "127.0.0.1:0" // random port

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err := proxy.Run(ctx)
	if err != nil {
		t.Errorf("Run() error = %v", err)
	}
}
