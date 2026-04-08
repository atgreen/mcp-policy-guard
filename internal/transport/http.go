package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/atgreen/mcp-policy-guard/internal/approval"
	"github.com/atgreen/mcp-policy-guard/internal/audit"
	"github.com/atgreen/mcp-policy-guard/internal/contentfilter"
	"github.com/atgreen/mcp-policy-guard/internal/engine"
	"github.com/atgreen/mcp-policy-guard/internal/escalation"
	"github.com/atgreen/mcp-policy-guard/internal/jsonrpc"
	"github.com/atgreen/mcp-policy-guard/internal/mutate"
	"github.com/atgreen/mcp-policy-guard/internal/policy"
	"github.com/atgreen/mcp-policy-guard/internal/ratelimit"
	"github.com/atgreen/mcp-policy-guard/internal/toolfilter"
)

// HTTPProxy intercepts MCP JSON-RPC over HTTP, forwarding to an upstream.
type HTTPProxy struct {
	engine        *engine.Engine
	pipeline      *audit.Pipeline
	redactor      *audit.Redactor
	approvalReg   *approval.Registry
	approvalCfg   *policy.ApprovalConfig
	rateLimiter   ratelimit.Checker
	contentFilter *contentfilter.Engine
	escalator     *escalation.Dispatcher
	upstream      string
	listenAddr    string
	identityFunc  func(*http.Request) string
	client        *http.Client
}

// NewHTTPProxy creates an HTTP reverse proxy.
func NewHTTPProxy(
	eng *engine.Engine,
	pipeline *audit.Pipeline,
	redactor *audit.Redactor,
	approvalReg *approval.Registry,
	approvalCfg *policy.ApprovalConfig,
	rateLimiter ratelimit.Checker,
	contentFilter *contentfilter.Engine,
	escalator *escalation.Dispatcher,
	upstream string,
	listenAddr string,
	identityFunc func(*http.Request) string,
	httpClient *http.Client,
) *HTTPProxy {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Minute}
	}
	return &HTTPProxy{
		engine:        eng,
		pipeline:      pipeline,
		redactor:      redactor,
		approvalReg:   approvalReg,
		approvalCfg:   approvalCfg,
		rateLimiter:   rateLimiter,
		contentFilter: contentFilter,
		escalator:     escalator,
		upstream:      upstream,
		listenAddr:    listenAddr,
		identityFunc:  identityFunc,
		client:        httpClient,
	}
}

// Run starts the HTTP proxy server.
func (p *HTTPProxy) Run(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.handleRequest)

	server := &http.Server{
		Addr:    p.listenAddr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutdownCtx)
	}()

	slog.Info("HTTP proxy listening", "addr", p.listenAddr, "upstream", p.upstream)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("HTTP server error: %w", err)
	}
	return nil
}

func (p *HTTPProxy) handleRequest(w http.ResponseWriter, r *http.Request) {
	agentIdentity := "unknown"
	if p.identityFunc != nil {
		agentIdentity = p.identityFunc(r)
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Check if this is a JSON-RPC tools/call
	if !jsonrpc.IsRequest(body) || jsonrpc.IsBatch(body) {
		// Not a single request or is a batch — forward as-is
		p.forwardAndRelay(w, r, body, agentIdentity)
		return
	}

	req, err := jsonrpc.ParseRequest(body)
	if err != nil {
		p.forwardAndRelay(w, r, body, agentIdentity)
		return
	}

	if req.Method != "tools/call" {
		// Forward non-tool-call requests, but intercept tools/list responses
		p.forwardAndRelay(w, r, body, agentIdentity)
		return
	}

	// Handle tools/call with full policy pipeline
	p.handleToolCall(w, r, req, body, agentIdentity)
}

func (p *HTTPProxy) handleToolCall(w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, body []byte, agentIdentity string) {
	start := time.Now()
	requestID := uuid.New().String()

	tcp, err := jsonrpc.ParseToolCallParams(req.Params)
	if err != nil {
		slog.Warn("failed to parse tools/call params, forwarding", "error", err)
		p.forwardAndRelay(w, r, body, agentIdentity)
		return
	}

	// Rate limit check
	if p.rateLimiter != nil {
		rlResult := p.rateLimiter.Check(tcp.Name, agentIdentity)
		if rlResult.Exceeded {
			errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
				rlResult.Message,
				map[string]interface{}{"rule": rlResult.Rule.Name, "policy_guard": true, "rate_limited": true})
			w.Header().Set("Content-Type", "application/json")
			w.Write(errResp)
			rec := p.buildAuditRecord(requestID, tcp, "rate_limited", rlResult.Rule.Name, start, agentIdentity)
			p.emitAudit(rec)
			if rlResult.Rule.Escalate != nil && p.escalator != nil {
				p.escalator.Fire(rlResult.Rule.Escalate.Channel, escalation.Context{
					Tool: tcp.Name, Agent: agentIdentity, TriggerName: rlResult.Rule.Escalate.TriggerName})
			}
			return
		}
	}

	// Content filter check
	if p.contentFilter != nil {
		cfResult := p.contentFilter.CheckRequest(tcp.Name, tcp.Arguments)
		if cfResult.Matched && cfResult.Action == "block" {
			errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
				cfResult.Message,
				map[string]interface{}{"filter": cfResult.Filter.Name, "policy_guard": true, "content_blocked": true})
			w.Header().Set("Content-Type", "application/json")
			w.Write(errResp)
			rec := p.buildAuditRecord(requestID, tcp, "content_blocked", cfResult.Filter.Name, start, agentIdentity)
			p.emitAudit(rec)
			return
		}
	}

	// Policy evaluation
	result := p.engine.Evaluate(tcp.Name, agentIdentity, tcp.Arguments)

	// Escalation
	if result.Rule != nil && result.Rule.Escalate != nil && p.escalator != nil {
		p.escalator.Fire(result.Rule.Escalate.Channel, escalation.Context{
			Tool: tcp.Name, Agent: agentIdentity, Args: string(tcp.Arguments),
			TriggerName: result.Rule.Escalate.TriggerName})
	}

	switch result.Decision {
	case engine.Allow, engine.AuditOnly:
		p.forwardAndRelay(w, r, body, agentIdentity)
		if result.Audit {
			rec := p.buildAuditRecord(requestID, tcp, result.Decision.String(), ruleName(result.Rule), start, agentIdentity)
			p.emitAudit(rec)
		}

	case engine.Deny:
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			fmt.Sprintf("Tool call denied by policy: %s", tcp.Name),
			map[string]interface{}{"rule": ruleName(result.Rule), "policy_guard": true})
		w.Header().Set("Content-Type", "application/json")
		w.Write(errResp)
		if result.Audit {
			rec := p.buildAuditRecord(requestID, tcp, "deny", ruleName(result.Rule), start, agentIdentity)
			p.emitAudit(rec)
		}

	case engine.RequireApproval:
		p.handleHTTPApproval(w, r, req, tcp, body, agentIdentity, requestID, result, start)

	case engine.Mutate:
		p.handleHTTPMutate(w, r, req, tcp, body, agentIdentity, requestID, result, start)
	}
}

func (p *HTTPProxy) handleHTTPApproval(w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, tcp *jsonrpc.ToolCallParams, body []byte, agentIdentity, requestID string, result engine.EvalResult, start time.Time) {
	if result.Rule == nil || result.Rule.Approval == nil {
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			"Tool call requires approval but no approval channel configured",
			map[string]interface{}{"policy_guard": true})
		w.Header().Set("Content-Type", "application/json")
		w.Write(errResp)
		return
	}

	timeout := approval.DefaultTimeout(p.approvalCfg)
	if result.Rule.Approval.Timeout.Duration > 0 {
		timeout = result.Rule.Approval.Timeout.Duration
	}
	approvalCtx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	// Send SSE keepalives while waiting for approval
	flusher, canFlush := w.(http.Flusher)
	if canFlush {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
	}

	// Start keepalive in background
	keepaliveDone := make(chan struct{})
	if canFlush {
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					fmt.Fprintf(w, ": keepalive\n\n")
					flusher.Flush()
				case <-keepaliveDone:
					return
				}
			}
		}()
	}

	approvalReq := approval.Request{
		RequestID: requestID, ToolName: tcp.Name, Arguments: tcp.Arguments,
		RuleName: ruleName(result.Rule), Message: result.Rule.Approval.Message, Agent: agentIdentity,
	}

	approvalResult, err := p.approvalReg.Handle(approvalCtx, result.Rule.Approval.Channel, approvalReq)
	close(keepaliveDone)

	if err != nil || !approvalResult.Approved {
		reason := "rejected"
		if err != nil {
			reason = err.Error()
		} else if approvalResult.Reason != "" {
			reason = approvalResult.Reason
		}
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			fmt.Sprintf("Tool call rejected: %s", reason),
			map[string]interface{}{"rule": ruleName(result.Rule), "policy_guard": true})
		if canFlush {
			fmt.Fprintf(w, "data: %s\n\n", errResp)
			flusher.Flush()
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.Write(errResp)
		}
		rec := p.buildAuditRecord(requestID, tcp, "rejected", ruleName(result.Rule), start, agentIdentity)
		p.emitAudit(rec)
		return
	}

	// Approved — forward to upstream
	p.forwardAndRelaySSE(w, r, body, agentIdentity, canFlush, flusher)
	rec := p.buildAuditRecord(requestID, tcp, "approved", ruleName(result.Rule), start, agentIdentity)
	rec.Approver = approvalResult.Approver
	rec.ApprovalLatencyMs = approvalResult.LatencyMs
	p.emitAudit(rec)
}

func (p *HTTPProxy) handleHTTPMutate(w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, tcp *jsonrpc.ToolCallParams, body []byte, agentIdentity, requestID string, result engine.EvalResult, start time.Time) {
	if result.Rule == nil || result.Rule.Mutate == nil {
		p.forwardAndRelay(w, r, body, agentIdentity)
		return
	}

	mutated, err := mutate.Apply(result.Rule.Mutate.Arguments, tcp.Arguments, p.engine.CEL(), tcp.Name, agentIdentity)
	if err != nil {
		slog.Warn("mutation failed, forwarding original", "error", err)
		p.forwardAndRelay(w, r, body, agentIdentity)
		return
	}

	// Rebuild request with mutated arguments
	newParams := jsonrpc.ToolCallParams{Name: tcp.Name, Arguments: mutated}
	paramsJSON, _ := json.Marshal(newParams)
	newReq := jsonrpc.Request{Jsonrpc: req.Jsonrpc, Method: req.Method, Params: paramsJSON, ID: req.ID}
	newBody, _ := json.Marshal(newReq)

	p.forwardAndRelay(w, r, newBody, agentIdentity)
	if result.Audit {
		rec := p.buildAuditRecord(requestID, tcp, "mutated", ruleName(result.Rule), start, agentIdentity)
		p.emitAudit(rec)
	}
}

// forwardAndRelay sends the request to upstream and streams the response back.
func (p *HTTPProxy) forwardAndRelay(w http.ResponseWriter, origReq *http.Request, body []byte, agentIdentity string) {
	upstreamReq, err := http.NewRequestWithContext(origReq.Context(), origReq.Method, p.upstream, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusBadGateway)
		return
	}

	// Copy headers
	for k, vv := range origReq.Header {
		for _, v := range vv {
			upstreamReq.Header.Add(k, v)
		}
	}

	resp, err := p.client.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// If SSE response, filter tools/list if applicable
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		p.relaySSE(w, resp.Body, agentIdentity)
	} else {
		// Regular response — check for tools/list filtering
		respBody, _ := io.ReadAll(resp.Body)
		respBody = p.maybeFilterToolsList(respBody, agentIdentity)
		w.Write(respBody)
	}
}

func (p *HTTPProxy) forwardAndRelaySSE(w http.ResponseWriter, origReq *http.Request, body []byte, agentIdentity string, canFlush bool, flusher http.Flusher) {
	upstreamReq, err := http.NewRequestWithContext(origReq.Context(), origReq.Method, p.upstream, bytes.NewReader(body))
	if err != nil {
		return
	}
	for k, vv := range origReq.Header {
		for _, v := range vv {
			upstreamReq.Header.Add(k, v)
		}
	}

	resp, err := p.client.Do(upstreamReq)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if canFlush {
		p.relaySSE(w, resp.Body, agentIdentity)
	} else {
		respBody, _ := io.ReadAll(resp.Body)
		w.Write(respBody)
	}
}

func (p *HTTPProxy) relaySSE(w http.ResponseWriter, r io.Reader, agentIdentity string) {
	flusher, canFlush := w.(http.Flusher)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// Check if this is a data line with tools/list content
		if strings.HasPrefix(line, "data: ") {
			data := line[6:]
			filtered := p.maybeFilterToolsList([]byte(data), agentIdentity)
			fmt.Fprintf(w, "data: %s\n", filtered)
		} else {
			fmt.Fprintf(w, "%s\n", line)
		}

		if canFlush {
			flusher.Flush()
		}
	}
}

func (p *HTTPProxy) maybeFilterToolsList(data []byte, agentIdentity string) []byte {
	var resp jsonrpc.Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return data
	}
	if resp.Result == nil {
		return data
	}
	// Check if result has a "tools" array
	var probe struct {
		Tools json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(resp.Result, &probe) != nil || len(probe.Tools) == 0 {
		return data
	}

	resp.Result = toolfilter.FilterToolsList(resp.Result, p.engine, agentIdentity)
	out, err := json.Marshal(resp)
	if err != nil {
		return data
	}
	return out
}

func (p *HTTPProxy) buildAuditRecord(requestID string, tcp *jsonrpc.ToolCallParams, decision, rule string, start time.Time, agentIdentity string) audit.Record {
	return audit.Record{
		Timestamp: start.UTC(),
		RequestID: requestID,
		Agent:     agentIdentity,
		Tool:      tcp.Name,
		Arguments: tcp.Arguments,
		Decision:  decision,
		Rule:      rule,
		LatencyMs: time.Since(start).Milliseconds(),
	}
}

func (p *HTTPProxy) emitAudit(rec audit.Record) {
	if p.redactor != nil {
		rec = p.redactor.Redact(rec)
	}
	p.pipeline.Emit(rec)
}
