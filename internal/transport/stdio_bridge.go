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
	"os"
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

// StdioBridge reads MCP JSON-RPC from stdin, applies policy, and forwards
// allowed calls to an HTTP upstream. Responses are written to stdout.
// This enables using mcp-policy-guard as a stdio MCP server command
// while the actual MCP server is a remote HTTP endpoint.
type StdioBridge struct {
	engine        *engine.Engine
	pipeline      *audit.Pipeline
	redactor      *audit.Redactor
	approvalReg   *approval.Registry
	approvalCfg   *policy.ApprovalConfig
	rateLimiter   ratelimit.Checker
	contentFilter *contentfilter.Engine
	escalator     *escalation.Dispatcher
	agentIdentity string
	upstream      string
	client        *http.Client
}

// NewStdioBridge creates a stdio-to-HTTP bridge.
func NewStdioBridge(
	eng *engine.Engine,
	pipeline *audit.Pipeline,
	redactor *audit.Redactor,
	approvalReg *approval.Registry,
	approvalCfg *policy.ApprovalConfig,
	rateLimiter ratelimit.Checker,
	contentFilter *contentfilter.Engine,
	escalator *escalation.Dispatcher,
	agentIdentity string,
	upstream string,
) *StdioBridge {
	return &StdioBridge{
		engine:        eng,
		pipeline:      pipeline,
		redactor:      redactor,
		approvalReg:   approvalReg,
		approvalCfg:   approvalCfg,
		rateLimiter:   rateLimiter,
		contentFilter: contentFilter,
		escalator:     escalator,
		agentIdentity: agentIdentity,
		upstream:      upstream,
		client:        &http.Client{Timeout: 5 * time.Minute},
	}
}

// Run reads from stdin, applies policy, forwards to upstream, writes responses to stdout.
func (b *StdioBridge) Run(ctx context.Context) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		line := scanner.Bytes()

		if !jsonrpc.IsRequest(line) || jsonrpc.IsBatch(line) {
			// Forward to upstream, relay response
			b.forwardAndPrint(ctx, line)
			continue
		}

		req, err := jsonrpc.ParseRequest(line)
		if err != nil {
			b.forwardAndPrint(ctx, line)
			continue
		}

		if req.Method != "tools/call" {
			// Forward non-tool-call, filter tools/list responses
			b.forwardAndPrint(ctx, line)
			continue
		}

		b.handleToolCall(ctx, req, line)
	}
	return nil
}

func (b *StdioBridge) handleToolCall(ctx context.Context, req *jsonrpc.Request, originalLine []byte) {
	start := time.Now()
	requestID := uuid.New().String()

	tcp, err := jsonrpc.ParseToolCallParams(req.Params)
	if err != nil {
		slog.Warn("failed to parse tools/call params, forwarding", "error", err)
		b.forwardAndPrint(ctx, originalLine)
		return
	}

	// Rate limit
	if b.rateLimiter != nil {
		rlResult := b.rateLimiter.Check(tcp.Name, b.agentIdentity)
		if rlResult.Exceeded {
			errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
				rlResult.Message,
				map[string]interface{}{"rule": rlResult.Rule.Name, "policy_guard": true, "rate_limited": true})
			fmt.Fprintf(os.Stdout, "%s\n", errResp)
			b.emitAudit(audit.Record{Timestamp: start.UTC(), RequestID: requestID, Agent: b.agentIdentity, Tool: tcp.Name, Arguments: tcp.Arguments, Decision: "rate_limited", Rule: rlResult.Rule.Name, LatencyMs: time.Since(start).Milliseconds()})
			return
		}
	}

	// Content filter
	if b.contentFilter != nil {
		cfResult := b.contentFilter.CheckRequest(tcp.Name, tcp.Arguments)
		if cfResult.Matched && cfResult.Action == "block" {
			errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
				cfResult.Message,
				map[string]interface{}{"filter": cfResult.Filter.Name, "policy_guard": true, "content_blocked": true})
			fmt.Fprintf(os.Stdout, "%s\n", errResp)
			return
		}
	}

	// Policy evaluation
	result := b.engine.Evaluate(tcp.Name, b.agentIdentity, tcp.Arguments)

	// Escalation
	if result.Rule != nil && result.Rule.Escalate != nil && b.escalator != nil {
		b.escalator.Fire(result.Rule.Escalate.Channel, escalation.Context{
			Tool: tcp.Name, Agent: b.agentIdentity, Args: string(tcp.Arguments),
			TriggerName: result.Rule.Escalate.TriggerName})
	}

	switch result.Decision {
	case engine.Allow, engine.AuditOnly:
		b.forwardAndPrint(ctx, originalLine)
		if result.Audit {
			b.emitAudit(audit.Record{Timestamp: start.UTC(), RequestID: requestID, Agent: b.agentIdentity, Tool: tcp.Name, Arguments: tcp.Arguments, Decision: result.Decision.String(), Rule: ruleName(result.Rule), LatencyMs: time.Since(start).Milliseconds()})
		}

	case engine.Deny:
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			fmt.Sprintf("Tool call denied by policy: %s", tcp.Name),
			map[string]interface{}{"rule": ruleName(result.Rule), "policy_guard": true})
		fmt.Fprintf(os.Stdout, "%s\n", errResp)
		if result.Audit {
			b.emitAudit(audit.Record{Timestamp: start.UTC(), RequestID: requestID, Agent: b.agentIdentity, Tool: tcp.Name, Arguments: tcp.Arguments, Decision: "deny", Rule: ruleName(result.Rule), LatencyMs: time.Since(start).Milliseconds()})
		}

	case engine.RequireApproval:
		b.handleApproval(ctx, req, tcp, originalLine, requestID, result, start)

	case engine.Mutate:
		if result.Rule != nil && result.Rule.Mutate != nil {
			mutated, err := mutate.Apply(result.Rule.Mutate.Arguments, tcp.Arguments, b.engine.CEL(), tcp.Name, b.agentIdentity)
			if err != nil {
				slog.Warn("mutation failed, forwarding original", "error", err)
				b.forwardAndPrint(ctx, originalLine)
				return
			}
			newParams := jsonrpc.ToolCallParams{Name: tcp.Name, Arguments: mutated}
			paramsJSON, _ := json.Marshal(newParams)
			newReq := jsonrpc.Request{Jsonrpc: req.Jsonrpc, Method: req.Method, Params: paramsJSON, ID: req.ID}
			newLine, _ := json.Marshal(newReq)
			b.forwardAndPrint(ctx, newLine)
		} else {
			b.forwardAndPrint(ctx, originalLine)
		}
	}
}

func (b *StdioBridge) handleApproval(ctx context.Context, req *jsonrpc.Request, tcp *jsonrpc.ToolCallParams, originalLine []byte, requestID string, result engine.EvalResult, start time.Time) {
	if result.Rule == nil || result.Rule.Approval == nil {
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			"Tool call requires approval but no approval channel configured",
			map[string]interface{}{"policy_guard": true})
		fmt.Fprintf(os.Stdout, "%s\n", errResp)
		return
	}

	timeout := approval.DefaultTimeout(b.approvalCfg)
	if result.Rule.Approval.Timeout.Duration > 0 {
		timeout = result.Rule.Approval.Timeout.Duration
	}
	approvalCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	approvalReq := approval.Request{
		RequestID: requestID, ToolName: tcp.Name, Arguments: tcp.Arguments,
		RuleName: ruleName(result.Rule), Message: result.Rule.Approval.Message, Agent: b.agentIdentity,
	}

	approvalResult, err := b.approvalReg.Handle(approvalCtx, result.Rule.Approval.Channel, approvalReq)
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
		fmt.Fprintf(os.Stdout, "%s\n", errResp)
		return
	}

	// Approved — forward to upstream
	b.forwardAndPrint(ctx, originalLine)
}

// forwardAndPrint sends a JSON-RPC message to the HTTP upstream and prints the response to stdout.
func (b *StdioBridge) forwardAndPrint(ctx context.Context, body []byte) {
	httpReq, err := http.NewRequestWithContext(ctx, "POST", b.upstream, bytes.NewReader(body))
	if err != nil {
		slog.Error("creating upstream request", "error", err)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(httpReq)
	if err != nil {
		slog.Error("upstream request failed", "error", err)
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("reading upstream response", "error", err)
		return
	}

	// Filter tools/list responses
	respBody = b.maybeFilterToolsList(respBody)

	fmt.Fprintf(os.Stdout, "%s\n", respBody)
}

func (b *StdioBridge) maybeFilterToolsList(data []byte) []byte {
	var resp jsonrpc.Response
	if err := json.Unmarshal(data, &resp); err != nil {
		return data
	}
	if resp.Result == nil {
		return data
	}
	var probe struct {
		Tools json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(resp.Result, &probe) != nil || len(probe.Tools) == 0 {
		return data
	}
	resp.Result = toolfilter.FilterToolsList(resp.Result, b.engine, b.agentIdentity)
	out, err := json.Marshal(resp)
	if err != nil {
		return data
	}
	return out
}

func (b *StdioBridge) emitAudit(rec audit.Record) {
	if b.redactor != nil {
		rec = b.redactor.Redact(rec)
	}
	b.pipeline.Emit(rec)
}
