// Package transport implements the MCP stdio proxy.
package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/atgreen/mcp-policy-guard/internal/approval"
	"github.com/atgreen/mcp-policy-guard/internal/audit"
	"encoding/json"

	"github.com/atgreen/mcp-policy-guard/internal/contentfilter"
	"github.com/atgreen/mcp-policy-guard/internal/engine"
	"github.com/atgreen/mcp-policy-guard/internal/escalation"
	"github.com/atgreen/mcp-policy-guard/internal/jsonrpc"
	"github.com/atgreen/mcp-policy-guard/internal/mutate"
	"github.com/atgreen/mcp-policy-guard/internal/policy"
	"github.com/atgreen/mcp-policy-guard/internal/ratelimit"
	"github.com/atgreen/mcp-policy-guard/internal/toolfilter"
)

// StdioProxy intercepts MCP JSON-RPC messages between a client and
// a child MCP server process.
type StdioProxy struct {
	engine        *engine.Engine
	pipeline      *audit.Pipeline
	redactor      *audit.Redactor
	approvalReg   *approval.Registry
	approvalCfg   *policy.ApprovalConfig
	rateLimiter   *ratelimit.Limiter
	contentFilter *contentfilter.Engine
	escalator     *escalation.Dispatcher
	agentIdentity string
	childArgs     []string
}

// NewStdioProxy creates a stdio proxy.
func NewStdioProxy(
	eng *engine.Engine,
	pipeline *audit.Pipeline,
	redactor *audit.Redactor,
	approvalReg *approval.Registry,
	approvalCfg *policy.ApprovalConfig,
	rateLimiter *ratelimit.Limiter,
	contentFilter *contentfilter.Engine,
	escalator *escalation.Dispatcher,
	agentIdentity string,
	childArgs []string,
) *StdioProxy {
	return &StdioProxy{
		engine:        eng,
		pipeline:      pipeline,
		redactor:      redactor,
		approvalReg:   approvalReg,
		approvalCfg:   approvalCfg,
		rateLimiter:   rateLimiter,
		contentFilter: contentFilter,
		escalator:     escalator,
		agentIdentity: agentIdentity,
		childArgs:     childArgs,
	}
}

// Run starts the child process and proxies JSON-RPC messages.
func (p *StdioProxy) Run(ctx context.Context) error {
	if len(p.childArgs) == 0 {
		return fmt.Errorf("no child command specified")
	}

	cmd := exec.CommandContext(ctx, p.childArgs[0], p.childArgs[1:]...)
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	childStdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating child stdin pipe: %w", err)
	}
	childStdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating child stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting child process: %w", err)
	}

	var wg sync.WaitGroup

	// Server-to-client: relay child stdout -> our stdout (unmodified)
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.relayServerToClient(childStdout)
	}()

	// Client-to-server: intercept our stdin -> child stdin
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.interceptClientToServer(ctx, os.Stdin, childStdin)
		childStdin.Close()
	}()

	wg.Wait()

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("child exited with code %d", exitErr.ExitCode())
		}
		return err
	}
	return nil
}

// relayServerToClient copies lines from child stdout to our stdout,
// intercepting tools/list responses to filter denied tools.
func (p *StdioProxy) relayServerToClient(r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()

		// Try to intercept tools/list responses for filtering.
		// We detect these by checking if the response has a "result"
		// with a "tools" array. This is a heuristic — we track pending
		// tools/list request IDs for precise matching.
		if p.shouldFilterToolsList(line) {
			filtered := p.filterToolsListResponse(line)
			fmt.Fprintf(os.Stdout, "%s\n", filtered)
		} else {
			fmt.Fprintf(os.Stdout, "%s\n", line)
		}
	}
}

func (p *StdioProxy) shouldFilterToolsList(line []byte) bool {
	// Quick heuristic: check if it looks like a response with a "tools" field
	var probe struct {
		Result *struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(line, &probe); err != nil {
		return false
	}
	return probe.Result != nil && len(probe.Result.Tools) > 0
}

func (p *StdioProxy) filterToolsListResponse(line []byte) []byte {
	var resp jsonrpc.Response
	if err := json.Unmarshal(line, &resp); err != nil {
		return line
	}
	if resp.Result == nil {
		return line
	}

	filtered := toolfilter.FilterToolsList(resp.Result, p.engine, p.agentIdentity)
	resp.Result = filtered

	out, err := json.Marshal(resp)
	if err != nil {
		return line
	}
	return out
}

// interceptClientToServer reads lines from our stdin, intercepts tools/call,
// and either forwards or denies them.
func (p *StdioProxy) interceptClientToServer(ctx context.Context, r io.Reader, w io.Writer) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		// Quick check: is this a JSON-RPC request?
		if !jsonrpc.IsRequest(line) {
			// Not a request (maybe a response or notification) — forward verbatim
			fmt.Fprintf(w, "%s\n", line)
			continue
		}

		// Handle batched requests by rejecting the whole batch
		// (v0.1 simplification per plan)
		if jsonrpc.IsBatch(line) {
			fmt.Fprintf(w, "%s\n", line)
			continue
		}

		req, err := jsonrpc.ParseRequest(line)
		if err != nil {
			// Unparseable — forward verbatim
			fmt.Fprintf(w, "%s\n", line)
			continue
		}

		// Only intercept tools/call
		if req.Method != "tools/call" {
			fmt.Fprintf(w, "%s\n", line)
			continue
		}

		p.handleToolCall(ctx, req, line, w)
	}
}

func (p *StdioProxy) handleToolCall(ctx context.Context, req *jsonrpc.Request, originalLine []byte, childStdin io.Writer) {
	start := time.Now()
	requestID := uuid.New().String()

	// Parse tool call params
	tcp, err := jsonrpc.ParseToolCallParams(req.Params)
	if err != nil {
		slog.Warn("failed to parse tools/call params, forwarding", "error", err)
		fmt.Fprintf(childStdin, "%s\n", originalLine)
		return
	}

	// Check rate limits first
	if p.rateLimiter != nil {
		rlResult := p.rateLimiter.Check(tcp.Name, p.agentIdentity)
		if rlResult.Exceeded {
			errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
				rlResult.Message,
				map[string]interface{}{
					"rule":         rlResult.Rule.Name,
					"policy_guard": true,
					"rate_limited": true,
				})
			fmt.Fprintf(os.Stdout, "%s\n", errResp)
			rec := p.buildAuditRecord(requestID, tcp, engine.EvalResult{Decision: engine.Deny, Audit: true}, start)
			rec.Decision = "rate_limited"
			rec.Rule = rlResult.Rule.Name
			p.emitAudit(rec)
			// Fire escalation if configured
			if rlResult.Rule.Escalate != nil && p.escalator != nil {
				p.escalator.Fire(rlResult.Rule.Escalate.Channel, escalation.Context{
					Tool:        tcp.Name,
					Agent:       p.agentIdentity,
					TriggerName: rlResult.Rule.Escalate.TriggerName,
				})
			}
			return
		}
	}

	// Check content filters on request
	if p.contentFilter != nil {
		cfResult := p.contentFilter.CheckRequest(tcp.Name, tcp.Arguments)
		if cfResult.Matched && cfResult.Action == "block" {
			errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
				cfResult.Message,
				map[string]interface{}{
					"filter":       cfResult.Filter.Name,
					"policy_guard": true,
					"content_blocked": true,
				})
			fmt.Fprintf(os.Stdout, "%s\n", errResp)
			rec := p.buildAuditRecord(requestID, tcp, engine.EvalResult{Decision: engine.Deny, Audit: true}, start)
			rec.Decision = "content_blocked"
			rec.Rule = cfResult.Filter.Name
			p.emitAudit(rec)
			if cfResult.Filter.Escalate != nil && p.escalator != nil {
				p.escalator.Fire(cfResult.Filter.Escalate.Channel, escalation.Context{
					Tool:        tcp.Name,
					Agent:       p.agentIdentity,
					TriggerName: cfResult.Filter.Escalate.TriggerName,
				})
			}
			return
		}
	}

	// Evaluate policy rules
	result := p.engine.Evaluate(tcp.Name, p.agentIdentity, tcp.Arguments)

	// Fire escalation if rule has one
	if result.Rule != nil && result.Rule.Escalate != nil && p.escalator != nil {
		p.escalator.Fire(result.Rule.Escalate.Channel, escalation.Context{
			Tool:        tcp.Name,
			Agent:       p.agentIdentity,
			Args:        string(tcp.Arguments),
			TriggerName: result.Rule.Escalate.TriggerName,
		})
	}

	switch result.Decision {
	case engine.Allow, engine.AuditOnly:
		// Forward to child
		fmt.Fprintf(childStdin, "%s\n", originalLine)
		if result.Audit {
			rec := p.buildAuditRecord(requestID, tcp, result, start)
			p.emitAudit(rec)
		}

	case engine.Deny:
		// Return error to client
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			fmt.Sprintf("Tool call denied by policy: %s", tcp.Name),
			map[string]interface{}{
				"rule":         ruleName(result.Rule),
				"policy_guard": true,
			})
		fmt.Fprintf(os.Stdout, "%s\n", errResp)
		if result.Audit {
			rec := p.buildAuditRecord(requestID, tcp, result, start)
			p.emitAudit(rec)
		}

	case engine.RequireApproval:
		p.handleApproval(ctx, req, tcp, originalLine, childStdin, requestID, result, start)

	case engine.Mutate:
		p.handleMutate(req, tcp, originalLine, childStdin, requestID, result, start)
	}
}

func (p *StdioProxy) handleApproval(
	ctx context.Context,
	req *jsonrpc.Request,
	tcp *jsonrpc.ToolCallParams,
	originalLine []byte,
	childStdin io.Writer,
	requestID string,
	result engine.EvalResult,
	start time.Time,
) {
	if result.Rule == nil || result.Rule.Approval == nil {
		// No approval config — deny
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			"Tool call requires approval but no approval channel configured",
			map[string]interface{}{"policy_guard": true})
		fmt.Fprintf(os.Stdout, "%s\n", errResp)
		return
	}

	// Determine timeout
	timeout := approval.DefaultTimeout(p.approvalCfg)
	if result.Rule.Approval.Timeout.Duration > 0 {
		timeout = result.Rule.Approval.Timeout.Duration
	}
	approvalCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	approvalReq := approval.Request{
		RequestID: requestID,
		ToolName:  tcp.Name,
		Arguments: tcp.Arguments,
		RuleName:  ruleName(result.Rule),
		Message:   result.Rule.Approval.Message,
		Agent:     p.agentIdentity,
	}

	approvalResult, err := p.approvalReg.Handle(approvalCtx, result.Rule.Approval.Channel, approvalReq)

	if err != nil {
		slog.Error("approval handler error", "error", err)
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			fmt.Sprintf("Tool call approval failed: %v", err),
			map[string]interface{}{"policy_guard": true})
		fmt.Fprintf(os.Stdout, "%s\n", errResp)

		rec := p.buildAuditRecord(requestID, tcp, result, start)
		rec.Decision = "rejected"
		rec.DenyMessage = err.Error()
		p.emitAudit(rec)
		return
	}

	if approvalResult.Approved {
		// Forward to child
		fmt.Fprintf(childStdin, "%s\n", originalLine)

		rec := p.buildAuditRecord(requestID, tcp, result, start)
		rec.Decision = "approved"
		rec.Approver = approvalResult.Approver
		rec.ApprovalLatencyMs = approvalResult.LatencyMs
		p.emitAudit(rec)
	} else {
		// Rejected
		reason := approvalResult.Reason
		if reason == "" {
			reason = "rejected by approver"
		}
		errResp := jsonrpc.MakeErrorResponse(req.ID, jsonrpc.PolicyDeniedCode,
			fmt.Sprintf("Tool call rejected: %s", reason),
			map[string]interface{}{
				"rule":         ruleName(result.Rule),
				"policy_guard": true,
			})
		fmt.Fprintf(os.Stdout, "%s\n", errResp)

		rec := p.buildAuditRecord(requestID, tcp, result, start)
		rec.Decision = "rejected"
		rec.DenyMessage = reason
		rec.Approver = approvalResult.Approver
		rec.ApprovalLatencyMs = approvalResult.LatencyMs
		p.emitAudit(rec)
	}
}

func (p *StdioProxy) handleMutate(
	req *jsonrpc.Request,
	tcp *jsonrpc.ToolCallParams,
	originalLine []byte,
	childStdin io.Writer,
	requestID string,
	result engine.EvalResult,
	start time.Time,
) {
	if result.Rule == nil || result.Rule.Mutate == nil {
		// No mutation config — forward unchanged
		fmt.Fprintf(childStdin, "%s\n", originalLine)
		return
	}

	mutated, err := mutate.Apply(result.Rule.Mutate.Arguments, tcp.Arguments, p.engine.CEL(), tcp.Name, p.agentIdentity)
	if err != nil {
		slog.Warn("mutation failed, forwarding original", "error", err, "rule", result.Rule.Name)
		fmt.Fprintf(childStdin, "%s\n", originalLine)
		return
	}

	// Rebuild the JSON-RPC request with mutated arguments
	newParams := jsonrpc.ToolCallParams{Name: tcp.Name, Arguments: mutated}
	paramsJSON, _ := json.Marshal(newParams)
	newReq := jsonrpc.Request{
		Jsonrpc: req.Jsonrpc,
		Method:  req.Method,
		Params:  paramsJSON,
		ID:      req.ID,
	}
	newLine, _ := json.Marshal(newReq)
	fmt.Fprintf(childStdin, "%s\n", newLine)

	if result.Audit {
		rec := p.buildAuditRecord(requestID, tcp, result, start)
		rec.Decision = "mutated"
		p.emitAudit(rec)
	}
}

func (p *StdioProxy) buildAuditRecord(
	requestID string,
	tcp *jsonrpc.ToolCallParams,
	result engine.EvalResult,
	start time.Time,
) audit.Record {
	return audit.Record{
		Timestamp: start.UTC(),
		RequestID: requestID,
		Agent:     p.agentIdentity,
		Tool:      tcp.Name,
		Arguments: tcp.Arguments,
		Decision:  result.Decision.String(),
		Rule:      ruleName(result.Rule),
		LatencyMs: time.Since(start).Milliseconds(),
	}
}

func (p *StdioProxy) emitAudit(rec audit.Record) {
	if p.redactor != nil {
		rec = p.redactor.Redact(rec)
	}
	p.pipeline.Emit(rec)
}

func ruleName(rule *policy.Rule) string {
	if rule != nil {
		return rule.Name
	}
	return "default"
}
