// Package approval implements human-in-the-loop approval handlers.
package approval

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// Request is the data sent to an approval handler.
type Request struct {
	RequestID string          `json:"request_id"`
	ToolName  string          `json:"tool_name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	RuleName  string          `json:"rule_name"`
	Message   string          `json:"message,omitempty"`
	Agent     string          `json:"agent,omitempty"`
}

// Result is the outcome of an approval request.
type Result struct {
	Approved  bool
	Approver  string
	Reason    string
	LatencyMs int64
}

// Handler processes an approval request and returns a decision.
type Handler interface {
	RequestApproval(ctx context.Context, req Request) (Result, error)
}

// ErrNoTTY is returned when the terminal handler can't open /dev/tty.
var ErrNoTTY = fmt.Errorf("no controlling terminal available")

// Registry maps channel names to handlers and resolves fallbacks.
type Registry struct {
	handlers map[string]Handler
	channels map[string]*policy.ApprovalChannel
}

// NewRegistry creates a handler registry from approval config.
func NewRegistry(cfg *policy.ApprovalConfig) *Registry {
	r := &Registry{
		handlers: make(map[string]Handler),
		channels: make(map[string]*policy.ApprovalChannel),
	}
	if cfg == nil {
		return r
	}
	for i := range cfg.Channels {
		ch := &cfg.Channels[i]
		r.channels[ch.Name] = ch
		switch ch.Type {
		case "terminal":
			showArgs := true
			if ch.ShowArgs != nil {
				showArgs = *ch.ShowArgs
			}
			r.handlers[ch.Name] = NewTerminalHandler(showArgs)
		case "webhook":
			r.handlers[ch.Name] = NewWebhookHandler(ch)
		}
	}
	return r
}

// Handle runs the approval flow for the named channel with fallback.
func (r *Registry) Handle(ctx context.Context, channelName string, req Request) (Result, error) {
	return r.handleWithVisited(ctx, channelName, req, make(map[string]bool))
}

func (r *Registry) handleWithVisited(ctx context.Context, channelName string, req Request, visited map[string]bool) (Result, error) {
	if visited[channelName] {
		return Result{}, fmt.Errorf("circular fallback chain at channel %q", channelName)
	}
	visited[channelName] = true

	h, ok := r.handlers[channelName]
	if !ok {
		return Result{}, fmt.Errorf("unknown approval channel: %q", channelName)
	}

	result, err := h.RequestApproval(ctx, req)
	if err == ErrNoTTY {
		// Try fallback
		ch := r.channels[channelName]
		if ch != nil && ch.Fallback != "" {
			return r.handleWithVisited(ctx, ch.Fallback, req, visited)
		}
		return Result{}, fmt.Errorf("terminal approval unavailable and no fallback configured")
	}
	return result, err
}

// DefaultTimeout returns the configured timeout or 5 minutes.
func DefaultTimeout(cfg *policy.ApprovalConfig) time.Duration {
	if cfg != nil && cfg.Timeout.Duration > 0 {
		return cfg.Timeout.Duration
	}
	return 5 * time.Minute
}
