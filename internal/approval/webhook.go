package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// WebhookHandler sends approval requests to an HTTP endpoint
// and polls for a decision.
type WebhookHandler struct {
	endpoint     string
	method       string
	headers      map[string]string
	callbackMode string
	pollInterval time.Duration
	client       *http.Client
}

func NewWebhookHandler(ch *policy.ApprovalChannel) *WebhookHandler {
	mode := ch.CallbackMode
	if mode == "" {
		mode = "poll"
	}
	interval := ch.PollInterval.Duration
	if interval <= 0 {
		interval = 5 * time.Second
	}
	return &WebhookHandler{
		endpoint:     ch.Endpoint,
		method:       ch.Method,
		headers:      ch.Headers,
		callbackMode: mode,
		pollInterval: interval,
		client:       &http.Client{Timeout: 30 * time.Second},
	}
}

type webhookPayload struct {
	RequestID string          `json:"request_id"`
	ToolName  string          `json:"tool_name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	RuleName  string          `json:"rule_name"`
	Message   string          `json:"message,omitempty"`
	Agent     string          `json:"agent,omitempty"`
}

type webhookResponse struct {
	Decision string `json:"decision"` // "approve" or "reject"
	Reason   string `json:"reason,omitempty"`
	Approver string `json:"approver,omitempty"`
}

func (h *WebhookHandler) RequestApproval(ctx context.Context, req Request) (Result, error) {
	start := time.Now()

	payload := webhookPayload{
		RequestID: req.RequestID,
		ToolName:  req.ToolName,
		Arguments: req.Arguments,
		RuleName:  req.RuleName,
		Message:   req.Message,
		Agent:     req.Agent,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return Result{}, fmt.Errorf("marshaling approval request: %w", err)
	}

	// POST the approval request
	method := h.method
	if method == "" {
		method = "POST"
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, h.endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("creating approval HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range h.headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("sending approval request: %w", err)
	}
	defer resp.Body.Close()

	// If the initial POST returns a decision, use it directly
	if resp.StatusCode == http.StatusOK {
		var wr webhookResponse
		respBody, _ := io.ReadAll(resp.Body)
		if json.Unmarshal(respBody, &wr) == nil && wr.Decision != "" {
			return Result{
				Approved:  wr.Decision == "approve",
				Approver:  wr.Approver,
				Reason:    wr.Reason,
				LatencyMs: time.Since(start).Milliseconds(),
			}, nil
		}
	}

	// Otherwise poll for a decision
	ticker := time.NewTicker(h.pollInterval)
	defer ticker.Stop()

	pollURL := h.endpoint + "/" + req.RequestID

	for {
		select {
		case <-ctx.Done():
			return Result{
				Approved:  false,
				Reason:    "timeout",
				LatencyMs: time.Since(start).Milliseconds(),
			}, nil
		case <-ticker.C:
			pollReq, err := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
			if err != nil {
				continue
			}
			for k, v := range h.headers {
				pollReq.Header.Set(k, v)
			}

			pollResp, err := h.client.Do(pollReq)
			if err != nil {
				continue
			}
			respBody, _ := io.ReadAll(pollResp.Body)
			pollResp.Body.Close()

			if pollResp.StatusCode != http.StatusOK {
				continue
			}

			var wr webhookResponse
			if json.Unmarshal(respBody, &wr) == nil && wr.Decision != "" {
				return Result{
					Approved:  wr.Decision == "approve",
					Approver:  wr.Approver,
					Reason:    wr.Reason,
					LatencyMs: time.Since(start).Milliseconds(),
				}, nil
			}
		}
	}
}
