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

// SlackHandler sends approval requests as Slack interactive messages
// and polls for a decision via callback.
type SlackHandler struct {
	webhookURL  string
	channel     string
	callbackURL string
	client      *http.Client
}

func NewSlackHandler(ch *policy.ApprovalChannel) *SlackHandler {
	return &SlackHandler{
		webhookURL:  ch.WebhookURL,
		channel:     ch.Channel,
		callbackURL: ch.CallbackURL,
		client:      &http.Client{Timeout: 30 * time.Second},
	}
}

type slackMessage struct {
	Channel string       `json:"channel,omitempty"`
	Text    string       `json:"text"`
	Blocks  []slackBlock `json:"blocks"`
}

type slackBlock struct {
	Type     string          `json:"type"`
	Text     *slackText      `json:"text,omitempty"`
	Elements []slackElement  `json:"elements,omitempty"`
}

type slackText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type slackElement struct {
	Type     string     `json:"type"`
	Text     *slackText `json:"text"`
	Style    string     `json:"style,omitempty"`
	ActionID string     `json:"action_id"`
	Value    string     `json:"value,omitempty"`
}

func (h *SlackHandler) RequestApproval(ctx context.Context, req Request) (Result, error) {
	start := time.Now()

	// Build Slack message with approve/reject buttons
	msg := slackMessage{
		Channel: h.channel,
		Text:    fmt.Sprintf("Approval required: %s (tool: %s)", req.RuleName, req.ToolName),
		Blocks: []slackBlock{
			{
				Type: "section",
				Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf(
					"*Approval Required*\n*Tool:* `%s`\n*Rule:* %s\n*Agent:* %s",
					req.ToolName, req.RuleName, req.Agent)},
			},
			{
				Type: "section",
				Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf(
					"*Arguments:*\n```%s```", truncateArgs(req.Arguments, 500))},
			},
		},
	}
	if req.Message != "" {
		msg.Blocks = append(msg.Blocks, slackBlock{
			Type: "section",
			Text: &slackText{Type: "mrkdwn", Text: fmt.Sprintf("*Note:* %s", req.Message)},
		})
	}
	msg.Blocks = append(msg.Blocks, slackBlock{
		Type: "actions",
		Elements: []slackElement{
			{Type: "button", Text: &slackText{Type: "plain_text", Text: "Approve"}, Style: "primary", ActionID: "approve", Value: req.RequestID},
			{Type: "button", Text: &slackText{Type: "plain_text", Text: "Reject"}, Style: "danger", ActionID: "reject", Value: req.RequestID},
		},
	})

	body, _ := json.Marshal(msg)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", h.webhookURL, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("creating Slack request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("sending Slack message: %w", err)
	}
	resp.Body.Close()

	// Poll the callback URL for the decision
	if h.callbackURL == "" {
		// No callback URL — can't get the decision back
		return Result{
			Approved:  false,
			Reason:    "no callback URL configured for Slack approval",
			LatencyMs: time.Since(start).Milliseconds(),
		}, nil
	}

	pollURL := h.callbackURL + "/" + req.RequestID
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return Result{
				Approved:  false,
				Reason:    "timeout",
				LatencyMs: time.Since(start).Milliseconds(),
			}, nil
		case <-ticker.C:
			pollReq, _ := http.NewRequestWithContext(ctx, "GET", pollURL, nil)
			pollResp, err := h.client.Do(pollReq)
			if err != nil {
				continue
			}
			respBody, _ := io.ReadAll(pollResp.Body)
			pollResp.Body.Close()

			if pollResp.StatusCode != http.StatusOK {
				continue
			}

			var wr struct {
				Decision string `json:"decision"`
				Approver string `json:"approver"`
				Reason   string `json:"reason"`
			}
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
