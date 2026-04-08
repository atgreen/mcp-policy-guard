// Package escalation implements fire-and-forget escalation webhooks.
package escalation

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// Context provides the data available for escalation payload templates.
type Context struct {
	Tool              string
	Agent             string
	Args              string
	TriggerName       string
	TriggerExpression string
	MatchedValue      string
}

// Dispatcher sends escalation notifications to configured channels.
type Dispatcher struct {
	channels map[string]*policy.EscalationChannel
	client   *http.Client
}

// NewDispatcher creates a dispatcher from escalation config.
func NewDispatcher(cfg *policy.EscalationConfig) *Dispatcher {
	d := &Dispatcher{
		channels: make(map[string]*policy.EscalationChannel),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
	if cfg == nil {
		return d
	}
	for i := range cfg.Channels {
		ch := &cfg.Channels[i]
		d.channels[ch.Name] = ch
	}
	return d
}

// Fire sends an escalation to the named channel. Non-blocking (fire-and-forget).
func (d *Dispatcher) Fire(channelName string, ctx Context) {
	ch, ok := d.channels[channelName]
	if !ok {
		slog.Warn("escalation channel not found", "channel", channelName)
		return
	}

	go d.send(ch, ctx)
}

func (d *Dispatcher) send(ch *policy.EscalationChannel, ctx Context) {
	switch ch.Type {
	case "webhook":
		d.sendWebhook(ch, ctx)
	case "pagerduty":
		d.sendPagerDuty(ch, ctx)
	case "email":
		slog.Warn("email escalation not yet implemented", "channel", ch.Name)
	default:
		slog.Warn("unknown escalation channel type", "type", ch.Type, "channel", ch.Name)
	}
}

func (d *Dispatcher) sendWebhook(ch *policy.EscalationChannel, ctx Context) {
	body := expandTemplate(ch.PayloadTemplate, ctx)
	if body == "" {
		body = fmt.Sprintf(`{"trigger":"%s","tool":"%s","agent":"%s"}`, ctx.TriggerName, ctx.Tool, ctx.Agent)
	}

	method := ch.Method
	if method == "" {
		method = "POST"
	}

	req, err := http.NewRequest(method, ch.Endpoint, bytes.NewBufferString(body))
	if err != nil {
		slog.Error("escalation webhook request error", "error", err, "channel", ch.Name)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range ch.Headers {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		slog.Error("escalation webhook send error", "error", err, "channel", ch.Name)
		return
	}
	resp.Body.Close()
	slog.Info("escalation fired", "channel", ch.Name, "trigger", ctx.TriggerName, "status", resp.StatusCode)
}

func (d *Dispatcher) sendPagerDuty(ch *policy.EscalationChannel, ctx Context) {
	severity := ch.Severity
	if severity == "" {
		severity = "critical"
	}

	body := fmt.Sprintf(`{
		"routing_key": "%s",
		"event_action": "trigger",
		"payload": {
			"summary": "Agent escalation: %s (tool: %s, agent: %s)",
			"severity": "%s",
			"source": "mcp-policy-guard",
			"custom_details": {
				"trigger": "%s",
				"tool": "%s",
				"agent": "%s"
			}
		}
	}`, ch.RoutingKey, ctx.TriggerName, ctx.Tool, ctx.Agent, severity, ctx.TriggerName, ctx.Tool, ctx.Agent)

	req, err := http.NewRequest("POST", "https://events.pagerduty.com/v2/enqueue", bytes.NewBufferString(body))
	if err != nil {
		slog.Error("pagerduty request error", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		slog.Error("pagerduty send error", "error", err)
		return
	}
	resp.Body.Close()
	slog.Info("pagerduty escalation fired", "channel", ch.Name, "trigger", ctx.TriggerName, "status", resp.StatusCode)
}

func expandTemplate(tmpl string, ctx Context) string {
	if tmpl == "" {
		return ""
	}
	r := strings.NewReplacer(
		"${tool}", ctx.Tool,
		"${agent}", ctx.Agent,
		"${args}", ctx.Args,
		"${trigger_name}", ctx.TriggerName,
		"${trigger_expression}", ctx.TriggerExpression,
		"${matched_value}", ctx.MatchedValue,
	)
	return r.Replace(tmpl)
}
