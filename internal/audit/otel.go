package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// OTelEmitter sends audit records as OpenTelemetry spans.
type OTelEmitter struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

// NewOTelEmitter creates an OTel emitter that exports spans to the given endpoint.
func NewOTelEmitter(endpoint, protocol string) (*OTelEmitter, error) {
	ctx := context.Background()

	var exporter sdktrace.SpanExporter
	var err error

	switch protocol {
	case "http":
		exporter, err = otlptracehttp.New(ctx,
			otlptracehttp.WithEndpoint(endpoint),
			otlptracehttp.WithInsecure(),
		)
	default: // "grpc" or empty
		exporter, err = otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("creating OTel exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
	)
	tracer := provider.Tracer("mcp-policy-guard")

	return &OTelEmitter{
		provider: provider,
		tracer:   tracer,
	}, nil
}

func (e *OTelEmitter) Emit(rec Record) error {
	ctx := context.Background()
	_, span := e.tracer.Start(ctx, "mcp.tool_call",
		trace.WithAttributes(
			attribute.String("mcp.tool", rec.Tool),
			attribute.String("mcp.agent", rec.Agent),
			attribute.String("mcp.decision", rec.Decision),
			attribute.String("mcp.rule", rec.Rule),
			attribute.String("mcp.request_id", rec.RequestID),
			attribute.Int64("mcp.latency_ms", rec.LatencyMs),
		),
	)
	if len(rec.Arguments) > 0 {
		// Truncate arguments for span attribute (max 4KB)
		args := string(rec.Arguments)
		if len(args) > 4096 {
			args = args[:4096] + "..."
		}
		span.SetAttributes(attribute.String("mcp.arguments", args))
	}
	if rec.DenyMessage != "" {
		span.SetAttributes(attribute.String("mcp.deny_message", rec.DenyMessage))
	}
	if rec.Approver != "" {
		span.SetAttributes(attribute.String("mcp.approver", rec.Approver))
		span.SetAttributes(attribute.Int64("mcp.approval_latency_ms", rec.ApprovalLatencyMs))
	}

	// Add event with full record as JSON
	recordJSON, err := json.Marshal(rec)
	if err == nil {
		span.AddEvent("audit_record", trace.WithAttributes(
			attribute.String("record", string(recordJSON)),
		))
	}

	span.End()
	return nil
}

func (e *OTelEmitter) Flush() error {
	if err := e.provider.ForceFlush(context.Background()); err != nil {
		slog.Warn("OTel flush error", "error", err)
		return err
	}
	return nil
}

func (e *OTelEmitter) Close() error {
	return e.provider.Shutdown(context.Background())
}
