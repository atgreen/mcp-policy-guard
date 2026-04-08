// mcp-policy-guard is an MCP protocol-aware policy middleware.
// It intercepts JSON-RPC tool calls and enforces governance policies
// including tool allowlists, human-in-the-loop approval, and audit logging.
package main

import (
	_ "embed"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/atgreen/mcp-policy-guard/internal/agentcard"
	"github.com/atgreen/mcp-policy-guard/internal/approval"
	"github.com/atgreen/mcp-policy-guard/internal/audit"
	"github.com/atgreen/mcp-policy-guard/internal/contentfilter"
	"github.com/atgreen/mcp-policy-guard/internal/engine"
	"github.com/atgreen/mcp-policy-guard/internal/escalation"
	"github.com/atgreen/mcp-policy-guard/internal/policy"
	"github.com/atgreen/mcp-policy-guard/internal/ratelimit"
	"github.com/atgreen/mcp-policy-guard/internal/transport"
)

//go:embed policy-schema.json
var schemaJSON []byte

func main() {
	policyPath := flag.String("policy", "", "Path to policy YAML file (required)")
	agentIdentity := flag.String("agent-identity", "", "Static agent identity for stdio mode")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: mcp-policy-guard --policy <path> [options] -- <command> [args...]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nThe command after -- is the MCP server to wrap.\n")
	}
	flag.Parse()

	// Configure structured logging to stderr (stdout is JSON-RPC)
	configureLogging(*logLevel)

	if *policyPath == "" {
		slog.Error("--policy is required")
		flag.Usage()
		os.Exit(1)
	}

	// Child command is everything after --
	childArgs := flag.Args()
	if len(childArgs) == 0 {
		slog.Error("no child command specified after --")
		flag.Usage()
		os.Exit(1)
	}

	// Load schema for policy validation
	policy.SetSchema(schemaJSON)

	// Load policy
	pol, err := policy.Load(*policyPath)
	if err != nil {
		slog.Error("failed to load policy", "error", err)
		os.Exit(1)
	}
	slog.Info("policy loaded", "path", *policyPath, "rules", len(pol.Rules))

	// Load agent card if configured
	if pol.AgentCard != nil && pol.AgentCard.Path != "" {
		card, err := agentcard.LoadFromFile(pol.AgentCard.Path)
		if err != nil {
			slog.Error("failed to load agent card", "error", err)
			os.Exit(1)
		}
		cardRules := agentcard.DeriveRules(card)
		pol.Rules = agentcard.MergeRules(pol.Rules, cardRules)
		slog.Info("agent card loaded", "path", pol.AgentCard.Path,
			"derived_rules", len(cardRules), "total_rules", len(pol.Rules))
	}

	// Resolve agent identity
	identity := *agentIdentity
	if identity == "" {
		identity = resolveStaticIdentity(pol)
	}

	// Build components
	eng := engine.New(pol)

	// Build audit pipeline
	emitters, err := buildAuditEmitters(pol.Audit)
	if err != nil {
		slog.Error("failed to build audit emitters", "error", err)
		os.Exit(1)
	}
	var redactor *audit.Redactor
	if pol.Audit != nil {
		redactor = audit.NewRedactor(pol.Audit.Redaction)
	}
	pipeline := audit.NewPipeline(emitters)
	defer pipeline.Close()

	// Build approval registry
	approvalReg := approval.NewRegistry(pol.Approval)

	// Build rate limiter
	limiter := ratelimit.NewLimiter(pol.RateLimits)
	if len(pol.RateLimits) > 0 {
		slog.Info("rate limits loaded", "count", len(pol.RateLimits))
	}

	// Build content filter engine
	cfEngine := contentfilter.NewEngine(pol.ContentFilters)
	if len(pol.ContentFilters) > 0 {
		slog.Info("content filters loaded", "count", len(pol.ContentFilters))
	}

	// Build escalation dispatcher
	escalator := escalation.NewDispatcher(pol.Escalation)

	// Build and run stdio proxy
	proxy := transport.NewStdioProxy(eng, pipeline, redactor, approvalReg, pol.Approval, limiter, cfEngine, escalator, identity, childArgs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		slog.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	if err := proxy.Run(ctx); err != nil {
		slog.Error("proxy exited with error", "error", err)
		os.Exit(1)
	}
}

func configureLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
}

func resolveStaticIdentity(pol *policy.Policy) string {
	if pol.Identity != nil {
		for _, src := range pol.Identity.Sources {
			if src.Type == "static" && src.Value != "" {
				return src.Value
			}
		}
	}
	return "unknown"
}

func buildAuditEmitters(cfg *policy.AuditConfig) ([]audit.Emitter, error) {
	if cfg == nil {
		// Default: JSON to stderr
		return []audit.Emitter{audit.NewStderrEmitter("json")}, nil
	}

	var emitters []audit.Emitter
	for _, out := range cfg.Outputs {
		switch out.Type {
		case "stdout":
			// In stdio mode, "stdout" actually goes to stderr
			format := out.Format
			if format == "" {
				format = "json"
			}
			emitters = append(emitters, audit.NewStderrEmitter(format))

		case "file":
			maxMB := 100
			maxFiles := 10
			if out.Rotate != nil {
				if out.Rotate.MaxSizeMB > 0 {
					maxMB = out.Rotate.MaxSizeMB
				}
				if out.Rotate.MaxFiles > 0 {
					maxFiles = out.Rotate.MaxFiles
				}
			}
			e, err := audit.NewFileEmitter(out.Path, maxMB, maxFiles)
			if err != nil {
				return nil, err
			}
			emitters = append(emitters, e)

		case "webhook":
			method := out.Method
			if method == "" {
				method = "POST"
			}
			maxBatch := 100
			interval := 5 * time.Second
			if out.Batch != nil {
				if out.Batch.MaxSize > 0 {
					maxBatch = out.Batch.MaxSize
				}
				if out.Batch.FlushInterval.Duration > 0 {
					interval = out.Batch.FlushInterval.Duration
				}
			}
			e := audit.NewWebhookEmitter(out.Endpoint, method, out.Headers, maxBatch, interval)
			emitters = append(emitters, e)

		default:
			slog.Warn("unknown audit output type, skipping", "type", out.Type)
		}
	}

	if len(emitters) == 0 {
		emitters = append(emitters, audit.NewStderrEmitter("json"))
	}
	return emitters, nil
}
