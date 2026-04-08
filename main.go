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
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	listenAddr := flag.String("listen", "", "HTTP listen address (e.g., :8081). Enables HTTP proxy mode.")
	upstream := flag.String("upstream", "", "Upstream MCP endpoint URL (required for HTTP mode)")
	redisURL := flag.String("redis", "", "Redis URL for shared rate limiting (e.g., redis://localhost:6379)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  stdio:  mcp-policy-guard --policy <path> [options] -- <command> [args...]\n")
		fmt.Fprintf(os.Stderr, "  http:   mcp-policy-guard --policy <path> --listen :8081 --upstream http://mcp-gateway:8080/mcp\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	configureLogging(*logLevel)

	if *policyPath == "" {
		slog.Error("--policy is required")
		flag.Usage()
		os.Exit(1)
	}

	// Determine mode
	httpMode := *listenAddr != ""
	childArgs := flag.Args()

	if httpMode {
		if *upstream == "" {
			slog.Error("--upstream is required in HTTP mode")
			os.Exit(1)
		}
	} else {
		if len(childArgs) == 0 {
			slog.Error("no child command specified after -- (or use --listen for HTTP mode)")
			flag.Usage()
			os.Exit(1)
		}
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

	// Build rate limiter (Redis or in-memory)
	var limiter ratelimit.Checker
	if *redisURL != "" && len(pol.RateLimits) > 0 {
		rl, err := ratelimit.NewRedisLimiter(pol.RateLimits, *redisURL)
		if err != nil {
			slog.Error("failed to connect to Redis for rate limiting", "error", err)
			os.Exit(1)
		}
		limiter = rl
		slog.Info("rate limits loaded (Redis)", "count", len(pol.RateLimits))
	} else if len(pol.RateLimits) > 0 {
		limiter = ratelimit.NewLimiter(pol.RateLimits)
		slog.Info("rate limits loaded (in-memory)", "count", len(pol.RateLimits))
	}

	// Build content filter engine
	cfEngine := contentfilter.NewEngine(pol.ContentFilters)
	if len(pol.ContentFilters) > 0 {
		slog.Info("content filters loaded", "count", len(pol.ContentFilters))
	}

	// Build escalation dispatcher
	escalator := escalation.NewDispatcher(pol.Escalation)

	// Set up policy file watcher for hot-reload
	watcher, err := policy.NewWatcher(*policyPath, func() {
		newPol, err := policy.Load(*policyPath)
		if err != nil {
			slog.Error("failed to reload policy", "error", err)
			return
		}
		eng.Reload(newPol)
		slog.Info("policy reloaded", "rules", len(newPol.Rules))
	})
	if err != nil {
		slog.Warn("failed to start policy watcher, hot-reload disabled", "error", err)
	} else {
		defer watcher.Close()
		slog.Info("policy file watcher started", "path", *policyPath)
	}

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

	if httpMode {
		// HTTP reverse proxy mode
		identityFunc := func(r *http.Request) string {
			// Try X-Agent-Id header first, then JWT sub, then static
			if id := r.Header.Get("X-Agent-Id"); id != "" {
				return id
			}
			if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				// Simple JWT sub extraction would go here
				// For now, use the static identity
			}
			return identity
		}

		proxy := transport.NewHTTPProxy(eng, pipeline, redactor, approvalReg, pol.Approval,
			limiter, cfEngine, escalator, *upstream, *listenAddr, identityFunc)

		if err := proxy.Run(ctx); err != nil {
			slog.Error("HTTP proxy exited with error", "error", err)
			os.Exit(1)
		}
	} else {
		// stdio proxy mode
		proxy := transport.NewStdioProxy(eng, pipeline, redactor, approvalReg, pol.Approval,
			limiter, cfEngine, escalator, identity, childArgs)

		if err := proxy.Run(ctx); err != nil {
			slog.Error("proxy exited with error", "error", err)
			os.Exit(1)
		}
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
		return []audit.Emitter{audit.NewStderrEmitter("json")}, nil
	}

	var emitters []audit.Emitter
	for _, out := range cfg.Outputs {
		switch out.Type {
		case "stdout":
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

		case "otel":
			protocol := out.Protocol
			if protocol == "" {
				protocol = "grpc"
			}
			e, err := audit.NewOTelEmitter(out.Endpoint, protocol)
			if err != nil {
				return nil, fmt.Errorf("creating OTel emitter: %w", err)
			}
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
