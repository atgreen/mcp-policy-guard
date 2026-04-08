package engine

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// CELEvaluator compiles and caches CEL expressions for policy evaluation.
type CELEvaluator struct {
	env   *cel.Env
	mu    sync.RWMutex
	cache map[string]cel.Program
}

// NewCELEvaluator creates a CEL evaluator with the standard variables:
// args (map), tool (string), agent (string).
func NewCELEvaluator() (*CELEvaluator, error) {
	env, err := cel.NewEnv(
		cel.Variable("args", cel.DynType),
		cel.Variable("tool", cel.StringType),
		cel.Variable("agent", cel.StringType),
	)
	if err != nil {
		return nil, fmt.Errorf("creating CEL environment: %w", err)
	}
	return &CELEvaluator{
		env:   env,
		cache: make(map[string]cel.Program),
	}, nil
}

// Evaluate runs a CEL expression against the given tool call data.
// Returns true if the expression evaluates to true.
func (e *CELEvaluator) Evaluate(expr string, toolName, agentIdentity string, arguments json.RawMessage) (bool, error) {
	prg, err := e.getOrCompile(expr)
	if err != nil {
		return false, err
	}

	// Parse arguments JSON into a map for CEL
	var args interface{}
	if len(arguments) > 0 {
		if err := json.Unmarshal(arguments, &args); err != nil {
			return false, fmt.Errorf("parsing arguments for CEL: %w", err)
		}
	}
	if args == nil {
		args = map[string]interface{}{}
	}

	out, _, err := prg.Eval(map[string]interface{}{
		"args":  args,
		"tool":  toolName,
		"agent": agentIdentity,
	})
	if err != nil {
		return false, fmt.Errorf("evaluating CEL expression: %w", err)
	}

	// Coerce result to bool
	if out.Type() == types.BoolType {
		return out.Value().(bool), nil
	}
	// Non-bool truthy: any non-null value is true
	if out == types.NullValue {
		return false, nil
	}
	return out.Type() != types.ErrType && out != ref.Val(nil), nil
}

// EvaluateRaw runs a CEL expression and returns the raw result value.
// Used by mutation to compute replacement values.
func (e *CELEvaluator) EvaluateRaw(expr string, toolName, agentIdentity string, arguments json.RawMessage) (interface{}, error) {
	prg, err := e.getOrCompile(expr)
	if err != nil {
		return nil, err
	}

	var args interface{}
	if len(arguments) > 0 {
		if err := json.Unmarshal(arguments, &args); err != nil {
			return nil, fmt.Errorf("parsing arguments for CEL: %w", err)
		}
	}
	if args == nil {
		args = map[string]interface{}{}
	}

	out, _, err := prg.Eval(map[string]interface{}{
		"args":  args,
		"tool":  toolName,
		"agent": agentIdentity,
	})
	if err != nil {
		return nil, fmt.Errorf("evaluating CEL expression: %w", err)
	}
	return out.Value(), nil
}

func (e *CELEvaluator) getOrCompile(expr string) (cel.Program, error) {
	e.mu.RLock()
	prg, ok := e.cache[expr]
	e.mu.RUnlock()
	if ok {
		return prg, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check after acquiring write lock
	if prg, ok := e.cache[expr]; ok {
		return prg, nil
	}

	ast, issues := e.env.Compile(expr)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compiling CEL expression %q: %w", expr, issues.Err())
	}

	prg, err := e.env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("programming CEL expression %q: %w", expr, err)
	}

	e.cache[expr] = prg
	return prg, nil
}
