// Package mutate implements argument mutation for MCP tool calls.
package mutate

import (
	"encoding/json"
	"fmt"

	jsonpatch "github.com/evanphx/json-patch/v5"

	"github.com/atgreen/mcp-policy-guard/internal/engine"
	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// Apply applies mutation operations to tool call arguments.
// Returns the mutated arguments JSON.
func Apply(ops []policy.MutateOp, arguments json.RawMessage, celEval *engine.CELEvaluator, toolName, agentIdentity string) (json.RawMessage, error) {
	if len(ops) == 0 || len(arguments) == 0 {
		return arguments, nil
	}

	current := arguments

	for _, op := range ops {
		var value interface{}

		if op.CEL != "" && celEval != nil {
			// Evaluate CEL expression to compute the value
			result, err := celEval.EvaluateRaw(op.CEL, toolName, agentIdentity, current)
			if err != nil {
				return nil, fmt.Errorf("CEL evaluation for mutate op %q: %w", op.Path, err)
			}
			value = result
		} else if op.Value != nil {
			value = op.Value
		}

		patch, err := buildPatch(op.Op, op.Path, value)
		if err != nil {
			return nil, fmt.Errorf("building patch for %q: %w", op.Path, err)
		}

		result, err := patch.Apply(current)
		if err != nil {
			return nil, fmt.Errorf("applying patch %s %q: %w", op.Op, op.Path, err)
		}
		current = result
	}

	return current, nil
}

func buildPatch(op, path string, value interface{}) (jsonpatch.Patch, error) {
	patchOp := map[string]interface{}{
		"op":   op,
		"path": path,
	}
	if op != "remove" && value != nil {
		patchOp["value"] = value
	}

	patchJSON, err := json.Marshal([]interface{}{patchOp})
	if err != nil {
		return nil, err
	}

	return jsonpatch.DecodePatch(patchJSON)
}
