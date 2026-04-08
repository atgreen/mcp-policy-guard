// Package toolfilter removes denied tools from tools/list responses.
package toolfilter

import (
	"encoding/json"

	"github.com/atgreen/mcp-policy-guard/internal/engine"
)

// toolsListResult is the structure of a tools/list response result.
type toolsListResult struct {
	Tools  []json.RawMessage `json:"tools"`
	Cursor string            `json:"cursor,omitempty"`
}

// toolEntry is the minimal parse of a tool to extract its name.
type toolEntry struct {
	Name string `json:"name"`
}

// FilterToolsList removes tools from a tools/list response that the agent
// is not allowed to call according to the policy engine.
func FilterToolsList(resultJSON json.RawMessage, eng *engine.Engine, agentIdentity string) json.RawMessage {
	if len(resultJSON) == 0 {
		return resultJSON
	}

	var result toolsListResult
	if err := json.Unmarshal(resultJSON, &result); err != nil {
		return resultJSON
	}

	filtered := make([]json.RawMessage, 0, len(result.Tools))
	for _, toolRaw := range result.Tools {
		var entry toolEntry
		if err := json.Unmarshal(toolRaw, &entry); err != nil {
			filtered = append(filtered, toolRaw) // keep unparseable entries
			continue
		}

		eval := eng.Evaluate(entry.Name, agentIdentity)
		if eval.Decision != engine.Deny {
			filtered = append(filtered, toolRaw)
		}
	}

	result.Tools = filtered
	out, err := json.Marshal(result)
	if err != nil {
		return resultJSON
	}
	return out
}
