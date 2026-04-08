// Package contentfilter implements regex-based content inspection for MCP traffic.
package contentfilter

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// Direction indicates whether a filter applies to requests, responses, or both.
type Direction int

const (
	Request  Direction = iota
	Response
	Both
)

// Match represents a pattern match found by a filter.
type Match struct {
	FilterName  string
	PatternName string
	Value       string
}

// Result is the outcome of running content filters.
type Result struct {
	Matched bool
	Matches []Match
	Filter  *policy.ContentFilter
	Action  string // block | redact | flag
	Message string
}

// compiledFilter is a pre-compiled content filter.
type compiledFilter struct {
	config   *policy.ContentFilter
	patterns []compiledPattern
}

type compiledPattern struct {
	name string
	re   *regexp.Regexp
}

// Engine evaluates content filters on tool call arguments and responses.
type Engine struct {
	filters []compiledFilter
}

// NewEngine creates a content filter engine from policy config.
func NewEngine(filters []policy.ContentFilter) *Engine {
	e := &Engine{}
	for i := range filters {
		cf := &filters[i]
		var patterns []compiledPattern
		for _, p := range cf.Patterns {
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				continue
			}
			patterns = append(patterns, compiledPattern{name: p.Name, re: re})
		}
		if len(patterns) > 0 {
			e.filters = append(e.filters, compiledFilter{config: cf, patterns: patterns})
		}
	}
	return e
}

// CheckRequest runs request-direction filters on tool call arguments.
func (e *Engine) CheckRequest(toolName string, arguments json.RawMessage) Result {
	return e.check(toolName, arguments, Request)
}

// CheckResponse runs response-direction filters on tool call responses.
func (e *Engine) CheckResponse(toolName string, response json.RawMessage) Result {
	return e.check(toolName, response, Response)
}

// Redact applies redaction filters and returns modified content.
func (e *Engine) Redact(toolName string, content json.RawMessage, dir Direction) json.RawMessage {
	text := string(content)
	for _, f := range e.filters {
		if f.config.Action != "redact" {
			continue
		}
		if !matchDirection(f.config.Direction, dir) {
			continue
		}
		if !matchFilterTools(f.config.Match.Tools, toolName) {
			continue
		}
		for _, p := range f.patterns {
			text = p.re.ReplaceAllString(text, fmt.Sprintf("[REDACTED:%s]", p.name))
		}
	}
	return json.RawMessage(text)
}

func (e *Engine) check(toolName string, content json.RawMessage, dir Direction) Result {
	if len(content) == 0 {
		return Result{}
	}

	text := extractText(content)

	for _, f := range e.filters {
		if !matchDirection(f.config.Direction, dir) {
			continue
		}
		if !matchFilterTools(f.config.Match.Tools, toolName) {
			continue
		}

		var matches []Match
		for _, p := range f.patterns {
			found := p.re.FindAllString(text, 5)
			for _, v := range found {
				matches = append(matches, Match{
					FilterName:  f.config.Name,
					PatternName: p.name,
					Value:       truncate(v, 100),
				})
			}
		}

		if len(matches) > 0 {
			msg := f.config.BlockMessage
			if msg == "" {
				msg = fmt.Sprintf("Content filter %q matched: %s", f.config.Name, matches[0].PatternName)
			}
			return Result{
				Matched: true,
				Matches: matches,
				Filter:  f.config,
				Action:  f.config.Action,
				Message: msg,
			}
		}
	}

	return Result{}
}

// extractText recursively extracts all string values from JSON for pattern matching.
func extractText(data json.RawMessage) string {
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return string(data)
	}
	var sb strings.Builder
	collectStrings(raw, &sb)
	return sb.String()
}

func collectStrings(v interface{}, sb *strings.Builder) {
	switch v := v.(type) {
	case string:
		sb.WriteString(v)
		sb.WriteByte('\n')
	case map[string]interface{}:
		for _, val := range v {
			collectStrings(val, sb)
		}
	case []interface{}:
		for _, val := range v {
			collectStrings(val, sb)
		}
	}
}

func matchDirection(filterDir string, dir Direction) bool {
	switch filterDir {
	case "both":
		return true
	case "request":
		return dir == Request
	case "response":
		return dir == Response
	default:
		return false
	}
}

func matchFilterTools(patterns []string, toolName string) bool {
	for _, p := range patterns {
		if matched, _ := path.Match(p, toolName); matched {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
