package audit

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/atgreen/mcp-policy-guard/internal/policy"
)

// Redactor removes sensitive data from audit records.
type Redactor struct {
	fields   map[string]bool
	patterns []compiledPattern
}

type compiledPattern struct {
	re          *regexp.Regexp
	replacement string
}

// NewRedactor creates a redactor from policy redaction config.
func NewRedactor(cfg *policy.AuditRedaction) *Redactor {
	if cfg == nil {
		return &Redactor{}
	}

	r := &Redactor{
		fields: make(map[string]bool, len(cfg.Fields)),
	}
	for _, f := range cfg.Fields {
		r.fields[strings.ToLower(f)] = true
	}
	for _, p := range cfg.Patterns {
		re, err := regexp.Compile(p.Regex)
		if err != nil {
			continue
		}
		r.patterns = append(r.patterns, compiledPattern{
			re:          re,
			replacement: p.Replacement,
		})
	}
	return r
}

// Redact removes sensitive data from a record's Arguments field.
func (r *Redactor) Redact(rec Record) Record {
	if len(rec.Arguments) == 0 {
		return rec
	}
	if len(r.fields) == 0 && len(r.patterns) == 0 {
		return rec
	}

	var args interface{}
	if err := json.Unmarshal(rec.Arguments, &args); err != nil {
		return rec
	}

	args = r.redactValue(args)
	redacted, err := json.Marshal(args)
	if err != nil {
		return rec
	}
	rec.Arguments = redacted
	return rec
}

func (r *Redactor) redactValue(v interface{}) interface{} {
	switch v := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, val := range v {
			if r.fields[strings.ToLower(k)] {
				out[k] = "[REDACTED]"
			} else {
				out[k] = r.redactValue(val)
			}
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, val := range v {
			out[i] = r.redactValue(val)
		}
		return out
	case string:
		return r.redactString(v)
	default:
		return v
	}
}

func (r *Redactor) redactString(s string) string {
	for _, p := range r.patterns {
		s = p.re.ReplaceAllString(s, p.replacement)
	}
	return s
}
