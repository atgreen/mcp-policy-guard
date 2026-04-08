package policy

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// SchemaJSON holds the policy JSON Schema, set by main via SetSchema.
var SchemaJSON []byte

// SetSchema sets the embedded schema bytes. Called by main.go.
func SetSchema(data []byte) {
	SchemaJSON = data
}

// Load reads a policy YAML file, expands environment variables,
// validates against the JSON Schema, and returns the typed policy.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	// Expand ${VAR} references
	expanded := os.ExpandEnv(string(data))

	// Unmarshal to generic map for schema validation
	var raw interface{}
	if err := yaml.Unmarshal([]byte(expanded), &raw); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}

	// Convert YAML types to JSON-compatible types for schema validation
	raw = normalizeYAML(raw)

	if err := validateSchema(raw); err != nil {
		return nil, fmt.Errorf("policy schema validation: %w", err)
	}

	// Unmarshal to typed struct
	var pol Policy
	if err := yaml.Unmarshal([]byte(expanded), &pol); err != nil {
		return nil, fmt.Errorf("unmarshaling policy: %w", err)
	}

	// Semantic validation
	if err := validate(&pol); err != nil {
		return nil, err
	}

	return &pol, nil
}

func validateSchema(doc interface{}) error {
	schemaData := SchemaJSON
	if len(schemaData) == 0 {
		return fmt.Errorf("schema not loaded: call policy.SetSchema first")
	}

	var schemaDoc interface{}
	if err := json.Unmarshal(schemaData, &schemaDoc); err != nil {
		return fmt.Errorf("parsing schema JSON: %w", err)
	}

	c := jsonschema.NewCompiler()
	if err := c.AddResource("schema.json", schemaDoc); err != nil {
		return fmt.Errorf("adding schema resource: %w", err)
	}
	sch, err := c.Compile("schema.json")
	if err != nil {
		return fmt.Errorf("compiling schema: %w", err)
	}

	if err := sch.Validate(doc); err != nil {
		return err
	}
	return nil
}

// validate performs semantic checks beyond what JSON Schema can express.
func validate(pol *Policy) error {
	if pol.Version != 1 {
		return fmt.Errorf("unsupported policy version: %d", pol.Version)
	}

	if len(pol.Rules) == 0 && pol.AgentCard == nil {
		return fmt.Errorf("policy must have either 'rules' or 'agent_card'")
	}

	// Check that require_approval rules reference valid channels
	channelNames := make(map[string]bool)
	if pol.Approval != nil {
		for _, ch := range pol.Approval.Channels {
			channelNames[ch.Name] = true
		}
	}

	for _, rule := range pol.Rules {
		if rule.Action == "require_approval" {
			if rule.Approval == nil {
				return fmt.Errorf("rule %q has action 'require_approval' but no approval config", rule.Name)
			}
			if !channelNames[rule.Approval.Channel] {
				return fmt.Errorf("rule %q references approval channel %q which is not defined", rule.Name, rule.Approval.Channel)
			}
		}
	}

	return nil
}

// normalizeYAML converts YAML-specific types to JSON-compatible types.
// YAML maps use interface{} keys; JSON Schema expects string keys.
func normalizeYAML(v interface{}) interface{} {
	switch v := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, val := range v {
			out[k] = normalizeYAML(val)
		}
		return out
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(v))
		for k, val := range v {
			out[fmt.Sprintf("%v", k)] = normalizeYAML(val)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, val := range v {
			out[i] = normalizeYAML(val)
		}
		return out
	default:
		return v
	}
}
