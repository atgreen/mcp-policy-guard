// Package agentcard parses FINOS Agent Cards and derives policy rules.
package agentcard

import (
	"encoding/json"
	"fmt"
	"os"
)

// Card is a partial parse of a FINOS Agent Card — only the fields
// needed for policy derivation.
type Card struct {
	Governance    Governance    `json:"governance"`
	AgentSecurity AgentSecurity `json:"agentSecurity"`
}

type Governance struct {
	ApprovedActionList  []string            `json:"approvedActionList"`
	HumanOversightModel string              `json:"humanOversightModel"`
	EscalationContacts  []EscalationContact `json:"escalationContacts"`
}

type EscalationContact struct {
	Name               string   `json:"name"`
	Email              string   `json:"email"`
	Role               string   `json:"role"`
	EscalationTriggers []string `json:"escalationTriggers"`
}

type AgentSecurity struct {
	RateLimiting RateLimiting `json:"rateLimiting"`
}

type RateLimiting struct {
	Enabled bool `json:"enabled"`
}

// LoadFromFile reads and parses an agent card JSON file.
func LoadFromFile(path string) (*Card, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading agent card: %w", err)
	}
	return Parse(data)
}

// Parse parses agent card JSON.
func Parse(data []byte) (*Card, error) {
	var card Card
	if err := json.Unmarshal(data, &card); err != nil {
		return nil, fmt.Errorf("parsing agent card JSON: %w", err)
	}
	return &card, nil
}
