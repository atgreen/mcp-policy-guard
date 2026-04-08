// Package jsonrpc provides JSON-RPC 2.0 message types for MCP protocol interception.
package jsonrpc

import (
	"encoding/json"
	"fmt"
)

// Request represents a JSON-RPC 2.0 request.
type Request struct {
	Jsonrpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"` // string, number, or null
}

// Response represents a JSON-RPC 2.0 response.
type Response struct {
	Jsonrpc string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ToolCallParams represents the params payload for a tools/call request.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// IsRequest returns true if the raw JSON looks like a request (has "method" field).
func IsRequest(data []byte) bool {
	var probe struct {
		Method *string `json:"method"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Method != nil
}

// IsBatch returns true if the raw JSON is a JSON array (batched request).
func IsBatch(data []byte) bool {
	for _, b := range data {
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

// ParseRequest parses a single JSON-RPC request from raw JSON.
func ParseRequest(data []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC request: %w", err)
	}
	return &req, nil
}

// ParseToolCallParams extracts the tool name and arguments from a tools/call request.
func ParseToolCallParams(params json.RawMessage) (*ToolCallParams, error) {
	var tcp ToolCallParams
	if err := json.Unmarshal(params, &tcp); err != nil {
		return nil, fmt.Errorf("invalid tools/call params: %w", err)
	}
	return &tcp, nil
}

// MakeErrorResponse constructs a JSON-RPC error response.
func MakeErrorResponse(id json.RawMessage, code int, message string, data map[string]interface{}) []byte {
	resp := Response{
		Jsonrpc: "2.0",
		ID:      id,
	}
	rpcErr := &RPCError{
		Code:    code,
		Message: message,
	}
	if data != nil {
		d, _ := json.Marshal(data)
		rpcErr.Data = d
	}
	resp.Error = rpcErr
	out, _ := json.Marshal(resp)
	return out
}

// PolicyDeniedCode is the JSON-RPC error code for policy-denied tool calls.
const PolicyDeniedCode = -32600
