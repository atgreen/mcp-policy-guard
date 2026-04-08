// Package audit provides the audit trail subsystem for mcp-policy-guard.
package audit

import (
	"encoding/json"
	"time"
)

// Record is a single audit trail entry.
type Record struct {
	Timestamp         time.Time       `json:"timestamp"`
	RequestID         string          `json:"request_id"`
	Agent             string          `json:"agent,omitempty"`
	Tool              string          `json:"tool"`
	Arguments         json.RawMessage `json:"arguments,omitempty"`
	Decision          string          `json:"decision"` // allow | deny | held | approved | rejected
	Rule              string          `json:"rule,omitempty"`
	DenyMessage       string          `json:"deny_message,omitempty"`
	LatencyMs         int64           `json:"latency_ms,omitempty"`
	ResponseSizeBytes int             `json:"response_size_bytes,omitempty"`
	Approver          string          `json:"approver,omitempty"`
	ApprovalLatencyMs int64           `json:"approval_latency_ms,omitempty"`
}

// Emitter writes audit records to an output target.
type Emitter interface {
	Emit(Record) error
	Flush() error
	Close() error
}

// Pipeline fans out audit records to multiple emitters via a buffered channel.
type Pipeline struct {
	ch       chan Record
	emitters []Emitter
	done     chan struct{}
}

// NewPipeline creates an audit pipeline with the given emitters.
func NewPipeline(emitters []Emitter) *Pipeline {
	p := &Pipeline{
		ch:       make(chan Record, 256),
		emitters: emitters,
		done:     make(chan struct{}),
	}
	go p.run()
	return p
}

func (p *Pipeline) run() {
	defer close(p.done)
	for rec := range p.ch {
		for _, e := range p.emitters {
			_ = e.Emit(rec)
		}
	}
}

// Emit sends a record to the pipeline. Non-blocking if buffer has space.
func (p *Pipeline) Emit(rec Record) {
	select {
	case p.ch <- rec:
	default:
		// Drop record if buffer is full — avoid blocking the hot path
	}
}

// Close flushes and shuts down the pipeline.
func (p *Pipeline) Close() error {
	close(p.ch)
	<-p.done
	for _, e := range p.emitters {
		_ = e.Flush()
		_ = e.Close()
	}
	return nil
}
