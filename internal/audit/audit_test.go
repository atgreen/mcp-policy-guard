package audit

import (
	"sync"
	"testing"
	"time"
)

// mockEmitter records all emitted records for assertions.
type mockEmitter struct {
	mu      sync.Mutex
	records []Record
	flushed bool
	closed  bool
}

func (e *mockEmitter) Emit(rec Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.records = append(e.records, rec)
	return nil
}

func (e *mockEmitter) Flush() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.flushed = true
	return nil
}

func (e *mockEmitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return nil
}

func (e *mockEmitter) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.records)
}

func TestPipeline_EmitAndClose(t *testing.T) {
	mock := &mockEmitter{}
	p := NewPipeline([]Emitter{mock})

	p.Emit(Record{Tool: "echo", Decision: "allow"})
	p.Emit(Record{Tool: "drop", Decision: "deny"})

	p.Close()

	if mock.count() != 2 {
		t.Errorf("expected 2 records, got %d", mock.count())
	}
	if !mock.flushed {
		t.Error("expected emitter to be flushed")
	}
	if !mock.closed {
		t.Error("expected emitter to be closed")
	}
}

func TestPipeline_FanOut(t *testing.T) {
	mock1 := &mockEmitter{}
	mock2 := &mockEmitter{}
	p := NewPipeline([]Emitter{mock1, mock2})

	p.Emit(Record{Tool: "test"})
	p.Close()

	if mock1.count() != 1 {
		t.Errorf("emitter1: expected 1 record, got %d", mock1.count())
	}
	if mock2.count() != 1 {
		t.Errorf("emitter2: expected 1 record, got %d", mock2.count())
	}
}

func TestPipeline_NonBlocking(t *testing.T) {
	// Pipeline should not block the caller even if emitter is slow
	mock := &mockEmitter{}
	p := NewPipeline([]Emitter{mock})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			p.Emit(Record{Tool: "test"})
		}
		close(done)
	}()

	select {
	case <-done:
		// OK
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked for too long")
	}

	p.Close()
}
