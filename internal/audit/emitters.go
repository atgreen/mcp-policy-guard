package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// StderrEmitter writes JSON or text audit records to stderr.
// Named "stdout" in config, but in stdio mode stdout is JSON-RPC,
// so we write to stderr.
type StderrEmitter struct {
	w      io.Writer
	format string // "json" or "text"
	mu     sync.Mutex
}

func NewStderrEmitter(format string) *StderrEmitter {
	return &StderrEmitter{w: os.Stderr, format: format}
}

func (e *StderrEmitter) Emit(rec Record) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.format == "text" {
		_, err := fmt.Fprintf(e.w, "%s %s tool=%s decision=%s rule=%s\n",
			rec.Timestamp.Format(time.RFC3339), rec.RequestID, rec.Tool, rec.Decision, rec.Rule)
		return err
	}

	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.w, "%s\n", data)
	return err
}

func (e *StderrEmitter) Flush() error { return nil }
func (e *StderrEmitter) Close() error { return nil }

// FileEmitter writes JSONL to a file with optional rotation.
type FileEmitter struct {
	path      string
	maxBytes  int64
	maxFiles  int
	mu        sync.Mutex
	f         *os.File
}

func NewFileEmitter(path string, maxSizeMB, maxFiles int) (*FileEmitter, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("opening audit log: %w", err)
	}
	maxBytes := int64(maxSizeMB) * 1024 * 1024
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024 // default 100MB
	}
	if maxFiles <= 0 {
		maxFiles = 10
	}
	return &FileEmitter{
		path:     path,
		maxBytes: maxBytes,
		maxFiles: maxFiles,
		f:        f,
	}, nil
}

func (e *FileEmitter) Emit(rec Record) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Check rotation
	info, err := e.f.Stat()
	if err == nil && info.Size() >= e.maxBytes {
		e.rotate()
	}

	_, err = fmt.Fprintf(e.f, "%s\n", data)
	return err
}

func (e *FileEmitter) rotate() {
	e.f.Close()

	// Shift existing rotated files
	for i := e.maxFiles - 1; i > 0; i-- {
		old := fmt.Sprintf("%s.%d", e.path, i)
		new := fmt.Sprintf("%s.%d", e.path, i+1)
		os.Rename(old, new)
	}
	os.Rename(e.path, e.path+".1")

	// Remove overflow file
	os.Remove(fmt.Sprintf("%s.%d", e.path, e.maxFiles+1))

	e.f, _ = os.OpenFile(e.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
}

func (e *FileEmitter) Flush() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.f.Sync()
}

func (e *FileEmitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.f.Close()
}

// WebhookEmitter batches records and POSTs them.
type WebhookEmitter struct {
	endpoint string
	method   string
	headers  map[string]string
	maxBatch int
	interval time.Duration
	mu       sync.Mutex
	batch    []Record
	client   *http.Client
	ticker   *time.Ticker
	done     chan struct{}
}

func NewWebhookEmitter(endpoint, method string, headers map[string]string, maxBatch int, interval time.Duration) *WebhookEmitter {
	if method == "" {
		method = "POST"
	}
	if maxBatch <= 0 {
		maxBatch = 100
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}

	e := &WebhookEmitter{
		endpoint: endpoint,
		method:   method,
		headers:  headers,
		maxBatch: maxBatch,
		interval: interval,
		client:   &http.Client{Timeout: 10 * time.Second},
		ticker:   time.NewTicker(interval),
		done:     make(chan struct{}),
	}
	go e.flushLoop()
	return e
}

func (e *WebhookEmitter) flushLoop() {
	for {
		select {
		case <-e.ticker.C:
			e.Flush()
		case <-e.done:
			return
		}
	}
}

func (e *WebhookEmitter) Emit(rec Record) error {
	e.mu.Lock()
	e.batch = append(e.batch, rec)
	shouldFlush := len(e.batch) >= e.maxBatch
	e.mu.Unlock()

	if shouldFlush {
		return e.Flush()
	}
	return nil
}

func (e *WebhookEmitter) Flush() error {
	e.mu.Lock()
	if len(e.batch) == 0 {
		e.mu.Unlock()
		return nil
	}
	batch := e.batch
	e.batch = nil
	e.mu.Unlock()

	data, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(e.method, e.endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (e *WebhookEmitter) Close() error {
	e.ticker.Stop()
	close(e.done)
	return e.Flush()
}
