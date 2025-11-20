package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"go.fergus.london/nopasswords/core"
)

// NopLogger is a no-op implementation of core.AuditLogger that discards all events.
// This is useful when audit logging is not required or for testing.
//
// This implementation has zero overhead and is safe for concurrent use.
type NopLogger struct{}

// NewNopLogger creates a new no-op audit logger.
func NewNopLogger() *NopLogger {
	return &NopLogger{}
}

// Log implements core.AuditLogger by discarding the event.
func (n *NopLogger) Log(ctx context.Context, event core.AuditEvent) error {
	// Intentionally do nothing
	return nil
}

// StdoutLogger is an implementation of core.AuditLogger that writes JSON-formatted
// events to stdout. This is useful for development, debugging, and containerized
// environments where logs are collected from stdout.
//
// This implementation is safe for concurrent use by multiple goroutines.
//
// @mitigation Information Disclosure: The AuditEvent struct is designed to exclude
// sensitive data. This logger outputs the event as-is; ensure no sensitive data
// is added to the Metadata field by calling code.
//
// @risk Denial of Service: In high-traffic scenarios, synchronous writes to stdout
// may become a bottleneck. Consider using buffered or async logging for production.
type StdoutLogger struct {
	mu      sync.Mutex
	encoder *json.Encoder
	pretty  bool
}

// NewStdoutLogger creates a new stdout audit logger.
//
// If pretty is true, JSON output will be indented for readability.
// For production use, pretty should typically be false to minimize output size.
func NewStdoutLogger(pretty bool) *StdoutLogger {
	logger := &StdoutLogger{
		encoder: json.NewEncoder(os.Stdout),
		pretty:  pretty,
	}

	if pretty {
		logger.encoder.SetIndent("", "  ")
	}

	return logger
}

// Log implements core.AuditLogger by writing JSON to stdout.
func (s *StdoutLogger) Log(ctx context.Context, event core.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.encoder.Encode(event); err != nil {
		// Fall back to fmt.Fprintf if JSON encoding fails
		// This ensures we still get some output even if the event is malformed
		_, _ = fmt.Fprintf(os.Stderr, "ERROR: Failed to encode audit event: %v\n", err)
		return err
	}

	return nil
}

// StderrLogger is similar to StdoutLogger but writes to stderr instead.
// This is useful for separating audit logs from application output.
type StderrLogger struct {
	mu      sync.Mutex
	encoder *json.Encoder
	pretty  bool
}

// NewStderrLogger creates a new stderr audit logger.
//
// If pretty is true, JSON output will be indented for readability.
func NewStderrLogger(pretty bool) *StderrLogger {
	logger := &StderrLogger{
		encoder: json.NewEncoder(os.Stderr),
		pretty:  pretty,
	}

	if pretty {
		logger.encoder.SetIndent("", "  ")
	}

	return logger
}

// Log implements core.AuditLogger by writing JSON to stderr.
func (s *StderrLogger) Log(ctx context.Context, event core.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.encoder.Encode(event); err != nil {
		// If we can't encode, there's not much we can do for stderr logger
		return err
	}

	return nil
}

// BufferedLogger wraps another AuditLogger and buffers events in memory before
// writing them in batches. This can improve performance in high-throughput scenarios.
//
// Events are flushed when:
// - The buffer reaches maxSize events
// - Flush() is called explicitly
// - The logger is closed via Close()
//
// This implementation is safe for concurrent use by multiple goroutines.
type BufferedLogger struct {
	mu        sync.Mutex
	logger    core.AuditLogger
	buffer    []core.AuditEvent
	maxSize   int
	autoFlush bool
}

// NewBufferedLogger creates a new buffered audit logger.
//
// maxSize determines how many events are buffered before automatic flushing.
// The underlying logger receives the batched events.
func NewBufferedLogger(logger core.AuditLogger, maxSize int) *BufferedLogger {
	return &BufferedLogger{
		logger:    logger,
		buffer:    make([]core.AuditEvent, 0, maxSize),
		maxSize:   maxSize,
		autoFlush: true,
	}
}

// Log implements core.AuditLogger by buffering the event.
func (b *BufferedLogger) Log(ctx context.Context, event core.AuditEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.buffer = append(b.buffer, event)

	if b.autoFlush && len(b.buffer) >= b.maxSize {
		return b.flushLocked(ctx)
	}

	return nil
}

// Flush writes all buffered events to the underlying logger.
func (b *BufferedLogger) Flush(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.flushLocked(ctx)
}

// flushLocked flushes the buffer without acquiring the lock (caller must hold lock).
func (b *BufferedLogger) flushLocked(ctx context.Context) error {
	if len(b.buffer) == 0 {
		return nil
	}

	// Write all buffered events
	for _, event := range b.buffer {
		if err := b.logger.Log(ctx, event); err != nil {
			// Return the error but don't clear the buffer
			// Caller can retry the flush
			return err
		}
	}

	// Clear the buffer after successful flush
	b.buffer = b.buffer[:0]
	return nil
}

// Close flushes any remaining events and cleans up resources.
func (b *BufferedLogger) Close(ctx context.Context) error {
	return b.Flush(ctx)
}
