package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/core"
)

func TestNopLogger_Log(t *testing.T) {
	logger := NewNopLogger()
	ctx := context.Background()

	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
		UserID:    "user456",
		Outcome:   core.OutcomeSuccess,
	}

	// Should not error and should do nothing
	err := logger.Log(ctx, event)
	require.NoError(t, err)
}

func TestStdoutLogger_Log(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := NewStdoutLogger(false)
	ctx := context.Background()

	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
		Method:    "webauthn",
		UserID:    "user456",
		Outcome:   core.OutcomeSuccess,
		Reason:    "valid_credential",
	}

	err := logger.Log(ctx, event)
	require.NoError(t, err)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Parse JSON output
	var logged core.AuditEvent
	err = json.Unmarshal(buf.Bytes(), &logged)
	require.NoError(t, err)

	assert.Equal(t, event.EventID, logged.EventID)
	assert.Equal(t, event.EventType, logged.EventType)
	assert.Equal(t, event.Method, logged.Method)
	assert.Equal(t, event.UserID, logged.UserID)
	assert.Equal(t, event.Outcome, logged.Outcome)
	assert.Equal(t, event.Reason, logged.Reason)
}

func TestStdoutLogger_Log_Pretty(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := NewStdoutLogger(true)
	ctx := context.Background()

	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
		UserID:    "user456",
		Outcome:   core.OutcomeSuccess,
	}

	err := logger.Log(ctx, event)
	require.NoError(t, err)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	output := buf.String()

	// Pretty output should contain newlines and indentation
	assert.Contains(t, output, "\n")
	assert.Contains(t, output, "  ") // Indentation
}

func TestStdoutLogger_ConcurrentAccess(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := NewStdoutLogger(false)
	ctx := context.Background()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent logging
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				event := core.AuditEvent{
					EventID:   string(rune('A' + id)),
					Timestamp: time.Now(),
					EventType: core.EventAuthSuccess,
					Outcome:   core.OutcomeSuccess,
				}
				_ = logger.Log(ctx, event)
			}
		}(i)
	}

	wg.Wait()

	// Restore stdout
	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Should have received output (exact format doesn't matter, just no panic)
	assert.NotEmpty(t, buf.String())
}

func TestStderrLogger_Log(t *testing.T) {
	// Capture stderr
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	logger := NewStderrLogger(false)
	ctx := context.Background()

	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthFailure,
		UserID:    "user456",
		Outcome:   core.OutcomeFailure,
		Reason:    "invalid_credential",
	}

	err := logger.Log(ctx, event)
	require.NoError(t, err)

	// Restore stderr and read captured output
	w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Parse JSON output
	var logged core.AuditEvent
	err = json.Unmarshal(buf.Bytes(), &logged)
	require.NoError(t, err)

	assert.Equal(t, event.EventID, logged.EventID)
	assert.Equal(t, event.EventType, logged.EventType)
	assert.Equal(t, event.UserID, logged.UserID)
	assert.Equal(t, event.Outcome, logged.Outcome)
}

func TestBufferedLogger_Log(t *testing.T) {
	// Use NopLogger as underlying logger for testing
	underlying := NewNopLogger()
	logger := NewBufferedLogger(underlying, 3)
	ctx := context.Background()

	event1 := core.AuditEvent{EventID: "event1", Timestamp: time.Now()}
	event2 := core.AuditEvent{EventID: "event2", Timestamp: time.Now()}

	// Log events (should buffer)
	err := logger.Log(ctx, event1)
	require.NoError(t, err)
	err = logger.Log(ctx, event2)
	require.NoError(t, err)

	// Flush
	err = logger.Flush(ctx)
	require.NoError(t, err)
}

func TestBufferedLogger_AutoFlush(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	underlying := NewStdoutLogger(false)
	logger := NewBufferedLogger(underlying, 2) // Auto-flush at 2 events
	ctx := context.Background()

	event1 := core.AuditEvent{EventID: "event1", Timestamp: time.Now(), EventType: "test"}
	event2 := core.AuditEvent{EventID: "event2", Timestamp: time.Now(), EventType: "test"}
	event3 := core.AuditEvent{EventID: "event3", Timestamp: time.Now(), EventType: "test"}

	// Log 2 events - should auto-flush
	_ = logger.Log(ctx, event1)
	_ = logger.Log(ctx, event2)

	// Log 1 more - should buffer
	_ = logger.Log(ctx, event3)

	// Close and flush remaining
	_ = logger.Close(ctx)

	// Restore stdout and read
	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Should have logged all 3 events
	output := buf.String()
	assert.Contains(t, output, "event1")
	assert.Contains(t, output, "event2")
	assert.Contains(t, output, "event3")
}

func TestBufferedLogger_Close(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	underlying := NewStdoutLogger(false)
	logger := NewBufferedLogger(underlying, 10) // Large buffer
	ctx := context.Background()

	event := core.AuditEvent{EventID: "event1", Timestamp: time.Now(), EventType: "test"}

	// Log without triggering auto-flush
	_ = logger.Log(ctx, event)

	// Close should flush
	err := logger.Close(ctx)
	require.NoError(t, err)

	// Restore stdout and read
	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Should have logged the event
	assert.Contains(t, buf.String(), "event1")
}

func TestBufferedLogger_FlushEmpty(t *testing.T) {
	underlying := NewNopLogger()
	logger := NewBufferedLogger(underlying, 10)
	ctx := context.Background()

	// Flush empty buffer should not error
	err := logger.Flush(ctx)
	require.NoError(t, err)
}

func TestBufferedLogger_ConcurrentAccess(t *testing.T) {
	underlying := NewNopLogger()
	logger := NewBufferedLogger(underlying, 100)
	ctx := context.Background()

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent logging
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				event := core.AuditEvent{
					EventID:   string(rune('A' + id)),
					Timestamp: time.Now(),
					EventType: core.EventAuthSuccess,
				}
				_ = logger.Log(ctx, event)
			}
		}(i)
	}

	wg.Wait()

	// Final flush
	err := logger.Flush(ctx)
	require.NoError(t, err)
}

// Verify implementations satisfy the interface
var _ core.AuditLogger = (*NopLogger)(nil)
var _ core.AuditLogger = (*StdoutLogger)(nil)
var _ core.AuditLogger = (*StderrLogger)(nil)
var _ core.AuditLogger = (*BufferedLogger)(nil)
