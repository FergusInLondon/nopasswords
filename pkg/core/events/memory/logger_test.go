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
	"go.fergus.london/nopasswords/pkg/core/events"
)

func TestNopLogger_Log(t *testing.T) {
	logger := NewNopLogger()
	ctx := context.Background()

	event := events.Event{
		EventID:        "event123",
		Timestamp:      time.Now(),
		Type:           events.EventAssertionSuccess,
		UserIdentifier: "user456",
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

	event := events.Event{
		EventID:        "event123",
		Timestamp:      time.Now(),
		Type:           events.EventAssertionSuccess,
		Protocol:       events.ProtocolWebAuthn,
		UserIdentifier: "user456",
		Reason:         "valid_credential",
	}

	err := logger.Log(ctx, event)
	require.NoError(t, err)

	// Restore stdout and read captured output
	w.Close()
	os.Stdout = oldStdout
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Parse JSON output
	var logged events.Event
	err = json.Unmarshal(buf.Bytes(), &logged)
	require.NoError(t, err)

	assert.Equal(t, event.EventID, logged.EventID)
	assert.Equal(t, event.Type, logged.Type)
	assert.Equal(t, event.Protocol, logged.Protocol)
	assert.Equal(t, event.UserIdentifier, logged.UserIdentifier)
	assert.Equal(t, event.Reason, logged.Reason)
}

func TestStdoutLogger_Log_Pretty(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logger := NewStdoutLogger(true)
	ctx := context.Background()

	event := events.Event{
		EventID:        "event123",
		Timestamp:      time.Now(),
		Type:           events.EventAssertionSuccess,
		UserIdentifier: "user456",
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

	const numGoroutines = 10
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent logging
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				event := events.Event{
					EventID:   string(rune('A' + id)),
					Timestamp: time.Now(),
					Type:      events.EventAssertionSuccess,
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

	event := events.Event{
		EventID:        "event123",
		Timestamp:      time.Now(),
		Type:           events.EventAssertionFailure,
		UserIdentifier: "user456",
		Reason:         "invalid_credential",
	}

	err := logger.Log(ctx, event)
	require.NoError(t, err)

	// Restore stderr and read captured output
	w.Close()
	os.Stderr = oldStderr
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)

	// Parse JSON output
	var logged events.Event
	err = json.Unmarshal(buf.Bytes(), &logged)
	require.NoError(t, err)

	assert.Equal(t, event.EventID, logged.EventID)
	assert.Equal(t, event.Type, logged.Type)
	assert.Equal(t, event.UserIdentifier, logged.UserIdentifier)
}

func TestBufferedLogger_Log(t *testing.T) {
	// Use NopLogger as underlying logger for testing
	underlying := NewNopLogger()
	logger := NewBufferedLogger(underlying, 3)
	ctx := context.Background()

	event1 := events.Event{EventID: "event1", Timestamp: time.Now()}
	event2 := events.Event{EventID: "event2", Timestamp: time.Now()}

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

	event1 := events.Event{EventID: "event1", Timestamp: time.Now(), Type: events.EventAssertionAttempt}
	event2 := events.Event{EventID: "event2", Timestamp: time.Now(), Type: events.EventAssertionSuccess}
	event3 := events.Event{EventID: "event3", Timestamp: time.Now(), Type: events.EventAssertionFailure}

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

	event := events.Event{EventID: "event1", Timestamp: time.Now(), Type: events.EventAssertionAttempt}

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
				event := events.Event{
					EventID:   string(rune('A' + id)),
					Timestamp: time.Now(),
					Type:      events.EventAssertionSuccess,
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
var _ events.EventLogger = (*NopLogger)(nil)
var _ events.EventLogger = (*StdoutLogger)(nil)
var _ events.EventLogger = (*StderrLogger)(nil)
var _ events.EventLogger = (*BufferedLogger)(nil)
