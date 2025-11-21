package memory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/core"
)

func TestFileLogger_NewFileLogger(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileLogger(logPath)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer logger.Close()

	// File should exist
	_, err = os.Stat(logPath)
	assert.NoError(t, err)
}

func TestFileLogger_NewFileLogger_CreatesDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "logs", "nested", "audit.log")

	logger, err := NewFileLogger(logPath)
	require.NoError(t, err)
	require.NotNil(t, logger)
	defer logger.Close()

	// Directory and file should exist
	_, err = os.Stat(filepath.Join(tmpDir, "logs", "nested"))
	assert.NoError(t, err)

	_, err = os.Stat(logPath)
	assert.NoError(t, err)
}

func TestFileLogger_Log(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileLogger(logPath)
	require.NoError(t, err)
	defer logger.Close()

	ctx := context.Background()
	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
		Method:    "webauthn",
		UserIdentifier:    "user456",
		Outcome:   core.OutcomeSuccess,
		Metadata:  map[string]interface{}{"test": "value"},
	}

	err = logger.Log(ctx, event)
	require.NoError(t, err)

	// Sync to ensure data is written
	err = logger.Sync()
	require.NoError(t, err)

	// Read the file and verify content
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	var logged core.AuditEvent
	err = json.Unmarshal(data, &logged)
	require.NoError(t, err)

	assert.Equal(t, event.EventID, logged.EventID)
	assert.Equal(t, event.EventType, logged.EventType)
	assert.Equal(t, event.Method, logged.Method)
	assert.Equal(t, event.UserIdentifier, logged.UserIdentifier)
	assert.Equal(t, event.Outcome, logged.Outcome)
}

func TestFileLogger_Log_MultipleEvents(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileLogger(logPath)
	require.NoError(t, err)
	defer logger.Close()

	ctx := context.Background()

	// Log multiple events
	events := []core.AuditEvent{
		{EventID: "event1", Timestamp: time.Now(), EventType: core.EventAuthSuccess, Outcome: core.OutcomeSuccess},
		{EventID: "event2", Timestamp: time.Now(), EventType: core.EventAuthFailure, Outcome: core.OutcomeFailure},
		{EventID: "event3", Timestamp: time.Now(), EventType: core.EventTokenGenerate, Outcome: core.OutcomeSuccess},
	}

	for _, event := range events {
		err = logger.Log(ctx, event)
		require.NoError(t, err)
	}

	err = logger.Sync()
	require.NoError(t, err)

	// Read the file
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Should contain all three events (each on a separate line)
	assert.Contains(t, string(data), "event1")
	assert.Contains(t, string(data), "event2")
	assert.Contains(t, string(data), "event3")
}

func TestFileLogger_Log_Append(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	// Create first logger and write an event
	logger1, err := NewFileLogger(logPath)
	require.NoError(t, err)

	ctx := context.Background()
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
		Outcome:   core.OutcomeSuccess,
	}

	err = logger1.Log(ctx, event1)
	require.NoError(t, err)
	err = logger1.Close()
	require.NoError(t, err)

	// Create second logger (should append, not overwrite)
	logger2, err := NewFileLogger(logPath)
	require.NoError(t, err)
	defer logger2.Close()

	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		EventType: core.EventAuthFailure,
		Outcome:   core.OutcomeFailure,
	}

	err = logger2.Log(ctx, event2)
	require.NoError(t, err)
	err = logger2.Sync()
	require.NoError(t, err)

	// Read the file
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Should contain both events
	assert.Contains(t, string(data), "event1")
	assert.Contains(t, string(data), "event2")
}

func TestFileLogger_WithPrettyPrint(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileLogger(logPath, WithPrettyPrint(true))
	require.NoError(t, err)
	defer logger.Close()

	ctx := context.Background()
	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
		Outcome:   core.OutcomeSuccess,
	}

	err = logger.Log(ctx, event)
	require.NoError(t, err)
	err = logger.Sync()
	require.NoError(t, err)

	// Read the file
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)

	// Pretty-printed JSON should contain newlines and indentation
	assert.Contains(t, string(data), "\n")
	assert.Contains(t, string(data), "  ")
}

func TestFileLogger_Close(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileLogger(logPath)
	require.NoError(t, err)

	ctx := context.Background()
	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
	}

	err = logger.Log(ctx, event)
	require.NoError(t, err)

	// Close the logger
	err = logger.Close()
	require.NoError(t, err)

	// File should still exist and contain the event
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "event123")

	// Closing again should not error
	err = logger.Close()
	require.NoError(t, err)
}

func TestFileLogger_Sync(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileLogger(logPath)
	require.NoError(t, err)
	defer logger.Close()

	ctx := context.Background()
	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
	}

	err = logger.Log(ctx, event)
	require.NoError(t, err)

	// Explicit sync
	err = logger.Sync()
	require.NoError(t, err)

	// Data should be flushed to disk
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "event123")
}

func TestFileLogger_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileLogger(logPath)
	require.NoError(t, err)
	defer logger.Close()

	ctx := context.Background()
	const numGoroutines = 10
	const eventsPerGoroutine = 10

	// Concurrent logging
	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < eventsPerGoroutine; j++ {
				event := core.AuditEvent{
					EventID:   string(rune('A' + id)),
					Timestamp: time.Now(),
					EventType: core.EventAuthSuccess,
				}
				_ = logger.Log(ctx, event)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	err = logger.Sync()
	require.NoError(t, err)

	// Verify file was written without corruption
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.NotEmpty(t, data)
}

// Verify FileLogger implements core.AuditLogger
var _ core.AuditLogger = (*FileLogger)(nil)
