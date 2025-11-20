package memory

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/core"
)

// mockLogger is a test logger that records events
type mockLogger struct {
	mu     sync.Mutex
	events []core.AuditEvent
	err    error
}

func (m *mockLogger) Log(ctx context.Context, event core.AuditEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.events = append(m.events, event)
	return nil
}

func (m *mockLogger) Events() []core.AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]core.AuditEvent{}, m.events...)
}

func TestMultiLogger_Log(t *testing.T) {
	logger1 := &mockLogger{}
	logger2 := &mockLogger{}
	logger3 := &mockLogger{}

	multiLogger := NewMultiLogger(logger1, logger2, logger3)
	ctx := context.Background()

	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
		UserID:    "user456",
		Outcome:   core.OutcomeSuccess,
	}

	err := multiLogger.Log(ctx, event)
	require.NoError(t, err)

	// All three loggers should have received the event
	assert.Len(t, logger1.Events(), 1)
	assert.Len(t, logger2.Events(), 1)
	assert.Len(t, logger3.Events(), 1)

	assert.Equal(t, event.EventID, logger1.Events()[0].EventID)
	assert.Equal(t, event.EventID, logger2.Events()[0].EventID)
	assert.Equal(t, event.EventID, logger3.Events()[0].EventID)
}

func TestMultiLogger_Log_WithErrors(t *testing.T) {
	logger1 := &mockLogger{}
	logger2 := &mockLogger{err: errors.New("logger2 error")}
	logger3 := &mockLogger{}

	multiLogger := NewMultiLogger(logger1, logger2, logger3)
	ctx := context.Background()

	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
	}

	err := multiLogger.Log(ctx, event)
	require.Error(t, err)

	// Should be a MultiLoggerError
	var multiErr *MultiLoggerError
	assert.True(t, errors.As(err, &multiErr))
	assert.Len(t, multiErr.Errors, 1)

	// logger1 and logger3 should still have received the event
	assert.Len(t, logger1.Events(), 1)
	assert.Len(t, logger2.Events(), 0) // logger2 failed
	assert.Len(t, logger3.Events(), 1)
}

func TestMultiLogger_AddLogger(t *testing.T) {
	logger1 := &mockLogger{}
	multiLogger := NewMultiLogger(logger1)

	logger2 := &mockLogger{}
	multiLogger.AddLogger(logger2)

	ctx := context.Background()
	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
	}

	err := multiLogger.Log(ctx, event)
	require.NoError(t, err)

	// Both loggers should have received the event
	assert.Len(t, logger1.Events(), 1)
	assert.Len(t, logger2.Events(), 1)
}

func TestMultiLoggerError_Error(t *testing.T) {
	t.Run("single error", func(t *testing.T) {
		err := &MultiLoggerError{
			Errors: []error{errors.New("test error")},
		}
		assert.Contains(t, err.Error(), "test error")
	})

	t.Run("multiple errors", func(t *testing.T) {
		err := &MultiLoggerError{
			Errors: []error{
				errors.New("error1"),
				errors.New("error2"),
			},
		}
		assert.Contains(t, err.Error(), "2 errors")
	})
}

func TestFilteredLogger_EventTypeFilter(t *testing.T) {
	baseLogger := &mockLogger{}
	filter := EventTypeFilter(core.EventAuthSuccess, core.EventAuthFailure)
	filteredLogger := NewFilteredLogger(baseLogger, filter)

	ctx := context.Background()

	// Should be logged (matches filter)
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
	}
	err := filteredLogger.Log(ctx, event1)
	require.NoError(t, err)

	// Should be logged (matches filter)
	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		EventType: core.EventAuthFailure,
	}
	err = filteredLogger.Log(ctx, event2)
	require.NoError(t, err)

	// Should NOT be logged (doesn't match filter)
	event3 := core.AuditEvent{
		EventID:   "event3",
		Timestamp: time.Now(),
		EventType: core.EventTokenGenerate,
	}
	err = filteredLogger.Log(ctx, event3)
	require.NoError(t, err)

	// Only 2 events should be logged
	assert.Len(t, baseLogger.Events(), 2)
	assert.Equal(t, "event1", baseLogger.Events()[0].EventID)
	assert.Equal(t, "event2", baseLogger.Events()[1].EventID)
}

func TestFilteredLogger_ExcludeEventTypeFilter(t *testing.T) {
	baseLogger := &mockLogger{}
	filter := ExcludeEventTypeFilter(core.EventTokenGenerate, core.EventTokenRevoke)
	filteredLogger := NewFilteredLogger(baseLogger, filter)

	ctx := context.Background()

	// Should be logged (not excluded)
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
	}
	err := filteredLogger.Log(ctx, event1)
	require.NoError(t, err)

	// Should NOT be logged (excluded)
	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		EventType: core.EventTokenGenerate,
	}
	err = filteredLogger.Log(ctx, event2)
	require.NoError(t, err)

	// Only 1 event should be logged
	assert.Len(t, baseLogger.Events(), 1)
	assert.Equal(t, "event1", baseLogger.Events()[0].EventID)
}

func TestFilteredLogger_OutcomeFilter(t *testing.T) {
	baseLogger := &mockLogger{}
	filter := OutcomeFilter(core.OutcomeFailure)
	filteredLogger := NewFilteredLogger(baseLogger, filter)

	ctx := context.Background()

	// Should NOT be logged (success)
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
		Outcome:   core.OutcomeSuccess,
	}
	err := filteredLogger.Log(ctx, event1)
	require.NoError(t, err)

	// Should be logged (failure)
	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		EventType: core.EventAuthFailure,
		Outcome:   core.OutcomeFailure,
	}
	err = filteredLogger.Log(ctx, event2)
	require.NoError(t, err)

	// Only 1 event should be logged
	assert.Len(t, baseLogger.Events(), 1)
	assert.Equal(t, "event2", baseLogger.Events()[0].EventID)
}

func TestFilteredLogger_MethodFilter(t *testing.T) {
	baseLogger := &mockLogger{}
	filter := MethodFilter("webauthn", "srp")
	filteredLogger := NewFilteredLogger(baseLogger, filter)

	ctx := context.Background()

	// Should be logged
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		Method:    "webauthn",
	}
	err := filteredLogger.Log(ctx, event1)
	require.NoError(t, err)

	// Should NOT be logged
	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		Method:    "signed_token",
	}
	err = filteredLogger.Log(ctx, event2)
	require.NoError(t, err)

	assert.Len(t, baseLogger.Events(), 1)
	assert.Equal(t, "event1", baseLogger.Events()[0].EventID)
}

func TestFilteredLogger_UserFilter(t *testing.T) {
	baseLogger := &mockLogger{}
	filter := UserFilter("user123", "user456")
	filteredLogger := NewFilteredLogger(baseLogger, filter)

	ctx := context.Background()

	// Should be logged
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		UserID:    "user123",
	}
	err := filteredLogger.Log(ctx, event1)
	require.NoError(t, err)

	// Should NOT be logged
	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		UserID:    "user789",
	}
	err = filteredLogger.Log(ctx, event2)
	require.NoError(t, err)

	assert.Len(t, baseLogger.Events(), 1)
	assert.Equal(t, "event1", baseLogger.Events()[0].EventID)
}

func TestFilteredLogger_AndFilter(t *testing.T) {
	baseLogger := &mockLogger{}
	filter := AndFilter(
		MethodFilter("webauthn"),
		OutcomeFilter(core.OutcomeFailure),
	)
	filteredLogger := NewFilteredLogger(baseLogger, filter)

	ctx := context.Background()

	// Should be logged (both conditions match)
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		Method:    "webauthn",
		Outcome:   core.OutcomeFailure,
	}
	err := filteredLogger.Log(ctx, event1)
	require.NoError(t, err)

	// Should NOT be logged (method matches but outcome doesn't)
	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		Method:    "webauthn",
		Outcome:   core.OutcomeSuccess,
	}
	err = filteredLogger.Log(ctx, event2)
	require.NoError(t, err)

	// Should NOT be logged (outcome matches but method doesn't)
	event3 := core.AuditEvent{
		EventID:   "event3",
		Timestamp: time.Now(),
		Method:    "srp",
		Outcome:   core.OutcomeFailure,
	}
	err = filteredLogger.Log(ctx, event3)
	require.NoError(t, err)

	assert.Len(t, baseLogger.Events(), 1)
	assert.Equal(t, "event1", baseLogger.Events()[0].EventID)
}

func TestFilteredLogger_OrFilter(t *testing.T) {
	baseLogger := &mockLogger{}
	filter := OrFilter(
		MethodFilter("webauthn"),
		OutcomeFilter(core.OutcomeFailure),
	)
	filteredLogger := NewFilteredLogger(baseLogger, filter)

	ctx := context.Background()

	// Should be logged (both match)
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		Method:    "webauthn",
		Outcome:   core.OutcomeFailure,
	}
	err := filteredLogger.Log(ctx, event1)
	require.NoError(t, err)

	// Should be logged (method matches)
	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		Method:    "webauthn",
		Outcome:   core.OutcomeSuccess,
	}
	err = filteredLogger.Log(ctx, event2)
	require.NoError(t, err)

	// Should be logged (outcome matches)
	event3 := core.AuditEvent{
		EventID:   "event3",
		Timestamp: time.Now(),
		Method:    "srp",
		Outcome:   core.OutcomeFailure,
	}
	err = filteredLogger.Log(ctx, event3)
	require.NoError(t, err)

	// Should NOT be logged (neither match)
	event4 := core.AuditEvent{
		EventID:   "event4",
		Timestamp: time.Now(),
		Method:    "signed_token",
		Outcome:   core.OutcomeSuccess,
	}
	err = filteredLogger.Log(ctx, event4)
	require.NoError(t, err)

	assert.Len(t, baseLogger.Events(), 3)
}

func TestFilteredLogger_NotFilter(t *testing.T) {
	baseLogger := &mockLogger{}
	filter := NotFilter(OutcomeFilter(core.OutcomeSuccess))
	filteredLogger := NewFilteredLogger(baseLogger, filter)

	ctx := context.Background()

	// Should NOT be logged (success, but we're inverting)
	event1 := core.AuditEvent{
		EventID:   "event1",
		Timestamp: time.Now(),
		Outcome:   core.OutcomeSuccess,
	}
	err := filteredLogger.Log(ctx, event1)
	require.NoError(t, err)

	// Should be logged (failure)
	event2 := core.AuditEvent{
		EventID:   "event2",
		Timestamp: time.Now(),
		Outcome:   core.OutcomeFailure,
	}
	err = filteredLogger.Log(ctx, event2)
	require.NoError(t, err)

	assert.Len(t, baseLogger.Events(), 1)
	assert.Equal(t, "event2", baseLogger.Events()[0].EventID)
}

func TestAsyncLogger_Log(t *testing.T) {
	baseLogger := &mockLogger{}
	asyncLogger := NewAsyncLogger(baseLogger, 10)
	defer asyncLogger.Close()

	ctx := context.Background()
	event := core.AuditEvent{
		EventID:   "event123",
		Timestamp: time.Now(),
		EventType: core.EventAuthSuccess,
	}

	err := asyncLogger.Log(ctx, event)
	require.NoError(t, err)

	// Wait a bit for async processing
	time.Sleep(100 * time.Millisecond)

	// Event should be logged
	events := baseLogger.Events()
	assert.Len(t, events, 1)
	assert.Equal(t, "event123", events[0].EventID)
}

func TestAsyncLogger_Close(t *testing.T) {
	baseLogger := &mockLogger{}
	asyncLogger := NewAsyncLogger(baseLogger, 10)

	ctx := context.Background()

	// Log multiple events
	for i := 0; i < 5; i++ {
		event := core.AuditEvent{
			EventID:   string(rune('A' + i)),
			Timestamp: time.Now(),
			EventType: core.EventAuthSuccess,
		}
		err := asyncLogger.Log(ctx, event)
		require.NoError(t, err)
	}

	// Close should flush all pending events
	err := asyncLogger.Close()
	require.NoError(t, err)

	// All events should be logged
	events := baseLogger.Events()
	assert.Len(t, events, 5)
}

func TestAsyncLogger_ConcurrentAccess(t *testing.T) {
	baseLogger := &mockLogger{}
	asyncLogger := NewAsyncLogger(baseLogger, 100)
	defer asyncLogger.Close()

	ctx := context.Background()
	const numGoroutines = 10
	const eventsPerGoroutine = 10

	done := make(chan bool, numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < eventsPerGoroutine; j++ {
				event := core.AuditEvent{
					EventID:   string(rune('A' + id)),
					Timestamp: time.Now(),
					EventType: core.EventAuthSuccess,
				}
				_ = asyncLogger.Log(ctx, event)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Close and wait for flush
	err := asyncLogger.Close()
	require.NoError(t, err)

	// Should have logged all events
	events := baseLogger.Events()
	assert.Len(t, events, numGoroutines*eventsPerGoroutine)
}

// Verify implementations satisfy the interface
var _ core.AuditLogger = (*MultiLogger)(nil)
var _ core.AuditLogger = (*FilteredLogger)(nil)
var _ core.AuditLogger = (*AsyncLogger)(nil)
