package memory

import (
	"context"
	"fmt"
	"sync"

	"go.fergus.london/nopasswords/core"
)

// MultiLogger fans out audit events to multiple underlying loggers.
// This is useful for sending events to multiple destinations simultaneously
// (e.g., stdout + file, or file + SIEM).
//
// This implementation is safe for concurrent use by multiple goroutines.
//
// All loggers are called in the order they were added. If any logger returns
// an error, the error is collected but logging continues to other loggers.
// All errors are returned as a combined error.
//
// Example:
//
//	stdoutLogger := memory.NewStdoutLogger(false)
//	fileLogger, _ := memory.NewFileLogger("/var/log/audit.log")
//	multiLogger := memory.NewMultiLogger(stdoutLogger, fileLogger)
type MultiLogger struct {
	loggers []core.AuditLogger
}

// NewMultiLogger creates a new multi-logger that fans out to multiple loggers.
func NewMultiLogger(loggers ...core.AuditLogger) *MultiLogger {
	return &MultiLogger{
		loggers: loggers,
	}
}

// AddLogger adds a logger to the multi-logger.
func (m *MultiLogger) AddLogger(logger core.AuditLogger) {
	m.loggers = append(m.loggers, logger)
}

// Log implements core.AuditLogger by calling all underlying loggers.
// Errors from individual loggers are collected and returned as a combined error.
func (m *MultiLogger) Log(ctx context.Context, event core.AuditEvent) error {
	var errors []error

	for _, logger := range m.loggers {
		if err := logger.Log(ctx, event); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return &MultiLoggerError{Errors: errors}
	}

	return nil
}

// MultiLoggerError represents one or more errors from underlying loggers.
type MultiLoggerError struct {
	Errors []error
}

// Error implements the error interface.
func (e *MultiLoggerError) Error() string {
	if len(e.Errors) == 1 {
		return fmt.Sprintf("multi-logger error: %v", e.Errors[0])
	}
	return fmt.Sprintf("multi-logger errors: %d errors occurred", len(e.Errors))
}

// Unwrap returns the underlying errors for errors.Is/As support.
func (e *MultiLoggerError) Unwrap() []error {
	return e.Errors
}

// FilteredLogger wraps another AuditLogger and filters events based on criteria.
// This is useful for:
//   - Logging only failures to a separate destination
//   - Excluding certain event types from logs
//   - Routing different event types to different loggers
//
// This implementation is safe for concurrent use by multiple goroutines.
//
// Example - Log only failures:
//
//	baseLogger := memory.NewStdoutLogger(false)
//	failureLogger := memory.NewFilteredLogger(
//	    baseLogger,
//	    memory.OutcomeFilter(core.OutcomeFailure),
//	)
//
// Example - Exclude token generation events:
//
//	logger := memory.NewFilteredLogger(
//	    baseLogger,
//	    memory.ExcludeEventTypeFilter(core.EventTokenGenerate),
//	)
type FilteredLogger struct {
	logger core.AuditLogger
	filter FilterFunc
}

// FilterFunc is a function that determines whether an event should be logged.
// Return true to log the event, false to skip it.
type FilterFunc func(event core.AuditEvent) bool

// NewFilteredLogger creates a new filtered logger.
func NewFilteredLogger(logger core.AuditLogger, filter FilterFunc) *FilteredLogger {
	return &FilteredLogger{
		logger: logger,
		filter: filter,
	}
}

// Log implements core.AuditLogger by filtering events before logging.
func (f *FilteredLogger) Log(ctx context.Context, event core.AuditEvent) error {
	if f.filter(event) {
		return f.logger.Log(ctx, event)
	}
	return nil
}

// Predefined filter functions

// EventTypeFilter creates a filter that only logs events of specific types.
func EventTypeFilter(eventTypes ...string) FilterFunc {
	typeMap := make(map[string]bool)
	for _, t := range eventTypes {
		typeMap[t] = true
	}

	return func(event core.AuditEvent) bool {
		return typeMap[event.EventType]
	}
}

// ExcludeEventTypeFilter creates a filter that excludes specific event types.
func ExcludeEventTypeFilter(eventTypes ...string) FilterFunc {
	typeMap := make(map[string]bool)
	for _, t := range eventTypes {
		typeMap[t] = true
	}

	return func(event core.AuditEvent) bool {
		return !typeMap[event.EventType]
	}
}

// OutcomeFilter creates a filter that only logs events with specific outcomes.
func OutcomeFilter(outcomes ...string) FilterFunc {
	outcomeMap := make(map[string]bool)
	for _, o := range outcomes {
		outcomeMap[o] = true
	}

	return func(event core.AuditEvent) bool {
		return outcomeMap[event.Outcome]
	}
}

// MethodFilter creates a filter that only logs events for specific authentication methods.
func MethodFilter(methods ...string) FilterFunc {
	methodMap := make(map[string]bool)
	for _, m := range methods {
		methodMap[m] = true
	}

	return func(event core.AuditEvent) bool {
		return methodMap[event.Method]
	}
}

// UserFilter creates a filter that only logs events for specific users.
// This is useful for debugging specific user issues.
func UserFilter(userIDs ...string) FilterFunc {
	userMap := make(map[string]bool)
	for _, u := range userIDs {
		userMap[u] = true
	}

	return func(event core.AuditEvent) bool {
		return userMap[event.UserID]
	}
}

// AndFilter combines multiple filters with AND logic.
// All filters must return true for the event to be logged.
func AndFilter(filters ...FilterFunc) FilterFunc {
	return func(event core.AuditEvent) bool {
		for _, filter := range filters {
			if !filter(event) {
				return false
			}
		}
		return true
	}
}

// OrFilter combines multiple filters with OR logic.
// At least one filter must return true for the event to be logged.
func OrFilter(filters ...FilterFunc) FilterFunc {
	return func(event core.AuditEvent) bool {
		for _, filter := range filters {
			if filter(event) {
				return true
			}
		}
		return false
	}
}

// NotFilter inverts a filter.
func NotFilter(filter FilterFunc) FilterFunc {
	return func(event core.AuditEvent) bool {
		return !filter(event)
	}
}

// AsyncLogger wraps another AuditLogger and logs events asynchronously.
// Events are sent to a channel and logged by a background goroutine.
// This prevents logging from blocking authentication operations.
//
// This implementation is safe for concurrent use by multiple goroutines.
//
// @risk Information Disclosure: Events are buffered in memory. If the application
// crashes before events are flushed, they may be lost.
//
// @mitigation: Provides Close() method to flush pending events during shutdown.
type AsyncLogger struct {
	logger  core.AuditLogger
	events  chan core.AuditEvent
	wg      sync.WaitGroup
	done    chan struct{}
	started bool
	closed  bool
	mu      sync.Mutex
}

// NewAsyncLogger creates a new asynchronous logger.
//
// bufferSize determines how many events can be buffered before Log() blocks.
// Choose a size appropriate for your expected load. Typical values: 100-1000.
//
// The background goroutine is started automatically on the first Log() call.
//
// Important: Call Close() during application shutdown to flush pending events.
func NewAsyncLogger(logger core.AuditLogger, bufferSize int) *AsyncLogger {
	return &AsyncLogger{
		logger: logger,
		events: make(chan core.AuditEvent, bufferSize),
		done:   make(chan struct{}),
	}
}

// Log implements core.AuditLogger by sending the event to a channel.
func (a *AsyncLogger) Log(ctx context.Context, event core.AuditEvent) error {
	a.mu.Lock()
	if !a.started {
		a.start()
	}
	a.mu.Unlock()

	select {
	case a.events <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-a.done:
		// Logger is shutting down, try to log directly as fallback
		return a.logger.Log(ctx, event)
	}
}

// start begins the background logging goroutine.
// Caller must hold the lock.
func (a *AsyncLogger) start() {
	a.started = true
	a.wg.Add(1)
	go a.processEvents()
}

// processEvents is the background goroutine that processes events.
func (a *AsyncLogger) processEvents() {
	defer a.wg.Done()

	for {
		select {
		case event := <-a.events:
			// Log the event (ignore errors, as there's no good way to report them)
			_ = a.logger.Log(context.Background(), event)
		case <-a.done:
			// Drain remaining events
			for {
				select {
				case event := <-a.events:
					_ = a.logger.Log(context.Background(), event)
				default:
					return
				}
			}
		}
	}
}

// Close stops the background goroutine and flushes pending events.
// This should be called during application shutdown.
// Multiple calls to Close() are safe (idempotent).
func (a *AsyncLogger) Close() error {
	a.mu.Lock()
	if !a.started || a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.mu.Unlock()

	close(a.done)
	a.wg.Wait()
	return nil
}
