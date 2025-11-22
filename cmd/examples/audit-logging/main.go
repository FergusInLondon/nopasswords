// An example of the audit logging capabilities of the library; for enhanced
// logging and context.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.fergus.london/nopasswords/pkg/core/events"
	"go.fergus.london/nopasswords/pkg/core/events/memory"
)

// Example demonstrating the various audit logging features in NoPasswords.
// This example shows:
// - Using different logger implementations (stdout, file, multi, filtered, async)
// - Using the AuditEventBuilder for constructing events
// - Filtering events by type, outcome, method, etc.
// - Combining multiple loggers

func main() {
	fmt.Println("=== NoPasswords Audit Logging Examples ===")

	// Example 1: Simple stdout logging
	example1SimpleStdoutLogging()

	// Example 2: File-based logging
	example2FileLogging()

	// Example 3: Multi-logger (fan out to multiple destinations)
	example3MultiLogger()

	// Example 4: Filtered logging (log only failures)
	example4FilteredLogging()

	// Example 5: Async logging (non-blocking)
	example5AsyncLogging()

	// Example 6: Complex filtering (AND/OR logic)
	example6ComplexFiltering()

	fmt.Println("\n=== All examples completed successfully ===")
}

func example1SimpleStdoutLogging() {
	fmt.Println("Example 1: Simple Stdout Logging")
	fmt.Println("-----------------------------------")

	logger := memory.NewStdoutLogger(true) // pretty-print for readability
	ctx := context.Background()

	event := events.AuditEvent{
		EventID:        "evt-001",
		Timestamp:      time.Now(),
		EventType:      events.EventAuthSuccess,
		Method:         "webauthn",
		UserIdentifier: "user123",
		Outcome:        events.OutcomeSuccess,
		Metadata:       map[string]interface{}{"example": 1},
	}

	_ = logger.Log(ctx, event)
	fmt.Println()
}

func example2FileLogging() {
	fmt.Println("Example 2: File-based Logging")
	fmt.Println("------------------------------")

	tmpDir := os.TempDir()
	logPath := fmt.Sprintf("%s/nopasswords-audit-%d.log", tmpDir, time.Now().Unix())

	logger, err := memory.NewFileLogger(logPath)
	if err != nil {
		log.Fatalf("Failed to create file logger: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Log multiple events
	events := []events.AuditEvent{
		{
			EventID:        "evt-002",
			Timestamp:      time.Now(),
			EventType:      events.EventAuthSuccess,
			Method:         "srp",
			UserIdentifier: "user456",
			Outcome:        events.OutcomeSuccess,
		},
		{
			EventID:        "evt-003",
			Timestamp:      time.Now(),
			EventType:      events.EventAuthFailure,
			Method:         "srp",
			UserIdentifier: "user456",
			Outcome:        events.OutcomeFailure,
			Reason:         "invalid_password",
		},
	}

	for _, event := range events {
		_ = logger.Log(ctx, event)
	}

	fmt.Printf("✓ Logged %d events to: %s\n\n", len(events), logPath)
}

func example3MultiLogger() {
	fmt.Println("Example 3: Multi-logger (fan out to multiple destinations)")
	fmt.Println("-----------------------------------------------------------")

	// Create multiple loggers
	stdoutLogger := memory.NewStdoutLogger(false)
	tmpDir := os.TempDir()
	logPath := fmt.Sprintf("%s/nopasswords-multi-%d.log", tmpDir, time.Now().Unix())
	fileLogger, _ := memory.NewFileLogger(logPath)
	defer fileLogger.Close()

	// Combine them
	multiLogger := memory.NewMultiLogger(stdoutLogger, fileLogger)

	ctx := context.Background()
	event := events.AuditEvent{
		EventID:        "evt-004",
		Timestamp:      time.Now(),
		EventType:      events.EventTokenGenerate,
		Method:         "signed_token",
		UserIdentifier: "user789",
		Outcome:        events.OutcomeSuccess,
	}

	_ = multiLogger.Log(ctx, event)
	fmt.Printf("✓ Event logged to both stdout and file: %s\n\n", logPath)
}

func example4FilteredLogging() {
	fmt.Println("Example 4: Filtered Logging (failures only)")
	fmt.Println("--------------------------------------------")

	baseLogger := memory.NewStdoutLogger(true)

	// Filter to log only failures
	failureFilter := memory.OutcomeFilter(events.OutcomeFailure)
	filteredLogger := memory.NewFilteredLogger(baseLogger, failureFilter)

	ctx := context.Background()

	// This will be logged (failure)
	event1 := events.AuditEvent{
		EventID:        "evt-005",
		Timestamp:      time.Now(),
		EventType:      events.EventAuthFailure,
		Method:         "webauthn",
		UserIdentifier: "user999",
		Outcome:        events.OutcomeFailure,
		Reason:         "invalid_signature",
	}
	_ = filteredLogger.Log(ctx, event1)

	// This will NOT be logged (success)
	event2 := events.AuditEvent{
		EventID:        "evt-006",
		Timestamp:      time.Now(),
		EventType:      events.EventAuthSuccess,
		Method:         "webauthn",
		UserIdentifier: "user999",
		Outcome:        events.OutcomeSuccess,
	}
	_ = filteredLogger.Log(ctx, event2)

	fmt.Println("(Note: Only the failure event was logged above)")
	fmt.Println()
}

func example5AsyncLogging() {
	fmt.Println("Example 5: Async Logging (non-blocking)")
	fmt.Println("----------------------------------------")

	baseLogger := memory.NewStdoutLogger(false)
	asyncLogger := memory.NewAsyncLogger(baseLogger, 100)
	defer asyncLogger.Close() // Flush on shutdown

	ctx := context.Background()

	// Log events without blocking
	for i := 1; i <= 5; i++ {
		event := events.AuditEvent{
			EventID:        fmt.Sprintf("evt-async-%d", i),
			Timestamp:      time.Now(),
			EventType:      events.EventAuthSuccess,
			Method:         "webauthn",
			UserIdentifier: fmt.Sprintf("user%d", i),
			Outcome:        events.OutcomeSuccess,
		}
		_ = asyncLogger.Log(ctx, event)
	}

	fmt.Println("✓ Logged 5 events asynchronously")
	fmt.Println("(Events may appear in stdout after this message)")
	fmt.Println()

	// Give async logger time to process
	time.Sleep(200 * time.Millisecond)
}

func example6ComplexFiltering() {
	fmt.Println("Example 6: Complex Filtering (AND/OR logic)")
	fmt.Println("--------------------------------------------")

	baseLogger := memory.NewStdoutLogger(true)

	// Filter: WebAuthn failures OR SRP events
	filter := memory.OrFilter(
		memory.AndFilter(
			memory.MethodFilter("webauthn"),
			memory.OutcomeFilter(events.OutcomeFailure),
		),
		memory.MethodFilter("srp"),
	)

	filteredLogger := memory.NewFilteredLogger(baseLogger, filter)
	ctx := context.Background()

	fmt.Println("Filter: (webauthn AND failure) OR srp")
	fmt.Println()

	// Should be logged: WebAuthn failure
	event1 := events.AuditEvent{
		EventID:   "evt-007",
		Timestamp: time.Now(),
		EventType: events.EventAuthFailure,
		Method:    "webauthn",
		Outcome:   events.OutcomeFailure,
	}
	_ = filteredLogger.Log(ctx, event1)
	fmt.Println("✓ Logged: WebAuthn failure")

	// Should be logged: SRP (any outcome)
	event2 := events.AuditEvent{
		EventID:   "evt-008",
		Timestamp: time.Now(),
		EventType: events.EventAuthSuccess,
		Method:    "srp",
		Outcome:   events.OutcomeSuccess,
	}
	_ = filteredLogger.Log(ctx, event2)
	fmt.Println("✓ Logged: SRP success")

	// Should NOT be logged: WebAuthn success
	event3 := events.AuditEvent{
		EventID:   "evt-009",
		Timestamp: time.Now(),
		EventType: events.EventAuthSuccess,
		Method:    "webauthn",
		Outcome:   events.OutcomeSuccess,
	}
	_ = filteredLogger.Log(ctx, event3)
	fmt.Println("✗ Skipped: WebAuthn success (doesn't match filter)")
	fmt.Println()
}
