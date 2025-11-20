# Audit Logging Examples

This example demonstrates the comprehensive audit logging features provided by the NoPasswords library.

## Overview

The NoPasswords library provides a flexible audit logging interface that allows you to:
- Log security-relevant events across all authentication methods
- Fan out events to multiple destinations simultaneously
- Filter events based on various criteria
- Log asynchronously to avoid blocking authentication operations
- Build events using a convenient fluent API

## Running the Example

```bash
cd examples/audit-logging
go run main.go
```

## Features Demonstrated

### 1. Simple Stdout Logging

The most basic logger that writes JSON events to stdout. Useful for development and containerized environments where logs are collected from stdout.

```go
logger := memory.NewStdoutLogger(true) // pretty-print
event := core.AuditEvent{...}
logger.Log(ctx, event)
```

### 2. File-based Logging

Writes events to a file in JSON Lines format (one event per line). Supports automatic directory creation.

```go
logger, err := memory.NewFileLogger("/var/log/app/audit.log")
defer logger.Close()
logger.Log(ctx, event)
```

**Note**: This logger does not implement automatic rotation. Use external tools like `logrotate` for production deployments.

### 3. Multi-logger

Fans out events to multiple logger implementations simultaneously. Perfect for logging to both a file and stdout, or to multiple files.

```go
multiLogger := memory.NewMultiLogger(
    memory.NewStdoutLogger(false),
    fileLogger,
)
multiLogger.Log(ctx, event)
```

### 4. Filtered Logging

Filter events based on criteria like event type, outcome, method, or user ID. Useful for routing different types of events to different destinations.

```go
// Log only failures
failureFilter := memory.OutcomeFilter(core.OutcomeFailure)
filteredLogger := memory.NewFilteredLogger(baseLogger, failureFilter)
```

Available filters:
- `EventTypeFilter` - Include specific event types
- `ExcludeEventTypeFilter` - Exclude specific event types
- `OutcomeFilter` - Filter by outcome (success/failure/error)
- `MethodFilter` - Filter by authentication method
- `UserFilter` - Filter by user ID

Filter combinators:
- `AndFilter` - All conditions must match
- `OrFilter` - At least one condition must match
- `NotFilter` - Invert a filter

### 5. Async Logging

Log events asynchronously in a background goroutine to avoid blocking authentication operations.

```go
asyncLogger := memory.NewAsyncLogger(baseLogger, 100) // buffer size: 100
defer asyncLogger.Close() // Flush pending events on shutdown
asyncLogger.Log(ctx, event)
```

**Important**: Always call `Close()` during application shutdown to flush pending events.

### 6. AuditEventBuilder

Build audit events using a fluent API with auto-generated event IDs and timestamps.

```go
event := core.NewAuditEventBuilder().
    WithEventType(core.EventAuthSuccess).
    WithMethod("webauthn").
    WithUserID("user123").
    WithOutcome(core.OutcomeSuccess).
    WithIPAddress("203.0.113.42").
    WithMetadata("key", "value").
    Build()
```

## Production Recommendations

### File Logging

Use `logrotate` for file rotation:

```
/var/log/app/audit.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        systemctl reload myapp
    endscript
}
```

### Async Logging

For high-throughput applications, use async logging to prevent audit logging from blocking authentication:

```go
stdoutLogger := memory.NewStdoutLogger(false)
asyncLogger := memory.NewAsyncLogger(stdoutLogger, 1000)
defer asyncLogger.Close()
```

### Multiple Destinations

Send all events to a file, but also send failures to stderr:

```go
fileLogger, _ := memory.NewFileLogger("/var/log/app/audit.log")
stderrLogger := memory.NewStderrLogger(false)
failureLogger := memory.NewFilteredLogger(stderrLogger,
    memory.OutcomeFilter(core.OutcomeFailure))

multiLogger := memory.NewMultiLogger(fileLogger, failureLogger)
```

### Custom Loggers

Implement the `core.AuditLogger` interface to integrate with your logging infrastructure:

```go
type MyCustomLogger struct {
    // Your logger implementation
}

func (l *MyCustomLogger) Log(ctx context.Context, event core.AuditEvent) error {
    // Send to your logging system (e.g., syslog, journald, cloud logging)
    return nil
}
```

## Security Considerations

### Information Disclosure

The `AuditEvent` struct is designed to **exclude sensitive data**. Never add:
- Passwords or password hashes
- Private keys or tokens
- Full credential data

Use the `Metadata` field judiciously and ensure it contains only non-sensitive context.

### Denial of Service

Audit logging can fill disk space. Mitigation strategies:
- Use external log rotation (`logrotate`)
- Monitor disk usage with alerting
- Set log retention policies
- Consider async logging to prevent backpressure

### Repudiation

Audit logs are essential for security investigations:
- Ensure logs are written reliably (use `Sync()` for critical events)
- Protect log files with appropriate permissions (0644 or stricter)
- Consider shipping logs to a centralized logging system
- Implement tamper detection if required by compliance

## Event Types

Standard event types defined in `core.AuditEvent`:

- `EventAuthAttempt` - Authentication attempt started
- `EventAuthSuccess` - Authentication succeeded
- `EventAuthFailure` - Authentication failed
- `EventCredentialRegister` - New credential registered
- `EventCredentialDelete` - Credential deleted
- `EventCredentialUpdate` - Credential updated (e.g., sign counter)
- `EventTokenGenerate` - Signed token generated
- `EventTokenVerify` - Token verification attempted
- `EventTokenRevoke` - Token revoked

## Outcomes

- `OutcomeSuccess` - Operation succeeded
- `OutcomeFailure` - Operation failed (expected failure, e.g., wrong password)
- `OutcomeError` - Operation error (unexpected error, e.g., database failure)
