package memory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"go.fergus.london/nopasswords/pkg/core/events"
)

// FileLogger writes audit events to a file in JSON format.
// Each event is written as a single line of JSON (JSON Lines format).
//
// This implementation is safe for concurrent use by multiple goroutines.
//
// @risk Denial of Service: Unbounded logging can fill disk space. Applications
// should implement external log rotation (e.g., logrotate) and disk monitoring.
//
// Note: This logger does not implement automatic rotation. Use external tools
// like logrotate, systemd journald, or container orchestration log management.
type FileLogger struct {
	mu       sync.Mutex
	file     *os.File
	encoder  *json.Encoder
	filepath string
	pretty   bool
}

// FileLoggerOption configures a FileLogger.
type FileLoggerOption func(*FileLogger)

// WithPrettyPrint enables pretty-printed JSON output (indented).
// Default: false (compact JSON, one event per line - JSON Lines format).
//
// Note: Pretty printing is useful for debugging but increases file size.
func WithPrettyPrint(pretty bool) FileLoggerOption {
	return func(f *FileLogger) {
		f.pretty = pretty
	}
}

// NewFileLogger creates a new file-based audit logger.
//
// The file will be created if it doesn't exist, or appended to if it does.
// Directory paths will be created automatically.
//
// Options:
//   - WithPrettyPrint: Enable pretty-printed JSON (default: compact JSON Lines)
//
// Example:
//
//	logger, err := memory.NewFileLogger("/var/log/app/audit.log")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer logger.Close()
//
// For log rotation, use external tools like logrotate with a configuration:
//
//	/var/log/app/audit.log {
//	    daily
//	    rotate 7
//	    compress
//	    missingok
//	    notifempty
//	    postrotate
//	        systemctl reload myapp
//	    endscript
//	}
func NewFileLogger(filepath string, opts ...FileLoggerOption) (*FileLogger, error) {
	// Create directory if it doesn't exist
	dir := filepath
	if idx := len(filepath) - 1; idx >= 0 {
		for idx >= 0 && filepath[idx] != '/' {
			idx--
		}
		if idx >= 0 {
			dir = filepath[:idx]
		}
	}

	if dir != "" && dir != filepath {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}
	}

	// Open file for appending
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	logger := &FileLogger{
		file:     file,
		encoder:  json.NewEncoder(file),
		filepath: filepath,
	}

	// Apply options
	for _, opt := range opts {
		opt(logger)
	}

	// Configure pretty printing
	if logger.pretty {
		logger.encoder.SetIndent("", "  ")
	}

	return logger, nil
}

// Log implements events.AuditLogger by writing JSON to the file.
func (f *FileLogger) Log(ctx context.Context, event events.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Encode the event
	if err := f.encoder.Encode(event); err != nil {
		return fmt.Errorf("failed to encode audit event: %w", err)
	}

	return nil
}

// Close flushes and closes the log file.
// This should be called when the application shuts down.
func (f *FileLogger) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file != nil {
		if err := f.file.Sync(); err != nil {
			_ = f.file.Close()
			return fmt.Errorf("failed to sync log file: %w", err)
		}
		if err := f.file.Close(); err != nil {
			return fmt.Errorf("failed to close log file: %w", err)
		}
		f.file = nil
	}

	return nil
}

// Sync flushes the log file to disk.
// This is useful for ensuring events are persisted before critical operations.
func (f *FileLogger) Sync() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file != nil {
		if err := f.file.Sync(); err != nil {
			return fmt.Errorf("failed to sync log file: %w", err)
		}
	}

	return nil
}
