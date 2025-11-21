package srp

import (
	"fmt"
	"time"

	"go.fergus.london/nopasswords/core"
	"go.fergus.london/nopasswords/core/memory"
)

const (
	// DefaultGroup is the default RFC5054 group (3 = 2048-bit)
	// This provides a good balance between security and performance.
	DefaultGroup = 3

	// DefaultSessionTimeout is the default timeout for authentication sessions.
	DefaultSessionTimeout = 5 * time.Minute

	// MinSaltLength is the minimum salt length in bytes (128 bits).
	MinSaltLength = 16

	// DefaultSaltLength is the default salt length in bytes (256 bits).
	DefaultSaltLength = 32
)

// Config holds the configuration for SRP operations.
//
// Configuration must be identical between client and server to ensure
// compatibility and security.
type Config struct {
	// Group identifies which RFC5054 group to use (3, 4, or 5)
	// Group 3: 2048-bit (default, recommended for most applications)
	// Group 4: 3072-bit (stronger security, higher CPU cost)
	// Group 5: 4096-bit (strongest security, significant CPU cost)
	//
	// @risk Spoofing: Weak group parameters allow offline attacks.
	// Always use RFC5054 standard groups.
	// @risk Denial of Service: Larger groups require more CPU time.
	Group int

	// SaltLength is the length of the random salt in bytes (minimum 16).
	// Larger salts provide better security against rainbow table attacks.
	SaltLength int

	// AuditLogger receives security audit events.
	// Optional: Defaults to no-op logger if not provided.
	AuditLogger core.AuditLogger
}

// Option is a functional option for configuring the SRP Manager.
type Option func(*Config) error

// WithGroup sets the RFC5054 group to use.
//
// Valid groups: 3 (2048-bit), 4 (3072-bit), 5 (4096-bit)
// Default: 3 (2048-bit)
//
// Example:
//
//	manager := NewManager(WithGroup(4)) // Use 3072-bit group
func WithGroup(groupID int) Option {
	return func(c *Config) error {
		if groupID < 3 || groupID > 5 {
			return fmt.Errorf("invalid group ID: %d (valid: 3, 4, 5)", groupID)
		}
		c.Group = groupID
		return nil
	}
}

// WithSaltLength sets the length of the random salt in bytes.
//
// Minimum: 16 bytes (128 bits)
// Default: 32 bytes (256 bits)
//
// Example:
//
//	manager := NewManager(WithSaltLength(32))
func WithSaltLength(length int) Option {
	return func(c *Config) error {
		if length < MinSaltLength {
			return fmt.Errorf("salt length must be at least %d bytes", MinSaltLength)
		}
		if length > 256 {
			return fmt.Errorf("salt length cannot exceed 256 bytes")
		}
		c.SaltLength = length
		return nil
	}
}

// WithAuditLogger sets the audit logger for security events.
//
// Optional: Defaults to no-op logger if not provided.
//
// Example:
//
//	logger := memory.NewStdoutLogger()
//	manager := NewManager(WithAuditLogger(logger))
func WithAuditLogger(logger core.AuditLogger) Option {
	return func(c *Config) error {
		if logger == nil {
			return fmt.Errorf("audit logger cannot be nil")
		}
		c.AuditLogger = logger
		return nil
	}
}

// NewConfig creates a new SRP configuration with defaults and applies the given options.
//
// Required options: WithCredentialStore
// Optional options have sensible defaults.
func NewConfig(opts ...Option) (*Config, error) {
	// Default configuration
	config := &Config{
		Group:          DefaultGroup,
		SaltLength:     DefaultSaltLength,
		AuditLogger:    memory.NewNopLogger(),
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, fmt.Errorf("configuration error: %w", err)
		}
	}

	// Validate required fields
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks if the configuration is valid and complete.
func (c *Config) Validate() error {
	// Validate group
	if c.Group < 3 || c.Group > 5 {
		return fmt.Errorf("invalid group ID: %d (valid: 3, 4, 5)", c.Group)
	}

	// Validate salt length
	if c.SaltLength < MinSaltLength {
		return fmt.Errorf("salt length must be at least %d bytes", MinSaltLength)
	}
	if c.SaltLength > 256 {
		return fmt.Errorf("salt length cannot exceed 256 bytes")
	}

	// Audit logger defaults to no-op if not set
	if c.AuditLogger == nil {
		c.AuditLogger = memory.NewNopLogger()
	}

	return nil
}
