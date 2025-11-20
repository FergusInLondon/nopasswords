package signedtoken

import (
	"fmt"
	"time"

	"go.fergus.london/nopasswords/core"
	"go.fergus.london/nopasswords/core/memory"
)

const (
	// DefaultTokenLifetime is the default validity period for tokens (1 hour).
	DefaultTokenLifetime = 1 * time.Hour
)

// Config holds the configuration for the signed token manager.
type Config struct {
	// Embed the base config for common options
	core.Config

	// Signer is the cryptographic signer for tokens.
	// Required: Must be set before use.
	Signer Signer

	// DefaultLifetime is the default validity period for tokens.
	// Can be overridden per-token in GenerateToken.
	// Maximum allowed: MaxTokenLifetime (24 hours).
	DefaultLifetime time.Duration

	// UseOpaqueIDs when true will expect userIDs to be opaque identifiers
	// rather than actual user identifiers. This reduces information disclosure
	// risk when tokens are exposed in URLs.
	//
	// When enabled, the application is responsible for mapping opaque IDs
	// to actual user identifiers.
	//
	// @mitigation Information Disclosure: Using opaque IDs prevents leaking
	// user identifiers in URLs, logs, or other exposed contexts.
	UseOpaqueIDs bool
}

// Option is a functional option for configuring the Manager.
type Option func(*Config)

// WithSigner sets the cryptographic signer for tokens.
//
// This is required and must be set before the Manager can be used.
// For most use cases, use NewHMACSignerSHA256 with a strong random key.
//
// Example:
//   key := make([]byte, 32)
//   rand.Read(key)
//   signer, _ := NewHMACSignerSHA256(key)
//   manager := NewManager(WithSigner(signer))
func WithSigner(signer Signer) Option {
	return func(c *Config) {
		c.Signer = signer
	}
}

// WithDefaultLifetime sets the default token validity period.
//
// This can be overridden on a per-token basis in GenerateToken.
// The maximum allowed lifetime is MaxTokenLifetime (24 hours).
//
// Example:
//   manager := NewManager(WithDefaultLifetime(30 * time.Minute))
func WithDefaultLifetime(lifetime time.Duration) Option {
	return func(c *Config) {
		c.DefaultLifetime = lifetime
	}
}

// WithOpaqueIDs enables opaque identifier mode.
//
// When enabled, the Manager expects userID parameters to be opaque identifiers
// that don't directly reveal user information. The application is responsible
// for mapping these opaque IDs to actual user identifiers.
//
// This reduces the risk of information disclosure when tokens appear in URLs.
//
// Example:
//   manager := NewManager(WithOpaqueIDs(true))
//   // Use UUIDs or random strings as user IDs instead of email addresses
//   token, _ := manager.GenerateToken(ctx, "550e8400-e29b-41d4-a716-446655440000", nil)
func WithOpaqueIDs(useOpaque bool) Option {
	return func(c *Config) {
		c.UseOpaqueIDs = useOpaque
	}
}

// WithTokenStore sets the token storage implementation for revocation support.
//
// If not provided, token revocation will not be supported (tokens are purely stateless).
// Provide a TokenStore implementation if you need to revoke tokens before they expire.
//
// Example:
//   store := memory.NewMemoryTokenStore()
//   manager := NewManager(WithTokenStore(store))
func WithTokenStore(store core.TokenStore) Option {
	return func(c *Config) {
		c.TokenStore = store
	}
}

// WithAuditLogger sets the audit logger for security events.
//
// If not provided, a no-op logger will be used (events are not logged).
//
// Example:
//   logger := memory.NewStdoutLogger()
//   manager := NewManager(WithAuditLogger(logger))
func WithAuditLogger(logger core.AuditLogger) Option {
	return func(c *Config) {
		c.AuditLogger = logger
	}
}

// NewConfig creates a new Config with defaults and applies the given options.
func NewConfig(opts ...Option) (*Config, error) {
	config := &Config{
		DefaultLifetime: DefaultTokenLifetime,
		UseOpaqueIDs:    false,
	}

	// Apply options
	for _, opt := range opts {
		opt(config)
	}

	// Set defaults for base config if not provided
	if config.TokenStore == nil {
		// Use a no-op store if none provided (revocation not supported)
		config.TokenStore = nil
	}

	if config.AuditLogger == nil {
		// Use no-op logger if none provided
		config.AuditLogger = memory.NewNopLogger()
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, err
	}

	return config, nil
}

// Validate checks if the configuration is valid and complete.
func (c *Config) Validate() error {
	// Signer is required
	if c.Signer == nil {
		return fmt.Errorf("signer is required")
	}

	// Validate default lifetime
	if c.DefaultLifetime <= 0 {
		return fmt.Errorf("default lifetime must be positive")
	}

	if c.DefaultLifetime > MaxTokenLifetime {
		return fmt.Errorf("default lifetime %v exceeds maximum %v", c.DefaultLifetime, MaxTokenLifetime)
	}

	return nil
}
