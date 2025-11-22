// Package srp implements Secure Remote Password (SRP) protocol as defined in RFC 5054.
//
// SRP is a password-authenticated key exchange (PAKE) protocol that allows a client to
// authenticate to a server using a password without ever transmitting the password over
// the network. The server stores only a verifier derived from the password, which cannot
// be used to impersonate the client or recover the password.
//
// Security Properties:
//   - Password never transmitted over the network
//   - Server stores only verifiers, not passwords
//   - Mutual authentication (both parties prove knowledge of the password)
//   - Protection against man-in-the-middle attacks
//   - Resistance to offline dictionary attacks (even with compromised verifier database)
//
// Protocol Flow:
//  1. Attestation (Registration): Client sends verifier and salt to server
//  2. Assertion Initiation: Client requests authentication, server sends challenge
//  3. Assertion Completion: Client computes proof, server verifies and responds
//
// Example usage:
//
//	manager, err := srp.NewManager(
//	    srp.WithGroup(3),
//	    srp.WithParameterStore(myStore),
//	    srp.WithStateCache(myCache),
//	    srp.WithEventLogger(myLogger),
//	)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	http.HandleFunc("/register", manager.AttestationHandlerFunc(onSuccess))
//	http.HandleFunc("/auth/begin", manager.AssertionBeginHandler())
//	http.HandleFunc("/auth/finish", manager.AssertionVerificationHandler(onAuth))
package srp

import (
	"fmt"
	"time"

	"go.fergus.london/nopasswords/pkg/core/events"
	"go.fergus.london/nopasswords/pkg/core/events/memory"
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

// Parameters represents the SRP verifier stored on the server.
// The verifier is derived from the user's password and salt, but cannot be used
// to recover the password (one-way function).
//
// Security Considerations:
// @mitigation Information Disclosure: Verifiers do not allow password recovery.
// Even if the database is compromised, attackers cannot derive the password from the verifier.
type Parameters struct {
	// UserID identifies the user this verifier belongs to
	UserIdentifier string `json:"user_id"`

	// Salt is the random salt used during registration (minimum 128 bits)
	Salt []byte `json:"salt"`

	// Verifier is the SRP verifier value (v = g^x mod N, where x = H(salt | password))
	Verifier []byte `json:"verifier"`

	// Group identifies which RFC5054 group was used (3, 4, or 5)
	Group int `json:"group"`
}

// ParameterStore defines the interface for persisting and retrieving SRP parameters.
//
// Parameters include the user's salt and verifier, which are required for authentication.
// The verifier is a one-way hash of the password and cannot be used to recover the
// original password, even if the database is compromised.
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Security Considerations:
//   - Store verifiers securely; while they don't reveal passwords, they enable authentication
//   - Implement rate limiting to prevent brute-force attacks
//   - Consider encrypting the database at rest
//   - Audit all access to parameter stores
//
// Example implementations:
//   - memory.ParameterStore (in-memory, for testing)
//   - Custom database-backed stores (PostgreSQL, MongoDB, etc.)
type ParameterStore interface {
	GetForUserIdentifier(string) (*Parameters, error)
	StoreForUserIdentifier(string, *Parameters) error
}

// StateCache defines the interface for temporarily storing SRP authentication state.
//
// During the assertion (authentication) flow, ephemeral values (B, b) must be stored
// between the initiation and completion requests. These values should be purged after
// successful authentication or after a timeout.
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Security Considerations:
//   - State should expire after a short timeout (default: 5 minutes)
//   - Purge state immediately after successful authentication
//   - Store state securely to prevent session hijacking
//   - Consider using a distributed cache for multi-server deployments (Redis, Memcached)
//
// Example implementations:
//   - memory.StateCache (in-memory, single server only)
//   - Redis-backed cache (for distributed deployments)
type StateCache interface {
	GetForUserIdentifier(string) (*AssertionState, error)
	StoreForUserIdentifier(string, *AssertionState) error
	PurgeForUserIdentity(string) error
}

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
	AuditLogger events.EventLogger

	// TODO...
	Store ParameterStore

	// TODO...
	Cache StateCache
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

// WithParameterStore sets the Parameter Store for retrieving user-specific
// Parameters.
func WithParameterStore(store ParameterStore) Option {
	return func(c *Config) error {
		if store == nil {
			return fmt.Errorf("parameter store cannot be nil")
		}

		c.Store = store
		return nil
	}
}

// WithStateCache sets the StateCache for storing state during the assertion
// flow.
func WithStateCache(cache StateCache) Option {
	return func(c *Config) error {
		if cache == nil {
			return fmt.Errorf("state cache cannot be nil")
		}

		c.Cache = cache
		return nil
	}
}

// WithEventLogger sets the event logger for security and debug.
func WithEventLogger(logger events.EventLogger) Option {
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
// Required options: WithParameterStore, WithStateCache
// Optional options have sensible defaults.
func NewConfig(opts ...Option) (*Config, error) {
	// Default configuration
	config := &Config{
		Group:       DefaultGroup,
		SaltLength:  DefaultSaltLength,
		AuditLogger: memory.NewNopLogger(),
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

	if c.Store == nil {
		return fmt.Errorf("parameter store must be provided to srp manager")
	}

	if c.Cache == nil {
		return fmt.Errorf("state cache must be provided to srp manager")
	}

	return nil
}
