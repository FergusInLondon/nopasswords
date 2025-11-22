package webauthn

import (
	"context"
	"fmt"
	"os"

	"go.fergus.london/nopasswords/pkg/core/events"
	"go.fergus.london/nopasswords/pkg/core/events/memory"
)

// CredentialStore defines the interface for storing and retrieving authentication
// credentials across different authentication methods (WebAuthn, SRP, etc.).
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Security Considerations:
//
// @risk Tampering: Implementations must handle concurrent access safely to prevent
// data races and corruption. Consider using appropriate locking mechanisms.
//
// @risk Elevation of Privilege: This interface is designed to prevent credential
// enumeration attacks. List operations require explicit user context and should
// not allow global enumeration of all credentials.
//
// @risk Denial of Service: Implementations should consider rate limiting and
// resource bounds. The interface does not enforce cleanup policies; implementers
// must handle TTL and storage limits.
type CredentialStore interface {
	// StoreCredential saves a credential for a user. The credentialID must be unique
	// within the scope of this store. The data parameter contains the credential-specific
	// information (e.g., WebAuthn public key, SRP verifier).
	//
	// Returns ErrAlreadyExists if a credential with the same ID already exists.
	StoreCredential(ctx context.Context, userID string, credentialID string, data []byte) error

	// GetCredential retrieves a specific credential by its ID for a given user.
	//
	// Returns ErrNotFound if the credential does not exist.
	GetCredential(ctx context.Context, userID string, credentialID string) ([]byte, error)

	// ListCredentials returns all credential IDs for a given user. This is useful
	// for scenarios where a user has multiple credentials (e.g., multiple security keys).
	//
	// The returned slice may be empty if the user has no credentials.
	// Implementations should not return an error for non-existent users; return an empty slice instead.
	ListCredentials(ctx context.Context, userID string) ([]string, error)

	// DeleteCredential removes a credential from storage.
	//
	// Returns ErrNotFound if the credential does not exist.
	// Implementations should ensure this operation is idempotent where possible.
	DeleteCredential(ctx context.Context, userID string, credentialID string) error

	// UpdateCredential updates the data for an existing credential. This is useful
	// for updating counter values in WebAuthn or other mutable credential properties.
	//
	// Returns ErrNotFound if the credential does not exist.
	UpdateCredential(ctx context.Context, userID string, credentialID string, data []byte) error
}

// Config holds the configuration for WebAuthn operations.
type Config struct {
	// RPDisplayName is the human-readable name of the relying party
	RPDisplayName string
	// RPID is the relying party identifier (domain)
	RPID string
	// RPOrigins is the list of allowed origins for WebAuthn operations
	RPOrigins []string
	// UserVerification is the default user verification requirement
	UserVerification UserVerificationRequirement
	// AttestationPreference is the default attestation preference
	AttestationPreference AttestationPreference
	// Timeout is the default timeout for WebAuthn ceremonies (in milliseconds)
	Timeout int
	// AuthenticatorSelection specifies default authenticator requirements
	AuthenticatorSelection AuthenticatorSelection
	// CredentialStore is the storage backend for credentials
	CredentialStore CredentialStore
	// AuditLogger is the logger for security events
	AuditLogger events.EventLogger
}

// Option is a functional option for configuring WebAuthn.
type Option func(*Config) error

// WithRPDisplayName sets the relying party display name.
func WithRPDisplayName(name string) Option {
	return func(c *Config) error {
		if name == "" {
			return fmt.Errorf("relying party display name cannot be empty")
		}
		c.RPDisplayName = name
		return nil
	}
}

// WithRPID sets the relying party identifier.
// Falls back to WEBAUTHN_RP_ID environment variable if not provided.
func WithRPID(id string) Option {
	return func(c *Config) error {
		if id == "" {
			if envID := os.Getenv("WEBAUTHN_RP_ID"); envID != "" {
				id = envID
			} else {
				return fmt.Errorf("relying party ID cannot be empty (set WEBAUTHN_RP_ID or use WithRPID)")
			}
		}
		c.RPID = id
		return nil
	}
}

// WithRPOrigins sets the allowed origins for WebAuthn operations.
// Falls back to WEBAUTHN_RP_ORIGINS environment variable (comma-separated) if not provided.
//
// Security Considerations:
// @risk Spoofing: Incorrect origin validation allows phishing attacks. Always validate
// that origins match your application's actual origins. Never use wildcards or overly
// permissive patterns.
func WithRPOrigins(origins ...string) Option {
	return func(c *Config) error {
		if len(origins) == 0 {
			if envOrigins := os.Getenv("WEBAUTHN_RP_ORIGINS"); envOrigins != "" {
				// Simple comma-split for environment variable
				origins = []string{envOrigins}
			} else {
				return fmt.Errorf("at least one origin must be specified (set WEBAUTHN_RP_ORIGINS or use WithRPOrigins)")
			}
		}
		c.RPOrigins = origins
		return nil
	}
}

// WithUserVerification sets the default user verification requirement.
func WithUserVerification(uv UserVerificationRequirement) Option {
	return func(c *Config) error {
		switch uv {
		case VerificationRequired, VerificationPreferred, VerificationDiscouraged:
			c.UserVerification = uv
			return nil
		default:
			return fmt.Errorf("invalid user verification requirement: %s", uv)
		}
	}
}

// WithAttestationPreference sets the default attestation preference.
func WithAttestationPreference(pref AttestationPreference) Option {
	return func(c *Config) error {
		switch pref {
		case AttestationNone, AttestationIndirect, AttestationDirect, AttestationEnterprise:
			c.AttestationPreference = pref
			return nil
		default:
			return fmt.Errorf("invalid attestation preference: %s", pref)
		}
	}
}

// WithTimeout sets the default timeout for WebAuthn ceremonies in milliseconds.
func WithTimeout(timeoutMS int) Option {
	return func(c *Config) error {
		if timeoutMS <= 0 {
			return fmt.Errorf("timeout must be positive")
		}
		if timeoutMS > 600000 { // 10 minutes
			return fmt.Errorf("timeout cannot exceed 10 minutes (600000ms)")
		}
		c.Timeout = timeoutMS
		return nil
	}
}

// WithAuthenticatorSelection sets the default authenticator selection criteria.
func WithAuthenticatorSelection(selection AuthenticatorSelection) Option {
	return func(c *Config) error {
		c.AuthenticatorSelection = selection
		return nil
	}
}

// WithCredentialStore sets the credential storage backend.
func WithCredentialStore(store CredentialStore) Option {
	return func(c *Config) error {
		if store == nil {
			return fmt.Errorf("credential store cannot be nil")
		}
		c.CredentialStore = store
		return nil
	}
}

// WithAuditLogger sets the audit logger.
func WithAuditLogger(logger events.EventLogger) Option {
	return func(c *Config) error {
		if logger == nil {
			return fmt.Errorf("audit logger cannot be nil")
		}
		c.AuditLogger = logger
		return nil
	}
}

// NewConfig creates a new WebAuthn configuration with the given options.
// Required options: RPDisplayName, RPID, RPOrigins, CredentialStore
// Optional options have sensible defaults.
func NewConfig(opts ...Option) (*Config, error) {
	// Default configuration
	config := &Config{
		UserVerification:      VerificationPreferred,
		AttestationPreference: AttestationNone,
		Timeout:               60000, // 60 seconds
		AuthenticatorSelection: AuthenticatorSelection{
			AuthenticatorAttachment: "",
			RequireResidentKey:      false,
			UserVerification:        VerificationPreferred,
		},
		AuditLogger: memory.NewNopLogger(),
	}

	// Apply options
	for _, opt := range opts {
		if err := opt(config); err != nil {
			return nil, fmt.Errorf("configuration error: %w", err)
		}
	}

	// Validate required fields
	if config.RPDisplayName == "" {
		return nil, fmt.Errorf("relying party display name is required (use WithRPDisplayName)")
	}
	if config.RPID == "" {
		// Try environment variable as fallback
		if envID := os.Getenv("WEBAUTHN_RP_ID"); envID != "" {
			config.RPID = envID
		} else {
			return nil, fmt.Errorf("relying party ID is required (use WithRPID or set WEBAUTHN_RP_ID)")
		}
	}
	if len(config.RPOrigins) == 0 {
		// Try environment variable as fallback
		if envOrigins := os.Getenv("WEBAUTHN_RP_ORIGINS"); envOrigins != "" {
			config.RPOrigins = []string{envOrigins}
		} else {
			return nil, fmt.Errorf("at least one origin is required (use WithRPOrigins or set WEBAUTHN_RP_ORIGINS)")
		}
	}
	if config.CredentialStore == nil {
		return nil, fmt.Errorf("credential store is required (use WithCredentialStore)")
	}

	// Sync authenticator selection with config user verification if not explicitly set
	if config.AuthenticatorSelection.UserVerification == "" {
		config.AuthenticatorSelection.UserVerification = config.UserVerification
	}

	return config, nil
}
