package webauthn

import (
	"context"
	"fmt"
	"os"

	"go.fergus.london/nopasswords/core"
)

// nopLogger is a no-op implementation of core.AuditLogger
type nopLogger struct{}

func (n *nopLogger) Log(ctx context.Context, event core.AuditEvent) error {
	return nil
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
	CredentialStore core.CredentialStore
	// AuditLogger is the logger for security events
	AuditLogger core.AuditLogger
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
func WithCredentialStore(store core.CredentialStore) Option {
	return func(c *Config) error {
		if store == nil {
			return fmt.Errorf("credential store cannot be nil")
		}
		c.CredentialStore = store
		return nil
	}
}

// WithAuditLogger sets the audit logger.
func WithAuditLogger(logger core.AuditLogger) Option {
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
		AuditLogger: &nopLogger{},
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
