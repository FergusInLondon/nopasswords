package core

import (
	"time"
)

// AuthResult represents the outcome of an authentication attempt.
// It provides a standardized structure for all authentication methods.
type AuthResult struct {
	// Success indicates whether authentication succeeded.
	Success bool

	// UserID is the identifier of the authenticated user.
	// Only populated when Success is true.
	UserID string

	// CredentialID identifies which credential was used for authentication.
	// This is relevant for methods that support multiple credentials per user (e.g., WebAuthn).
	CredentialID string

	// Method indicates which authentication method was used (e.g., "webauthn", "srp", "signed_token").
	Method string

	// Timestamp records when the authentication occurred.
	Timestamp time.Time

	// Metadata contains method-specific additional information.
	// For example, WebAuthn might include authenticator data, SRP might include session key info.
	// This should NOT contain sensitive information like private keys or passwords.
	Metadata map[string]interface{}

	// Error contains the error if authentication failed.
	// This is typically an *AuthError with security context.
	Error error
}

// AuditEvent represents a security-relevant event for logging purposes.
//
// Security Note: This struct is designed to exclude sensitive information.
// Do not add fields that might contain passwords, private keys, or full credential data.
//
// @mitigation Information Disclosure: Explicitly excludes sensitive fields to prevent
// accidental logging of credentials or keys.
type AuditEvent struct {
	// EventID is a unique identifier for this event (e.g., UUID).
	EventID string

	// Timestamp records when the event occurred.
	Timestamp time.Time

	// EventType categorizes the event (e.g., "auth.attempt", "auth.success", "auth.failure",
	// "credential.register", "token.generate", "token.revoke").
	EventType string

	// Method indicates the authentication method involved (e.g., "webauthn", "srp", "signed_token").
	Method string

	// UserID identifies the user associated with this event.
	// May be empty for anonymous operations or registration attempts.
	UserID string

	// CredentialID identifies the credential involved, if applicable.
	CredentialID string

	// Outcome indicates the result of the operation (e.g., "success", "failure", "error").
	Outcome string

	// Reason provides additional context for the outcome (e.g., "expired_token", "invalid_signature").
	// This should be a machine-readable code, not a user-facing message.
	Reason string

	// IPAddress records the source IP address of the request, if available.
	IPAddress string

	// UserAgent records the user agent string, if available.
	UserAgent string

	// Metadata contains additional event-specific context.
	// MUST NOT contain sensitive information.
	Metadata map[string]interface{}
}

// EventType constants for common audit events.
const (
	EventAuthAttempt        = "auth.attempt"
	EventAuthSuccess        = "auth.success"
	EventAuthFailure        = "auth.failure"
	EventCredentialRegister = "credential.register"
	EventCredentialDelete   = "credential.delete"
	EventCredentialUpdate   = "credential.update"
	EventTokenGenerate      = "token.generate"
	EventTokenVerify        = "token.verify"
	EventTokenRevoke        = "token.revoke"
)

// Outcome constants for audit events.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeError   = "error"
)

// Config provides base configuration structure that can be embedded by
// authentication method-specific configs.
type Config struct {
	// CredentialStore is the storage backend for credentials.
	// If nil, a default in-memory store will be used.
	CredentialStore CredentialStore

	// AuditLogger receives security audit events.
	// If nil, a no-op logger will be used.
	AuditLogger AuditLogger

	// ApplicationName identifies the application using this library.
	// Used in audit logs and WebAuthn relying party configuration.
	ApplicationName string
}

// Option is a functional option for configuring authentication methods.
type Option func(*Config)

// WithCredentialStore sets the credential storage implementation.
func WithCredentialStore(store CredentialStore) Option {
	return func(c *Config) {
		c.CredentialStore = store
	}
}

// WithAuditLogger sets the audit logging implementation.
func WithAuditLogger(logger AuditLogger) Option {
	return func(c *Config) {
		c.AuditLogger = logger
	}
}

// WithApplicationName sets the application name for audit logs and RP configuration.
func WithApplicationName(name string) Option {
	return func(c *Config) {
		c.ApplicationName = name
	}
}

// ApplyOptions applies functional options to a config.
func ApplyOptions(config *Config, opts ...Option) {
	for _, opt := range opts {
		opt(config)
	}
}
