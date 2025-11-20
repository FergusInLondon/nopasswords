// Package core provides the foundational interfaces and types for the NoPasswords
// authentication library. It defines common abstractions for storage, logging, and
// configuration that remain unopinionated about underlying implementations.
package core

import (
	"context"
	"time"
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

// TokenStore provides optional storage for authentication tokens, primarily to support
// token revocation. Not all authentication methods require token storage.
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Security Considerations:
//
// @risk Denial of Service: Token storage can grow unbounded without proper cleanup.
// Implementations should implement TTL-based cleanup or size limits.
//
// @risk Information Disclosure: Tokens may contain sensitive information. Ensure
// storage is appropriately secured (encryption at rest, access controls, etc.).
type TokenStore interface {
	// StoreToken saves a token with an associated expiration time. The tokenID should
	// be unique and derived from the token itself (e.g., hash of the token).
	//
	// Returns ErrAlreadyExists if a token with the same ID already exists.
	StoreToken(ctx context.Context, tokenID string, userID string, expiresAt time.Time) error

	// IsTokenRevoked checks if a token has been explicitly revoked.
	//
	// Returns false if the token is not found (not revoked), true if explicitly revoked.
	// This method should not return errors for non-existent tokens.
	IsTokenRevoked(ctx context.Context, tokenID string) (bool, error)

	// RevokeToken marks a token as revoked, preventing its further use.
	//
	// This operation should be idempotent; revoking an already-revoked token is not an error.
	RevokeToken(ctx context.Context, tokenID string) error

	// CleanupExpired removes expired tokens from storage. Implementations should call
	// this periodically to prevent unbounded growth.
	//
	// Returns the number of tokens cleaned up and any error encountered.
	CleanupExpired(ctx context.Context) (int, error)
}

// AuditLogger defines the interface for structured security event logging.
// All authentication operations generate audit events that are passed to this interface.
//
// Implementations must be safe for concurrent use by multiple goroutines.
//
// Security Considerations:
//
// @risk Information Disclosure: Implementations MUST NOT log sensitive data such as
// passwords, private keys, tokens, or full credentials. The AuditEvent struct is
// designed to exclude such data; custom implementations should maintain this contract.
//
// @risk Repudiation: Comprehensive audit logging is essential for security investigations
// and compliance. Ensure events are logged reliably and cannot be easily tampered with.
//
// @risk Denial of Service: Unbounded logging can fill disk space. Implementations
// should include log rotation, rate limiting, or external log aggregation.
type AuditLogger interface {
	// Log records a security audit event. This method should not block for extended
	// periods; consider using buffering or async logging for I/O operations.
	//
	// Implementations should not return errors for logging failures unless absolutely
	// necessary. Consider logging errors to stderr or a fallback mechanism rather than
	// disrupting authentication flows.
	Log(ctx context.Context, event AuditEvent) error
}
