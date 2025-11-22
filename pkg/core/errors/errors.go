// Package errors provides error types and utilities for the NoPasswords library.
//
// This package defines common error values and the AuthError type, which wraps
// errors with additional security context suitable for logging and debugging while
// maintaining appropriate information boundaries for user-facing messages.
//
// Key features:
//   - Predefined sentinel errors for common scenarios (ErrNotFound, ErrExpired, etc.)
//   - AuthError type with rich context (user ID, credential ID, error codes)
//   - Support for internal vs. external error messages
//   - Compatible with Go 1.13+ error wrapping (errors.Is, errors.As)
//
// Security Considerations:
//   - Error messages are designed to avoid leaking sensitive information
//   - Internal errors can be marked to prevent exposure to end users
//   - Use UserMessage() method for user-facing error text
//
// Example:
//
//	err := errors.NewAuthError(
//	    errors.CodeAuthFailed,
//	    "Authentication failed",
//	    errors.ErrInvalidSignature,
//	).WithUserID("user123").WithMethod("webauthn")
//
//	// For logging (includes all context)
//	log.Error(err.Error())
//
//	// For user display (safe message only)
//	http.Error(w, err.UserMessage(), http.StatusUnauthorized)
package errors

import (
	"errors"
	"fmt"
)

// Common errors returned by the NoPasswords library.
//
// These errors are designed to provide meaningful context without leaking
// sensitive information. Error messages should be safe to display to users
// or include in logs.
var (
	// ErrNotFound indicates that a requested credential, token, or resource was not found.
	ErrNotFound = errors.New("not found")

	// ErrAlreadyExists indicates that a resource with the same identifier already exists.
	ErrAlreadyExists = errors.New("already exists")

	// ErrInvalidCredential indicates that a credential is malformed or invalid.
	// This does NOT mean authentication failed; it means the credential data itself is invalid.
	ErrInvalidCredential = errors.New("invalid credential")

	// ErrInvalidToken indicates that a token is malformed or invalid.
	ErrInvalidToken = errors.New("invalid token")

	// ErrExpired indicates that a token or session has expired.
	ErrExpired = errors.New("expired")

	// ErrRevoked indicates that a token has been explicitly revoked.
	ErrRevoked = errors.New("revoked")

	// ErrInvalidSignature indicates that a cryptographic signature verification failed.
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrAuthenticationFailed indicates that authentication failed due to incorrect
	// credentials, wrong password, or signature mismatch.
	ErrAuthenticationFailed = errors.New("authentication failed")

	// ErrInvalidConfiguration indicates that the library configuration is invalid.
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrNotImplemented indicates that a feature is not yet implemented.
	ErrNotImplemented = errors.New("not implemented")

	// ErrOperationNotPermitted indicates that an operation was rejected due to policy.
	ErrOperationNotPermitted = errors.New("operation not permitted")
)

// AuthError wraps an error with additional security context.
// This provides rich error information for logging and debugging while
// maintaining appropriate boundaries for user-facing messages.
type AuthError struct {
	// Code is a machine-readable error code (e.g., "invalid_signature", "expired_token").
	Code string

	// Message is a human-readable error message. This should be safe to display
	// to end users and should not contain sensitive information.
	Message string

	// Err is the underlying error that caused this AuthError.
	Err error

	// Method indicates which authentication method generated this error.
	Method string

	// UserID is the user associated with the error, if known.
	// May be empty for errors that occur before user identification.
	UserID string

	// CredentialID is the credential associated with the error, if applicable.
	CredentialID string

	// Internal indicates whether this error should be logged but not exposed
	// to the end user. Internal errors may contain debugging information.
	Internal bool
}

// Error implements the error interface.
func (e *AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap implements error unwrapping for errors.Is and errors.As.
func (e *AuthError) Unwrap() error {
	return e.Err
}

// Is implements error comparison for errors.Is.
func (e *AuthError) Is(target error) bool {
	return errors.Is(e.Err, target)
}

// NewAuthError creates a new AuthError with the specified parameters.
func NewAuthError(code, message string, err error) *AuthError {
	return &AuthError{
		Code:    code,
		Message: message,
		Err:     err,
	}
}

// WithMethod adds method context to an AuthError.
func (e *AuthError) WithMethod(method string) *AuthError {
	e.Method = method
	return e
}

// WithUserID adds user context to an AuthError.
func (e *AuthError) WithUserID(userID string) *AuthError {
	e.UserID = userID
	return e
}

// WithCredentialID adds credential context to an AuthError.
func (e *AuthError) WithCredentialID(credentialID string) *AuthError {
	e.CredentialID = credentialID
	return e
}

// WithInternal marks an error as internal (not to be exposed to users).
func (e *AuthError) WithInternal() *AuthError {
	e.Internal = true
	return e
}

// UserMessage returns a safe message suitable for display to end users.
// For internal errors, this returns a generic message.
func (e *AuthError) UserMessage() string {
	if e.Internal {
		return "An internal error occurred"
	}
	return e.Message
}

// Error code constants for common scenarios.
const (
	CodeInvalidSignature     = "invalid_signature"
	CodeExpiredToken         = "expired_token"
	CodeRevokedToken         = "revoked_token"
	CodeInvalidToken         = "invalid_token"
	CodeInvalidCredential    = "invalid_credential"
	CodeAuthFailed           = "authentication_failed"
	CodeNotFound             = "not_found"
	CodeAlreadyExists        = "already_exists"
	CodeInvalidConfiguration = "invalid_configuration"
	CodeInternalError        = "internal_error"
)
