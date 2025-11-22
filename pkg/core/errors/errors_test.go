package errors

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCommonErrors(t *testing.T) {
	// Verify error constants are defined
	assert.ErrorIs(t, ErrNotFound, ErrNotFound)
	assert.ErrorIs(t, ErrAlreadyExists, ErrAlreadyExists)
	assert.ErrorIs(t, ErrInvalidCredential, ErrInvalidCredential)
	assert.ErrorIs(t, ErrInvalidToken, ErrInvalidToken)
	assert.ErrorIs(t, ErrExpired, ErrExpired)
	assert.ErrorIs(t, ErrRevoked, ErrRevoked)
	assert.ErrorIs(t, ErrInvalidSignature, ErrInvalidSignature)
	assert.ErrorIs(t, ErrAuthenticationFailed, ErrAuthenticationFailed)
	assert.ErrorIs(t, ErrInvalidConfiguration, ErrInvalidConfiguration)
	assert.ErrorIs(t, ErrNotImplemented, ErrNotImplemented)
	assert.ErrorIs(t, ErrOperationNotPermitted, ErrOperationNotPermitted)
}

func TestNewAuthError(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	authErr := NewAuthError(CodeInvalidSignature, "Signature verification failed", underlyingErr)

	assert.Equal(t, CodeInvalidSignature, authErr.Code)
	assert.Equal(t, "Signature verification failed", authErr.Message)
	assert.Equal(t, underlyingErr, authErr.Err)
	assert.False(t, authErr.Internal)
}

func TestAuthError_Error(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	authErr := NewAuthError(CodeInvalidToken, "Token is invalid", underlyingErr)

	expected := "Token is invalid: underlying error"
	assert.Equal(t, expected, authErr.Error())
}

func TestAuthError_Error_NoUnderlying(t *testing.T) {
	authErr := NewAuthError(CodeAuthFailed, "Authentication failed", nil)

	assert.Equal(t, "Authentication failed", authErr.Error())
}

func TestAuthError_Unwrap(t *testing.T) {
	underlyingErr := errors.New("underlying error")
	authErr := NewAuthError(CodeInternalError, "Internal error", underlyingErr)

	unwrapped := authErr.Unwrap()
	assert.Equal(t, underlyingErr, unwrapped)
}

func TestAuthError_Is(t *testing.T) {
	authErr := NewAuthError(CodeExpiredToken, "Token expired", ErrExpired)

	// Should match the underlying error
	assert.True(t, errors.Is(authErr, ErrExpired))
	assert.False(t, errors.Is(authErr, ErrNotFound))
}

func TestAuthError_WithMethod(t *testing.T) {
	authErr := NewAuthError(CodeAuthFailed, "Auth failed", nil)
	authErr = authErr.WithMethod("webauthn")

	assert.Equal(t, "webauthn", authErr.Method)
}

func TestAuthError_WithUserID(t *testing.T) {
	authErr := NewAuthError(CodeAuthFailed, "Auth failed", nil)
	authErr = authErr.WithUserID("user123")

	assert.Equal(t, "user123", authErr.UserID)
}

func TestAuthError_WithCredentialID(t *testing.T) {
	authErr := NewAuthError(CodeAuthFailed, "Auth failed", nil)
	authErr = authErr.WithCredentialID("cred456")

	assert.Equal(t, "cred456", authErr.CredentialID)
}

func TestAuthError_WithInternal(t *testing.T) {
	authErr := NewAuthError(CodeInternalError, "Database connection failed", nil)
	authErr = authErr.WithInternal()

	assert.True(t, authErr.Internal)
}

func TestAuthError_WithMethod_Chaining(t *testing.T) {
	authErr := NewAuthError(CodeAuthFailed, "Auth failed", ErrAuthenticationFailed).
		WithMethod("srp").
		WithUserID("user123").
		WithCredentialID("cred456")

	assert.Equal(t, "srp", authErr.Method)
	assert.Equal(t, "user123", authErr.UserID)
	assert.Equal(t, "cred456", authErr.CredentialID)
}

func TestAuthError_UserMessage(t *testing.T) {
	tests := []struct {
		name     string
		authErr  *AuthError
		expected string
	}{
		{
			name: "public error",
			authErr: &AuthError{
				Code:     CodeAuthFailed,
				Message:  "Authentication failed",
				Internal: false,
			},
			expected: "Authentication failed",
		},
		{
			name: "internal error",
			authErr: &AuthError{
				Code:     CodeInternalError,
				Message:  "Database connection failed: timeout after 30s",
				Internal: true,
			},
			expected: "An internal error occurred",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.authErr.UserMessage())
		})
	}
}

func TestAuthError_UserMessage_NoSensitiveData(t *testing.T) {
	// Verify that internal errors don't leak sensitive information
	authErr := &AuthError{
		Code:     CodeInternalError,
		Message:  "SQL query failed: SELECT * FROM users WHERE api_key='secret123'",
		Internal: true,
	}

	userMsg := authErr.UserMessage()
	assert.NotContains(t, userMsg, "secret123")
	assert.NotContains(t, userMsg, "SQL")
	assert.Equal(t, "An internal error occurred", userMsg)
}

func TestErrorCodeConstants(t *testing.T) {
	// Verify error code constants are defined
	assert.Equal(t, "invalid_signature", CodeInvalidSignature)
	assert.Equal(t, "expired_token", CodeExpiredToken)
	assert.Equal(t, "revoked_token", CodeRevokedToken)
	assert.Equal(t, "invalid_token", CodeInvalidToken)
	assert.Equal(t, "invalid_credential", CodeInvalidCredential)
	assert.Equal(t, "authentication_failed", CodeAuthFailed)
	assert.Equal(t, "not_found", CodeNotFound)
	assert.Equal(t, "already_exists", CodeAlreadyExists)
	assert.Equal(t, "invalid_configuration", CodeInvalidConfiguration)
	assert.Equal(t, "internal_error", CodeInternalError)
}

func TestAuthError_ComplexChaining(t *testing.T) {
	// Simulate a real-world error scenario
	dbErr := errors.New("connection timeout")
	authErr := NewAuthError(CodeInternalError, "Failed to retrieve credential", dbErr).
		WithMethod("webauthn").
		WithUserID("user@example.com").
		WithCredentialID("security-key-1").
		WithInternal()

	// Verify all fields are set
	assert.Equal(t, CodeInternalError, authErr.Code)
	assert.Equal(t, "Failed to retrieve credential", authErr.Message)
	assert.Equal(t, "webauthn", authErr.Method)
	assert.Equal(t, "user@example.com", authErr.UserID)
	assert.Equal(t, "security-key-1", authErr.CredentialID)
	assert.True(t, authErr.Internal)
	assert.True(t, errors.Is(authErr, dbErr))

	// Verify user message is safe
	assert.Equal(t, "An internal error occurred", authErr.UserMessage())

	// Verify full error message contains details
	fullError := authErr.Error()
	assert.Contains(t, fullError, "Failed to retrieve credential")
	assert.Contains(t, fullError, "connection timeout")
}

func TestAuthError_ErrorsAs(t *testing.T) {
	// Test that errors.As works with AuthError
	underlyingErr := errors.New("underlying error")
	authErr := NewAuthError(CodeAuthFailed, "Auth failed", underlyingErr)

	var ae *AuthError
	require.True(t, errors.As(authErr, &ae))
	assert.Equal(t, CodeAuthFailed, ae.Code)
}
