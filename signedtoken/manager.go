package signedtoken

import (
	"context"
	"fmt"
	"time"

	"go.fergus.london/nopasswords/core"
)

// Manager handles the generation and verification of signed authentication tokens.
//
// The Manager is the main entry point for using signed token authentication.
// It coordinates token creation, signing, verification, and optional revocation.
//
// Manager instances are safe for concurrent use by multiple goroutines.
type Manager struct {
	config *Config
}

// NewManager creates a new token manager with the given options.
//
// The Signer option is required; all other options have sensible defaults.
//
// Example:
//   key := make([]byte, 32)
//   rand.Read(key)
//   signer, _ := NewHMACSignerSHA256(key)
//   manager, err := NewManager(
//       WithSigner(signer),
//       WithDefaultLifetime(30 * time.Minute),
//       WithAuditLogger(logger),
//   )
//
// Returns an error if the configuration is invalid (e.g., no signer provided).
func NewManager(opts ...Option) (*Manager, error) {
	config, err := NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &Manager{
		config: config,
	}, nil
}

// GenerateToken creates a new signed token for the given user.
//
// Parameters:
//   - ctx: Context for cancellation and deadlines
//   - userID: User identifier (or opaque ID if UseOpaqueIDs is enabled)
//   - metadata: Optional application-specific data (max 1KB serialized)
//
// The token lifetime can be specified via GenerateTokenWithLifetime, or the
// default lifetime from the config will be used.
//
// Returns the URL-safe encoded token string or an error if generation fails.
//
// Security Considerations:
//
// @risk Information Disclosure: User IDs are included in tokens. Use opaque
// identifiers (WithOpaqueIDs option) if this is a concern.
//
// @mitigation Repudiation: Generates audit events for token creation.
func (m *Manager) GenerateToken(ctx context.Context, userID string, metadata map[string]interface{}) (string, error) {
	return m.GenerateTokenWithLifetime(ctx, userID, metadata, m.config.DefaultLifetime)
}

// GenerateTokenWithLifetime creates a new signed token with a specific lifetime.
//
// This allows overriding the default lifetime on a per-token basis.
// The lifetime must not exceed MaxTokenLifetime (24 hours).
//
// Returns the URL-safe encoded token string or an error if generation fails.
func (m *Manager) GenerateTokenWithLifetime(ctx context.Context, userID string, metadata map[string]interface{}, lifetime time.Duration) (string, error) {
	// Create the token
	token, err := NewToken(userID, lifetime, metadata)
	if err != nil {
		m.logAuditEvent(ctx, core.EventTokenGenerate, userID, "", core.OutcomeError, err.Error(), nil)
		return "", fmt.Errorf("failed to create token: %w", err)
	}

	// Encode the token payload
	tokenData, err := token.Encode()
	if err != nil {
		m.logAuditEvent(ctx, core.EventTokenGenerate, userID, "", core.OutcomeError, "encoding_failed", nil)
		return "", fmt.Errorf("failed to encode token: %w", err)
	}

	// Sign the token
	signature, err := m.config.Signer.Sign(tokenData)
	if err != nil {
		m.logAuditEvent(ctx, core.EventTokenGenerate, userID, "", core.OutcomeError, "signing_failed", nil)
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Create signed token
	signedToken := &SignedToken{
		Token:     *token,
		Signature: signature,
	}

	// Encode to URL-safe string
	tokenString, err := signedToken.EncodeToString()
	if err != nil {
		m.logAuditEvent(ctx, core.EventTokenGenerate, userID, "", core.OutcomeError, "encoding_failed", nil)
		return "", fmt.Errorf("failed to encode signed token: %w", err)
	}

	// Store token for revocation support if TokenStore is configured
	if m.config.TokenStore != nil {
		tokenID := signedToken.ID()
		if err := m.config.TokenStore.StoreToken(ctx, tokenID, userID, token.ExpiresAt); err != nil {
			// Log but don't fail - revocation support is optional
			m.logAuditEvent(ctx, core.EventTokenGenerate, userID, tokenID, core.OutcomeError, "store_failed", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Log successful generation
	// @mitigation Repudiation: Log token generation for audit trail
	m.logAuditEvent(ctx, core.EventTokenGenerate, userID, signedToken.ID(), core.OutcomeSuccess, "", map[string]interface{}{
		"expires_at": token.ExpiresAt.Unix(),
		"lifetime":   lifetime.String(),
	})

	return tokenString, nil
}

// VerifyToken verifies a signed token and returns the token payload.
//
// This method:
// 1. Decodes the token from the URL-safe string
// 2. Verifies the cryptographic signature
// 3. Checks if the token has expired
// 4. Checks if the token has been revoked (if TokenStore is configured)
//
// Returns the verified token or an error if verification fails.
//
// Security Considerations:
//
// @mitigation Tampering: Verifies cryptographic signature before accepting token.
// @mitigation Information Disclosure: Uses constant-time comparison in signature verification.
// @mitigation Repudiation: Generates audit events for all verification attempts.
func (m *Manager) VerifyToken(ctx context.Context, tokenString string) (*Token, error) {
	// Decode the signed token
	signedToken, err := DecodeFromString(tokenString)
	if err != nil {
		m.logAuditEvent(ctx, core.EventTokenVerify, "", "", core.OutcomeFailure, "invalid_format", nil)
		return nil, core.NewAuthError(core.CodeInvalidToken, "Invalid token format", err).WithMethod("signed_token")
	}

	tokenID := signedToken.ID()
	userID := signedToken.Token.UserID

	// Encode the token payload for signature verification
	tokenData, err := signedToken.Token.Encode()
	if err != nil {
		m.logAuditEvent(ctx, core.EventTokenVerify, userID, tokenID, core.OutcomeFailure, "encoding_failed", nil)
		return nil, core.NewAuthError(core.CodeInvalidToken, "Failed to encode token for verification", err).WithMethod("signed_token").WithUserID(userID)
	}

	// Verify the signature
	// @mitigation Tampering: Cryptographic signature verification prevents token modification
	if err := m.config.Signer.Verify(tokenData, signedToken.Signature); err != nil {
		m.logAuditEvent(ctx, core.EventTokenVerify, userID, tokenID, core.OutcomeFailure, core.CodeInvalidSignature, nil)
		return nil, core.NewAuthError(core.CodeInvalidSignature, "Token signature verification failed", err).WithMethod("signed_token").WithUserID(userID)
	}

	// Check if token has expired
	if signedToken.Token.IsExpired() {
		m.logAuditEvent(ctx, core.EventTokenVerify, userID, tokenID, core.OutcomeFailure, core.CodeExpiredToken, map[string]interface{}{
			"expired_at": signedToken.Token.ExpiresAt.Unix(),
		})
		return nil, core.NewAuthError(core.CodeExpiredToken, "Token has expired", core.ErrExpired).WithMethod("signed_token").WithUserID(userID)
	}

	// Check if token has been revoked (if TokenStore is configured)
	if m.config.TokenStore != nil {
		revoked, err := m.config.TokenStore.IsTokenRevoked(ctx, tokenID)
		if err != nil {
			// Log error but don't fail - this is a storage issue, not a token issue
			m.logAuditEvent(ctx, core.EventTokenVerify, userID, tokenID, core.OutcomeError, "revocation_check_failed", map[string]interface{}{
				"error": err.Error(),
			})
			// Continue with verification despite storage error
		} else if revoked {
			m.logAuditEvent(ctx, core.EventTokenVerify, userID, tokenID, core.OutcomeFailure, core.CodeRevokedToken, nil)
			return nil, core.NewAuthError(core.CodeRevokedToken, "Token has been revoked", core.ErrRevoked).WithMethod("signed_token").WithUserID(userID)
		}
	}

	// Token is valid
	// @mitigation Repudiation: Log successful verification
	m.logAuditEvent(ctx, core.EventTokenVerify, userID, tokenID, core.OutcomeSuccess, "", map[string]interface{}{
		"issued_at":  signedToken.Token.IssuedAt.Unix(),
		"expires_at": signedToken.Token.ExpiresAt.Unix(),
	})

	return &signedToken.Token, nil
}

// RevokeToken marks a token as revoked, preventing its further use.
//
// This requires a TokenStore to be configured. If no TokenStore is configured,
// this method returns an error.
//
// The tokenString parameter should be the complete URL-safe token string.
//
// Returns an error if revocation fails or if TokenStore is not configured.
//
// Security Considerations:
//
// @mitigation Repudiation: Logs token revocation events for audit trail.
func (m *Manager) RevokeToken(ctx context.Context, tokenString string) error {
	if m.config.TokenStore == nil {
		return fmt.Errorf("token revocation not supported: no TokenStore configured")
	}

	// Decode the token to get its ID and user
	signedToken, err := DecodeFromString(tokenString)
	if err != nil {
		return fmt.Errorf("failed to decode token for revocation: %w", err)
	}

	tokenID := signedToken.ID()
	userID := signedToken.Token.UserID

	// Revoke the token
	if err := m.config.TokenStore.RevokeToken(ctx, tokenID); err != nil {
		m.logAuditEvent(ctx, core.EventTokenRevoke, userID, tokenID, core.OutcomeError, "revocation_failed", map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	// Log successful revocation
	// @mitigation Repudiation: Log token revocation for audit trail
	m.logAuditEvent(ctx, core.EventTokenRevoke, userID, tokenID, core.OutcomeSuccess, "", nil)

	return nil
}

// logAuditEvent is a helper to log audit events.
func (m *Manager) logAuditEvent(ctx context.Context, eventType, userID, tokenID, outcome, reason string, metadata map[string]interface{}) {
	if m.config.AuditLogger == nil {
		return
	}

	event := core.AuditEvent{
		EventID:      fmt.Sprintf("%d", time.Now().UnixNano()), // Simple event ID based on timestamp
		Timestamp:    time.Now().UTC(),
		EventType:    eventType,
		Method:       "signed_token",
		UserID:       userID,
		CredentialID: tokenID, // Use token ID as credential ID
		Outcome:      outcome,
		Reason:       reason,
		Metadata:     metadata,
	}

	// Ignore logging errors - we don't want to fail operations due to logging issues
	_ = m.config.AuditLogger.Log(ctx, event)
}
