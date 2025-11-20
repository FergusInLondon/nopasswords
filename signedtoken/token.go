// Package signedtoken implements cryptographically signed tokens for magic link
// style authentication. Tokens are time-limited, URL-safe, and contain all
// required state for stateless authentication.
package signedtoken

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	// MaxMetadataSize is the maximum allowed size for token metadata in bytes.
	// This prevents abuse through excessively large tokens.
	//
	// @mitigation Denial of Service: Limit metadata size to prevent token size abuse.
	MaxMetadataSize = 1024 // 1KB

	// MaxTokenLifetime is the maximum allowed token validity period.
	// Tokens cannot be created with expiration times beyond this limit.
	//
	// @mitigation Information Disclosure: Limit token lifetime to reduce exposure window.
	MaxTokenLifetime = 24 * time.Hour

	// MaxURLLength is the recommended maximum URL length for compatibility.
	// While not strictly enforced, tokens exceeding this may cause issues in some contexts.
	MaxURLLength = 2048
)

var (
	// ErrMetadataTooLarge indicates that the token metadata exceeds MaxMetadataSize.
	ErrMetadataTooLarge = errors.New("metadata exceeds maximum size")

	// ErrTokenTooLong indicates that the resulting token may exceed URL length limits.
	ErrTokenTooLong = errors.New("token exceeds recommended URL length")

	// ErrInvalidTokenFormat indicates that a token string cannot be parsed.
	ErrInvalidTokenFormat = errors.New("invalid token format")

	// ErrLifetimeTooLong indicates that the requested token lifetime exceeds MaxTokenLifetime.
	ErrLifetimeTooLong = errors.New("token lifetime exceeds maximum allowed")
)

// Token represents a signed authentication token with all embedded state.
//
// Tokens are self-contained and include:
// - User identifier (or opaque identifier for privacy)
// - Issued-at timestamp
// - Expiration timestamp
// - Optional metadata (JSON-serializable)
// - Cryptographic signature
//
// Security Considerations:
//
// @risk Information Disclosure: User identifiers in tokens may be exposed in URLs.
// Consider using the opaque identifier option for sensitive scenarios.
//
// @risk Spoofing: Tokens are only secure with strong signing keys (minimum 256 bits).
// See SigningKey validation in config.go.
type Token struct {
	// UserID is the identifier of the user this token authenticates.
	// May be an opaque identifier if privacy is a concern.
	UserID string `json:"uid"`

	// IssuedAt is the timestamp when this token was created.
	IssuedAt time.Time `json:"iat"`

	// ExpiresAt is the timestamp when this token becomes invalid.
	ExpiresAt time.Time `json:"exp"`

	// Metadata contains optional application-specific data.
	// Must be JSON-serializable and is limited to MaxMetadataSize bytes.
	// MUST NOT contain sensitive information like passwords or keys.
	Metadata map[string]interface{} `json:"meta,omitempty"`
}

// SignedToken represents a token with its cryptographic signature.
type SignedToken struct {
	// Token is the token payload.
	Token Token `json:"token"`

	// Signature is the cryptographic signature over the token payload.
	Signature []byte `json:"sig"`
}

// NewToken creates a new token with the specified parameters.
//
// Parameters:
//   - userID: The user identifier (or opaque ID)
//   - lifetime: How long the token should be valid (max 24 hours)
//   - metadata: Optional application-specific data (max 1KB when serialized)
//
// Returns an error if:
//   - lifetime exceeds MaxTokenLifetime
//   - metadata exceeds MaxMetadataSize when serialized
func NewToken(userID string, lifetime time.Duration, metadata map[string]interface{}) (*Token, error) {
	// @mitigation Denial of Service: Enforce maximum token lifetime
	if lifetime > MaxTokenLifetime {
		return nil, fmt.Errorf("%w: requested %v, maximum %v", ErrLifetimeTooLong, lifetime, MaxTokenLifetime)
	}

	now := time.Now().UTC()
	token := &Token{
		UserID:    userID,
		IssuedAt:  now,
		ExpiresAt: now.Add(lifetime),
		Metadata:  metadata,
	}

	// Validate metadata size
	if err := token.ValidateMetadataSize(); err != nil {
		return nil, err
	}

	return token, nil
}

// ValidateMetadataSize checks if the token's metadata is within allowed limits.
func (t *Token) ValidateMetadataSize() error {
	if t.Metadata == nil {
		return nil
	}

	// Serialize metadata to check size
	metadataJSON, err := json.Marshal(t.Metadata)
	if err != nil {
		return fmt.Errorf("failed to serialize metadata: %w", err)
	}

	if len(metadataJSON) > MaxMetadataSize {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrMetadataTooLarge, len(metadataJSON), MaxMetadataSize)
	}

	return nil
}

// IsExpired checks if the token has passed its expiration time.
func (t *Token) IsExpired() bool {
	return time.Now().UTC().After(t.ExpiresAt)
}

// Encode serializes the token to JSON bytes for signing.
func (t *Token) Encode() ([]byte, error) {
	return json.Marshal(t)
}

// DecodeToken deserializes a token from JSON bytes.
func DecodeToken(data []byte) (*Token, error) {
	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTokenFormat, err)
	}
	return &token, nil
}

// EncodeToString serializes a signed token to a URL-safe base64 string.
//
// Format: base64url(json(SignedToken))
//
// The result is safe for use in URLs, emails, and other text contexts.
//
// @mitigation Tampering: The signature is included in the serialized form,
// preventing modification without detection.
func (st *SignedToken) EncodeToString() (string, error) {
	// Serialize the signed token
	data, err := json.Marshal(st)
	if err != nil {
		return "", fmt.Errorf("failed to serialize signed token: %w", err)
	}

	// Encode to base64 URL-safe format (no padding)
	encoded := base64.RawURLEncoding.EncodeToString(data)

	// Warn if token may be too long for URLs
	// @risk Information Disclosure: Very long URLs may be truncated in logs or proxies
	if len(encoded) > MaxURLLength {
		return encoded, fmt.Errorf("%w: token length %d exceeds recommended %d", ErrTokenTooLong, len(encoded), MaxURLLength)
	}

	return encoded, nil
}

// DecodeFromString deserializes a signed token from a URL-safe base64 string.
//
// This reverses EncodeToString and validates the format but does NOT verify
// the signature. Use Manager.Verify() to check signature validity.
func DecodeFromString(encoded string) (*SignedToken, error) {
	// Decode from base64 URL-safe format
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: base64 decode failed: %v", ErrInvalidTokenFormat, err)
	}

	// Deserialize the signed token
	var st SignedToken
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%w: json decode failed: %v", ErrInvalidTokenFormat, err)
	}

	return &st, nil
}

// ID returns a unique identifier for this signed token based on its content.
// This is used for token revocation support via TokenStore.
//
// The ID is a SHA-256 hash of the complete signed token, preventing token
// content disclosure through the token ID.
//
// @mitigation Information Disclosure: Use hash of token rather than embedding
// token ID, preventing leakage of token content through storage queries.
func (st *SignedToken) ID() string {
	// Hash the complete token including signature
	data, err := json.Marshal(st)
	if err != nil {
		// This should never happen for a valid SignedToken
		// If it does, return a zero hash as fallback
		return fmt.Sprintf("%x", sha256.Sum256([]byte("")))
	}

	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}
