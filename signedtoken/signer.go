package signedtoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
)

const (
	// MinSigningKeyLength is the minimum required length for signing keys in bytes.
	// This enforces a minimum security level of 256 bits.
	//
	// @mitigation Spoofing: Enforce strong key lengths to prevent brute force attacks.
	MinSigningKeyLength = 32 // 256 bits
)

var (
	// ErrWeakSigningKey indicates that the provided signing key is too short.
	ErrWeakSigningKey = errors.New("signing key is too weak")

	// ErrSignatureMismatch indicates that signature verification failed.
	ErrSignatureMismatch = errors.New("signature verification failed")
)

// Signer provides an interface for signing and verifying tokens.
//
// This abstraction allows for different signing mechanisms:
// - HMAC with various hash functions (SHA-256, SHA-512)
// - Asymmetric signatures (RSA, ECDSA)
// - External signing services (KMS, HSM)
//
// Implementations must be safe for concurrent use.
//
// Security Considerations:
//
// @risk Spoofing: Weak signing keys or algorithms allow token forgery.
// Always use cryptographically strong keys and algorithms.
//
// @risk Tampering: Signature verification must use constant-time comparison
// to prevent timing attacks.
type Signer interface {
	// Sign generates a cryptographic signature for the given data.
	//
	// The data is typically the JSON-serialized token payload.
	// Returns the signature bytes or an error if signing fails.
	Sign(data []byte) ([]byte, error)

	// Verify checks if the signature is valid for the given data.
	//
	// Returns nil if verification succeeds, or an error if the signature
	// is invalid or verification fails.
	//
	// @mitigation Tampering: MUST use constant-time comparison to prevent
	// timing attacks that could leak information about valid signatures.
	Verify(data []byte, signature []byte) error
}

// HMACSignerSHA256 implements the Signer interface using HMAC-SHA256.
//
// HMAC-SHA256 provides:
// - Strong cryptographic properties (SHA-256 hash function)
// - Symmetric key operation (same key for signing and verifying)
// - Fast computation
// - Widely supported and well-understood
//
// This is the default and recommended signer for most use cases.
//
// Security Considerations:
//
// @risk Spoofing: The signing key must be kept secret and should be at least
// 256 bits (32 bytes) in length. Keys should be randomly generated using a
// cryptographically secure random number generator.
//
// @mitigation Spoofing: Constructor enforces minimum key length.
type HMACSignerSHA256 struct {
	key []byte
}

// NewHMACSignerSHA256 creates a new HMAC-SHA256 signer with the given key.
//
// The key must be at least MinSigningKeyLength (32 bytes) to ensure adequate
// security. Keys should be randomly generated and kept secret.
//
// Example key generation:
//
//	key := make([]byte, 32)
//	if _, err := rand.Read(key); err != nil {
//	    // handle error
//	}
//	signer, err := NewHMACSignerSHA256(key)
//
// Returns ErrWeakSigningKey if the key is too short.
func NewHMACSignerSHA256(key []byte) (*HMACSignerSHA256, error) {
	// @mitigation Spoofing: Enforce minimum key length
	if len(key) < MinSigningKeyLength {
		return nil, fmt.Errorf("%w: key length %d, minimum required %d",
			ErrWeakSigningKey, len(key), MinSigningKeyLength)
	}

	// Make a copy of the key to prevent external modification
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &HMACSignerSHA256{
		key: keyCopy,
	}, nil
}

// Sign generates an HMAC-SHA256 signature for the given data.
func (s *HMACSignerSHA256) Sign(data []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, s.key)

	// Write is guaranteed to never return an error per the hash.Hash interface contract
	_, _ = mac.Write(data)

	signature := mac.Sum(nil)
	return signature, nil
}

// Verify checks if the HMAC-SHA256 signature is valid for the given data.
//
// Uses constant-time comparison to prevent timing attacks.
//
// @mitigation Tampering: Uses subtle.ConstantTimeCompare to prevent timing attacks.
func (s *HMACSignerSHA256) Verify(data []byte, signature []byte) error {
	// Compute the expected signature
	mac := hmac.New(sha256.New, s.key)

	// Write is guaranteed to never return an error per the hash.Hash interface contract
	_, _ = mac.Write(data)

	expectedSignature := mac.Sum(nil)

	// Constant-time comparison to prevent timing attacks
	// @mitigation Tampering: Constant-time comparison prevents information leakage
	if subtle.ConstantTimeCompare(signature, expectedSignature) != 1 {
		return ErrSignatureMismatch
	}

	return nil
}

// KeyLength returns the length of the signing key in bytes.
// This can be useful for logging or diagnostics (do not log the key itself).
func (s *HMACSignerSHA256) KeyLength() int {
	return len(s.key)
}
