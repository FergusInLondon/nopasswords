package srp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"go.fergus.london/nopasswords/core"
)

// Manager handles SRP registration and authentication operations.
//
// The Manager is safe for concurrent use by multiple goroutines.
type Manager struct {
	config *Config
	group  *Group
}

// NewManager creates a new SRP Manager with the given configuration options.
//
// Example:
//
//	store := memory.NewMemoryCredentialStore()
//	manager, err := NewManager(
//	    WithGroup(3),
//	    WithCredentialStore(store),
//	)
func NewManager(opts ...Option) (*Manager, error) {
	config, err := NewConfig(opts...)
	if err != nil {
		return nil, err
	}

	group, err := GetGroup(config.Group)
	if err != nil {
		return nil, fmt.Errorf("failed to load group: %w", err)
	}

	return &Manager{
		config: config,
		group:  group,
	}, nil
}

// computeU computes u = H(A | B) as defined in SRP-6a.
func (m *Manager) computeU(A, B *big.Int) *big.Int {
	// Pad A and B to the same length as N
	NBytes := m.group.N.Bytes()
	ABytes := padBytes(A.Bytes(), len(NBytes))
	BBytes := padBytes(B.Bytes(), len(NBytes))

	// u = H(A | B)
	combined := append(ABytes, BBytes...)
	hash := hashSHA256(combined)

	u := new(big.Int).SetBytes(hash)
	return u
}

// computeM1 computes the client's proof M1 = H(A | B | K).
// This is a simplified version; full RFC5054 includes H(N) XOR H(g) and other values.
func (m *Manager) computeM1(_ string, B, A, K []byte) []byte {
	// M1 = H(A | B | K)
	// Note: Full RFC5054 implementation would include H(N) XOR H(g), H(I), salt
	// For simplicity and cross-language compatibility, we use a simplified version
	combined := append(A, B...)
	combined = append(combined, K...)
	return hashSHA256(combined)
}

// computeM2 computes the server's proof M2 = H(A | M1 | K).
func (m *Manager) computeM2(A, M1, K []byte) []byte {
	// M2 = H(A | M1 | K)
	combined := append(A, M1...)
	combined = append(combined, K...)
	return hashSHA256(combined)
}

// logAuditEvent logs a security audit event. TODO: Half of these params can be put in a struct, to clean up the handlers.
func (m *Manager) logAuditEvent(ctx context.Context, eventID, eventType, UserIdentifier, credentialID, outcome, reason string, metadata map[string]interface{}) {
	event := core.AuditEvent{
		EventID:        eventID,
		Timestamp:      time.Now(),
		EventType:      eventType,
		Method:         "srp",
		UserIdentifier: UserIdentifier,
		CredentialID:   credentialID,
		Outcome:        outcome,
		Reason:         reason,
		Metadata:       metadata,
	}

	// Log errors are intentionally ignored to not disrupt authentication flow
	_ = m.config.AuditLogger.Log(ctx, event)
}

// Helper functions

// hashSHA256 computes the SHA-256 hash of the input.
func hashSHA256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

// generateRandomBigInt generates a cryptographically random big integer with the specified bit length.
//
// @mitigation Elevation of Privilege: Uses crypto/rand for cryptographic randomness.
func generateRandomBigInt(bitLength int) (*big.Int, error) {
	// Generate random bytes
	byteLength := (bitLength + 7) / 8
	randomBytes := make([]byte, byteLength)

	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Convert to big.Int
	randomInt := new(big.Int).SetBytes(randomBytes)
	return randomInt, nil
}

// padBytes pads a byte slice to the specified length with leading zeros.
func padBytes(data []byte, length int) []byte {
	if len(data) >= length {
		return data
	}

	padded := make([]byte, length)
	copy(padded[length-len(data):], data)
	return padded
}

// generateEventID generates a unique event ID for audit logging.
// TODO: Why cant this be handled within the core module?
func generateEventID() string {
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	return hex.EncodeToString(randomBytes)
}
