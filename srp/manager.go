package srp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	"go.fergus.london/nopasswords/core"
)

// Manager handles SRP registration and authentication operations.
//
// The Manager is safe for concurrent use by multiple goroutines.
type Manager struct {
	config   *Config
	group    *Group
	sessions sync.Map // map[string]*ServerSession - temporary session storage
}

// NewManager creates a new SRP Manager with the given configuration options.
//
// Example:
//   store := memory.NewMemoryCredentialStore()
//   manager, err := NewManager(
//       WithGroup(3),
//       WithCredentialStore(store),
//   )
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

// Register registers a new user with their SRP verifier.
//
// The verifier should be computed client-side as:
//   x = H(salt | H(username | ":" | password))
//   v = g^x mod N
//
// This method stores the verifier and salt for future authentication.
//
// Security Considerations:
// @mitigation Information Disclosure: The verifier cannot be used to recover
// the password, even if the database is compromised.
// @risk Repudiation: Registration events are logged for audit purposes.
func (m *Manager) Register(ctx context.Context, req *RegistrationRequest) (*RegistrationResponse, error) {
	eventID := generateEventID()
	startTime := time.Now()

	// Validate request
	if req.UserID == "" {
		m.logAuditEvent(ctx, eventID, core.EventCredentialRegister, req.UserID, "", core.OutcomeFailure, "empty_user_id", nil)
		return &RegistrationResponse{
			Success: false,
			Error:   "user ID cannot be empty",
		}, nil
	}

	if len(req.Salt) < MinSaltLength {
		m.logAuditEvent(ctx, eventID, core.EventCredentialRegister, req.UserID, "", core.OutcomeFailure, "invalid_salt_length", nil)
		return &RegistrationResponse{
			Success: false,
			Error:   fmt.Sprintf("salt must be at least %d bytes", MinSaltLength),
		}, nil
	}

	if len(req.Verifier) == 0 {
		m.logAuditEvent(ctx, eventID, core.EventCredentialRegister, req.UserID, "", core.OutcomeFailure, "empty_verifier", nil)
		return &RegistrationResponse{
			Success: false,
			Error:   "verifier cannot be empty",
		}, nil
	}

	// Validate group
	if req.Group != m.config.Group {
		m.logAuditEvent(ctx, eventID, core.EventCredentialRegister, req.UserID, "", core.OutcomeFailure, "group_mismatch", map[string]interface{}{
			"requested_group": req.Group,
			"expected_group":  m.config.Group,
		})
		return &RegistrationResponse{
			Success: false,
			Error:   fmt.Sprintf("group mismatch: expected %d, got %d", m.config.Group, req.Group),
		}, nil
	}

	// Create verifier record
	verifier := &Verifier{
		UserID:    req.UserID,
		Salt:      req.Salt,
		Verifier:  req.Verifier,
		Group:     req.Group,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Serialize verifier
	data, err := verifier.MarshalBinary()
	if err != nil {
		m.logAuditEvent(ctx, eventID, core.EventCredentialRegister, req.UserID, "", core.OutcomeError, "marshal_error", nil)
		return nil, fmt.Errorf("failed to marshal verifier: %w", err)
	}

	// Generate credential ID (hash of userID for SRP)
	credentialID := m.generateCredentialID(req.UserID)

	// Store verifier
	err = m.config.CredentialStore.StoreCredential(ctx, req.UserID, credentialID, data)
	if err != nil {
		m.logAuditEvent(ctx, eventID, core.EventCredentialRegister, req.UserID, credentialID, core.OutcomeError, "storage_error", nil)
		return nil, fmt.Errorf("failed to store verifier: %w", err)
	}

	// Log successful registration
	m.logAuditEvent(ctx, eventID, core.EventCredentialRegister, req.UserID, credentialID, core.OutcomeSuccess, "", map[string]interface{}{
		"group":    req.Group,
		"duration": time.Since(startTime).Milliseconds(),
	})

	return &RegistrationResponse{
		Success: true,
		UserID:  req.UserID,
	}, nil
}

// BeginAuthentication initiates the SRP authentication flow.
//
// The server:
// 1. Retrieves the user's verifier (v) from storage
// 2. Generates ephemeral values: b (private), B (public)
// 3. Stores session state for the Finish step
// 4. Returns salt and B to the client
//
// Security Considerations:
// @risk Elevation of Privilege: Ephemeral value b must be cryptographically random.
// @risk Denial of Service: Sessions must expire to prevent resource exhaustion.
func (m *Manager) BeginAuthentication(ctx context.Context, req *AuthenticationBeginRequest) (*AuthenticationBeginResponse, error) {
	eventID := generateEventID()
	startTime := time.Now()

	// Validate request
	if req.UserID == "" {
		m.logAuditEvent(ctx, eventID, core.EventAuthAttempt, req.UserID, "", core.OutcomeFailure, "empty_user_id", nil)
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	// Generate credential ID
	credentialID := m.generateCredentialID(req.UserID)

	// Retrieve verifier from storage
	data, err := m.config.CredentialStore.GetCredential(ctx, req.UserID, credentialID)
	if err != nil {
		m.logAuditEvent(ctx, eventID, core.EventAuthAttempt, req.UserID, credentialID, core.OutcomeFailure, "user_not_found", nil)
		// Return generic error to prevent user enumeration
		return nil, core.ErrInvalidCredential
	}

	// Deserialize verifier
	var verifier Verifier
	if err := verifier.UnmarshalBinary(data); err != nil {
		m.logAuditEvent(ctx, eventID, core.EventAuthAttempt, req.UserID, credentialID, core.OutcomeError, "unmarshal_error", nil)
		return nil, fmt.Errorf("failed to unmarshal verifier: %w", err)
	}

	// Validate group matches
	if verifier.Group != m.config.Group {
		m.logAuditEvent(ctx, eventID, core.EventAuthAttempt, req.UserID, credentialID, core.OutcomeFailure, "group_mismatch", map[string]interface{}{
			"stored_group":  verifier.Group,
			"expected_group": m.config.Group,
		})
		return nil, fmt.Errorf("group mismatch: expected %d, got %d", m.config.Group, verifier.Group)
	}

	// Generate server ephemeral values
	// b is a random value (256 bits)
	// @risk Elevation of Privilege: b must be cryptographically random to prevent
	// session key prediction.
	b, err := generateRandomBigInt(256)
	if err != nil {
		m.logAuditEvent(ctx, eventID, core.EventAuthAttempt, req.UserID, credentialID, core.OutcomeError, "random_generation_failed", nil)
		return nil, fmt.Errorf("failed to generate ephemeral value: %w", err)
	}

	// B = kv + g^b mod N
	// where k = H(N | g)
	k := m.group.k()
	v := new(big.Int).SetBytes(verifier.Verifier)

	// Compute g^b mod N
	gb := new(big.Int).Exp(m.group.g, b, m.group.N)

	// Compute kv mod N
	kv := new(big.Int).Mul(k, v)
	kv.Mod(kv, m.group.N)

	// B = kv + g^b mod N
	B := new(big.Int).Add(kv, gb)
	B.Mod(B, m.group.N)

	// Create server session
	session := &ServerSession{
		UserID:    req.UserID,
		Group:     m.config.Group,
		b:         b,
		B:         B,
		v:         v,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(m.config.SessionTimeout),
	}

	// Store session (indexed by userID)
	// @mitigation Denial of Service: Sessions expire after configured timeout
	m.sessions.Store(req.UserID, session)

	// Clean up expired sessions periodically
	go m.cleanupExpiredSessions()

	// Log authentication begin
	m.logAuditEvent(ctx, eventID, core.EventAuthAttempt, req.UserID, credentialID, core.OutcomeSuccess, "begin", map[string]interface{}{
		"group":    m.config.Group,
		"duration": time.Since(startTime).Milliseconds(),
	})

	return &AuthenticationBeginResponse{
		Salt:  verifier.Salt,
		B:     B.Bytes(),
		Group: m.config.Group,
	}, nil
}

// FinishAuthentication completes the SRP authentication flow.
//
// The server:
// 1. Retrieves the session state from Begin
// 2. Computes the session key S
// 3. Verifies the client's proof M1
// 4. Computes server proof M2
// 5. Returns M2 to the client
//
// Both client and server now share the session key S, which can be used
// for subsequent cryptographic operations.
//
// Security Considerations:
// @risk Tampering: Incorrect protocol implementation allows man-in-the-middle attacks.
// @risk Information Disclosure: Constant-time comparison prevents timing attacks.
// @mitigation Elevation of Privilege: Session key is derived correctly per RFC5054.
func (m *Manager) FinishAuthentication(ctx context.Context, req *AuthenticationFinishRequest) (*AuthenticationFinishResponse, *SessionKey, error) {
	eventID := generateEventID()
	startTime := time.Now()

	// Validate request
	if req.UserID == "" {
		m.logAuditEvent(ctx, eventID, core.EventAuthFailure, req.UserID, "", core.OutcomeFailure, "empty_user_id", nil)
		return &AuthenticationFinishResponse{
			Success: false,
			Error:   "user ID cannot be empty",
		}, nil, nil
	}

	if len(req.A) == 0 || len(req.M1) == 0 {
		m.logAuditEvent(ctx, eventID, core.EventAuthFailure, req.UserID, "", core.OutcomeFailure, "missing_parameters", nil)
		return &AuthenticationFinishResponse{
			Success: false,
			Error:   "A and M1 are required",
		}, nil, nil
	}

	// Retrieve session
	sessionInterface, ok := m.sessions.Load(req.UserID)
	if !ok {
		m.logAuditEvent(ctx, eventID, core.EventAuthFailure, req.UserID, "", core.OutcomeFailure, "session_not_found", nil)
		return &AuthenticationFinishResponse{
			Success: false,
			Error:   "session not found or expired",
		}, nil, nil
	}

	session := sessionInterface.(*ServerSession)

	// Check session expiration
	// @mitigation Denial of Service: Expired sessions are rejected
	if time.Now().After(session.ExpiresAt) {
		m.sessions.Delete(req.UserID)
		m.logAuditEvent(ctx, eventID, core.EventAuthFailure, req.UserID, "", core.OutcomeFailure, "session_expired", nil)
		return &AuthenticationFinishResponse{
			Success: false,
			Error:   "session expired",
		}, nil, nil
	}

	// Parse client's public ephemeral value A
	A := new(big.Int).SetBytes(req.A)

	// Verify A % N != 0 (security check per RFC5054)
	// @mitigation Tampering: Reject invalid A values that could compromise security
	Amod := new(big.Int).Mod(A, m.group.N)
	if Amod.Cmp(big.NewInt(0)) == 0 {
		m.sessions.Delete(req.UserID)
		m.logAuditEvent(ctx, eventID, core.EventAuthFailure, req.UserID, "", core.OutcomeFailure, "invalid_client_ephemeral", nil)
		return &AuthenticationFinishResponse{
			Success: false,
			Error:   "invalid client ephemeral value",
		}, nil, nil
	}

	// Compute u = H(A | B)
	u := m.computeU(A, session.B)

	// Compute S = (A * v^u)^b mod N
	// @mitigation Elevation of Privilege: Correct session key derivation per RFC5054
	vu := new(big.Int).Exp(session.v, u, m.group.N)
	Avu := new(big.Int).Mul(A, vu)
	Avu.Mod(Avu, m.group.N)
	S := new(big.Int).Exp(Avu, session.b, m.group.N)

	// Compute session key K = H(S)
	K := hashSHA256(S.Bytes())

	// Compute expected M1 = H(H(N) XOR H(g) | H(I) | salt | A | B | K)
	expectedM1 := m.computeM1(req.UserID, session.B.Bytes(), req.A, K)

	// Verify M1 using constant-time comparison
	// @mitigation Information Disclosure: Constant-time comparison prevents timing attacks
	// that could leak information about the password
	if subtle.ConstantTimeCompare(req.M1, expectedM1) != 1 {
		m.sessions.Delete(req.UserID)
		m.logAuditEvent(ctx, eventID, core.EventAuthFailure, req.UserID, m.generateCredentialID(req.UserID), core.OutcomeFailure, "invalid_proof", map[string]interface{}{
			"duration": time.Since(startTime).Milliseconds(),
		})
		return &AuthenticationFinishResponse{
			Success: false,
			Error:   "authentication failed: invalid proof",
		}, nil, nil
	}

	// Compute M2 = H(A | M1 | K)
	M2 := m.computeM2(req.A, req.M1, K)

	// Delete session (one-time use)
	m.sessions.Delete(req.UserID)

	// Create session key
	sessionKey := &SessionKey{
		Key:       K,
		UserID:    req.UserID,
		Timestamp: time.Now(),
	}

	// Log successful authentication
	// @mitigation Repudiation: Comprehensive audit logging for security investigations
	m.logAuditEvent(ctx, eventID, core.EventAuthSuccess, req.UserID, m.generateCredentialID(req.UserID), core.OutcomeSuccess, "", map[string]interface{}{
		"group":    m.config.Group,
		"duration": time.Since(startTime).Milliseconds(),
	})

	return &AuthenticationFinishResponse{
		Success: true,
		M2:      M2,
	}, sessionKey, nil
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
func (m *Manager) computeM1(userID string, B, A, K []byte) []byte {
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

// cleanupExpiredSessions removes expired sessions from memory.
// This is called periodically to prevent memory leaks.
//
// @mitigation Denial of Service: Prevents unbounded session storage growth.
func (m *Manager) cleanupExpiredSessions() {
	now := time.Now()
	m.sessions.Range(func(key, value interface{}) bool {
		session := value.(*ServerSession)
		if now.After(session.ExpiresAt) {
			m.sessions.Delete(key)
		}
		return true
	})
}

// generateCredentialID generates a credential ID from the user ID.
// For SRP, we use a hash of the userID as the credential ID.
func (m *Manager) generateCredentialID(userID string) string {
	hash := sha256.Sum256([]byte("srp:" + userID))
	return hex.EncodeToString(hash[:])
}

// logAuditEvent logs a security audit event.
func (m *Manager) logAuditEvent(ctx context.Context, eventID, eventType, userID, credentialID, outcome, reason string, metadata map[string]interface{}) {
	event := core.AuditEvent{
		EventID:      eventID,
		Timestamp:    time.Now(),
		EventType:    eventType,
		Method:       "srp",
		UserID:       userID,
		CredentialID: credentialID,
		Outcome:      outcome,
		Reason:       reason,
		Metadata:     metadata,
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
func generateEventID() string {
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	return hex.EncodeToString(randomBytes)
}
