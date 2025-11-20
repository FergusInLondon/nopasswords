package srp

import (
	"context"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/core/memory"
)

func TestNewManager(t *testing.T) {
	store := memory.NewMemoryCredentialStore()

	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
	}{
		{
			name: "Valid manager",
			opts: []Option{
				WithCredentialStore(store),
			},
			wantErr: false,
		},
		{
			name: "With custom group",
			opts: []Option{
				WithCredentialStore(store),
				WithGroup(4),
			},
			wantErr: false,
		},
		{
			name:    "Missing credential store",
			opts:    []Option{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewManager(tt.opts...)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				require.NoError(t, err)
				require.NotNil(t, manager)
				assert.NotNil(t, manager.config)
				assert.NotNil(t, manager.group)
			}
		})
	}
}

func TestManager_Register(t *testing.T) {
	store := memory.NewMemoryCredentialStore()
	manager, err := NewManager(
		WithCredentialStore(store),
		WithGroup(3),
	)
	require.NoError(t, err)

	ctx := context.Background()

	tests := []struct {
		name    string
		req     *RegistrationRequest
		wantErr bool
		wantMsg string
	}{
		{
			name: "Successful registration",
			req: &RegistrationRequest{
				UserID:   "test@example.com",
				Salt:     make([]byte, 32),
				Verifier: make([]byte, 256),
				Group:    3,
			},
			wantErr: false,
		},
		{
			name: "Empty user ID",
			req: &RegistrationRequest{
				UserID:   "",
				Salt:     make([]byte, 32),
				Verifier: make([]byte, 256),
				Group:    3,
			},
			wantErr: false,
			wantMsg: "user ID cannot be empty",
		},
		{
			name: "Salt too short",
			req: &RegistrationRequest{
				UserID:   "test@example.com",
				Salt:     make([]byte, 8),
				Verifier: make([]byte, 256),
				Group:    3,
			},
			wantErr: false,
			wantMsg: "salt must be at least",
		},
		{
			name: "Empty verifier",
			req: &RegistrationRequest{
				UserID:   "test@example.com",
				Salt:     make([]byte, 32),
				Verifier: []byte{},
				Group:    3,
			},
			wantErr: false,
			wantMsg: "verifier cannot be empty",
		},
		{
			name: "Group mismatch",
			req: &RegistrationRequest{
				UserID:   "test@example.com",
				Salt:     make([]byte, 32),
				Verifier: make([]byte, 256),
				Group:    4,
			},
			wantErr: false,
			wantMsg: "group mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := manager.Register(ctx, tt.req)

			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)

				if tt.wantMsg != "" {
					assert.False(t, resp.Success)
					assert.Contains(t, resp.Error, tt.wantMsg)
				} else {
					assert.True(t, resp.Success)
					assert.Equal(t, tt.req.UserID, resp.UserID)
				}
			}
		})
	}
}

func TestManager_AuthenticationFlow(t *testing.T) {
	store := memory.NewMemoryCredentialStore()
	manager, err := NewManager(
		WithCredentialStore(store),
		WithGroup(3),
		WithAuditLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	ctx := context.Background()
	userID := "test@example.com"
	password := "test-password"

	// Step 1: Register user
	salt, verifier := computeVerifier(manager.group, userID, password)

	regReq := &RegistrationRequest{
		UserID:   userID,
		Salt:     salt,
		Verifier: verifier,
		Group:    3,
	}

	regResp, err := manager.Register(ctx, regReq)
	require.NoError(t, err)
	require.True(t, regResp.Success)

	// Step 2: Begin authentication
	beginReq := &AuthenticationBeginRequest{
		UserID: userID,
		Group:  3,
	}

	beginResp, err := manager.BeginAuthentication(ctx, beginReq)
	require.NoError(t, err)
	require.NotNil(t, beginResp)
	assert.Equal(t, salt, beginResp.Salt)
	assert.NotEmpty(t, beginResp.B)

	// Step 3: Client computes A and M1
	A, M1, clientKey := computeClientProof(manager.group, userID, password, beginResp.Salt, beginResp.B)

	// Step 4: Finish authentication
	finishReq := &AuthenticationFinishRequest{
		UserID: userID,
		A:      A,
		M1:     M1,
	}

	finishResp, sessionKey, err := manager.FinishAuthentication(ctx, finishReq)
	require.NoError(t, err)
	require.NotNil(t, finishResp)
	require.NotNil(t, sessionKey)

	assert.True(t, finishResp.Success)
	assert.NotEmpty(t, finishResp.M2)
	assert.Equal(t, userID, sessionKey.UserID)

	// Verify session keys match
	assert.Equal(t, clientKey, sessionKey.Key)
}

func TestManager_AuthenticationFlow_WrongPassword(t *testing.T) {
	store := memory.NewMemoryCredentialStore()
	manager, err := NewManager(
		WithCredentialStore(store),
		WithGroup(3),
	)
	require.NoError(t, err)

	ctx := context.Background()
	userID := "test@example.com"
	correctPassword := "correct-password"
	wrongPassword := "wrong-password"

	// Register with correct password
	salt, verifier := computeVerifier(manager.group, userID, correctPassword)

	regReq := &RegistrationRequest{
		UserID:   userID,
		Salt:     salt,
		Verifier: verifier,
		Group:    3,
	}

	_, err = manager.Register(ctx, regReq)
	require.NoError(t, err)

	// Begin authentication
	beginReq := &AuthenticationBeginRequest{
		UserID: userID,
	}

	beginResp, err := manager.BeginAuthentication(ctx, beginReq)
	require.NoError(t, err)

	// Try to authenticate with wrong password
	A, M1, _ := computeClientProof(manager.group, userID, wrongPassword, beginResp.Salt, beginResp.B)

	finishReq := &AuthenticationFinishRequest{
		UserID: userID,
		A:      A,
		M1:     M1,
	}

	finishResp, sessionKey, err := manager.FinishAuthentication(ctx, finishReq)
	require.NoError(t, err)
	require.NotNil(t, finishResp)

	assert.False(t, finishResp.Success)
	assert.Contains(t, finishResp.Error, "invalid proof")
	assert.Nil(t, sessionKey)
}

func TestManager_BeginAuthentication_UserNotFound(t *testing.T) {
	store := memory.NewMemoryCredentialStore()
	manager, err := NewManager(
		WithCredentialStore(store),
		WithGroup(3),
	)
	require.NoError(t, err)

	ctx := context.Background()

	beginReq := &AuthenticationBeginRequest{
		UserID: "nonexistent@example.com",
	}

	_, err = manager.BeginAuthentication(ctx, beginReq)
	assert.Error(t, err)
}

func TestManager_FinishAuthentication_SessionExpired(t *testing.T) {
	store := memory.NewMemoryCredentialStore()
	manager, err := NewManager(
		WithCredentialStore(store),
		WithGroup(3),
		WithSessionTimeout(1*time.Millisecond), // Very short timeout
	)
	require.NoError(t, err)

	ctx := context.Background()
	userID := "test@example.com"
	password := "test-password"

	// Register user
	salt, verifier := computeVerifier(manager.group, userID, password)
	regReq := &RegistrationRequest{
		UserID:   userID,
		Salt:     salt,
		Verifier: verifier,
		Group:    3,
	}
	_, err = manager.Register(ctx, regReq)
	require.NoError(t, err)

	// Begin authentication
	beginReq := &AuthenticationBeginRequest{
		UserID: userID,
	}
	beginResp, err := manager.BeginAuthentication(ctx, beginReq)
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)

	// Try to finish authentication
	A, M1, _ := computeClientProof(manager.group, userID, password, beginResp.Salt, beginResp.B)
	finishReq := &AuthenticationFinishRequest{
		UserID: userID,
		A:      A,
		M1:     M1,
	}

	finishResp, sessionKey, err := manager.FinishAuthentication(ctx, finishReq)
	require.NoError(t, err)
	require.NotNil(t, finishResp)

	assert.False(t, finishResp.Success)
	assert.Contains(t, finishResp.Error, "expired")
	assert.Nil(t, sessionKey)
}

func TestManager_FinishAuthentication_InvalidA(t *testing.T) {
	store := memory.NewMemoryCredentialStore()
	manager, err := NewManager(
		WithCredentialStore(store),
		WithGroup(3),
	)
	require.NoError(t, err)

	ctx := context.Background()
	userID := "test@example.com"
	password := "test-password"

	// Register user
	salt, verifier := computeVerifier(manager.group, userID, password)
	regReq := &RegistrationRequest{
		UserID:   userID,
		Salt:     salt,
		Verifier: verifier,
		Group:    3,
	}
	_, err = manager.Register(ctx, regReq)
	require.NoError(t, err)

	// Begin authentication
	beginReq := &AuthenticationBeginRequest{
		UserID: userID,
	}
	_, err = manager.BeginAuthentication(ctx, beginReq)
	require.NoError(t, err)

	// Send invalid A (A = 0 mod N)
	finishReq := &AuthenticationFinishRequest{
		UserID: userID,
		A:      manager.group.N.Bytes(), // A = N, so A mod N = 0
		M1:     make([]byte, 32),
	}

	finishResp, sessionKey, err := manager.FinishAuthentication(ctx, finishReq)
	require.NoError(t, err)
	require.NotNil(t, finishResp)

	assert.False(t, finishResp.Success)
	assert.Contains(t, finishResp.Error, "invalid client ephemeral")
	assert.Nil(t, sessionKey)
}

// Helper functions for testing

// computeVerifier computes the SRP verifier on the client side.
// This simulates what the JavaScript client would do.
func computeVerifier(group *Group, userID, password string) ([]byte, []byte) {
	// Generate salt
	salt := make([]byte, 32)
	// For testing, use deterministic salt based on userID
	saltHash := sha256.Sum256([]byte(userID))
	copy(salt, saltHash[:])

	// Compute x = H(salt | H(userID | ":" | password))
	innerHash := sha256.Sum256([]byte(userID + ":" + password))
	combined := append(salt, innerHash[:]...)
	xHash := sha256.Sum256(combined)
	x := new(big.Int).SetBytes(xHash[:])

	// Compute v = g^x mod N
	v := new(big.Int).Exp(group.g, x, group.N)

	return salt, v.Bytes()
}

// computeClientProof simulates the client side of SRP authentication.
// Returns A (client public ephemeral), M1 (client proof), and K (session key).
func computeClientProof(group *Group, userID, password string, salt, BBytes []byte) ([]byte, []byte, []byte) {
	// Compute x = H(salt | H(userID | ":" | password))
	innerHash := sha256.Sum256([]byte(userID + ":" + password))
	combined := append(salt, innerHash[:]...)
	xHash := sha256.Sum256(combined)
	x := new(big.Int).SetBytes(xHash[:])

	// Generate client ephemeral value a (random 256 bits)
	a, _ := generateRandomBigInt(256)

	// Compute A = g^a mod N
	A := new(big.Int).Exp(group.g, a, group.N)

	// Parse server's B
	B := new(big.Int).SetBytes(BBytes)

	// Compute u = H(A | B)
	NBytes := group.N.Bytes()
	ABytes := padBytes(A.Bytes(), len(NBytes))
	BBytesPadded := padBytes(B.Bytes(), len(NBytes))
	uHash := sha256.Sum256(append(ABytes, BBytesPadded...))
	u := new(big.Int).SetBytes(uHash[:])

	// Compute k = H(N | g)
	k := group.k()

	// Compute S = (B - kg^x)^(a + ux) mod N
	gx := new(big.Int).Exp(group.g, x, group.N)
	kgx := new(big.Int).Mul(k, gx)
	kgx.Mod(kgx, group.N)

	diff := new(big.Int).Sub(B, kgx)
	diff.Mod(diff, group.N)

	ux := new(big.Int).Mul(u, x)
	aux := new(big.Int).Add(a, ux)

	S := new(big.Int).Exp(diff, aux, group.N)

	// Compute session key K = H(S)
	K := hashSHA256(S.Bytes())

	// Compute M1 = H(A | B | K)
	m1Combined := append(A.Bytes(), B.Bytes()...)
	m1Combined = append(m1Combined, K...)
	M1 := hashSHA256(m1Combined)

	return A.Bytes(), M1, K
}
