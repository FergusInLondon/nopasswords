package srp

import (
	"bytes"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/pkg/core/events/memory"
)

// TestCompleteFlow tests the entire SRP flow: attestation -> assertion initiation -> assertion completion
func TestCompleteFlow(t *testing.T) {
	// Setup: Create a manager with in-memory stores
	store := newInMemoryParameterStore()
	cache := newInMemoryStateCache()
	logger := memory.NewNopLogger()

	manager, err := NewManager(
		WithParameterStore(store),
		WithStateCache(cache),
		WithEventLogger(logger),
		WithGroup(3), // 2048-bit group
	)
	require.NoError(t, err)

	const userID = "testuser"
	const password = "mySecurePassword123"

	// Step 1: Attestation (Registration)
	// Client computes verifier from password and sends to server
	salt := make([]byte, DefaultSaltLength)
	for i := range salt {
		salt[i] = byte(i) // Deterministic salt for testing
	}

	// Compute verifier: v = g^x mod N where x = H(salt | password)
	combined := append(salt, []byte(password)...)
	x := new(big.Int).SetBytes(hashSHA256(combined))
	v := new(big.Int).Exp(manager.group.g, x, manager.group.N)

	attestReq := &AttestationRequest{
		UserIdentifier: userID,
		Salt:           salt,
		Verifier:       v.Bytes(),
		Group:          3,
	}

	attestHandlerInvoked := false
	attestHandler := manager.AttestationHandlerFunc(func(params Parameters) {
		attestHandlerInvoked = true
	})

	attestBody, _ := json.Marshal(attestReq)
	attestHTTPReq := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(attestBody))
	attestHTTPReq.Header.Set("Content-Type", "application/json")
	attestRecorder := httptest.NewRecorder()
	attestHandler.ServeHTTP(attestRecorder, attestHTTPReq)

	require.Equal(t, http.StatusOK, attestRecorder.Code, "attestation should succeed")
	require.Equal(t, true, attestHandlerInvoked, "attestation handler should be invoked")

	var attestResp AttestationResponse
	err = json.NewDecoder(attestRecorder.Body).Decode(&attestResp)
	require.NoError(t, err)
	assert.True(t, attestResp.Success)

	// Step 2: Assertion Initiation (Begin authentication)
	beginReq := &AssertionInitiationRequest{
		UserIdentifier: userID,
		Group:          3,
	}

	beginHandler := manager.AssertionBeginHandler()

	beginBody, _ := json.Marshal(beginReq)
	beginHTTPReq := httptest.NewRequest(http.MethodPost, "/assert/begin", bytes.NewReader(beginBody))
	beginHTTPReq.Header.Set("Content-Type", "application/json")
	beginRecorder := httptest.NewRecorder()
	beginHandler.ServeHTTP(beginRecorder, beginHTTPReq)

	require.Equal(t, http.StatusOK, beginRecorder.Code, "assertion begin should succeed")

	var beginResp AssertionInitiationResponse
	err = json.NewDecoder(beginRecorder.Body).Decode(&beginResp)
	require.NoError(t, err)
	assert.NotEmpty(t, beginResp.Salt)
	assert.NotEmpty(t, beginResp.B)
	assert.Equal(t, 3, beginResp.Group)

	// Step 3: Client-side computation (simulating what the client does)
	// Generate client ephemeral (a is random, A = g^a mod N)
	a, err := generateRandomBigInt(256)
	require.NoError(t, err)
	A := new(big.Int).Exp(manager.group.g, a, manager.group.N)

	// Compute u = H(A | B)
	B := new(big.Int).SetBytes(beginResp.B)
	NBytes := manager.group.N.Bytes()
	ABytes := padBytes(A.Bytes(), len(NBytes))
	BBytes := padBytes(beginResp.B, len(NBytes))
	uCombined := append(ABytes, BBytes...)
	u := new(big.Int).SetBytes(hashSHA256(uCombined))

	// Compute k = H(N | g)
	k := manager.group.k()

	// Client computes session key S = (B - kg^x)^(a + ux) mod N
	kv := new(big.Int).Mul(k, v)
	kv.Mod(kv, manager.group.N)
	base := new(big.Int).Sub(B, kv)
	base.Mod(base, manager.group.N)
	ux := new(big.Int).Mul(u, x)
	exp := new(big.Int).Add(a, ux)
	S := new(big.Int).Exp(base, exp, manager.group.N)

	// Compute session key K = H(S)
	K := hashSHA256(S.Bytes())

	// Compute M1 = H(A | B | K)
	m1Combined := append(A.Bytes(), beginResp.B...)
	m1Combined = append(m1Combined, K...)
	M1 := hashSHA256(m1Combined)

	// Step 4: Assertion Completion (Verify proof)
	verifyReq := &AssertionCompletionRequest{
		UserIdentifier: userID,
		A:              A.Bytes(),
		M1:             M1,
	}

	var callbackInvoked bool
	verifyHandler := manager.AssertionVerificationHandler(func(userID string, w http.ResponseWriter, r *http.Request) error {
		callbackInvoked = true
		return nil
	})

	verifyBody, _ := json.Marshal(verifyReq)
	verifyHTTPReq := httptest.NewRequest(http.MethodPost, "/assert/verify", bytes.NewReader(verifyBody))
	verifyHTTPReq.Header.Set("Content-Type", "application/json")
	verifyRecorder := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRecorder, verifyHTTPReq)

	require.Equal(t, http.StatusOK, verifyRecorder.Code, "assertion verification should succeed")

	var verifyResp AssertionCompletionResponse
	err = json.NewDecoder(verifyRecorder.Body).Decode(&verifyResp)
	require.NoError(t, err)
	assert.True(t, verifyResp.Success)
	assert.NotEmpty(t, verifyResp.M2)
	assert.True(t, callbackInvoked, "success callback should be invoked")

	// Verify M2 is correct: M2 = H(A | M1 | K)
	expectedM2Combined := append(A.Bytes(), M1...)
	expectedM2Combined = append(expectedM2Combined, K...)
	expectedM2 := hashSHA256(expectedM2Combined)
	assert.Equal(t, expectedM2, verifyResp.M2, "server M2 should match expected value")
}

// Helper implementations for in-memory stores (duplicating memory package to avoid import cycle)
type inMemoryParameterStore struct {
	store map[string]*Parameters
}

func newInMemoryParameterStore() *inMemoryParameterStore {
	return &inMemoryParameterStore{
		store: make(map[string]*Parameters),
	}
}

func (s *inMemoryParameterStore) GetForUserIdentifier(id string) (*Parameters, error) {
	if params, ok := s.store[id]; ok {
		return params, nil
	}
	return nil, &ErrNoParameters{UserIdentifier: id}
}

func (s *inMemoryParameterStore) StoreForUserIdentifier(id string, params *Parameters) error {
	s.store[id] = params
	return nil
}

type inMemoryStateCache struct {
	cache map[string]*AssertionState
}

func newInMemoryStateCache() *inMemoryStateCache {
	return &inMemoryStateCache{
		cache: make(map[string]*AssertionState),
	}
}

func (c *inMemoryStateCache) GetForUserIdentifier(id string) (*AssertionState, error) {
	if state, ok := c.cache[id]; ok {
		return state, nil
	}
	return nil, &ErrNoState{UserIdentifier: id}
}

func (c *inMemoryStateCache) StoreForUserIdentifier(id string, state *AssertionState) error {
	c.cache[id] = state
	return nil
}

func (c *inMemoryStateCache) PurgeForUserIdentity(id string) error {
	delete(c.cache, id)
	return nil
}

// Error types for store/cache
type ErrNoParameters struct {
	UserIdentifier string
}

func (e *ErrNoParameters) Error() string {
	return "no params available for '" + e.UserIdentifier + "'"
}

type ErrNoState struct {
	UserIdentifier string
}

func (e *ErrNoState) Error() string {
	return "no state available for '" + e.UserIdentifier + "'"
}
