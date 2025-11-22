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

func TestAssertionVerificationHandler_InvalidJSON(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AssertionVerificationHandler(func(userID string, w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	req := httptest.NewRequest(http.MethodPost, "/assert/verify", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestAssertionVerificationHandler_EmptyUserIdentifier(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AssertionVerificationHandler(func(userID string, w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	verifyReq := &AssertionCompletionRequest{
		UserIdentifier: "", // Empty
		A:              []byte{1, 2, 3},
		M1:             []byte{4, 5, 6},
	}

	body, _ := json.Marshal(verifyReq)
	req := httptest.NewRequest(http.MethodPost, "/assert/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestAssertionVerificationHandler_NoState(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()), // Empty cache - no state
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AssertionVerificationHandler(func(userID string, w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	verifyReq := &AssertionCompletionRequest{
		UserIdentifier: "testuser",
		A:              []byte{1, 2, 3},
		M1:             []byte{4, 5, 6},
	}

	body, _ := json.Marshal(verifyReq)
	req := httptest.NewRequest(http.MethodPost, "/assert/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestAssertionVerificationHandler_InvalidClientEphemeral(t *testing.T) {
	cache := newInMemoryStateCache()

	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(cache),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	// Store state with some values
	cache.StoreForUserIdentifier("testuser", &AssertionState{
		Group: DefaultGroup,
		b:     big.NewInt(123),
		B:     big.NewInt(456),
		v:     big.NewInt(789),
	})

	handler := manager.AssertionVerificationHandler(func(userID string, w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	// A = N means A % N == 0, which should be rejected
	group, _ := GetGroup(DefaultGroup)

	verifyReq := &AssertionCompletionRequest{
		UserIdentifier: "testuser",
		A:              group.N.Bytes(), // A = N, so A % N = 0
		M1:             []byte{1, 2, 3},
	}

	body, _ := json.Marshal(verifyReq)
	req := httptest.NewRequest(http.MethodPost, "/assert/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "invalid client ephemeral value")
}

func TestAssertionVerificationHandler_InvalidProof(t *testing.T) {
	cache := newInMemoryStateCache()

	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(cache),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	// Store state
	cache.StoreForUserIdentifier("testuser", &AssertionState{
		Group: DefaultGroup,
		b:     big.NewInt(123),
		B:     big.NewInt(456),
		v:     big.NewInt(789),
	})

	handler := manager.AssertionVerificationHandler(func(userID string, w http.ResponseWriter, r *http.Request) error {
		return nil
	})

	verifyReq := &AssertionCompletionRequest{
		UserIdentifier: "testuser",
		A:              []byte{1, 2, 3},
		M1:             []byte{9, 9, 9}, // Wrong proof
	}

	body, _ := json.Marshal(verifyReq)
	req := httptest.NewRequest(http.MethodPost, "/assert/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "authentication failed")
}
