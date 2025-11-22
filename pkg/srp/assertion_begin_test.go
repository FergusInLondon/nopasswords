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

func TestAssertionBeginHandler_InvalidJSON(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AssertionBeginHandler()

	req := httptest.NewRequest(http.MethodPost, "/assert/begin", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestAssertionBeginHandler_EmptyUserIdentifier(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AssertionBeginHandler()

	beginReq := &AssertionInitiationRequest{
		UserIdentifier: "", // Empty
		Group:          DefaultGroup,
	}

	body, _ := json.Marshal(beginReq)
	req := httptest.NewRequest(http.MethodPost, "/assert/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestAssertionBeginHandler_UserNotFound(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()), // Empty store
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AssertionBeginHandler()

	beginReq := &AssertionInitiationRequest{
		UserIdentifier: "nonexistent",
		Group:          DefaultGroup,
	}

	body, _ := json.Marshal(beginReq)
	req := httptest.NewRequest(http.MethodPost, "/assert/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
}

func TestAssertionBeginHandler_GroupMismatch(t *testing.T) {
	store := newInMemoryParameterStore()

	// Store parameters with group 4
	salt := make([]byte, DefaultSaltLength)
	verifier := big.NewInt(12345).Bytes()
	store.StoreForUserIdentifier("testuser", &Parameters{
		UserIdentifier: "testuser",
		Salt:           salt,
		Verifier:       verifier,
		Group:          4, // Stored with group 4
	})

	manager, err := NewManager(
		WithParameterStore(store),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
		WithGroup(3), // Server configured for group 3
	)
	require.NoError(t, err)

	handler := manager.AssertionBeginHandler()

	beginReq := &AssertionInitiationRequest{
		UserIdentifier: "testuser",
		Group:          DefaultGroup,
	}

	body, _ := json.Marshal(beginReq)
	req := httptest.NewRequest(http.MethodPost, "/assert/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	assert.Equal(t, http.StatusUnauthorized, recorder.Code)
	assert.Contains(t, recorder.Body.String(), "group mismatch")
}
