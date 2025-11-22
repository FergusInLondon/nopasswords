package srp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/pkg/core/events/memory"
)

func TestAttestationHandler_InvalidJSON(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AttestationHandlerFunc(func(params Parameters) {})

	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	var resp AttestationResponse
	err = json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.Success)
}

func TestAttestationHandler_EmptyUserIdentifier(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AttestationHandlerFunc(func(params Parameters) {})

	attestReq := &AttestationRequest{
		UserIdentifier: "", // Empty user ID
		Salt:           make([]byte, DefaultSaltLength),
		Verifier:       []byte{1, 2, 3},
		Group:          DefaultGroup,
	}

	body, _ := json.Marshal(attestReq)
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	var resp AttestationResponse
	err = json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.UserIdentifier, "user ID cannot be empty")
}

func TestAttestationHandler_SaltTooShort(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AttestationHandlerFunc(func(params Parameters) {})

	attestReq := &AttestationRequest{
		UserIdentifier: "testuser",
		Salt:           make([]byte, MinSaltLength-1), // Too short
		Verifier:       []byte{1, 2, 3},
		Group:          DefaultGroup,
	}

	body, _ := json.Marshal(attestReq)
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	var resp AttestationResponse
	err = json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.UserIdentifier, "insufficient salt length")
}

func TestAttestationHandler_EmptyVerifier(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
	)
	require.NoError(t, err)

	handler := manager.AttestationHandlerFunc(func(params Parameters) {})

	attestReq := &AttestationRequest{
		UserIdentifier: "testuser",
		Salt:           make([]byte, DefaultSaltLength),
		Verifier:       []byte{}, // Empty verifier
		Group:          DefaultGroup,
	}

	body, _ := json.Marshal(attestReq)
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	var resp AttestationResponse
	err = json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.UserIdentifier, "verifier cannot be empty")
}

func TestAttestationHandler_GroupMismatch(t *testing.T) {
	manager, err := NewManager(
		WithParameterStore(newInMemoryParameterStore()),
		WithStateCache(newInMemoryStateCache()),
		WithEventLogger(memory.NewNopLogger()),
		WithGroup(3), // Server configured for group 3
	)
	require.NoError(t, err)

	handler := manager.AttestationHandlerFunc(func(params Parameters) {})

	attestReq := &AttestationRequest{
		UserIdentifier: "testuser",
		Salt:           make([]byte, DefaultSaltLength),
		Verifier:       []byte{1, 2, 3},
		Group:          4, // Client requesting group 4
	}

	body, _ := json.Marshal(attestReq)
	req := httptest.NewRequest(http.MethodPost, "/attest", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	var resp AttestationResponse
	err = json.NewDecoder(recorder.Body).Decode(&resp)
	require.NoError(t, err)
	assert.False(t, resp.Success)
	assert.Contains(t, resp.UserIdentifier, "group mismatch")
}
