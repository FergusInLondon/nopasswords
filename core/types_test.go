package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthResult(t *testing.T) {
	now := time.Now()

	result := AuthResult{
		Success:      true,
		UserIdentifier:       "user123",
		CredentialID: "cred456",
		Method:       "webauthn",
		Timestamp:    now,
		Metadata: map[string]interface{}{
			"key": "value",
		},
		Error: nil,
	}

	assert.True(t, result.Success)
	assert.Equal(t, "user123", result.UserIdentifier)
	assert.Equal(t, "cred456", result.CredentialID)
	assert.Equal(t, "webauthn", result.Method)
	assert.Equal(t, now, result.Timestamp)
	assert.Nil(t, result.Error)
	assert.Equal(t, "value", result.Metadata["key"])
}

func TestAuditEvent(t *testing.T) {
	now := time.Now()

	event := AuditEvent{
		EventID:      "evt123",
		Timestamp:    now,
		EventType:    EventAuthSuccess,
		Method:       "srp",
		UserIdentifier:       "user456",
		CredentialID: "cred789",
		Outcome:      OutcomeSuccess,
		Reason:       "valid_password",
		IPAddress:    "192.168.1.1",
		UserAgent:    "Mozilla/5.0",
		Metadata: map[string]interface{}{
			"session": "sess123",
		},
	}

	assert.Equal(t, "evt123", event.EventID)
	assert.Equal(t, now, event.Timestamp)
	assert.Equal(t, EventAuthSuccess, event.EventType)
	assert.Equal(t, "srp", event.Method)
	assert.Equal(t, "user456", event.UserIdentifier)
	assert.Equal(t, "cred789", event.CredentialID)
	assert.Equal(t, OutcomeSuccess, event.Outcome)
	assert.Equal(t, "valid_password", event.Reason)
	assert.Equal(t, "192.168.1.1", event.IPAddress)
	assert.Equal(t, "Mozilla/5.0", event.UserAgent)
	assert.Equal(t, "sess123", event.Metadata["session"])
}

func TestEventTypeConstants(t *testing.T) {
	// Verify event type constants are defined
	assert.Equal(t, "auth.attempt", EventAuthAttempt)
	assert.Equal(t, "auth.success", EventAuthSuccess)
	assert.Equal(t, "auth.failure", EventAuthFailure)
	assert.Equal(t, "credential.register", EventCredentialRegister)
	assert.Equal(t, "credential.delete", EventCredentialDelete)
	assert.Equal(t, "credential.update", EventCredentialUpdate)
	assert.Equal(t, "token.generate", EventTokenGenerate)
	assert.Equal(t, "token.verify", EventTokenVerify)
	assert.Equal(t, "token.revoke", EventTokenRevoke)
}

func TestOutcomeConstants(t *testing.T) {
	// Verify outcome constants are defined
	assert.Equal(t, "success", OutcomeSuccess)
	assert.Equal(t, "failure", OutcomeFailure)
	assert.Equal(t, "error", OutcomeError)
}

func TestConfig(t *testing.T) {
	config := Config{
		ApplicationName: "TestApp",
	}

	assert.Equal(t, "TestApp", config.ApplicationName)
	assert.Nil(t, config.CredentialStore)
	assert.Nil(t, config.AuditLogger)
}

func TestWithCredentialStore(t *testing.T) {
	mockStore := &mockCredentialStore{}
	config := &Config{}

	opt := WithCredentialStore(mockStore)
	opt(config)

	assert.Equal(t, mockStore, config.CredentialStore)
}

func TestWithAuditLogger(t *testing.T) {
	mockLogger := &mockAuditLogger{}
	config := &Config{}

	opt := WithAuditLogger(mockLogger)
	opt(config)

	assert.Equal(t, mockLogger, config.AuditLogger)
}

func TestWithApplicationName(t *testing.T) {
	config := &Config{}

	opt := WithApplicationName("MyApp")
	opt(config)

	assert.Equal(t, "MyApp", config.ApplicationName)
}

func TestApplyOptions(t *testing.T) {
	mockStore := &mockCredentialStore{}
	mockLogger := &mockAuditLogger{}

	config := &Config{}

	ApplyOptions(config,
		WithCredentialStore(mockStore),
		WithAuditLogger(mockLogger),
		WithApplicationName("TestApp"),
	)

	assert.Equal(t, mockStore, config.CredentialStore)
	assert.Equal(t, mockLogger, config.AuditLogger)
	assert.Equal(t, "TestApp", config.ApplicationName)
}

func TestApplyOptions_Empty(t *testing.T) {
	config := &Config{}

	// Should not panic with no options
	ApplyOptions(config)

	assert.Nil(t, config.CredentialStore)
	assert.Nil(t, config.AuditLogger)
}

// Mock implementations for testing

type mockCredentialStore struct{}

func (m *mockCredentialStore) StoreCredential(ctx context.Context, userID string, credentialID string, data []byte) error {
	return nil
}

func (m *mockCredentialStore) GetCredential(ctx context.Context, userID string, credentialID string) ([]byte, error) {
	return nil, nil
}

func (m *mockCredentialStore) ListCredentials(ctx context.Context, userID string) ([]string, error) {
	return nil, nil
}

func (m *mockCredentialStore) DeleteCredential(ctx context.Context, userID string, credentialID string) error {
	return nil
}

func (m *mockCredentialStore) UpdateCredential(ctx context.Context, userID string, credentialID string, data []byte) error {
	return nil
}

type mockAuditLogger struct{}

func (m *mockAuditLogger) Log(ctx context.Context, event AuditEvent) error {
	return nil
}
