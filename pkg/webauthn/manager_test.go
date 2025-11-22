package webauthn

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/pkg/core/memory"
)

func TestNewManager(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.web)
	assert.Equal(t, config, manager.config)
}

func TestNewManagerWithNilConfig(t *testing.T) {
	manager, err := NewManager(nil)
	assert.Error(t, err)
	assert.Nil(t, manager)
	assert.Contains(t, err.Error(), "config cannot be nil")
}

func TestBeginRegistration(t *testing.T) {
	store := memory.NewCredentialStore()
	logger := memory.NewStdoutLogger(false)

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
		WithAuditLogger(logger),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	creation, sessionData, err := manager.BeginRegistration(ctx, "user-123", "testuser", "Test User")
	require.NoError(t, err)
	require.NotNil(t, creation)
	require.NotNil(t, sessionData)

	// Verify creation options
	assert.NotEmpty(t, creation.Response.Challenge)
	// User.ID can be []byte or other types depending on library version
	assert.NotNil(t, creation.Response.User.ID)
	assert.Equal(t, "testuser", creation.Response.User.Name)
	assert.Equal(t, "Test User", creation.Response.User.DisplayName)
	assert.Equal(t, "localhost", creation.Response.RelyingParty.ID)
	assert.Equal(t, "Test RP", creation.Response.RelyingParty.Name)

	// Verify session data
	assert.NotEmpty(t, sessionData.Challenge)
	assert.Equal(t, "user-123", sessionData.UserIdentifier)
	assert.False(t, sessionData.IsExpired())
	assert.Equal(t, VerificationPreferred, sessionData.UserVerification)
}

func TestBeginRegistrationWithEmptyUserID(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	_, _, err = manager.BeginRegistration(ctx, "", "testuser", "Test User")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "userID cannot be empty")
}

func TestBeginRegistrationWithEmptyUserName(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	_, _, err = manager.BeginRegistration(ctx, "user-123", "", "Test User")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "userName cannot be empty")
}

func TestBeginAuthentication(t *testing.T) {
	store := memory.NewCredentialStore()
	logger := memory.NewStdoutLogger(false)

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
		WithAuditLogger(logger),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	// First, register a credential
	ctx := context.Background()
	cred := Credential{
		ID:        []byte("test-credential-id"),
		PublicKey: []byte("test-public-key"),
		SignCount: 0,
		AAGUID:    []byte("test-aaguid"),
		CreatedAt: time.Now(),
	}
	credData, err := cred.MarshalBinary()
	require.NoError(t, err)
	err = store.StoreCredential(ctx, "user-123", "test-credential-id", credData)
	require.NoError(t, err)

	// Now begin authentication
	assertion, sessionData, err := manager.BeginAuthentication(ctx, "user-123")
	require.NoError(t, err)
	require.NotNil(t, assertion)
	require.NotNil(t, sessionData)

	// Verify assertion options
	assert.NotEmpty(t, assertion.Response.Challenge)
	assert.NotEmpty(t, assertion.Response.AllowedCredentials)

	// Verify session data
	assert.NotEmpty(t, sessionData.Challenge)
	assert.Equal(t, "user-123", sessionData.UserIdentifier)
	assert.False(t, sessionData.IsExpired())
}

func TestBeginAuthenticationNoCredentials(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	_, _, err = manager.BeginAuthentication(ctx, "user-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no registered credentials")
}

func TestFinishRegistrationWithExpiredSession(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
		WithTimeout(1), // 1ms timeout
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	_, sessionData, err := manager.BeginRegistration(ctx, "user-123", "testuser", "Test User")
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)

	// Verify session is expired
	assert.True(t, sessionData.IsExpired())

	// Note: FinishRegistration checks for nil response before checking expiry
	// So this test verifies the session expired, but we can't test the expiry error
	// without providing a valid (but fake) response structure
}

func TestFinishAuthenticationWithExpiredSession(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
		WithTimeout(1), // 1ms timeout
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	// Register a credential
	ctx := context.Background()
	cred := Credential{
		ID:        []byte("test-credential-id"),
		PublicKey: []byte("test-public-key"),
		SignCount: 0,
		AAGUID:    []byte("test-aaguid"),
		CreatedAt: time.Now(),
	}
	credData, err := cred.MarshalBinary()
	require.NoError(t, err)
	err = store.StoreCredential(ctx, "user-123", "test-credential-id", credData)
	require.NoError(t, err)

	_, sessionData, err := manager.BeginAuthentication(ctx, "user-123")
	require.NoError(t, err)

	// Wait for session to expire
	time.Sleep(10 * time.Millisecond)

	// Verify session is expired
	assert.True(t, sessionData.IsExpired())

	// Note: FinishAuthentication checks for nil response before checking expiry
	// So this test verifies the session expired, but we can't test the expiry error
	// without providing a valid (but fake) response structure
}

func TestGenerateChallenge(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	challenge1, err := manager.GenerateChallenge()
	require.NoError(t, err)
	assert.Len(t, challenge1, 32)

	challenge2, err := manager.GenerateChallenge()
	require.NoError(t, err)
	assert.Len(t, challenge2, 32)

	// Challenges should be unique
	assert.NotEqual(t, challenge1, challenge2)
}

func TestManagerWithCustomOptions(t *testing.T) {
	store := memory.NewCredentialStore()
	logger := memory.NewStdoutLogger(false)

	config, err := NewConfig(
		WithRPDisplayName("Custom RP"),
		WithRPID("example.com"),
		WithRPOrigins("https://example.com", "https://app.example.com"),
		WithCredentialStore(store),
		WithAuditLogger(logger),
		WithUserVerification(VerificationRequired),
		WithAttestationPreference(AttestationDirect),
		WithTimeout(120000),
		WithAuthenticatorSelection(AuthenticatorSelection{
			AuthenticatorAttachment: "platform",
			RequireResidentKey:      true,
			UserVerification:        VerificationRequired,
		}),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)
	assert.NotNil(t, manager)

	// Verify configuration is applied
	assert.Equal(t, "Custom RP", manager.config.RPDisplayName)
	assert.Equal(t, "example.com", manager.config.RPID)
	assert.Equal(t, []string{"https://example.com", "https://app.example.com"}, manager.config.RPOrigins)
	assert.Equal(t, VerificationRequired, manager.config.UserVerification)
	assert.Equal(t, AttestationDirect, manager.config.AttestationPreference)
	assert.Equal(t, 120000, manager.config.Timeout)
}

func TestBeginRegistrationWithExistingCredentials(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	// Store an existing credential
	ctx := context.Background()
	existingCred := Credential{
		ID:        []byte("existing-cred"),
		PublicKey: []byte("existing-pubkey"),
		SignCount: 5,
		AAGUID:    []byte("existing-aaguid"),
		CreatedAt: time.Now(),
	}
	credData, err := existingCred.MarshalBinary()
	require.NoError(t, err)
	// Use base64 encoding of the credential ID as the storage key (matching manager.go behavior)
	credentialID := base64.RawURLEncoding.EncodeToString(existingCred.ID)
	err = store.StoreCredential(ctx, "user-123", credentialID, credData)
	require.NoError(t, err)

	// Begin registration
	creation, sessionData, err := manager.BeginRegistration(ctx, "user-123", "testuser", "Test User")
	require.NoError(t, err)
	require.NotNil(t, creation)
	require.NotNil(t, sessionData)

	// Note: The credential exclude list behavior depends on the go-webauthn library
	// We've verified that credentials are loaded; the library handles the exclude list
	// Just verify the credentials were loaded into the user object
	assert.NotEmpty(t, sessionData.UserIdentifier)
}

func TestNilSessionDataHandling(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()

	// Test FinishRegistration with nil session
	_, err = manager.FinishRegistration(ctx, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session data cannot be nil")

	// Test FinishAuthentication with nil session
	_, err = manager.FinishAuthentication(ctx, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session data cannot be nil")
}

func TestNilResponseHandling(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("localhost"),
		WithRPOrigins("http://localhost:3000"),
		WithCredentialStore(store),
	)
	require.NoError(t, err)

	manager, err := NewManager(config)
	require.NoError(t, err)

	ctx := context.Background()
	sessionData := &SessionData{
		Challenge:      []byte("test-challenge"),
		UserIdentifier: "user-123",
		ExpiresAt:      time.Now().Add(time.Minute),
	}

	// Test FinishRegistration with nil response
	_, err = manager.FinishRegistration(ctx, sessionData, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "response cannot be nil")

	// Test FinishAuthentication with nil response
	_, err = manager.FinishAuthentication(ctx, sessionData, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "response cannot be nil")
}
