package webauthn

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"go.fergus.london/nopasswords/pkg/core"
)

// Manager handles WebAuthn registration and authentication operations.
// It wraps the go-webauthn library with NoPasswords interfaces and patterns.
//
// Manager is safe for concurrent use by multiple goroutines.
type Manager struct {
	config *Config
	web    *webauthn.WebAuthn
}

// NewManager creates a new WebAuthn manager with the given configuration.
func NewManager(config *Config) (*Manager, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Create underlying webauthn instance
	wconfig := &webauthn.Config{
		RPDisplayName: config.RPDisplayName,
		RPID:          config.RPID,
		RPOrigins:     config.RPOrigins,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Duration(config.Timeout) * time.Millisecond,
				TimeoutUVD: time.Duration(config.Timeout) * time.Millisecond,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Duration(config.Timeout) * time.Millisecond,
				TimeoutUVD: time.Duration(config.Timeout) * time.Millisecond,
			},
		},
	}

	web, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create webauthn instance: %w", err)
	}

	return &Manager{
		config: config,
		web:    web,
	}, nil
}

// BeginRegistration initiates the WebAuthn registration ceremony (attestation).
// It generates a credential creation challenge and options for the client.
//
// The returned challenge and session data must be stored server-side and associated
// with the user's session. The session data will be needed to complete registration.
//
// Security Considerations:
// @risk Elevation of Privilege: The challenge must be cryptographically random and
// stored securely. Session data must be bound to the user's session to prevent
// replay attacks.
//
// Parameters:
//   - ctx: Context for the operation
//   - userID: Unique identifier for the user
//   - userName: Username (should be unique and not contain sensitive info)
//   - userDisplayName: Human-readable display name
//
// Returns:
//   - *protocol.CredentialCreation: Challenge and options to send to the client
//   - *SessionData: Session data to store server-side
//   - error: Any error that occurred
func (m *Manager) BeginRegistration(ctx context.Context, userID, userName, userDisplayName string) (*protocol.CredentialCreation, *SessionData, error) {
	if userID == "" {
		return nil, nil, fmt.Errorf("userID cannot be empty")
	}
	if userName == "" {
		return nil, nil, fmt.Errorf("userName cannot be empty")
	}

	// Log audit event
	_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
		Timestamp:      time.Now(),
		EventType:      "webauthn.registration.begin",
		UserIdentifier: userID,
		Outcome:        "initiated",
		Metadata: map[string]interface{}{
			"userName": userName,
		},
	})

	// Load existing credentials for this user (for excluded credentials)
	credentialIDs, err := m.config.CredentialStore.ListCredentials(ctx, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list existing credentials: %w", err)
	}

	// Build user object
	user := &User{
		ID:          []byte(userID),
		Name:        userName,
		DisplayName: userDisplayName,
		Credentials: make([]Credential, 0),
	}

	// Load existing credentials
	for _, credID := range credentialIDs {
		credData, err := m.config.CredentialStore.GetCredential(ctx, userID, credID)
		if err != nil {
			continue // Skip invalid credentials
		}
		var cred Credential
		if err := cred.UnmarshalBinary(credData); err != nil {
			continue // Skip invalid credentials
		}
		user.Credentials = append(user.Credentials, cred)
	}

	// Configure registration options
	var authSelection *protocol.AuthenticatorSelection
	if m.config.AuthenticatorSelection.AuthenticatorAttachment != "" ||
		m.config.AuthenticatorSelection.RequireResidentKey {
		authSelection = &protocol.AuthenticatorSelection{
			RequireResidentKey: &m.config.AuthenticatorSelection.RequireResidentKey,
			UserVerification:   protocol.UserVerificationRequirement(m.config.UserVerification),
		}
		if m.config.AuthenticatorSelection.AuthenticatorAttachment != "" {
			attachment := protocol.AuthenticatorAttachment(m.config.AuthenticatorSelection.AuthenticatorAttachment)
			authSelection.AuthenticatorAttachment = attachment
		}
	}

	options := []webauthn.RegistrationOption{
		webauthn.WithConveyancePreference(protocol.ConveyancePreference(m.config.AttestationPreference)),
	}
	if authSelection != nil {
		options = append(options, webauthn.WithAuthenticatorSelection(*authSelection))
	}

	// Generate registration challenge
	creation, session, err := m.web.BeginRegistration(user, options...)
	if err != nil {
		_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
			Timestamp:      time.Now(),
			EventType:      "webauthn.registration.begin",
			UserIdentifier: userID,
			Outcome:        "failure",
			Metadata: map[string]interface{}{
				"error": err.Error(),
			},
		})
		return nil, nil, fmt.Errorf("failed to begin registration: %w", err)
	}

	// Create session data
	// Decode challenge from base64 string to bytes
	challengeBytes, err := base64.RawURLEncoding.DecodeString(session.Challenge)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode challenge: %w", err)
	}

	sessionData := &SessionData{
		Challenge:        challengeBytes,
		UserIdentifier:   userID,
		ExpiresAt:        time.Now().Add(time.Duration(m.config.Timeout) * time.Millisecond),
		UserVerification: m.config.UserVerification,
	}

	return creation, sessionData, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
// It verifies the attestation response from the client and stores the credential.
//
// Security Considerations:
// @risk Tampering: Insufficient attestation verification allows credential injection.
// The go-webauthn library handles verification, but we must ensure the session data
// matches and hasn't been tampered with.
//
// @risk Denial of Service: Unbounded credential storage per user. Applications should
// implement limits on credentials per user.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionData: The session data from BeginRegistration
//   - response: The attestation response from the client (parsed from JSON)
//
// Returns:
//   - *RegistrationResult: Details of the registered credential
//   - error: Any error that occurred
func (m *Manager) FinishRegistration(ctx context.Context, sessionData *SessionData, response *protocol.ParsedCredentialCreationData) (*RegistrationResult, error) {
	if sessionData == nil {
		return nil, fmt.Errorf("session data cannot be nil")
	}
	if response == nil {
		return nil, fmt.Errorf("response cannot be nil")
	}

	// Load user
	credentialIDs, err := m.config.CredentialStore.ListCredentials(ctx, sessionData.UserIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	user := &User{
		ID:          []byte(sessionData.UserIdentifier),
		Name:        sessionData.UserIdentifier, // Applications should map this properly
		DisplayName: sessionData.UserIdentifier,
		Credentials: make([]Credential, 0),
	}

	// Load existing credentials
	for _, credID := range credentialIDs {
		credData, err := m.config.CredentialStore.GetCredential(ctx, sessionData.UserIdentifier, credID)
		if err != nil {
			continue
		}
		var cred Credential
		if err := cred.UnmarshalBinary(credData); err != nil {
			continue
		}
		user.Credentials = append(user.Credentials, cred)
	}

	// Reconstruct session for verification
	// Encode challenge from bytes to base64 string
	webSession := webauthn.SessionData{
		Challenge:        base64.RawURLEncoding.EncodeToString(sessionData.Challenge),
		UserID:           []byte(sessionData.UserIdentifier),
		UserVerification: protocol.UserVerificationRequirement(sessionData.UserVerification),
	}

	// Verify attestation
	credential, err := m.web.CreateCredential(user, webSession, response)
	if err != nil {
		_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
			Timestamp:      time.Now(),
			EventType:      "webauthn.registration.finish",
			UserIdentifier: sessionData.UserIdentifier,
			Outcome:        "failure",
			Metadata: map[string]interface{}{
				"error": "attestation verification failed",
			},
		})
		return nil, fmt.Errorf("attestation verification failed: %w", err)
	}

	// Convert to our credential format
	cred := Credential{
		ID:         credential.ID,
		PublicKey:  credential.PublicKey,
		SignCount:  credential.Authenticator.SignCount,
		AAGUID:     credential.Authenticator.AAGUID,
		Transport:  transportStrings(credential.Transport),
		CreatedAt:  time.Now(),
		LastUsedAt: time.Time{},
	}

	// Store credential
	credData, err := cred.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	credentialID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if err := m.config.CredentialStore.StoreCredential(ctx, sessionData.UserIdentifier, credentialID, credData); err != nil {
		_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
			Timestamp:      time.Now(),
			EventType:      "webauthn.registration.finish",
			UserIdentifier: sessionData.UserIdentifier,
			Outcome:        "failure",
			Metadata: map[string]interface{}{
				"error": "failed to store credential",
			},
		})
		return nil, fmt.Errorf("failed to store credential: %w", err)
	}

	// Log success
	_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
		Timestamp:      time.Now(),
		EventType:      "webauthn.registration.finish",
		UserIdentifier: sessionData.UserIdentifier,
		Outcome:        "success",
		Metadata: map[string]interface{}{
			"credentialID": credentialID,
		},
	})

	result := &RegistrationResult{
		Credential:     cred,
		UserIdentifier: sessionData.UserIdentifier,
		Timestamp:      time.Now(),
	}

	return result, nil
}

// BeginAuthentication initiates the WebAuthn authentication ceremony (assertion).
// It generates an assertion challenge for the client.
//
// If userID is provided, the challenge will be scoped to that user's credentials.
// If userID is empty, it allows discoverable credentials (resident keys).
//
// Security Considerations:
// @risk Elevation of Privilege: Challenge must be cryptographically random and verified.
// @risk Information Disclosure: Timing attacks on credential enumeration. Consider
// using constant-time operations and rate limiting.
//
// Parameters:
//   - ctx: Context for the operation
//   - userID: User identifier (empty string for discoverable credentials)
//
// Returns:
//   - *protocol.CredentialAssertion: Challenge and options to send to the client
//   - *SessionData: Session data to store server-side
//   - error: Any error that occurred
func (m *Manager) BeginAuthentication(ctx context.Context, userID string) (*protocol.CredentialAssertion, *SessionData, error) {
	// Log audit event
	_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
		Timestamp:      time.Now(),
		EventType:      "webauthn.authentication.begin",
		UserIdentifier: userID,
		Outcome:        "initiated",
		Metadata:       map[string]interface{}{},
	})

	var user *User
	var allowedCredentials [][]byte

	if userID != "" {
		// User-scoped authentication
		credentialIDs, err := m.config.CredentialStore.ListCredentials(ctx, userID)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list credentials: %w", err)
		}

		if len(credentialIDs) == 0 {
			_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
				Timestamp:      time.Now(),
				EventType:      "webauthn.authentication.begin",
				UserIdentifier: userID,
				Outcome:        "failure",
				Metadata: map[string]interface{}{
					"error": "no credentials found",
				},
			})
			return nil, nil, fmt.Errorf("user has no registered credentials")
		}

		user = &User{
			ID:          []byte(userID),
			Name:        userID,
			DisplayName: userID,
			Credentials: make([]Credential, 0),
		}

		// Load credentials
		for _, credID := range credentialIDs {
			credData, err := m.config.CredentialStore.GetCredential(ctx, userID, credID)
			if err != nil {
				continue
			}
			var cred Credential
			if err := cred.UnmarshalBinary(credData); err != nil {
				continue
			}
			user.Credentials = append(user.Credentials, cred)
			allowedCredentials = append(allowedCredentials, cred.ID)
		}

		if len(user.Credentials) == 0 {
			return nil, nil, fmt.Errorf("failed to load user credentials")
		}
	} else {
		// Discoverable credential authentication (no user specified)
		// Create empty user for the library
		user = &User{
			ID:          []byte{},
			Name:        "",
			DisplayName: "",
			Credentials: make([]Credential, 0),
		}
	}

	// Generate authentication challenge
	options := []webauthn.LoginOption{
		webauthn.WithUserVerification(protocol.UserVerificationRequirement(m.config.UserVerification)),
	}

	assertion, session, err := m.web.BeginLogin(user, options...)
	if err != nil {
		_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
			Timestamp:      time.Now(),
			EventType:      "webauthn.authentication.begin",
			UserIdentifier: userID,
			Outcome:        "failure",
			Metadata: map[string]interface{}{
				"error": err.Error(),
			},
		})
		return nil, nil, fmt.Errorf("failed to begin authentication: %w", err)
	}

	// Create session data
	// Decode challenge from base64 string to bytes
	challengeBytes, err := base64.RawURLEncoding.DecodeString(session.Challenge)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode challenge: %w", err)
	}

	sessionData := &SessionData{
		Challenge:          challengeBytes,
		UserIdentifier:     userID,
		ExpiresAt:          time.Now().Add(time.Duration(m.config.Timeout) * time.Millisecond),
		AllowedCredentials: allowedCredentials,
		UserVerification:   m.config.UserVerification,
	}

	return assertion, sessionData, nil
}

// FinishAuthentication completes the WebAuthn authentication ceremony.
// It verifies the assertion response from the client and updates the credential.
//
// Security Considerations:
// @risk Tampering: The assertion signature must be verified against the stored public key.
// The go-webauthn library handles this, but we must ensure proper credential lookup.
//
// @risk Elevation of Privilege: Sign counter must be validated to detect cloned credentials.
// A counter that doesn't increment or goes backward indicates a potential security issue.
//
// Parameters:
//   - ctx: Context for the operation
//   - sessionData: The session data from BeginAuthentication
//   - response: The assertion response from the client (parsed from JSON)
//
// Returns:
//   - *AuthenticationResult: Details of the authentication
//   - error: Any error that occurred
func (m *Manager) FinishAuthentication(ctx context.Context, sessionData *SessionData, response *protocol.ParsedCredentialAssertionData) (*AuthenticationResult, error) {
	if sessionData == nil {
		return nil, fmt.Errorf("session data cannot be nil")
	}
	if response == nil {
		return nil, fmt.Errorf("response cannot be nil")
	}

	// Check session expiry
	// @mitigation Elevation of Privilege: Enforce session timeout to prevent replay attacks
	if sessionData.IsExpired() {
		_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
			Timestamp:      time.Now(),
			EventType:      "webauthn.authentication.finish",
			UserIdentifier: sessionData.UserIdentifier,
			Outcome:        "failure",
			Metadata: map[string]interface{}{
				"error": "session expired",
			},
		})
		return nil, fmt.Errorf("session has expired")
	}

	// For discoverable credentials, we need to find the user from the credential
	userID := sessionData.UserIdentifier
	if userID == "" {
		// This would require iterating through all users, which is not scalable
		// Applications should either:
		// 1. Use user-scoped authentication
		// 2. Implement a credential-to-user mapping in their CredentialStore
		return nil, fmt.Errorf("discoverable credentials require credential-to-user mapping (not implemented)")
	}

	// Load user credentials
	credentialIDs, err := m.config.CredentialStore.ListCredentials(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list credentials: %w", err)
	}

	user := &User{
		ID:          []byte(userID),
		Name:        userID,
		DisplayName: userID,
		Credentials: make([]Credential, 0),
	}

	// Load credentials
	for _, credID := range credentialIDs {
		credData, err := m.config.CredentialStore.GetCredential(ctx, userID, credID)
		if err != nil {
			continue
		}
		var cred Credential
		if err := cred.UnmarshalBinary(credData); err != nil {
			continue
		}
		user.Credentials = append(user.Credentials, cred)
	}

	if len(user.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials found for user")
	}

	// Reconstruct session for verification
	// Encode challenge from bytes to base64 string
	webSession := webauthn.SessionData{
		Challenge:        base64.RawURLEncoding.EncodeToString(sessionData.Challenge),
		UserID:           []byte(userID),
		UserVerification: protocol.UserVerificationRequirement(sessionData.UserVerification),
	}

	// Verify assertion
	credential, err := m.web.ValidateLogin(user, webSession, response)
	if err != nil {
		_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
			Timestamp:      time.Now(),
			EventType:      "webauthn.authentication.finish",
			UserIdentifier: userID,
			Outcome:        "failure",
			Metadata: map[string]interface{}{
				"error": "assertion verification failed",
			},
		})
		return nil, fmt.Errorf("assertion verification failed: %w", err)
	}

	// Update credential with new sign count and last used time
	credentialID := base64.RawURLEncoding.EncodeToString(credential.ID)
	credData, err := m.config.CredentialStore.GetCredential(ctx, userID, credentialID)
	if err != nil {
		return nil, fmt.Errorf("failed to get credential: %w", err)
	}

	var cred Credential
	if err := cred.UnmarshalBinary(credData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	// @mitigation Elevation of Privilege: Validate sign counter to detect cloned authenticators
	// If the counter doesn't increment, it could indicate a cloned credential
	if credential.Authenticator.SignCount > 0 && credential.Authenticator.SignCount <= cred.SignCount {
		_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
			Timestamp:      time.Now(),
			EventType:      "webauthn.authentication.finish",
			UserIdentifier: userID,
			Outcome:        "failure",
			Metadata: map[string]interface{}{
				"error":          "sign counter anomaly detected",
				"stored_count":   cred.SignCount,
				"received_count": credential.Authenticator.SignCount,
			},
		})
		return nil, fmt.Errorf("sign counter anomaly: possible cloned authenticator")
	}

	// Update credential
	cred.SignCount = credential.Authenticator.SignCount
	cred.LastUsedAt = time.Now()

	updatedData, err := cred.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}

	if err := m.config.CredentialStore.UpdateCredential(ctx, userID, credentialID, updatedData); err != nil {
		_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
			Timestamp:      time.Now(),
			EventType:      "webauthn.authentication.finish",
			UserIdentifier: userID,
			Outcome:        "warning",
			Metadata: map[string]interface{}{
				"error": "failed to update credential",
			},
		})
		// Don't fail authentication if update fails, but log it
	}

	// Log success
	_ = m.config.AuditLogger.Log(ctx, core.AuditEvent{
		Timestamp:      time.Now(),
		EventType:      "webauthn.authentication.finish",
		UserIdentifier: userID,
		Outcome:        "success",
		Metadata: map[string]interface{}{
			"credentialID": credentialID,
		},
	})

	result := &AuthenticationResult{
		UserIdentifier: userID,
		CredentialID:   credential.ID,
		SignCount:      credential.Authenticator.SignCount,
		Timestamp:      time.Now(),
		UserVerified:   response.Response.AuthenticatorData.Flags.HasUserVerified(),
		UserPresent:    response.Response.AuthenticatorData.Flags.HasUserPresent(),
	}

	return result, nil
}

// GenerateChallenge generates a cryptographically random challenge.
// This is useful for custom flows that need explicit challenge generation.
func (m *Manager) GenerateChallenge() ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %w", err)
	}
	return challenge, nil
}

// transportStrings converts protocol transport types to strings.
func transportStrings(transports []protocol.AuthenticatorTransport) []string {
	if len(transports) == 0 {
		return nil
	}
	result := make([]string, len(transports))
	for i, t := range transports {
		result[i] = string(t)
	}
	return result
}
