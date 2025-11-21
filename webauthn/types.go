// Package webauthn provides WebAuthn/FIDO2 authentication support for the NoPasswords
// library. It wraps the go-webauthn library with NoPasswords interfaces and patterns.
package webauthn

import (
	"encoding/json"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// UserVerificationRequirement specifies the user verification requirement for WebAuthn operations.
type UserVerificationRequirement string

const (
	// VerificationRequired requires user verification (biometric, PIN, etc.)
	VerificationRequired UserVerificationRequirement = "required"
	// VerificationPreferred requests user verification but allows fallback
	VerificationPreferred UserVerificationRequirement = "preferred"
	// VerificationDiscouraged actively discourages user verification
	VerificationDiscouraged UserVerificationRequirement = "discouraged"
)

// AttestationPreference specifies the attestation conveyance preference.
type AttestationPreference string

const (
	// AttestationNone requests no attestation (most privacy-friendly)
	AttestationNone AttestationPreference = "none"
	// AttestationIndirect allows anonymized attestation
	AttestationIndirect AttestationPreference = "indirect"
	// AttestationDirect requests full attestation chain
	AttestationDirect AttestationPreference = "direct"
	// AttestationEnterprise requests enterprise attestation (if supported)
	AttestationEnterprise AttestationPreference = "enterprise"
)

// AuthenticatorSelection specifies requirements for the authenticator.
type AuthenticatorSelection struct {
	// AuthenticatorAttachment specifies platform or cross-platform authenticator
	// Empty string means no preference
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	// RequireResidentKey specifies if a resident key is required
	RequireResidentKey bool `json:"requireResidentKey"`
	// UserVerification specifies the user verification requirement
	UserVerification UserVerificationRequirement `json:"userVerification"`
}

// Credential represents a stored WebAuthn credential with all necessary data
// for authentication verification.
//
// Security Considerations:
// @risk Information Disclosure: This structure contains sensitive cryptographic material.
// The PublicKey should be protected from unauthorized access.
type Credential struct {
	// ID is the unique identifier for this credential (raw bytes)
	ID []byte `json:"id"`
	// PublicKey is the credential public key in COSE format
	PublicKey []byte `json:"publicKey"`
	// SignCount is the authenticator's signature counter (for clone detection)
	SignCount uint32 `json:"signCount"`
	// AAGUID is the authenticator's Attestation GUID
	AAGUID []byte `json:"aaguid"`
	// Transport indicates how the authenticator communicates (USB, NFC, BLE, internal)
	Transport []string `json:"transport,omitempty"`
	// CreatedAt is when the credential was registered
	CreatedAt time.Time `json:"createdAt"`
	// LastUsedAt is when the credential was last used for authentication
	LastUsedAt time.Time `json:"lastUsedAt,omitempty"`
}

// MarshalBinary encodes the credential to JSON for storage.
func (c *Credential) MarshalBinary() ([]byte, error) {
	return json.Marshal(c)
}

// UnmarshalBinary decodes the credential from JSON storage.
func (c *Credential) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, c)
}

// User represents a WebAuthn user, implementing the webauthn.User interface.
// This is a lightweight wrapper that applications should adapt to their user model.
type User struct {
	ID          []byte
	Name        string
	DisplayName string
	// Credentials is the list of WebAuthn credentials for this user
	Credentials []Credential
}

// WebAuthnID returns the user's ID as required by the webauthn.User interface.
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the user's username as required by the webauthn.User interface.
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name as required by the webauthn.User interface.
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnIcon returns the user's icon URL (deprecated in WebAuthn spec, returns empty string).
func (u *User) WebAuthnIcon() string {
	return ""
}

// WebAuthnCredentials returns the user's credentials as required by the webauthn.User interface.
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	credentials := make([]webauthn.Credential, len(u.Credentials))
	for i, cred := range u.Credentials {
		credentials[i] = webauthn.Credential{
			ID:              cred.ID,
			PublicKey:       cred.PublicKey,
			AttestationType: "",
			Transport:       protocolTransport(cred.Transport),
			Flags: webauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: false,
				BackupState:    false,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:    cred.AAGUID,
				SignCount: cred.SignCount,
			},
		}
	}
	return credentials
}

// protocolTransport converts string transport types to protocol types.
func protocolTransport(transports []string) []protocol.AuthenticatorTransport {
	if len(transports) == 0 {
		return nil
	}
	result := make([]protocol.AuthenticatorTransport, len(transports))
	for i, t := range transports {
		result[i] = protocol.AuthenticatorTransport(t)
	}
	return result
}

// RegistrationResult contains the outcome of a successful WebAuthn registration.
type RegistrationResult struct {
	// Credential is the newly registered credential
	Credential Credential
	// UserID is the user identifier
	UserIdentifier string
	// Timestamp is when the registration completed
	Timestamp time.Time
}

// AuthenticationResult contains the outcome of a successful WebAuthn authentication.
type AuthenticationResult struct {
	// UserID is the authenticated user's identifier
	UserIdentifier string
	// CredentialID is the credential used for authentication
	CredentialID []byte
	// SignCount is the new signature counter value
	SignCount uint32
	// Timestamp is when the authentication completed
	Timestamp time.Time
	// UserVerified indicates if user verification was performed
	UserVerified bool
	// UserPresent indicates if user presence was verified
	UserPresent bool
}

// SessionData represents temporary data stored during multi-step WebAuthn ceremonies.
// This must be stored server-side and associated with the user's session.
//
// Security Considerations:
// @risk Elevation of Privilege: Session data MUST be stored securely and bound to the
// user's session. Failure to properly validate session data enables replay attacks.
//
// @risk Tampering: Challenge values must be cryptographically random and verified.
// The session data should be stored server-side, never sent to the client.
type SessionData struct {
	// Challenge is the cryptographic challenge for this ceremony
	Challenge []byte `json:"challenge"`
	// UserID is the user identifier for this ceremony
	UserIdentifier string `json:"userID"`
	// ExpiresAt is when this session data expires
	ExpiresAt time.Time `json:"expiresAt"`
	// AllowedCredentials lists the credential IDs allowed for this ceremony (for assertion)
	AllowedCredentials [][]byte `json:"allowedCredentials,omitempty"`
	// UserVerification is the verification requirement for this ceremony
	UserVerification UserVerificationRequirement `json:"userVerification"`
}

// MarshalBinary encodes session data to JSON.
func (s *SessionData) MarshalBinary() ([]byte, error) {
	return json.Marshal(s)
}

// UnmarshalBinary decodes session data from JSON.
func (s *SessionData) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, s)
}

// IsExpired checks if the session data has expired.
func (s *SessionData) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
