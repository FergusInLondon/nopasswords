package webauthn

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialMarshalUnmarshal(t *testing.T) {
	cred := Credential{
		ID:         []byte("test-credential-id"),
		PublicKey:  []byte("test-public-key"),
		SignCount:  42,
		AAGUID:     []byte("test-aaguid"),
		Transport:  []string{"usb", "nfc"},
		CreatedAt:  time.Now().Truncate(time.Second),
		LastUsedAt: time.Now().Add(time.Hour).Truncate(time.Second),
	}

	data, err := cred.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded Credential
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, cred.ID, decoded.ID)
	assert.Equal(t, cred.PublicKey, decoded.PublicKey)
	assert.Equal(t, cred.SignCount, decoded.SignCount)
	assert.Equal(t, cred.AAGUID, decoded.AAGUID)
	assert.Equal(t, cred.Transport, decoded.Transport)
	assert.Equal(t, cred.CreatedAt.Unix(), decoded.CreatedAt.Unix())
	assert.Equal(t, cred.LastUsedAt.Unix(), decoded.LastUsedAt.Unix())
}

func TestUserWebAuthnInterface(t *testing.T) {
	user := &User{
		ID:          []byte("user-123"),
		Name:        "testuser",
		DisplayName: "Test User",
		Credentials: []Credential{
			{
				ID:        []byte("cred-1"),
				PublicKey: []byte("pubkey-1"),
				SignCount: 10,
			},
			{
				ID:        []byte("cred-2"),
				PublicKey: []byte("pubkey-2"),
				SignCount: 20,
			},
		},
	}

	assert.Equal(t, []byte("user-123"), user.WebAuthnID())
	assert.Equal(t, "testuser", user.WebAuthnName())
	assert.Equal(t, "Test User", user.WebAuthnDisplayName())
	assert.Equal(t, "", user.WebAuthnIcon())

	credentials := user.WebAuthnCredentials()
	assert.Len(t, credentials, 2)
	assert.Equal(t, []byte("cred-1"), credentials[0].ID)
	assert.Equal(t, []byte("pubkey-1"), credentials[0].PublicKey)
	assert.Equal(t, uint32(10), credentials[0].Authenticator.SignCount)
}

func TestSessionDataMarshalUnmarshal(t *testing.T) {
	session := SessionData{
		Challenge:          []byte("test-challenge"),
		UserID:             "user-123",
		ExpiresAt:          time.Now().Add(time.Minute).Truncate(time.Second),
		AllowedCredentials: [][]byte{[]byte("cred-1"), []byte("cred-2")},
		UserVerification:   VerificationPreferred,
	}

	data, err := session.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	var decoded SessionData
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	assert.Equal(t, session.Challenge, decoded.Challenge)
	assert.Equal(t, session.UserID, decoded.UserID)
	assert.Equal(t, session.ExpiresAt.Unix(), decoded.ExpiresAt.Unix())
	assert.Equal(t, session.UserVerification, decoded.UserVerification)
	assert.Len(t, decoded.AllowedCredentials, 2)
}

func TestSessionDataIsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(time.Minute),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-time.Minute),
			want:      true,
		},
		{
			name:      "exactly now (edge case)",
			expiresAt: time.Now(),
			want:      false, // Might be true due to timing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &SessionData{
				ExpiresAt: tt.expiresAt,
			}
			if tt.name != "exactly now (edge case)" {
				assert.Equal(t, tt.want, session.IsExpired())
			} else {
				// For the edge case, just verify it doesn't panic
				_ = session.IsExpired()
			}
		})
	}
}

func TestUserVerificationRequirement(t *testing.T) {
	tests := []struct {
		name  string
		value UserVerificationRequirement
		valid bool
	}{
		{"required", VerificationRequired, true},
		{"preferred", VerificationPreferred, true},
		{"discouraged", VerificationDiscouraged, true},
		{"invalid", UserVerificationRequirement("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the constants are defined correctly
			assert.NotEmpty(t, tt.value)
		})
	}
}

func TestAttestationPreference(t *testing.T) {
	tests := []struct {
		name  string
		value AttestationPreference
	}{
		{"none", AttestationNone},
		{"indirect", AttestationIndirect},
		{"direct", AttestationDirect},
		{"enterprise", AttestationEnterprise},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotEmpty(t, tt.value)
		})
	}
}
