package webauthn

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/pkg/core/events/memory"
)

func TestNewConfig(t *testing.T) {
	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid configuration",
			opts: []Option{
				WithRPDisplayName("Test RP"),
				WithRPID("example.com"),
				WithRPOrigins("https://example.com"),
			},
			wantErr: false,
		},
		{
			name: "missing display name",
			opts: []Option{
				WithRPID("example.com"),
				WithRPOrigins("https://example.com"),
				WithCredentialStore(store),
			},
			wantErr: true,
			errMsg:  "relying party display name is required",
		},
		{
			name: "missing RP ID",
			opts: []Option{
				WithRPDisplayName("Test RP"),
				WithRPOrigins("https://example.com"),
				WithCredentialStore(store),
			},
			wantErr: true,
			errMsg:  "relying party ID is required",
		},
		{
			name: "missing origins",
			opts: []Option{
				WithRPDisplayName("Test RP"),
				WithRPID("example.com"),
				WithCredentialStore(store),
			},
			wantErr: true,
			errMsg:  "at least one origin is required",
		},
		{
			name: "missing credential store",
			opts: []Option{
				WithRPDisplayName("Test RP"),
				WithRPID("example.com"),
				WithRPOrigins("https://example.com"),
			},
			wantErr: true,
			errMsg:  "credential store is required",
		},
		{
			name: "with all options",
			opts: []Option{
				WithRPDisplayName("Test RP"),
				WithRPID("example.com"),
				WithRPOrigins("https://example.com", "https://app.example.com"),
				WithCredentialStore(store),
				WithUserVerification(VerificationRequired),
				WithAttestationPreference(AttestationDirect),
				WithTimeout(30000),
				WithAuthenticatorSelection(AuthenticatorSelection{
					AuthenticatorAttachment: "platform",
					RequireResidentKey:      true,
					UserVerification:        VerificationRequired,
				}),
				WithAuditLogger(memory.NewNopLogger()),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewConfig(tt.opts...)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}
			require.NoError(t, err)
			require.NotNil(t, config)
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	store := memory.NewCredentialStore()

	config, err := NewConfig(
		WithRPDisplayName("Test RP"),
		WithRPID("example.com"),
		WithRPOrigins("https://example.com"),
		WithCredentialStore(store),
	)

	require.NoError(t, err)
	assert.Equal(t, VerificationPreferred, config.UserVerification)
	assert.Equal(t, AttestationNone, config.AttestationPreference)
	assert.Equal(t, 60000, config.Timeout)
	assert.NotNil(t, config.AuditLogger)
}

func TestWithRPDisplayName(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid name", "Test RP", false},
		{"empty name", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{}
			err := WithRPDisplayName(tt.value)(config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.value, config.RPDisplayName)
			}
		})
	}
}

func TestWithRPID(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid ID", "example.com", false},
		{"empty ID", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{}
			err := WithRPID(tt.value)(config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.value, config.RPID)
			}
		})
	}
}

func TestWithRPIDFromEnv(t *testing.T) {
	os.Setenv("WEBAUTHN_RP_ID", "env.example.com")
	defer os.Unsetenv("WEBAUTHN_RP_ID")

	config := &Config{}
	err := WithRPID("")(config)
	require.NoError(t, err)
	assert.Equal(t, "env.example.com", config.RPID)
}

func TestWithRPOrigins(t *testing.T) {
	tests := []struct {
		name    string
		origins []string
		wantErr bool
	}{
		{"single origin", []string{"https://example.com"}, false},
		{"multiple origins", []string{"https://example.com", "https://app.example.com"}, false},
		{"empty origins", []string{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{}
			err := WithRPOrigins(tt.origins...)(config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.origins, config.RPOrigins)
			}
		})
	}
}

func TestWithRPOriginsFromEnv(t *testing.T) {
	os.Setenv("WEBAUTHN_RP_ORIGINS", "https://env.example.com")
	defer os.Unsetenv("WEBAUTHN_RP_ORIGINS")

	config := &Config{}
	err := WithRPOrigins()(config)
	require.NoError(t, err)
	assert.Equal(t, []string{"https://env.example.com"}, config.RPOrigins)
}

func TestWithUserVerification(t *testing.T) {
	tests := []struct {
		name    string
		value   UserVerificationRequirement
		wantErr bool
	}{
		{"required", VerificationRequired, false},
		{"preferred", VerificationPreferred, false},
		{"discouraged", VerificationDiscouraged, false},
		{"invalid", UserVerificationRequirement("invalid"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{}
			err := WithUserVerification(tt.value)(config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.value, config.UserVerification)
			}
		})
	}
}

func TestWithAttestationPreference(t *testing.T) {
	tests := []struct {
		name    string
		value   AttestationPreference
		wantErr bool
	}{
		{"none", AttestationNone, false},
		{"indirect", AttestationIndirect, false},
		{"direct", AttestationDirect, false},
		{"enterprise", AttestationEnterprise, false},
		{"invalid", AttestationPreference("invalid"), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{}
			err := WithAttestationPreference(tt.value)(config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.value, config.AttestationPreference)
			}
		})
	}
}

func TestWithTimeout(t *testing.T) {
	tests := []struct {
		name    string
		value   int
		wantErr bool
	}{
		{"valid timeout", 30000, false},
		{"min timeout", 1, false},
		{"max timeout", 600000, false},
		{"zero timeout", 0, true},
		{"negative timeout", -1, true},
		{"excessive timeout", 600001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{}
			err := WithTimeout(tt.value)(config)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.value, config.Timeout)
			}
		})
	}
}

func TestWithCredentialStore(t *testing.T) {
	store := memory.NewCredentialStore()

	config := &Config{}
	err := WithCredentialStore(store)(config)
	require.NoError(t, err)
	assert.Equal(t, store, config.CredentialStore)

	// Test nil store
	err = WithCredentialStore(nil)(config)
	assert.Error(t, err)
}

func TestWithAuditLogger(t *testing.T) {
	logger := memory.NewNopLogger()

	config := &Config{}
	err := WithAuditLogger(logger)(config)
	require.NoError(t, err)
	assert.Equal(t, logger, config.AuditLogger)

	// Test nil logger
	err = WithAuditLogger(nil)(config)
	assert.Error(t, err)
}

func TestWithAuthenticatorSelection(t *testing.T) {
	selection := AuthenticatorSelection{
		AuthenticatorAttachment: "platform",
		RequireResidentKey:      true,
		UserVerification:        VerificationRequired,
	}

	config := &Config{}
	err := WithAuthenticatorSelection(selection)(config)
	require.NoError(t, err)
	assert.Equal(t, selection, config.AuthenticatorSelection)
}
