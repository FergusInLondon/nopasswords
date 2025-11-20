package srp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/core/memory"
)

func TestNewConfig(t *testing.T) {
	store := memory.NewMemoryCredentialStore()

	tests := []struct {
		name    string
		opts    []Option
		wantErr bool
		check   func(*testing.T, *Config)
	}{
		{
			name: "Minimal valid config",
			opts: []Option{
				WithCredentialStore(store),
			},
			wantErr: false,
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultGroup, c.Group)
				assert.Equal(t, DefaultSessionTimeout, c.SessionTimeout)
				assert.Equal(t, DefaultSaltLength, c.SaltLength)
				assert.NotNil(t, c.CredentialStore)
				assert.NotNil(t, c.AuditLogger)
			},
		},
		{
			name: "Custom group",
			opts: []Option{
				WithCredentialStore(store),
				WithGroup(4),
			},
			wantErr: false,
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, 4, c.Group)
			},
		},
		{
			name: "Custom session timeout",
			opts: []Option{
				WithCredentialStore(store),
				WithSessionTimeout(10 * time.Minute),
			},
			wantErr: false,
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, 10*time.Minute, c.SessionTimeout)
			},
		},
		{
			name: "Custom salt length",
			opts: []Option{
				WithCredentialStore(store),
				WithSaltLength(64),
			},
			wantErr: false,
			check: func(t *testing.T, c *Config) {
				assert.Equal(t, 64, c.SaltLength)
			},
		},
		{
			name:    "Missing credential store",
			opts:    []Option{},
			wantErr: true,
		},
		{
			name: "Invalid group",
			opts: []Option{
				WithCredentialStore(store),
				WithGroup(99),
			},
			wantErr: true,
		},
		{
			name: "Invalid session timeout (negative)",
			opts: []Option{
				WithCredentialStore(store),
				WithSessionTimeout(-1 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "Invalid session timeout (too long)",
			opts: []Option{
				WithCredentialStore(store),
				WithSessionTimeout(2 * time.Hour),
			},
			wantErr: true,
		},
		{
			name: "Invalid salt length (too short)",
			opts: []Option{
				WithCredentialStore(store),
				WithSaltLength(8),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewConfig(tt.opts...)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, config)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, config)

			if tt.check != nil {
				tt.check(t, config)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	store := memory.NewMemoryCredentialStore()

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "Valid config",
			config: &Config{
				Group:           3,
				SessionTimeout:  5 * time.Minute,
				SaltLength:      32,
				CredentialStore: store,
				AuditLogger:     memory.NewNopLogger(),
			},
			wantErr: false,
		},
		{
			name: "Invalid group (too low)",
			config: &Config{
				Group:           2,
				SessionTimeout:  5 * time.Minute,
				SaltLength:      32,
				CredentialStore: store,
			},
			wantErr: true,
		},
		{
			name: "Invalid group (too high)",
			config: &Config{
				Group:           6,
				SessionTimeout:  5 * time.Minute,
				SaltLength:      32,
				CredentialStore: store,
			},
			wantErr: true,
		},
		{
			name: "Missing credential store",
			config: &Config{
				Group:          3,
				SessionTimeout: 5 * time.Minute,
				SaltLength:     32,
			},
			wantErr: true,
		},
		{
			name: "Salt too short",
			config: &Config{
				Group:           3,
				SessionTimeout:  5 * time.Minute,
				SaltLength:      8,
				CredentialStore: store,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWithOptions(t *testing.T) {
	store := memory.NewMemoryCredentialStore()
	logger := memory.NewStdoutLogger(false)

	config := &Config{}

	// Apply WithGroup
	err := WithGroup(4)(config)
	assert.NoError(t, err)
	assert.Equal(t, 4, config.Group)

	// Apply WithSessionTimeout
	err = WithSessionTimeout(15 * time.Minute)(config)
	assert.NoError(t, err)
	assert.Equal(t, 15*time.Minute, config.SessionTimeout)

	// Apply WithSaltLength
	err = WithSaltLength(48)(config)
	assert.NoError(t, err)
	assert.Equal(t, 48, config.SaltLength)

	// Apply WithCredentialStore
	err = WithCredentialStore(store)(config)
	assert.NoError(t, err)
	assert.Equal(t, store, config.CredentialStore)

	// Apply WithAuditLogger
	err = WithAuditLogger(logger)(config)
	assert.NoError(t, err)
	assert.Equal(t, logger, config.AuditLogger)
}
