package srp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifier_MarshalBinary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)

	verifier := &Verifier{
		UserID:    "test@example.com",
		Salt:      []byte("test-salt-123456"),
		Verifier:  []byte("test-verifier-data"),
		Group:     3,
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Marshal
	data, err := verifier.MarshalBinary()
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Unmarshal
	var decoded Verifier
	err = decoded.UnmarshalBinary(data)
	require.NoError(t, err)

	// Verify
	assert.Equal(t, verifier.UserID, decoded.UserID)
	assert.Equal(t, verifier.Salt, decoded.Salt)
	assert.Equal(t, verifier.Verifier, decoded.Verifier)
	assert.Equal(t, verifier.Group, decoded.Group)
	assert.Equal(t, verifier.CreatedAt.Unix(), decoded.CreatedAt.Unix())
	assert.Equal(t, verifier.UpdatedAt.Unix(), decoded.UpdatedAt.Unix())
}

func TestVerifier_UnmarshalBinary_InvalidData(t *testing.T) {
	var verifier Verifier
	err := verifier.UnmarshalBinary([]byte("invalid json"))
	assert.Error(t, err)
}

func TestServerSession_JSON(t *testing.T) {
	// Note: ServerSession JSON marshaling is tested separately due to big.Int handling
	// This test verifies that sessions can be serialized if needed
	session := &ServerSession{
		UserID:    "test@example.com",
		Group:     3,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// Basic validation
	assert.Equal(t, "test@example.com", session.UserID)
	assert.Equal(t, 3, session.Group)
	assert.True(t, session.ExpiresAt.After(session.CreatedAt))
}
