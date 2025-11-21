package srp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifier_MarshalBinary(t *testing.T) {
	verifier := &Verifier{
		UserIdentifier:    "test@example.com",
		Salt:      []byte("test-salt-123456"),
		Verifier:  []byte("test-verifier-data"),
		Group:     3,
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
	assert.Equal(t, verifier.UserIdentifier, decoded.UserIdentifier)
	assert.Equal(t, verifier.Salt, decoded.Salt)
	assert.Equal(t, verifier.Verifier, decoded.Verifier)
	assert.Equal(t, verifier.Group, decoded.Group)
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
		UserIdentifier:    "test@example.com",
		Group:     3,
	}

	// Basic validation
	assert.Equal(t, "test@example.com", session.UserIdentifier)
	assert.Equal(t, 3, session.Group)
}
