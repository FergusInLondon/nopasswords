package signedtoken

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewToken(t *testing.T) {
	t.Run("creates valid token", func(t *testing.T) {
		userID := "user123"
		lifetime := 1 * time.Hour
		metadata := map[string]interface{}{
			"key": "value",
		}

		token, err := NewToken(userID, lifetime, metadata)

		require.NoError(t, err)
		assert.Equal(t, userID, token.UserID)
		assert.Equal(t, metadata, token.Metadata)
		assert.False(t, token.IssuedAt.IsZero())
		assert.False(t, token.ExpiresAt.IsZero())
		assert.True(t, token.ExpiresAt.After(token.IssuedAt))
	})

	t.Run("enforces maximum lifetime", func(t *testing.T) {
		userID := "user123"
		lifetime := 25 * time.Hour // Exceeds MaxTokenLifetime

		token, err := NewToken(userID, lifetime, nil)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrLifetimeTooLong)
		assert.Nil(t, token)
	})

	t.Run("accepts maximum lifetime", func(t *testing.T) {
		userID := "user123"
		lifetime := MaxTokenLifetime

		token, err := NewToken(userID, lifetime, nil)

		require.NoError(t, err)
		assert.NotNil(t, token)
	})

	t.Run("rejects oversized metadata", func(t *testing.T) {
		userID := "user123"
		lifetime := 1 * time.Hour

		// Create metadata that exceeds 1KB when serialized
		largeMetadata := make(map[string]interface{})
		// Each entry is roughly 20 bytes, so 60 entries ≈ 1200 bytes
		for i := 0; i < 60; i++ {
			largeMetadata[string(rune('a'+i%26))+string(rune('0'+i/26))] = "value1234567890"
		}

		token, err := NewToken(userID, lifetime, largeMetadata)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMetadataTooLarge)
		assert.Nil(t, token)
	})

	t.Run("accepts nil metadata", func(t *testing.T) {
		userID := "user123"
		lifetime := 1 * time.Hour

		token, err := NewToken(userID, lifetime, nil)

		require.NoError(t, err)
		assert.Nil(t, token.Metadata)
	})

	t.Run("accepts empty metadata", func(t *testing.T) {
		userID := "user123"
		lifetime := 1 * time.Hour
		metadata := make(map[string]interface{})

		token, err := NewToken(userID, lifetime, metadata)

		require.NoError(t, err)
		assert.NotNil(t, token.Metadata)
		assert.Empty(t, token.Metadata)
	})
}

func TestToken_IsExpired(t *testing.T) {
	t.Run("not expired token", func(t *testing.T) {
		token, err := NewToken("user123", 1*time.Hour, nil)
		require.NoError(t, err)

		assert.False(t, token.IsExpired())
	})

	t.Run("expired token", func(t *testing.T) {
		token := &Token{
			UserID:    "user123",
			IssuedAt:  time.Now().UTC().Add(-2 * time.Hour),
			ExpiresAt: time.Now().UTC().Add(-1 * time.Hour),
		}

		assert.True(t, token.IsExpired())
	})

	t.Run("token expiring now", func(t *testing.T) {
		token := &Token{
			UserID:    "user123",
			IssuedAt:  time.Now().UTC().Add(-1 * time.Hour),
			ExpiresAt: time.Now().UTC(),
		}

		// This might be flaky due to timing, but should be expired
		// since ExpiresAt is now and time has moved forward
		time.Sleep(1 * time.Millisecond)
		assert.True(t, token.IsExpired())
	})
}

func TestToken_EncodeDecode(t *testing.T) {
	t.Run("encode and decode token", func(t *testing.T) {
		original, err := NewToken("user123", 1*time.Hour, map[string]interface{}{
			"key1": "value1",
			"key2": 123,
		})
		require.NoError(t, err)

		// Encode
		encoded, err := original.Encode()
		require.NoError(t, err)
		assert.NotEmpty(t, encoded)

		// Decode
		decoded, err := DecodeToken(encoded)
		require.NoError(t, err)

		assert.Equal(t, original.UserID, decoded.UserID)
		assert.True(t, original.IssuedAt.Equal(decoded.IssuedAt))
		assert.True(t, original.ExpiresAt.Equal(decoded.ExpiresAt))
		// JSON unmarshaling converts numbers to float64
		assert.Equal(t, "value1", decoded.Metadata["key1"])
		assert.Equal(t, float64(123), decoded.Metadata["key2"])
	})

	t.Run("decode invalid JSON", func(t *testing.T) {
		invalidJSON := []byte("not valid json")

		decoded, err := DecodeToken(invalidJSON)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTokenFormat)
		assert.Nil(t, decoded)
	})
}

func TestSignedToken_EncodeToString(t *testing.T) {
	t.Run("encodes to URL-safe base64", func(t *testing.T) {
		token, err := NewToken("user123", 1*time.Hour, nil)
		require.NoError(t, err)

		signedToken := &SignedToken{
			Token:     *token,
			Signature: []byte("mock_signature"),
		}

		encoded, err := signedToken.EncodeToString()

		require.NoError(t, err)
		assert.NotEmpty(t, encoded)

		// Check that it's URL-safe (no +, /, or = characters)
		assert.NotContains(t, encoded, "+")
		assert.NotContains(t, encoded, "/")
		assert.NotContains(t, encoded, "=")
	})

	t.Run("warns on long tokens", func(t *testing.T) {
		// Create a token with metadata that will result in a long URL
		// but stays under the 1KB metadata limit
		largeMetadata := make(map[string]interface{})
		// Create metadata just under 1KB but that will result in a long encoded token
		for i := 0; i < 25; i++ {
			key := "k" + string(rune('a'+i))
			value := strings.Repeat("v", 25)
			largeMetadata[key] = value
		}

		token, err := NewToken("user123", 1*time.Hour, largeMetadata)
		require.NoError(t, err)

		// Add a long signature to push it over URL length limit
		longSignature := make([]byte, 2000)
		for i := range longSignature {
			longSignature[i] = byte(i % 256)
		}

		signedToken := &SignedToken{
			Token:     *token,
			Signature: longSignature,
		}

		encoded, err := signedToken.EncodeToString()

		// Should still encode but return a warning
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrTokenTooLong)
		assert.NotEmpty(t, encoded)
		assert.Greater(t, len(encoded), MaxURLLength)
	})
}

func TestSignedToken_DecodeFromString(t *testing.T) {
	t.Run("decodes valid token string", func(t *testing.T) {
		original, err := NewToken("user123", 1*time.Hour, map[string]interface{}{
			"key": "value",
		})
		require.NoError(t, err)

		signedToken := &SignedToken{
			Token:     *original,
			Signature: []byte("test_signature"),
		}

		// Encode
		encoded, err := signedToken.EncodeToString()
		require.NoError(t, err)

		// Decode
		decoded, err := DecodeFromString(encoded)
		require.NoError(t, err)

		assert.Equal(t, signedToken.Token.UserID, decoded.Token.UserID)
		assert.True(t, signedToken.Token.IssuedAt.Equal(decoded.Token.IssuedAt))
		assert.True(t, signedToken.Token.ExpiresAt.Equal(decoded.Token.ExpiresAt))
		assert.Equal(t, signedToken.Token.Metadata, decoded.Token.Metadata)
		assert.Equal(t, signedToken.Signature, decoded.Signature)
	})

	t.Run("rejects invalid base64", func(t *testing.T) {
		invalid := "not!valid!base64!@#$%"

		decoded, err := DecodeFromString(invalid)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTokenFormat)
		assert.Nil(t, decoded)
	})

	t.Run("rejects invalid JSON", func(t *testing.T) {
		// Valid base64 but invalid JSON content
		invalid := "aW52YWxpZA" // base64 of "invalid"

		decoded, err := DecodeFromString(invalid)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidTokenFormat)
		assert.Nil(t, decoded)
	})
}

func TestSignedToken_ID(t *testing.T) {
	t.Run("generates consistent ID", func(t *testing.T) {
		token, err := NewToken("user123", 1*time.Hour, nil)
		require.NoError(t, err)

		signedToken := &SignedToken{
			Token:     *token,
			Signature: []byte("signature"),
		}

		id1 := signedToken.ID()
		id2 := signedToken.ID()

		assert.Equal(t, id1, id2)
		assert.NotEmpty(t, id1)
		assert.Len(t, id1, 64) // SHA-256 hex string is 64 characters
	})

	t.Run("different tokens have different IDs", func(t *testing.T) {
		token1, err := NewToken("user123", 1*time.Hour, nil)
		require.NoError(t, err)

		token2, err := NewToken("user456", 1*time.Hour, nil)
		require.NoError(t, err)

		signedToken1 := &SignedToken{
			Token:     *token1,
			Signature: []byte("signature1"),
		}

		signedToken2 := &SignedToken{
			Token:     *token2,
			Signature: []byte("signature2"),
		}

		id1 := signedToken1.ID()
		id2 := signedToken2.ID()

		assert.NotEqual(t, id1, id2)
	})

	t.Run("same token different signatures have different IDs", func(t *testing.T) {
		token, err := NewToken("user123", 1*time.Hour, nil)
		require.NoError(t, err)

		signedToken1 := &SignedToken{
			Token:     *token,
			Signature: []byte("signature1"),
		}

		signedToken2 := &SignedToken{
			Token:     *token,
			Signature: []byte("signature2"),
		}

		id1 := signedToken1.ID()
		id2 := signedToken2.ID()

		assert.NotEqual(t, id1, id2)
	})
}

func TestToken_ValidateMetadataSize(t *testing.T) {
	t.Run("accepts small metadata", func(t *testing.T) {
		token := &Token{
			UserID: "user123",
			Metadata: map[string]interface{}{
				"key": "value",
			},
		}

		err := token.ValidateMetadataSize()

		assert.NoError(t, err)
	})

	t.Run("accepts nil metadata", func(t *testing.T) {
		token := &Token{
			UserID:   "user123",
			Metadata: nil,
		}

		err := token.ValidateMetadataSize()

		assert.NoError(t, err)
	})

	t.Run("rejects oversized metadata", func(t *testing.T) {
		largeMetadata := make(map[string]interface{})
		// Create metadata that exceeds 1KB
		for i := 0; i < 60; i++ {
			largeMetadata[string(rune('a'+i%26))+string(rune('0'+i/26))] = "value1234567890"
		}

		token := &Token{
			UserID:   "user123",
			Metadata: largeMetadata,
		}

		err := token.ValidateMetadataSize()

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrMetadataTooLarge)
	})

	t.Run("rejects unserializable metadata", func(t *testing.T) {
		token := &Token{
			UserID: "user123",
			Metadata: map[string]interface{}{
				"invalid": make(chan int), // channels can't be JSON serialized
			},
		}

		err := token.ValidateMetadataSize()

		assert.Error(t, err)
	})
}

func TestToken_JSONSerialization(t *testing.T) {
	t.Run("serializes to expected JSON structure", func(t *testing.T) {
		issuedAt := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
		expiresAt := issuedAt.Add(1 * time.Hour)

		token := &Token{
			UserID:    "user123",
			IssuedAt:  issuedAt,
			ExpiresAt: expiresAt,
			Metadata: map[string]interface{}{
				"key": "value",
			},
		}

		data, err := json.Marshal(token)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		assert.Equal(t, "user123", decoded["uid"])
		assert.NotNil(t, decoded["iat"])
		assert.NotNil(t, decoded["exp"])
		assert.NotNil(t, decoded["meta"])
	})

	t.Run("omits empty metadata in JSON", func(t *testing.T) {
		token := &Token{
			UserID:    "user123",
			IssuedAt:  time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(1 * time.Hour),
			Metadata:  nil,
		}

		data, err := json.Marshal(token)
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		_, hasMetadata := decoded["meta"]
		assert.False(t, hasMetadata, "meta field should be omitted when nil")
	})
}
