package signedtoken

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHMACSignerSHA256(t *testing.T) {
	t.Run("accepts valid key", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)

		require.NoError(t, err)
		assert.NotNil(t, signer)
		assert.Equal(t, 32, signer.KeyLength())
	})

	t.Run("accepts key longer than minimum", func(t *testing.T) {
		key := make([]byte, 64) // 512 bits
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)

		require.NoError(t, err)
		assert.NotNil(t, signer)
		assert.Equal(t, 64, signer.KeyLength())
	})

	t.Run("rejects weak key", func(t *testing.T) {
		weakKey := []byte("short")

		signer, err := NewHMACSignerSHA256(weakKey)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrWeakSigningKey)
		assert.Nil(t, signer)
	})

	t.Run("rejects key at minimum boundary", func(t *testing.T) {
		// 31 bytes - just below minimum
		key := make([]byte, 31)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrWeakSigningKey)
		assert.Nil(t, signer)
	})

	t.Run("accepts exact minimum key length", func(t *testing.T) {
		// Exactly 32 bytes - at minimum
		key := make([]byte, MinSigningKeyLength)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)

		require.NoError(t, err)
		assert.NotNil(t, signer)
	})

	t.Run("copies key to prevent external modification", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		originalKey := make([]byte, len(key))
		copy(originalKey, key)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		// Sign some data with original key
		data := []byte("test data")
		signature1, err := signer.Sign(data)
		require.NoError(t, err)

		// Modify the original key
		for i := range key {
			key[i] = 0
		}

		// Sign again - should produce same signature since key was copied
		signature2, err := signer.Sign(data)
		require.NoError(t, err)

		assert.Equal(t, signature1, signature2)
	})
}

func TestHMACSignerSHA256_Sign(t *testing.T) {
	t.Run("generates signature", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		data := []byte("test data")

		signature, err := signer.Sign(data)

		require.NoError(t, err)
		assert.NotEmpty(t, signature)
		assert.Len(t, signature, 32) // SHA-256 produces 32 bytes
	})

	t.Run("generates consistent signature", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		data := []byte("test data")

		signature1, err := signer.Sign(data)
		require.NoError(t, err)

		signature2, err := signer.Sign(data)
		require.NoError(t, err)

		assert.Equal(t, signature1, signature2)
	})

	t.Run("different data produces different signatures", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		data1 := []byte("test data 1")
		data2 := []byte("test data 2")

		signature1, err := signer.Sign(data1)
		require.NoError(t, err)

		signature2, err := signer.Sign(data2)
		require.NoError(t, err)

		assert.NotEqual(t, signature1, signature2)
	})

	t.Run("different keys produce different signatures", func(t *testing.T) {
		key1 := make([]byte, 32)
		_, err := rand.Read(key1)
		require.NoError(t, err)

		key2 := make([]byte, 32)
		_, err = rand.Read(key2)
		require.NoError(t, err)

		signer1, err := NewHMACSignerSHA256(key1)
		require.NoError(t, err)

		signer2, err := NewHMACSignerSHA256(key2)
		require.NoError(t, err)

		data := []byte("test data")

		signature1, err := signer1.Sign(data)
		require.NoError(t, err)

		signature2, err := signer2.Sign(data)
		require.NoError(t, err)

		assert.NotEqual(t, signature1, signature2)
	})

	t.Run("handles empty data", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		data := []byte{}

		signature, err := signer.Sign(data)

		require.NoError(t, err)
		assert.NotEmpty(t, signature)
	})
}

func TestHMACSignerSHA256_Verify(t *testing.T) {
	t.Run("verifies valid signature", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		data := []byte("test data")
		signature, err := signer.Sign(data)
		require.NoError(t, err)

		err = signer.Verify(data, signature)

		assert.NoError(t, err)
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		data := []byte("test data")
		invalidSignature := []byte("invalid signature bytes here!!")

		err = signer.Verify(data, invalidSignature)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrSignatureMismatch)
	})

	t.Run("rejects tampered data", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		originalData := []byte("test data")
		signature, err := signer.Sign(originalData)
		require.NoError(t, err)

		tamperedData := []byte("test data modified")

		err = signer.Verify(tamperedData, signature)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrSignatureMismatch)
	})

	t.Run("rejects signature from different key", func(t *testing.T) {
		key1 := make([]byte, 32)
		_, err := rand.Read(key1)
		require.NoError(t, err)

		key2 := make([]byte, 32)
		_, err = rand.Read(key2)
		require.NoError(t, err)

		signer1, err := NewHMACSignerSHA256(key1)
		require.NoError(t, err)

		signer2, err := NewHMACSignerSHA256(key2)
		require.NoError(t, err)

		data := []byte("test data")
		signature, err := signer1.Sign(data)
		require.NoError(t, err)

		// Try to verify with different key
		err = signer2.Verify(data, signature)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrSignatureMismatch)
	})

	t.Run("handles empty signature", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		data := []byte("test data")
		emptySignature := []byte{}

		err = signer.Verify(data, emptySignature)

		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrSignatureMismatch)
	})
}

func TestHMACSignerSHA256_SignVerifyRoundtrip(t *testing.T) {
	t.Run("sign and verify roundtrip", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		testData := [][]byte{
			[]byte("simple data"),
			[]byte("data with special chars: !@#$%^&*()"),
			[]byte(""),
			[]byte("very long data " + string(make([]byte, 10000))),
			[]byte("unicode: 你好世界 🌍"),
		}

		for _, data := range testData {
			signature, err := signer.Sign(data)
			require.NoError(t, err)

			err = signer.Verify(data, signature)
			assert.NoError(t, err, "Failed to verify data: %s", string(data))
		}
	})
}

func BenchmarkHMACSignerSHA256_Sign(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	signer, _ := NewHMACSignerSHA256(key)
	data := []byte("test data for benchmarking")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(data)
	}
}

func BenchmarkHMACSignerSHA256_Verify(b *testing.B) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	signer, _ := NewHMACSignerSHA256(key)
	data := []byte("test data for benchmarking")
	signature, _ := signer.Sign(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.Verify(data, signature)
	}
}

// Test that verification uses constant-time comparison
// This is difficult to test directly, but we can at least verify that
// the function doesn't panic or behave unexpectedly with edge cases
func TestHMACSignerSHA256_ConstantTimeVerification(t *testing.T) {
	t.Run("verification with signatures of different lengths", func(t *testing.T) {
		key := make([]byte, 32)
		_, err := rand.Read(key)
		require.NoError(t, err)

		signer, err := NewHMACSignerSHA256(key)
		require.NoError(t, err)

		data := []byte("test data")

		// Valid signature
		validSig, err := signer.Sign(data)
		require.NoError(t, err)

		// Shorter signature
		shortSig := validSig[:16]
		err = signer.Verify(data, shortSig)
		assert.Error(t, err)

		// Longer signature
		longSig := append(validSig, []byte("extra")...)
		err = signer.Verify(data, longSig)
		assert.Error(t, err)

		// Same length but wrong signature
		wrongSig := make([]byte, len(validSig))
		copy(wrongSig, validSig)
		wrongSig[0] ^= 1 // Flip one bit
		err = signer.Verify(data, wrongSig)
		assert.Error(t, err)
	})
}
