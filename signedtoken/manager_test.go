package signedtoken

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/core"
	"go.fergus.london/nopasswords/core/memory"
)

func createTestSigner(t *testing.T) Signer {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	signer, err := NewHMACSignerSHA256(key)
	require.NoError(t, err)

	return signer
}

func TestNewManager(t *testing.T) {
	t.Run("creates manager with valid config", func(t *testing.T) {
		signer := createTestSigner(t)

		manager, err := NewManager(
			WithSigner(signer),
		)

		require.NoError(t, err)
		assert.NotNil(t, manager)
	})

	t.Run("requires signer", func(t *testing.T) {
		manager, err := NewManager()

		assert.Error(t, err)
		assert.Nil(t, manager)
	})

	t.Run("accepts all options", func(t *testing.T) {
		signer := createTestSigner(t)
		tokenStore := memory.NewMemoryTokenStore()
		logger := memory.NewStdoutLogger(false)

		manager, err := NewManager(
			WithSigner(signer),
			WithDefaultLifetime(30*time.Minute),
			WithTokenStore(tokenStore),
			WithAuditLogger(logger),
			WithOpaqueIDs(true),
		)

		require.NoError(t, err)
		assert.NotNil(t, manager)
	})
}

func TestManager_GenerateToken(t *testing.T) {
	t.Run("generates valid token", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		userID := "user123"

		tokenString, err := manager.GenerateToken(ctx, userID, nil)

		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)
	})

	t.Run("generates token with metadata", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		metadata := map[string]interface{}{
			"key": "value",
			"num": 123,
		}

		tokenString, err := manager.GenerateToken(ctx, "user123", metadata)

		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)
	})

	t.Run("generates URL-safe token", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()

		tokenString, err := manager.GenerateToken(ctx, "user123", nil)

		require.NoError(t, err)
		assert.NotContains(t, tokenString, "+")
		assert.NotContains(t, tokenString, "/")
		assert.NotContains(t, tokenString, "=")
	})

	t.Run("stores token when TokenStore configured", func(t *testing.T) {
		signer := createTestSigner(t)
		tokenStore := memory.NewMemoryTokenStore()
		manager, err := NewManager(
			WithSigner(signer),
			WithTokenStore(tokenStore),
		)
		require.NoError(t, err)

		ctx := context.Background()

		tokenString, err := manager.GenerateToken(ctx, "user123", nil)
		require.NoError(t, err)

		// Decode to get token ID
		signedToken, err := DecodeFromString(tokenString)
		require.NoError(t, err)

		// Check that token is not revoked (it's stored)
		revoked, err := tokenStore.IsTokenRevoked(ctx, signedToken.ID())
		require.NoError(t, err)
		assert.False(t, revoked)
	})

	t.Run("generates different tokens for different users", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()

		token1, err := manager.GenerateToken(ctx, "user1", nil)
		require.NoError(t, err)

		token2, err := manager.GenerateToken(ctx, "user2", nil)
		require.NoError(t, err)

		assert.NotEqual(t, token1, token2)
	})

	t.Run("rejects oversized metadata", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()

		// Create oversized metadata
		largeMetadata := make(map[string]interface{})
		for i := 0; i < 60; i++ {
			largeMetadata[string(rune('a'+i%26))+string(rune('0'+i/26))] = "value1234567890"
		}

		tokenString, err := manager.GenerateToken(ctx, "user123", largeMetadata)

		assert.Error(t, err)
		assert.Empty(t, tokenString)
	})
}

func TestManager_GenerateTokenWithLifetime(t *testing.T) {
	t.Run("generates token with custom lifetime", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		lifetime := 30 * time.Minute

		tokenString, err := manager.GenerateTokenWithLifetime(ctx, "user123", nil, lifetime)

		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify the token and check its expiration
		token, err := manager.VerifyToken(ctx, tokenString)
		require.NoError(t, err)

		expectedExpiry := time.Now().UTC().Add(lifetime)
		assert.WithinDuration(t, expectedExpiry, token.ExpiresAt, 5*time.Second)
	})

	t.Run("rejects lifetime exceeding maximum", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		lifetime := 25 * time.Hour // Exceeds MaxTokenLifetime

		tokenString, err := manager.GenerateTokenWithLifetime(ctx, "user123", nil, lifetime)

		assert.Error(t, err)
		assert.Empty(t, tokenString)
	})
}

func TestManager_VerifyToken(t *testing.T) {
	t.Run("verifies valid token", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		userID := "user123"

		// Generate token
		tokenString, err := manager.GenerateToken(ctx, userID, nil)
		require.NoError(t, err)

		// Verify token
		token, err := manager.VerifyToken(ctx, tokenString)

		require.NoError(t, err)
		assert.Equal(t, userID, token.UserID)
		assert.False(t, token.IsExpired())
	})

	t.Run("verifies token with metadata", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		metadata := map[string]interface{}{
			"key": "value",
			"num": float64(123), // JSON numbers become float64
		}

		// Generate token
		tokenString, err := manager.GenerateToken(ctx, "user123", metadata)
		require.NoError(t, err)

		// Verify token
		token, err := manager.VerifyToken(ctx, tokenString)

		require.NoError(t, err)
		assert.Equal(t, metadata, token.Metadata)
	})

	t.Run("rejects invalid token format", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		invalidToken := "not-a-valid-token"

		token, err := manager.VerifyToken(ctx, invalidToken)

		assert.Error(t, err)
		assert.Nil(t, token)

		// Check that it's an AuthError with appropriate code
		var authErr *core.AuthError
		assert.ErrorAs(t, err, &authErr)
		assert.Equal(t, core.CodeInvalidToken, authErr.Code)
	})

	t.Run("rejects tampered token", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()

		// Generate valid token
		tokenString, err := manager.GenerateToken(ctx, "user123", nil)
		require.NoError(t, err)

		// Tamper with the token (flip a character)
		tampered := []byte(tokenString)
		if tampered[10] == 'A' {
			tampered[10] = 'B'
		} else {
			tampered[10] = 'A'
		}
		tamperedToken := string(tampered)

		// Try to verify tampered token
		token, err := manager.VerifyToken(ctx, tamperedToken)

		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("rejects expired token", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()

		// Generate token with very short lifetime
		tokenString, err := manager.GenerateTokenWithLifetime(ctx, "user123", nil, 1*time.Millisecond)
		require.NoError(t, err)

		// Wait for token to expire
		time.Sleep(10 * time.Millisecond)

		// Try to verify expired token
		token, err := manager.VerifyToken(ctx, tokenString)

		assert.Error(t, err)
		assert.Nil(t, token)

		// Check that it's an AuthError with expired code
		var authErr *core.AuthError
		assert.ErrorAs(t, err, &authErr)
		assert.Equal(t, core.CodeExpiredToken, authErr.Code)
	})

	t.Run("rejects token signed with different key", func(t *testing.T) {
		// Create first manager with one key
		signer1 := createTestSigner(t)
		manager1, err := NewManager(WithSigner(signer1))
		require.NoError(t, err)

		// Create second manager with different key
		signer2 := createTestSigner(t)
		manager2, err := NewManager(WithSigner(signer2))
		require.NoError(t, err)

		ctx := context.Background()

		// Generate token with first manager
		tokenString, err := manager1.GenerateToken(ctx, "user123", nil)
		require.NoError(t, err)

		// Try to verify with second manager (different key)
		token, err := manager2.VerifyToken(ctx, tokenString)

		assert.Error(t, err)
		assert.Nil(t, token)

		// Check that it's a signature error
		var authErr *core.AuthError
		assert.ErrorAs(t, err, &authErr)
		assert.Equal(t, core.CodeInvalidSignature, authErr.Code)
	})
}

func TestManager_RevokeToken(t *testing.T) {
	t.Run("revokes valid token", func(t *testing.T) {
		signer := createTestSigner(t)
		tokenStore := memory.NewMemoryTokenStore()
		manager, err := NewManager(
			WithSigner(signer),
			WithTokenStore(tokenStore),
		)
		require.NoError(t, err)

		ctx := context.Background()

		// Generate token
		tokenString, err := manager.GenerateToken(ctx, "user123", nil)
		require.NoError(t, err)

		// Verify it works before revocation
		token, err := manager.VerifyToken(ctx, tokenString)
		require.NoError(t, err)
		assert.NotNil(t, token)

		// Revoke token
		err = manager.RevokeToken(ctx, tokenString)
		require.NoError(t, err)

		// Try to verify revoked token
		token, err = manager.VerifyToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Nil(t, token)

		// Check that it's a revoked error
		var authErr *core.AuthError
		assert.ErrorAs(t, err, &authErr)
		assert.Equal(t, core.CodeRevokedToken, authErr.Code)
	})

	t.Run("fails without TokenStore", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()

		// Generate token
		tokenString, err := manager.GenerateToken(ctx, "user123", nil)
		require.NoError(t, err)

		// Try to revoke without TokenStore configured
		err = manager.RevokeToken(ctx, tokenString)

		assert.Error(t, err)
	})

	t.Run("idempotent revocation", func(t *testing.T) {
		signer := createTestSigner(t)
		tokenStore := memory.NewMemoryTokenStore()
		manager, err := NewManager(
			WithSigner(signer),
			WithTokenStore(tokenStore),
		)
		require.NoError(t, err)

		ctx := context.Background()

		// Generate token
		tokenString, err := manager.GenerateToken(ctx, "user123", nil)
		require.NoError(t, err)

		// Revoke token twice
		err = manager.RevokeToken(ctx, tokenString)
		require.NoError(t, err)

		err = manager.RevokeToken(ctx, tokenString)
		require.NoError(t, err) // Should not error on second revocation
	})
}

// Integration Tests
func TestManager_IntegrationGenerateVerifyCycle(t *testing.T) {
	t.Run("full generate and verify cycle", func(t *testing.T) {
		signer := createTestSigner(t)
		tokenStore := memory.NewMemoryTokenStore()
		logger := memory.NewStdoutLogger(false)

		manager, err := NewManager(
			WithSigner(signer),
			WithTokenStore(tokenStore),
			WithAuditLogger(logger),
			WithDefaultLifetime(1*time.Hour),
		)
		require.NoError(t, err)

		ctx := context.Background()
		userID := "user@example.com"
		metadata := map[string]interface{}{
			"purpose":    "login",
			"ip_address": "192.168.1.1",
		}

		// Generate token
		tokenString, err := manager.GenerateToken(ctx, userID, metadata)
		require.NoError(t, err)
		assert.NotEmpty(t, tokenString)

		// Verify token
		token, err := manager.VerifyToken(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, userID, token.UserID)
		assert.Equal(t, metadata["purpose"], token.Metadata["purpose"])
		assert.Equal(t, metadata["ip_address"], token.Metadata["ip_address"])
		assert.False(t, token.IsExpired())

		// Verify can be called multiple times
		token2, err := manager.VerifyToken(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, token.UserID, token2.UserID)
	})

	t.Run("multiple users with separate tokens", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()

		users := []string{"alice", "bob", "charlie"}
		tokens := make(map[string]string)

		// Generate tokens for each user
		for _, userID := range users {
			tokenString, err := manager.GenerateToken(ctx, userID, nil)
			require.NoError(t, err)
			tokens[userID] = tokenString
		}

		// Verify each token
		for userID, tokenString := range tokens {
			token, err := manager.VerifyToken(ctx, tokenString)
			require.NoError(t, err)
			assert.Equal(t, userID, token.UserID)
		}
	})

	t.Run("token lifecycle with revocation", func(t *testing.T) {
		signer := createTestSigner(t)
		tokenStore := memory.NewMemoryTokenStore()
		manager, err := NewManager(
			WithSigner(signer),
			WithTokenStore(tokenStore),
		)
		require.NoError(t, err)

		ctx := context.Background()
		userID := "user123"

		// 1. Generate token
		tokenString, err := manager.GenerateToken(ctx, userID, nil)
		require.NoError(t, err)

		// 2. Verify it works
		token, err := manager.VerifyToken(ctx, tokenString)
		require.NoError(t, err)
		assert.Equal(t, userID, token.UserID)

		// 3. Revoke token
		err = manager.RevokeToken(ctx, tokenString)
		require.NoError(t, err)

		// 4. Verify it's now rejected
		token, err = manager.VerifyToken(ctx, tokenString)
		assert.Error(t, err)
		assert.Nil(t, token)
	})
}

// Negative Tests
func TestManager_NegativeTests(t *testing.T) {
	t.Run("malformed base64", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		malformed := "this is not base64!@#$%^&*()"

		token, err := manager.VerifyToken(ctx, malformed)

		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("valid base64 but invalid JSON", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()
		// "invalid" in base64
		invalidJSON := "aW52YWxpZA"

		token, err := manager.VerifyToken(ctx, invalidJSON)

		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("empty token string", func(t *testing.T) {
		signer := createTestSigner(t)
		manager, err := NewManager(WithSigner(signer))
		require.NoError(t, err)

		ctx := context.Background()

		token, err := manager.VerifyToken(ctx, "")

		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("concurrent token operations", func(t *testing.T) {
		signer := createTestSigner(t)
		tokenStore := memory.NewMemoryTokenStore()
		manager, err := NewManager(
			WithSigner(signer),
			WithTokenStore(tokenStore),
		)
		require.NoError(t, err)

		ctx := context.Background()

		// Generate multiple tokens concurrently
		const numTokens = 50
		tokens := make([]string, numTokens)
		errors := make([]error, numTokens)

		// Use goroutines to generate tokens concurrently
		done := make(chan int, numTokens)
		for i := 0; i < numTokens; i++ {
			go func(idx int) {
				userID := "user" + string(rune('0'+idx%10))
				tokenString, err := manager.GenerateToken(ctx, userID, nil)
				tokens[idx] = tokenString
				errors[idx] = err
				done <- idx
			}(i)
		}

		// Wait for all goroutines to complete
		for i := 0; i < numTokens; i++ {
			<-done
		}

		// Check for generation errors
		for i, err := range errors {
			require.NoError(t, err, "Token generation failed for index %d", i)
		}

		// Verify all tokens concurrently
		verified := make([]bool, numTokens)
		verifyDone := make(chan int, numTokens)
		for i := 0; i < numTokens; i++ {
			go func(idx int) {
				token, err := manager.VerifyToken(ctx, tokens[idx])
				if err == nil && token != nil {
					verified[idx] = true
				} else {
					verified[idx] = false
				}
				verifyDone <- idx
			}(i)
		}

		// Wait for all verifications to complete
		for i := 0; i < numTokens; i++ {
			<-verifyDone
		}

		// Check all verifications succeeded
		for i, v := range verified {
			assert.True(t, v, "Token verification failed for index %d", i)
		}
	})
}

func BenchmarkManager_GenerateToken(b *testing.B) {
	signer := createTestSigner(&testing.T{})
	manager, _ := NewManager(WithSigner(signer))
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.GenerateToken(ctx, "user123", nil)
	}
}

func BenchmarkManager_VerifyToken(b *testing.B) {
	signer := createTestSigner(&testing.T{})
	manager, _ := NewManager(WithSigner(signer))
	ctx := context.Background()

	tokenString, _ := manager.GenerateToken(ctx, "user123", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.VerifyToken(ctx, tokenString)
	}
}
