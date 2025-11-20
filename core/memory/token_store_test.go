package memory

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/core"
)

func TestTokenStore_StoreToken(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	tokenID := "token123"
	userID := "user456"
	expiresAt := time.Now().Add(1 * time.Hour)

	err := store.StoreToken(ctx, tokenID, userID, expiresAt)
	require.NoError(t, err)

	// Verify token is not revoked
	revoked, err := store.IsTokenRevoked(ctx, tokenID)
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestTokenStore_StoreToken_AlreadyExists(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	tokenID := "token123"
	userID := "user456"
	expiresAt := time.Now().Add(1 * time.Hour)

	err := store.StoreToken(ctx, tokenID, userID, expiresAt)
	require.NoError(t, err)

	// Attempt to store again
	err = store.StoreToken(ctx, tokenID, userID, expiresAt)
	assert.ErrorIs(t, err, core.ErrAlreadyExists)
}

func TestTokenStore_RevokeToken(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	tokenID := "token123"
	userID := "user456"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Store token
	err := store.StoreToken(ctx, tokenID, userID, expiresAt)
	require.NoError(t, err)

	// Revoke token
	err = store.RevokeToken(ctx, tokenID)
	require.NoError(t, err)

	// Verify token is revoked
	revoked, err := store.IsTokenRevoked(ctx, tokenID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestTokenStore_RevokeToken_NotFound_Idempotent(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	// Revoke non-existent token (should not error - idempotent)
	err := store.RevokeToken(ctx, "nonexistent")
	require.NoError(t, err)

	// Verify it's marked as revoked
	revoked, err := store.IsTokenRevoked(ctx, "nonexistent")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestTokenStore_IsTokenRevoked_NotFound(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	// Check non-existent token (should return false, not error)
	revoked, err := store.IsTokenRevoked(ctx, "nonexistent")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestTokenStore_RevokeToken_Idempotent(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	tokenID := "token123"
	userID := "user456"
	expiresAt := time.Now().Add(1 * time.Hour)

	// Store and revoke token
	err := store.StoreToken(ctx, tokenID, userID, expiresAt)
	require.NoError(t, err)
	err = store.RevokeToken(ctx, tokenID)
	require.NoError(t, err)

	// Revoke again (should not error)
	err = store.RevokeToken(ctx, tokenID)
	require.NoError(t, err)

	// Still revoked
	revoked, err := store.IsTokenRevoked(ctx, tokenID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestTokenStore_CleanupExpired(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	now := time.Now()

	// Store expired tokens
	_ = store.StoreToken(ctx, "expired1", "user1", now.Add(-1*time.Hour))
	_ = store.StoreToken(ctx, "expired2", "user2", now.Add(-2*time.Hour))

	// Store valid tokens
	_ = store.StoreToken(ctx, "valid1", "user3", now.Add(1*time.Hour))
	_ = store.StoreToken(ctx, "valid2", "user4", now.Add(2*time.Hour))

	assert.Equal(t, 4, store.Size())

	// Cleanup expired
	count, err := store.CleanupExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Equal(t, 2, store.Size())

	// Verify expired tokens are gone
	revoked, err := store.IsTokenRevoked(ctx, "expired1")
	require.NoError(t, err)
	assert.False(t, revoked) // Not found = not revoked

	// Verify valid tokens remain
	revoked, err = store.IsTokenRevoked(ctx, "valid1")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestTokenStore_CleanupExpired_NoExpired(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	now := time.Now()

	// Store only valid tokens
	_ = store.StoreToken(ctx, "valid1", "user1", now.Add(1*time.Hour))
	_ = store.StoreToken(ctx, "valid2", "user2", now.Add(2*time.Hour))

	// Cleanup should find nothing
	count, err := store.CleanupExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Equal(t, 2, store.Size())
}

func TestTokenStore_CleanupExpired_Empty(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	// Cleanup empty store
	count, err := store.CleanupExpired(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestTokenStore_ConcurrentAccess(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	const numGoroutines = 100
	const numOpsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	expiresAt := time.Now().Add(1 * time.Hour)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				tokenID := fmt.Sprintf("%c-%d-%d", rune('A'+(id*numOpsPerGoroutine+j)%26), id, j)
				userID := "user"
				_ = store.StoreToken(ctx, tokenID, userID, expiresAt)
			}
		}(i)
	}

	wg.Wait()

	// Verify no corruption
	size := store.Size()
	assert.Greater(t, size, 0)
}

func TestTokenStore_ConcurrentRevokeAndCheck(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	// Pre-populate tokens
	expiresAt := time.Now().Add(1 * time.Hour)
	for i := 0; i < 10; i++ {
		tokenID := string(rune('A' + i))
		_ = store.StoreToken(ctx, tokenID, "user", expiresAt)
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Concurrent revokers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tokenID := string(rune('A' + ((id + j) % 10)))
				_ = store.RevokeToken(ctx, tokenID)
			}
		}(i)
	}

	// Concurrent checkers
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				tokenID := string(rune('A' + (j % 10)))
				_, _ = store.IsTokenRevoked(ctx, tokenID)
			}
		}()
	}

	wg.Wait()

	// Verify all tokens are revoked
	for i := 0; i < 10; i++ {
		tokenID := string(rune('A' + i))
		revoked, err := store.IsTokenRevoked(ctx, tokenID)
		require.NoError(t, err)
		assert.True(t, revoked)
	}
}

func TestTokenStore_Size(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	assert.Equal(t, 0, store.Size())

	expiresAt := time.Now().Add(1 * time.Hour)
	_ = store.StoreToken(ctx, "token1", "user1", expiresAt)
	assert.Equal(t, 1, store.Size())

	_ = store.StoreToken(ctx, "token2", "user2", expiresAt)
	assert.Equal(t, 2, store.Size())
}

func TestTokenStore_Clear(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	expiresAt := time.Now().Add(1 * time.Hour)

	// Add tokens
	_ = store.StoreToken(ctx, "token1", "user1", expiresAt)
	_ = store.StoreToken(ctx, "token2", "user2", expiresAt)
	assert.Equal(t, 2, store.Size())

	// Clear
	store.Clear()
	assert.Equal(t, 0, store.Size())

	// Verify tokens are gone
	revoked, err := store.IsTokenRevoked(ctx, "token1")
	require.NoError(t, err)
	assert.False(t, revoked) // Not found = not revoked
}

func TestTokenStore_StartCleanupRoutine(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	now := time.Now()

	// Store expired and valid tokens
	_ = store.StoreToken(ctx, "expired1", "user1", now.Add(-1*time.Second))
	_ = store.StoreToken(ctx, "valid1", "user2", now.Add(10*time.Second))

	// Start cleanup routine with very short interval
	stop := store.StartCleanupRoutine(ctx, 100*time.Millisecond)
	defer stop()

	// Wait for cleanup to run
	time.Sleep(200 * time.Millisecond)

	// Verify expired token was cleaned up
	assert.Equal(t, 1, store.Size())
}

func TestTokenStore_StartCleanupRoutine_Stop(t *testing.T) {
	store := NewTokenStore()
	ctx := context.Background()

	// Start cleanup routine
	stop := store.StartCleanupRoutine(ctx, 50*time.Millisecond)

	// Stop immediately
	stop()

	// Add expired token after stopping
	now := time.Now()
	_ = store.StoreToken(ctx, "expired", "user", now.Add(-1*time.Hour))

	// Wait to ensure cleanup doesn't run
	time.Sleep(150 * time.Millisecond)

	// Token should still be there (cleanup stopped)
	assert.Equal(t, 1, store.Size())
}

// Verify TokenStore implements the interface
var _ core.TokenStore = (*TokenStore)(nil)
