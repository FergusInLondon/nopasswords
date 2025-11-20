package memory

import (
	"context"
	"sync"
	"time"

	"go.fergus.london/nopasswords/core"
)

// token represents a stored token with its metadata.
type token struct {
	TokenID   string
	UserID    string
	ExpiresAt time.Time
	Revoked   bool
}

// TokenStore is an in-memory implementation of core.TokenStore.
//
// This implementation is safe for concurrent use by multiple goroutines.
//
// @mitigation Tampering: Uses sync.RWMutex to protect against concurrent access
// and prevent data races. All read operations use RLock, write operations use Lock.
//
// @risk Denial of Service: While CleanupExpired() is provided, it must be called
// explicitly by the implementer. Without periodic cleanup, expired tokens will
// accumulate in memory. Consider running cleanup in a background goroutine.
type TokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*token // key: tokenID
}

// NewTokenStore creates a new in-memory token store.
func NewTokenStore() *TokenStore {
	return &TokenStore{
		tokens: make(map[string]*token),
	}
}

// StoreToken implements core.TokenStore.
func (m *TokenStore) StoreToken(ctx context.Context, tokenID string, userID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.tokens[tokenID]; exists {
		return core.ErrAlreadyExists
	}

	m.tokens[tokenID] = &token{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		Revoked:   false,
	}

	return nil
}

// IsTokenRevoked implements core.TokenStore.
func (m *TokenStore) IsTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tok, exists := m.tokens[tokenID]
	if !exists {
		// Not found means not revoked
		return false, nil
	}

	return tok.Revoked, nil
}

// RevokeToken implements core.TokenStore.
func (m *TokenStore) RevokeToken(ctx context.Context, tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	tok, exists := m.tokens[tokenID]
	if !exists {
		// Idempotent: revoking non-existent token is not an error
		// Create a revoked entry to maintain idempotency
		m.tokens[tokenID] = &token{
			TokenID: tokenID,
			Revoked: true,
		}
		return nil
	}

	tok.Revoked = true
	return nil
}

// CleanupExpired implements core.TokenStore.
func (m *TokenStore) CleanupExpired(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	count := 0

	for tokenID, tok := range m.tokens {
		// Remove if expired (and not just revoked without expiry)
		if !tok.ExpiresAt.IsZero() && tok.ExpiresAt.Before(now) {
			delete(m.tokens, tokenID)
			count++
		}
	}

	return count, nil
}

// Size returns the number of tokens stored. Useful for testing and metrics.
func (m *TokenStore) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tokens)
}

// Clear removes all tokens. Useful for testing.
func (m *TokenStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens = make(map[string]*token)
}

// StartCleanupRoutine starts a background goroutine that periodically cleans up
// expired tokens. The cleanup runs at the specified interval.
//
// Returns a function that can be called to stop the cleanup routine.
//
// Example usage:
//
//	store := NewTokenStore()
//	stop := store.StartCleanupRoutine(context.Background(), 5*time.Minute)
//	defer stop() // Stop cleanup when done
func (m *TokenStore) StartCleanupRoutine(ctx context.Context, interval time.Duration) func() {
	ticker := time.NewTicker(interval)
	done := make(chan bool)

	go func() {
		for {
			select {
			case <-ticker.C:
				_, _ = m.CleanupExpired(ctx)
			case <-done:
				ticker.Stop()
				return
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()

	return func() {
		close(done)
	}
}
