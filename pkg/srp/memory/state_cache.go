package memory

import (
	"fmt"
	"sync"

	"go.fergus.london/nopasswords/pkg/srp"
)

// StateCache is an in-memory implementation of srp.StateCache.
//
// This implementation stores ephemeral SRP authentication state in memory using
// a thread-safe map. State is lost when the process terminates.
//
// State includes server ephemeral values (B, b) generated during assertion initiation
// that must be available during assertion completion.
//
// Use cases:
//   - Testing and development
//   - Single-server deployments
//   - Applications where authentication state loss is acceptable
//
// For multi-server deployments, implement a distributed cache (Redis, Memcached).
type StateCache struct {
	mtx   sync.RWMutex
	cache map[string]*srp.AssertionState
}

// NewInMemoryStateCache creates a new in-memory state cache.
//
// The cache is empty and ready to use. All operations are thread-safe.
//
// Example:
//
//	cache := memory.NewInMemoryStateCache()
//	manager, err := srp.NewManager(
//	    srp.WithStateCache(cache),
//	    // ... other options
//	)
func NewInMemoryStateCache() *StateCache {
	return &StateCache{
		mtx:   sync.RWMutex{},
		cache: make(map[string]*srp.AssertionState),
	}
}

// GetForUserIdentifier retrieves authentication state for a given user identifier.
//
// Returns an error if no state exists for the specified user.
// This typically indicates the user has not initiated authentication or the state expired.
//
// This method is thread-safe.
func (sc *StateCache) GetForUserIdentifier(ident string) (*srp.AssertionState, error) {
	sc.mtx.RLock()
	defer sc.mtx.RUnlock()

	if state, ok := sc.cache[ident]; ok {
		return state, nil
	}

	return nil, fmt.Errorf("no state available for '%s'", ident)
}

// StoreForUserIdentifier stores authentication state for a given user identifier.
//
// State is stored during assertion initiation and retrieved during assertion completion.
// If state already exists for this user, it is overwritten.
//
// This method is thread-safe.
func (sc *StateCache) StoreForUserIdentifier(ident string, state *srp.AssertionState) error {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sc.cache[ident] = state
	return nil
}

// PurgeForUserIdentity removes authentication state for a given user identifier.
//
// This should be called after successful authentication or when state expires.
// Removing non-existent state is not an error.
//
// This method is thread-safe.
func (sc *StateCache) PurgeForUserIdentity(ident string) error {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	delete(sc.cache, ident)
	return nil
}
