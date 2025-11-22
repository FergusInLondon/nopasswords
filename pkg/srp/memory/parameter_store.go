// Package memory provides in-memory implementations of SRP storage interfaces.
//
// These implementations are suitable for testing, development, and single-server
// deployments that don't require persistence across restarts.
//
// For production use with multiple servers or persistence requirements, implement
// custom stores backed by databases (PostgreSQL, MongoDB) or distributed caches (Redis).
//
// All implementations in this package are thread-safe and can be used concurrently.
package memory

import (
	"fmt"
	"sync"

	"go.fergus.london/nopasswords/pkg/srp"
)

// ParameterStore is an in-memory implementation of srp.ParameterStore.
//
// This implementation stores SRP parameters (salt and verifier) in memory using
// a thread-safe map. Data is lost when the process terminates.
//
// Use cases:
//   - Testing and development
//   - Single-server deployments without persistence requirements
//   - Proof-of-concept applications
//
// For production deployments, consider implementing a database-backed store.
type ParameterStore struct {
	mtx   sync.RWMutex
	store map[string]*srp.Parameters
}

// NewInMemoryParameterStore creates a new in-memory parameter store.
//
// The store is empty and ready to use. All operations are thread-safe.
//
// Example:
//
//	store := memory.NewInMemoryParameterStore()
//	manager, err := srp.NewManager(
//	    srp.WithParameterStore(store),
//	    // ... other options
//	)
func NewInMemoryParameterStore() *ParameterStore {
	return &ParameterStore{
		mtx:   sync.RWMutex{},
		store: make(map[string]*srp.Parameters),
	}
}

// GetForUserIdentifier retrieves SRP parameters for a given user identifier.
//
// Returns an error if no parameters exist for the specified user.
// This typically indicates the user has not registered.
//
// This method is thread-safe.
func (ps *ParameterStore) GetForUserIdentifier(ident string) (*srp.Parameters, error) {
	ps.mtx.RLock()
	defer ps.mtx.RUnlock()

	if params, ok := ps.store[ident]; ok {
		return params, nil
	}

	return nil, fmt.Errorf("no params available for '%s'", ident)
}

// StoreForUserIdentifier stores SRP parameters for a given user identifier.
//
// If parameters already exist for this user, they are overwritten.
// In production implementations, you may want to prevent overwrites
// or require explicit confirmation.
//
// This method is thread-safe.
func (ps *ParameterStore) StoreForUserIdentifier(ident string, params *srp.Parameters) error {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	ps.store[ident] = params
	return nil
}
