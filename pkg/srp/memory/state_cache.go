package memory

import (
	"fmt"
	"sync"

	"go.fergus.london/nopasswords/pkg/srp"
)

// StateCache ... TODO
type StateCache struct {
	mtx   sync.RWMutex
	cache map[string]*srp.AssertionState
}

// NewInMemoryStateCache ... TODO
func NewInMemoryStateCache() *StateCache {
	return &StateCache{
		mtx:   sync.RWMutex{},
		cache: make(map[string]*srp.AssertionState),
	}
}

// GetForUserIdentifier ... TODO
func (sc *StateCache) GetForUserIdentifier(ident string) (*srp.AssertionState, error) {
	sc.mtx.RLock()
	defer sc.mtx.RUnlock()

	if state, ok := sc.cache[ident]; ok {
		return state, nil
	}

	return nil, fmt.Errorf("no state available for '%s'", ident)
}

// StoreForUserIdentifier ... TODO
func (sc *StateCache) StoreForUserIdentifier(ident string, state *srp.AssertionState) error {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	sc.cache[ident] = state
	return nil
}

// PurgeForUserIdentity ... TODO
func (sc *StateCache) PurgeForUserIdentity(ident string) error {
	sc.mtx.Lock()
	defer sc.mtx.Unlock()

	delete(sc.cache, ident)
	return nil
}
