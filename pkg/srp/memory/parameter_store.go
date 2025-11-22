// Package memory ... TODO
package memory

import (
	"fmt"
	"sync"

	"go.fergus.london/nopasswords/pkg/srp"
)

// ParameterStore ... TODO
type ParameterStore struct {
	mtx   sync.RWMutex
	store map[string]*srp.Parameters
}

// NewInMemoryParameterStore ... TODO
func NewInMemoryParameterStore() *ParameterStore {
	return &ParameterStore{
		mtx:   sync.RWMutex{},
		store: make(map[string]*srp.Parameters),
	}
}

// GetForUserIdentifier ... TODO
func (ps *ParameterStore) GetForUserIdentifier(ident string) (*srp.Parameters, error) {
	ps.mtx.RLock()
	defer ps.mtx.RUnlock()

	if params, ok := ps.store[ident]; ok {
		return params, nil
	}

	return nil, fmt.Errorf("no params available for '%s'", ident)
}

// StoreForUserIdentifier ... TODO
func (ps *ParameterStore) StoreForUserIdentifier(ident string, params *srp.Parameters) error {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	ps.store[ident] = params
	return nil
}
