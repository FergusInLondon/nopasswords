package memory

import (
	"fmt"
	"sync"

	"go.fergus.london/nopasswords/pkg/srp"
)

type ParameterStore struct {
	mtx   sync.RWMutex
	store map[string]*srp.Parameters
}

func NewInMemoryParameterStore() *ParameterStore {
	return &ParameterStore{
		mtx:   sync.RWMutex{},
		store: make(map[string]*srp.Parameters),
	}
}

func (ps *ParameterStore) GetForUserIdentifier(ident string) (*srp.Parameters, error) {
	ps.mtx.RLock()
	defer ps.mtx.RUnlock()

	if params, ok := ps.store[ident]; ok {
		return params, nil
	}

	return nil, fmt.Errorf("no params available for '%s'", ident)
}

func (ps *ParameterStore) StoreForUserIdentifier(ident string, params *srp.Parameters) error {
	ps.mtx.Lock()
	defer ps.mtx.Unlock()

	ps.store[ident] = params
	return nil
}
