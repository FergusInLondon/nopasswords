// Package memory provides in-memory reference implementations of the core interfaces.
// These implementations are suitable for testing, development, and demonstrations.
//
// WARNING: These implementations are NOT suitable for production use as they:
// - Store data only in memory (no persistence)
// - Do not implement cleanup or TTL policies
// - May consume unbounded memory without proper management
//
// Production implementations should use persistent storage with appropriate
// backup, replication, and cleanup strategies.
package memory

import (
	"context"
	"sync"

	"go.fergus.london/nopasswords/core"
)

// credential represents a stored credential with its metadata.
type credential struct {
	UserID       string
	CredentialID string
	Data         []byte
}

// CredentialStore is an in-memory implementation of core.CredentialStore.
//
// This implementation is safe for concurrent use by multiple goroutines.
//
// @mitigation Tampering: Uses sync.RWMutex to protect against concurrent access
// and prevent data races. All read operations use RLock, write operations use Lock.
//
// @risk Denial of Service: Does not implement automatic cleanup or size limits.
// In a long-running application, this can lead to unbounded memory growth.
// Production implementations should include TTL and storage limits.
type CredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]*credential // key: userID:credentialID
}

// NewCredentialStore creates a new in-memory credential store.
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		credentials: make(map[string]*credential),
	}
}

// key generates a storage key from userID and credentialID.
func (m *CredentialStore) key(userID, credentialID string) string {
	return userID + ":" + credentialID
}

// StoreCredential implements core.CredentialStore.
func (m *CredentialStore) StoreCredential(ctx context.Context, userID string, credentialID string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.key(userID, credentialID)
	if _, exists := m.credentials[key]; exists {
		return core.ErrAlreadyExists
	}

	// Create a copy of the data to prevent external modification
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	m.credentials[key] = &credential{
		UserID:       userID,
		CredentialID: credentialID,
		Data:         dataCopy,
	}

	return nil
}

// GetCredential implements core.CredentialStore.
func (m *CredentialStore) GetCredential(ctx context.Context, userID string, credentialID string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := m.key(userID, credentialID)
	cred, exists := m.credentials[key]
	if !exists {
		return nil, core.ErrNotFound
	}

	// Return a copy to prevent external modification
	dataCopy := make([]byte, len(cred.Data))
	copy(dataCopy, cred.Data)

	return dataCopy, nil
}

// ListCredentials implements core.CredentialStore.
func (m *CredentialStore) ListCredentials(ctx context.Context, userID string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var credentialIDs []string
	for _, cred := range m.credentials {
		if cred.UserID == userID {
			credentialIDs = append(credentialIDs, cred.CredentialID)
		}
	}

	// Return empty slice instead of nil for consistency
	if credentialIDs == nil {
		credentialIDs = []string{}
	}

	return credentialIDs, nil
}

// DeleteCredential implements core.CredentialStore.
func (m *CredentialStore) DeleteCredential(ctx context.Context, userID string, credentialID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.key(userID, credentialID)
	if _, exists := m.credentials[key]; !exists {
		return core.ErrNotFound
	}

	delete(m.credentials, key)
	return nil
}

// UpdateCredential implements core.CredentialStore.
func (m *CredentialStore) UpdateCredential(ctx context.Context, userID string, credentialID string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := m.key(userID, credentialID)
	cred, exists := m.credentials[key]
	if !exists {
		return core.ErrNotFound
	}

	// Create a copy of the data to prevent external modification
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	cred.Data = dataCopy
	return nil
}

// Size returns the number of credentials stored. Useful for testing and metrics.
func (m *CredentialStore) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.credentials)
}

// Clear removes all credentials. Useful for testing.
func (m *CredentialStore) Clear() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.credentials = make(map[string]*credential)
}
