package memory

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.fergus.london/nopasswords/pkg/core"
)

func TestCredentialStore_StoreAndGet(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	userID := "user123"
	credentialID := "cred456"
	data := []byte("credential data")

	// Store credential
	err := store.StoreCredential(ctx, userID, credentialID, data)
	require.NoError(t, err)

	// Retrieve credential
	retrieved, err := store.GetCredential(ctx, userID, credentialID)
	require.NoError(t, err)
	assert.Equal(t, data, retrieved)
}

func TestCredentialStore_StoreCredential_AlreadyExists(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	userID := "user123"
	credentialID := "cred456"
	data := []byte("credential data")

	// Store credential
	err := store.StoreCredential(ctx, userID, credentialID, data)
	require.NoError(t, err)

	// Attempt to store again with same ID
	err = store.StoreCredential(ctx, userID, credentialID, []byte("different data"))
	assert.ErrorIs(t, err, core.ErrAlreadyExists)
}

func TestCredentialStore_GetCredential_NotFound(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	_, err := store.GetCredential(ctx, "nonexistent", "cred123")
	assert.ErrorIs(t, err, core.ErrNotFound)
}

func TestCredentialStore_ListCredentials(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	userID := "user123"

	// Store multiple credentials
	err := store.StoreCredential(ctx, userID, "cred1", []byte("data1"))
	require.NoError(t, err)
	err = store.StoreCredential(ctx, userID, "cred2", []byte("data2"))
	require.NoError(t, err)
	err = store.StoreCredential(ctx, userID, "cred3", []byte("data3"))
	require.NoError(t, err)

	// Store credential for different user
	err = store.StoreCredential(ctx, "user456", "cred4", []byte("data4"))
	require.NoError(t, err)

	// List credentials for user123
	creds, err := store.ListCredentials(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, creds, 3)
	assert.Contains(t, creds, "cred1")
	assert.Contains(t, creds, "cred2")
	assert.Contains(t, creds, "cred3")
	assert.NotContains(t, creds, "cred4")
}

func TestCredentialStore_ListCredentials_Empty(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	// List credentials for non-existent user
	creds, err := store.ListCredentials(ctx, "nonexistent")
	require.NoError(t, err)
	assert.NotNil(t, creds)
	assert.Len(t, creds, 0)
}

func TestCredentialStore_DeleteCredential(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	userID := "user123"
	credentialID := "cred456"
	data := []byte("credential data")

	// Store credential
	err := store.StoreCredential(ctx, userID, credentialID, data)
	require.NoError(t, err)

	// Delete credential
	err = store.DeleteCredential(ctx, userID, credentialID)
	require.NoError(t, err)

	// Verify it's gone
	_, err = store.GetCredential(ctx, userID, credentialID)
	assert.ErrorIs(t, err, core.ErrNotFound)
}

func TestCredentialStore_DeleteCredential_NotFound(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	err := store.DeleteCredential(ctx, "nonexistent", "cred123")
	assert.ErrorIs(t, err, core.ErrNotFound)
}

func TestCredentialStore_UpdateCredential(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	userID := "user123"
	credentialID := "cred456"
	originalData := []byte("original data")
	updatedData := []byte("updated data")

	// Store credential
	err := store.StoreCredential(ctx, userID, credentialID, originalData)
	require.NoError(t, err)

	// Update credential
	err = store.UpdateCredential(ctx, userID, credentialID, updatedData)
	require.NoError(t, err)

	// Verify update
	retrieved, err := store.GetCredential(ctx, userID, credentialID)
	require.NoError(t, err)
	assert.Equal(t, updatedData, retrieved)
}

func TestCredentialStore_UpdateCredential_NotFound(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	err := store.UpdateCredential(ctx, "nonexistent", "cred123", []byte("data"))
	assert.ErrorIs(t, err, core.ErrNotFound)
}

func TestCredentialStore_DataIsolation(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	userID := "user123"
	credentialID := "cred456"
	originalData := []byte("original data")

	// Store credential
	err := store.StoreCredential(ctx, userID, credentialID, originalData)
	require.NoError(t, err)

	// Modify the original data
	originalData[0] = 'X'

	// Retrieve credential and verify it wasn't affected
	retrieved, err := store.GetCredential(ctx, userID, credentialID)
	require.NoError(t, err)
	assert.Equal(t, byte('o'), retrieved[0])

	// Modify retrieved data
	retrieved[0] = 'Y'

	// Get again and verify no modification
	retrieved2, err := store.GetCredential(ctx, userID, credentialID)
	require.NoError(t, err)
	assert.Equal(t, byte('o'), retrieved2[0])
}

func TestCredentialStore_ConcurrentAccess(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	const numGoroutines = 100
	const numOpsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOpsPerGoroutine; j++ {
				userID := "user"
				credID := string(rune('A' + (id*numOpsPerGoroutine+j)%26))
				data := []byte{byte(id), byte(j)}
				_ = store.StoreCredential(ctx, userID, credID, data)
			}
		}(i)
	}

	wg.Wait()

	// Verify no corruption
	size := store.Size()
	assert.Greater(t, size, 0)
}

func TestCredentialStore_ConcurrentReadWrite(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	// Pre-populate some data
	for i := 0; i < 10; i++ {
		credID := string(rune('A' + i))
		_ = store.StoreCredential(ctx, "user", credID, []byte{byte(i)})
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 2)

	// Concurrent readers
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				credID := string(rune('A' + (j % 10)))
				_, _ = store.GetCredential(ctx, "user", credID)
			}
		}()
	}

	// Concurrent writers
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				credID := string(rune('A' + ((id + j) % 10)))
				_ = store.UpdateCredential(ctx, "user", credID, []byte{byte(id), byte(j)})
			}
		}(i)
	}

	wg.Wait()

	// Verify store is still functional
	creds, err := store.ListCredentials(ctx, "user")
	require.NoError(t, err)
	assert.NotEmpty(t, creds)
}

func TestCredentialStore_Size(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	assert.Equal(t, 0, store.Size())

	_ = store.StoreCredential(ctx, "user1", "cred1", []byte("data"))
	assert.Equal(t, 1, store.Size())

	_ = store.StoreCredential(ctx, "user1", "cred2", []byte("data"))
	assert.Equal(t, 2, store.Size())

	_ = store.DeleteCredential(ctx, "user1", "cred1")
	assert.Equal(t, 1, store.Size())
}

func TestCredentialStore_Clear(t *testing.T) {
	store := NewCredentialStore()
	ctx := context.Background()

	// Add some credentials
	_ = store.StoreCredential(ctx, "user1", "cred1", []byte("data"))
	_ = store.StoreCredential(ctx, "user2", "cred2", []byte("data"))
	assert.Equal(t, 2, store.Size())

	// Clear
	store.Clear()
	assert.Equal(t, 0, store.Size())

	// Verify credentials are gone
	_, err := store.GetCredential(ctx, "user1", "cred1")
	assert.ErrorIs(t, err, core.ErrNotFound)
}

// Verify CredentialStore implements the interface
var _ core.CredentialStore = (*CredentialStore)(nil)
