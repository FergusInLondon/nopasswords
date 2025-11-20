package srp

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetGroup(t *testing.T) {
	tests := []struct {
		name      string
		groupID   int
		bitLength int
		wantErr   bool
	}{
		{
			name:      "Group 3 (2048-bit)",
			groupID:   3,
			bitLength: 2048,
			wantErr:   false,
		},
		{
			name:      "Group 4 (3072-bit)",
			groupID:   4,
			bitLength: 3072,
			wantErr:   false,
		},
		{
			name:      "Group 5 (4096-bit)",
			groupID:   5,
			bitLength: 4096,
			wantErr:   false,
		},
		{
			name:    "Invalid group ID",
			groupID: 99,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group, err := GetGroup(tt.groupID)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, group)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, group)
			assert.Equal(t, tt.bitLength, group.BitLength)
			assert.NotNil(t, group.N)
			assert.NotNil(t, group.g)

			// Verify N is positive and has correct bit length
			assert.True(t, group.N.Sign() > 0)
			assert.Equal(t, tt.bitLength, group.N.BitLen())

			// Verify g is positive and small (2 or 5)
			assert.True(t, group.g.Sign() > 0)
			assert.True(t, group.g.Cmp(big.NewInt(10)) < 0)
		})
	}
}

func TestGroup_k(t *testing.T) {
	// Test that k computation is consistent
	group, err := GetGroup(3)
	require.NoError(t, err)

	k1 := group.k()
	k2 := group.k()

	// k should be deterministic
	assert.Equal(t, k1, k2)

	// k should be positive
	assert.True(t, k1.Sign() > 0)

	// k should be less than N
	assert.True(t, k1.Cmp(group.N) < 0)
}

func TestGroup_GetGenerator(t *testing.T) {
	group, err := GetGroup(3)
	require.NoError(t, err)

	g := group.GetGenerator()
	assert.NotNil(t, g)
	assert.True(t, g.Sign() > 0)

	// Modifying returned value should not affect original
	g.Add(g, big.NewInt(1))
	g2 := group.GetGenerator()
	assert.NotEqual(t, g, g2)
}

func TestGroup_GetPrime(t *testing.T) {
	group, err := GetGroup(3)
	require.NoError(t, err)

	N := group.GetPrime()
	assert.NotNil(t, N)
	assert.True(t, N.Sign() > 0)
	assert.Equal(t, 2048, N.BitLen())

	// Modifying returned value should not affect original
	N.Add(N, big.NewInt(1))
	N2 := group.GetPrime()
	assert.NotEqual(t, N, N2)
}

func TestGroup_Generators(t *testing.T) {
	// Verify generators match RFC5054 specification
	tests := []struct {
		groupID   int
		generator int64
	}{
		{3, 2},
		{4, 5},
		{5, 5},
	}

	for _, tt := range tests {
		t.Run("Group generator", func(t *testing.T) {
			group, err := GetGroup(tt.groupID)
			require.NoError(t, err)

			expected := big.NewInt(tt.generator)
			assert.Equal(t, expected, group.g)
		})
	}
}
