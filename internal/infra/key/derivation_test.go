package key

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDerivationPath(t *testing.T) {
	s := NewDerivationService()

	tests := []struct {
		name     string
		path     string
		expected []uint32
		wantErr  bool
	}{
		{
			name:     "Simple path",
			path:     "m/0/1/2",
			expected: []uint32{0, 1, 2},
			wantErr:  false,
		},
		{
			name:     "Hardened path with quote",
			path:     "m/44'/60'/0'/0/0",
			expected: []uint32{44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000, 0, 0},
			wantErr:  false,
		},
		{
			name:     "Hardened path with h",
			path:     "m/44h/60h/0h",
			expected: []uint32{44 | 0x80000000, 60 | 0x80000000, 0 | 0x80000000},
			wantErr:  false,
		},
		{
			name:     "Root path",
			path:     "m",
			expected: []uint32{},
			wantErr:  false,
		},
		{
			name:     "Empty path",
			path:     "",
			expected: []uint32{},
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			indices, err := s.ParseDerivationPath(tt.path)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, indices)
			}
		})
	}
}

func TestDeriveEd25519(t *testing.T) {
	s := NewDerivationService()

	// Test vectors would be ideal, but for now we check basic functionality
	// Generate a dummy Ed25519 public key (32 bytes)
	// For Ed25519, the base point is y=4/5...
	// We'll use a known valid public key or generate one using edwards library
	
	// Valid Ed25519 public key (32 bytes)
	// This is just a random 32 byte string, but for point addition to work, it MUST be a valid point on the curve.
	// We can't just use random bytes.
	
	// Let's use the generator point (Base Point)
	// Base Point encoded is:
	// 58 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66 66
	// (Actually it's y=4/5, x is determined)
	
	// Use a hex string for a valid Ed25519 pubkey (from a test vector)
	// PubKey: 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 (from RFC 8032 A.1)
	pubKeyHex := "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
	pubKeyBytes, _ := hex.DecodeString(pubKeyHex)
	
	chainCode := make([]byte, 32)
	for i := range chainCode {
		chainCode[i] = 0x01 // Use non-zero chaincode
	}

	// Derive index 0
	res, err := s.deriveEd25519(pubKeyBytes, chainCode, 0)
	if err != nil {
		t.Fatalf("deriveEd25519 failed: %v", err)
	}
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Len(t, res.PublicKey, 32)
	assert.Len(t, res.ChainCode, 32)
	assert.NotEqual(t, pubKeyBytes, res.PublicKey)
}
