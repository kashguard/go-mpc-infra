package backup

import (
	"crypto/rand"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	// 1. Generate recipient key pair
	privKey, err := crypto.GenerateKey()
	require.NoError(t, err)
	pubKey := &privKey.PublicKey

	// 2. Prepare data
	originalData := []byte("this is a secret share data for backup delivery")

	// 3. Encrypt
	encryptedData, err := EncryptShare(originalData, pubKey)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)

	// 4. Decrypt
	decryptedData, err := DecryptShare(encryptedData, privKey)
	require.NoError(t, err)

	// 5. Verify
	assert.Equal(t, originalData, decryptedData)
}

func TestDecryptWithWrongKey(t *testing.T) {
	// Alice
	alicePriv, _ := crypto.GenerateKey()
	alicePub := &alicePriv.PublicKey

	// Bob
	bobPriv, _ := crypto.GenerateKey()

	data := []byte("secret")

	// Encrypt for Alice
	encrypted, err := EncryptShare(data, alicePub)
	require.NoError(t, err)

	// Try to decrypt with Bob's key
	_, err = DecryptShare(encrypted, bobPriv)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt") // Likely GCM Open failure due to wrong key
}

func TestTamperedCiphertext(t *testing.T) {
	privKey, _ := crypto.GenerateKey()
	pubKey := &privKey.PublicKey
	data := []byte("secret")

	encrypted, err := EncryptShare(data, pubKey)
	require.NoError(t, err)

	// Tamper with the last byte (part of the tag or ciphertext)
	encrypted[len(encrypted)-1] ^= 0xFF

	_, err = DecryptShare(encrypted, privKey)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt")
}

func TestTamperedEphemeralKey(t *testing.T) {
	privKey, _ := crypto.GenerateKey()
	pubKey := &privKey.PublicKey
	data := []byte("secret")

	encrypted, err := EncryptShare(data, pubKey)
	require.NoError(t, err)

	// Tamper with the ephemeral public key (first 33 bytes)
	// We change a byte in the middle of the key
	encrypted[10] ^= 0xFF

	_, err = DecryptShare(encrypted, privKey)
	// It should fail either at DecompressPubkey or at Decryption
	assert.Error(t, err)
}

func TestEncryptShare_NilPubKey(t *testing.T) {
	_, err := EncryptShare([]byte("data"), nil)
	assert.Error(t, err)
	assert.Equal(t, "recipient public key is nil", err.Error())
}

func TestDecryptShare_NilPrivKey(t *testing.T) {
	_, err := DecryptShare([]byte("data"), nil)
	assert.Error(t, err)
	assert.Equal(t, "recipient private key is nil", err.Error())
}

func TestDecryptShare_ShortData(t *testing.T) {
	privKey, _ := crypto.GenerateKey()

	// Too short
	_, err := DecryptShare([]byte("short"), privKey)
	assert.Error(t, err)
}

func BenchmarkEncrypt(b *testing.B) {
	privKey, _ := crypto.GenerateKey()
	pubKey := &privKey.PublicKey
	data := make([]byte, 1024) // 1KB
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = EncryptShare(data, pubKey)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	privKey, _ := crypto.GenerateKey()
	pubKey := &privKey.PublicKey
	data := make([]byte, 1024) // 1KB
	rand.Read(data)
	encrypted, _ := EncryptShare(data, pubKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptShare(encrypted, privKey)
	}
}
