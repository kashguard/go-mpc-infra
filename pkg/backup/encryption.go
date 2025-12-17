package backup

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/hkdf"
)

const (
	// AESGCMNonceSize is the standard nonce size for GCM (12 bytes)
	AESGCMNonceSize = 12
	// KeySizeAES256 is the key size for AES-256 (32 bytes)
	KeySizeAES256 = 32
)

// EncryptShare encrypts the share data using ECIES with AES-256-GCM.
// Format: EphemeralPubKey (33/65 bytes) || Nonce (12 bytes) || Ciphertext (including tag)
func EncryptShare(share []byte, recipientPubKey *ecdsa.PublicKey) ([]byte, error) {
	if recipientPubKey == nil {
		return nil, errors.New("recipient public key is nil")
	}

	// 1. Generate ephemeral key pair
	ephemeralKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// 2. Perform ECDH to get shared secret
	// S = (r * K_B).X
	sharedSecret, err := computeSharedSecret(ephemeralKey, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// 3. Serialize ephemeral public key (compressed format is standard for storage)
	ephemeralPubBytes := crypto.CompressPubkey(&ephemeralKey.PublicKey)

	// 4. Derive encryption key using HKDF-SHA256
	// Salt = ephemeralPubBytes (binding the key to this specific exchange)
	// Info = "backup-delivery-v1"
	encKey, err := deriveKey(sharedSecret, ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// 5. Encrypt using AES-256-GCM
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	nonce := make([]byte, AESGCMNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Use ephemeral public key as AAD to bind it to the ciphertext
	ciphertext := gcm.Seal(nil, nonce, share, ephemeralPubBytes)

	// 6. Construct result: EphemeralPubKey || Nonce || Ciphertext
	result := make([]byte, 0, len(ephemeralPubBytes)+len(nonce)+len(ciphertext))
	result = append(result, ephemeralPubBytes...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptShare decrypts the encrypted share using the recipient's private key.
func DecryptShare(encryptedShare []byte, recipientPrivKey *ecdsa.PrivateKey) ([]byte, error) {
	if recipientPrivKey == nil {
		return nil, errors.New("recipient private key is nil")
	}

	// Parse the input
	// Ephemeral PubKey is 33 bytes (compressed) or 65 bytes (uncompressed)
	// We need to determine the length. crypto.CompressPubkey returns 33 bytes.
	// Let's assume compressed for now as we used it in EncryptShare.
	// If we want to support both, we check the first byte.
	if len(encryptedShare) < 33 {
		return nil, errors.New("invalid encrypted share length")
	}

	var pubKeyLen int
	switch encryptedShare[0] {
	case 2, 3: // Compressed
		pubKeyLen = 33
	case 4: // Uncompressed
		pubKeyLen = 65
	default:
		return nil, errors.New("invalid public key format")
	}

	if len(encryptedShare) < pubKeyLen+AESGCMNonceSize {
		return nil, errors.New("encrypted share too short")
	}

	ephemeralPubBytes := encryptedShare[:pubKeyLen]
	nonce := encryptedShare[pubKeyLen : pubKeyLen+AESGCMNonceSize]
	ciphertext := encryptedShare[pubKeyLen+AESGCMNonceSize:]

	// 1. Unmarshal ephemeral public key
	ephemeralPubKey, err := crypto.DecompressPubkey(ephemeralPubBytes)
	if err != nil {
		// Try uncompressed if failed (though we checked the byte prefix)
		ephemeralPubKey, err = crypto.UnmarshalPubkey(ephemeralPubBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal ephemeral public key: %w", err)
		}
	}

	// 2. Perform ECDH to get shared secret
	// S = (k_B * R).X
	// Note: computeSharedSecret handles the multiplication.
	// We need to treat the recipientPrivKey as the "private" part and ephemeral as "public".
	// The secret is the same: r * K_B = k_B * R
	sharedSecret, err := computeSharedSecret(recipientPrivKey, ephemeralPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// 3. Derive encryption key
	encKey, err := deriveKey(sharedSecret, ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	// 4. Decrypt using AES-256-GCM
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, ephemeralPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// computeSharedSecret computes the ECDH shared secret (x-coordinate).
func computeSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	if priv == nil || pub == nil {
		return nil, errors.New("key is nil")
	}
	// S256 is the secp256k1 curve
	if !crypto.S256().IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("public key is not on curve")
	}

	x, _ := crypto.S256().ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x == nil {
		return nil, errors.New("shared secret is nil")
	}
	return x.Bytes(), nil
}

// deriveKey derives the AES-256 key from the shared secret and salt using HKDF.
func deriveKey(secret, salt []byte) ([]byte, error) {
	// Info can be a protocol specific string
	info := []byte("backup-delivery-v1")

	// HKDF-SHA256
	kdf := hkdf.New(sha256.New, secret, salt, info)

	key := make([]byte, KeySizeAES256)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}

	return key, nil
}
