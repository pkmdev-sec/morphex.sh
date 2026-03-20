// encrypted_storage.go -- Tier 3: Secure Storage
//
// Provides AES-256-GCM encryption for secret values at rest.
// Each encryption uses a unique random nonce, ensuring identical
// plaintexts produce different ciphertexts. Standard library only.
package synapse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

// EncryptedStorage handles secure storage and retrieval of detected secret values.
// Secrets are encrypted at rest using AES-256-GCM with per-encryption nonces.
type EncryptedStorage struct {
	masterKey []byte // 32 bytes for AES-256
}

// NewEncryptedStorage creates a new encrypted storage with the given master key.
// masterKeyHex must be a 64-character hex string (32 bytes / 256 bits).
func NewEncryptedStorage(masterKeyHex string) (*EncryptedStorage, error) {
	key, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid master key hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (256 bits), got %d bytes", len(key))
	}
	return &EncryptedStorage{masterKey: key}, nil
}

// Encrypt encrypts a plaintext string using AES-256-GCM.
// Returns base64-encoded ciphertext (nonce prepended to ciphertext).
func (es *EncryptedStorage) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(es.masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt: nonce is prepended to the ciphertext
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a previously encrypted value.
// Input is base64-encoded ciphertext with prepended nonce.
func (es *EncryptedStorage) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	block, err := aes.NewCipher(es.masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, encrypted := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// EncryptFinding encrypts the sensitive fields of a finding (RawSecret).
func (es *EncryptedStorage) EncryptFinding(f *AgentTeamResult) error {
	if f.RawSecret == "" {
		return nil
	}
	encrypted, err := es.Encrypt(f.RawSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt finding: %w", err)
	}
	f.RawSecret = encrypted
	return nil
}

// DecryptFinding decrypts the sensitive fields of a finding.
func (es *EncryptedStorage) DecryptFinding(f *AgentTeamResult) error {
	if f.RawSecret == "" {
		return nil
	}
	decrypted, err := es.Decrypt(f.RawSecret)
	if err != nil {
		return fmt.Errorf("failed to decrypt finding: %w", err)
	}
	f.RawSecret = decrypted
	return nil
}
