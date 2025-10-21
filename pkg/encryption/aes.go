package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// AESEncryption handles 256-bit AES encryption/decryption
type AESEncryption struct {
	key []byte
}

// NewAESEncryption creates a new AES encryption instance
func NewAESEncryption(key string) (*AESEncryption, error) {
	// Ensure we have a 32-byte key for AES-256
	keyBytes := sha256.Sum256([]byte(key))
	
	return &AESEncryption{
		key: keyBytes[:],
	}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM
func (a *AESEncryption) Encrypt(plaintext []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM
func (a *AESEncryption) Decrypt(ciphertext []byte) ([]byte, error) {
	// Create cipher block
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Check minimum length
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// EncryptString encrypts a string and returns base64 encoded result
func (a *AESEncryption) EncryptString(plaintext string) (string, error) {
	encrypted, err := a.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptString decrypts a base64 encoded string
func (a *AESEncryption) DecryptString(ciphertext string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}
	
	decrypted, err := a.Decrypt(encrypted)
	if err != nil {
		return "", err
	}
	
	return string(decrypted), nil
}

// GenerateKey generates a new 256-bit encryption key
func GenerateKey() (string, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}
	
	return base64.StdEncoding.EncodeToString(key), nil
}

// HashData generates SHA-256 hash of data for blockchain storage
func HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%x", hash)
}