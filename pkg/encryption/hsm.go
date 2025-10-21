package encryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
)

// HSMClientImpl implements the HSMClient interface
type HSMClientImpl struct {
	config *config.HSMConfig
	logger *logger.Logger
	// In production, this would contain actual HSM SDK clients
	// For now, we'll simulate HSM operations
	keys map[string]*HSMKeyData
}

// HSMKeyData represents key data stored in HSM
type HSMKeyData struct {
	ID         string
	Type       string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CreatedAt  time.Time
}

// NewHSMClient creates a new HSM client
func NewHSMClient(config *config.HSMConfig, logger *logger.Logger) (*HSMClientImpl, error) {
	client := &HSMClientImpl{
		config: config,
		logger: logger,
		keys:   make(map[string]*HSMKeyData),
	}

	if config.Enabled {
		logger.Info("HSM client initialized", "provider", config.Provider)
	} else {
		logger.Warn("HSM is disabled, using software-based key management")
	}

	return client, nil
}

// GenerateKey generates a new key in the HSM
func (h *HSMClientImpl) GenerateKey(keyType string) (*HSMKey, error) {
	keyID := uuid.New().String()

	switch keyType {
	case "RSA-2048":
		return h.generateRSAKey(keyID, 2048)
	case "RSA-4096":
		return h.generateRSAKey(keyID, 4096)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// generateRSAKey generates an RSA key pair
func (h *HSMClientImpl) generateRSAKey(keyID string, bits int) (*HSMKey, error) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Store key data
	keyData := &HSMKeyData{
		ID:         keyID,
		Type:       fmt.Sprintf("RSA-%d", bits),
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
	}

	h.keys[keyID] = keyData

	hsmKey := &HSMKey{
		ID:        keyID,
		Type:      keyData.Type,
		PublicKey: keyData.PublicKey,
		CreatedAt: keyData.CreatedAt,
	}

	h.logger.Info("Generated new key in HSM", "keyID", keyID, "type", keyData.Type)
	return hsmKey, nil
}

// Sign signs data using the specified key
func (h *HSMClientImpl) Sign(keyID string, data []byte) ([]byte, error) {
	keyData, exists := h.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Create hash of data
	hash := sha256.Sum256(data)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, keyData.PrivateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	h.logger.Debug("Signed data with HSM key", "keyID", keyID, "dataSize", len(data))
	return signature, nil
}

// Decrypt decrypts data using the specified key
func (h *HSMClientImpl) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	keyData, exists := h.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Decrypt using RSA-OAEP
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, keyData.PrivateKey, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	h.logger.Debug("Decrypted data with HSM key", "keyID", keyID, "ciphertextSize", len(ciphertext))
	return plaintext, nil
}

// GetPublicKey retrieves the public key for the specified key ID
func (h *HSMClientImpl) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	keyData, exists := h.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	return keyData.PublicKey, nil
}

// DeleteKey deletes a key from the HSM
func (h *HSMClientImpl) DeleteKey(keyID string) error {
	if _, exists := h.keys[keyID]; !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	delete(h.keys, keyID)
	h.logger.Info("Deleted key from HSM", "keyID", keyID)
	return nil
}

// ListKeys lists all keys in the HSM
func (h *HSMClientImpl) ListKeys() ([]*HSMKey, error) {
	keys := make([]*HSMKey, 0, len(h.keys))

	for _, keyData := range h.keys {
		hsmKey := &HSMKey{
			ID:        keyData.ID,
			Type:      keyData.Type,
			PublicKey: keyData.PublicKey,
			CreatedAt: keyData.CreatedAt,
		}
		keys = append(keys, hsmKey)
	}

	return keys, nil
}

// RotateKey rotates an existing key (generates new version)
func (h *HSMClientImpl) RotateKey(keyID string) (*HSMKey, error) {
	oldKeyData, exists := h.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	// Generate new key with same type
	newKeyID := uuid.New().String()
	
	var bits int
	switch oldKeyData.Type {
	case "RSA-2048":
		bits = 2048
	case "RSA-4096":
		bits = 4096
	default:
		return nil, fmt.Errorf("unsupported key type for rotation: %s", oldKeyData.Type)
	}

	newKey, err := h.generateRSAKey(newKeyID, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rotated key: %w", err)
	}

	h.logger.Info("Rotated HSM key", "oldKeyID", keyID, "newKeyID", newKeyID)
	return newKey, nil
}