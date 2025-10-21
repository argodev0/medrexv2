package encryption

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PREService implements Proxy Re-Encryption functionality
type PREService struct {
	hsmClient HSMClient
	keyStore  KeyStore
}

// HSMClient interface for Hardware Security Module operations
type HSMClient interface {
	GenerateKey(keyType string) (*HSMKey, error)
	Sign(keyID string, data []byte) ([]byte, error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
	GetPublicKey(keyID string) (*rsa.PublicKey, error)
}

// KeyStore interface for key management
type KeyStore interface {
	StoreKey(key *EncryptionKey) error
	GetKey(keyID string) (*EncryptionKey, error)
	GetActiveKey(userID string) (*EncryptionKey, error)
	RevokeKey(keyID string) error
}

// HSMKey represents a key stored in HSM
type HSMKey struct {
	ID        string
	Type      string
	PublicKey *rsa.PublicKey
	CreatedAt time.Time
}

// EncryptionKey represents an encryption key with metadata
type EncryptionKey struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	KeyType     string    `json:"key_type"`
	HSMKeyID    string    `json:"hsm_key_id"`
	PublicKey   string    `json:"public_key"`
	KeyVersion  int       `json:"key_version"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	IsActive    bool      `json:"is_active"`
}

// ReEncryptionToken represents a token for proxy re-encryption
type ReEncryptionToken struct {
	ID           string    `json:"id"`
	FromUserID   string    `json:"from_user_id"`
	ToUserID     string    `json:"to_user_id"`
	ResourceID   string    `json:"resource_id"`
	TokenData    string    `json:"token_data"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsActive     bool      `json:"is_active"`
}

// NewPREService creates a new Proxy Re-Encryption service
func NewPREService(hsmClient HSMClient, keyStore KeyStore) *PREService {
	return &PREService{
		hsmClient: hsmClient,
		keyStore:  keyStore,
	}
}

// GenerateUserKeys generates a new key pair for a user
func (p *PREService) GenerateUserKeys(userID string) (*EncryptionKey, error) {
	// Generate key in HSM
	hsmKey, err := p.hsmClient.GenerateKey("RSA-2048")
	if err != nil {
		return nil, fmt.Errorf("failed to generate HSM key: %w", err)
	}

	// Encode public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(hsmKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Create encryption key record
	encKey := &EncryptionKey{
		ID:         uuid.New().String(),
		UserID:     userID,
		KeyType:    "RSA-2048",
		HSMKeyID:   hsmKey.ID,
		PublicKey:  string(publicKeyPEM),
		KeyVersion: 1,
		CreatedAt:  time.Now(),
		IsActive:   true,
	}

	// Store key metadata
	if err := p.keyStore.StoreKey(encKey); err != nil {
		return nil, fmt.Errorf("failed to store key: %w", err)
	}

	return encKey, nil
}

// CreateReEncryptionToken creates a token allowing proxy re-encryption
func (p *PREService) CreateReEncryptionToken(fromUserID, toUserID, resourceID string, expiresIn time.Duration) (*ReEncryptionToken, error) {
	// Get source user's key
	fromKey, err := p.keyStore.GetActiveKey(fromUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get source key: %w", err)
	}

	// Get target user's key
	toKey, err := p.keyStore.GetActiveKey(toUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target key: %w", err)
	}

	// Create token data (simplified PRE token generation)
	tokenData, err := p.generateTokenData(fromKey, toKey, resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token data: %w", err)
	}

	token := &ReEncryptionToken{
		ID:         uuid.New().String(),
		FromUserID: fromUserID,
		ToUserID:   toUserID,
		ResourceID: resourceID,
		TokenData:  tokenData,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(expiresIn),
		IsActive:   true,
	}

	return token, nil
}

// ValidateReEncryptionToken validates a re-encryption token
func (p *PREService) ValidateReEncryptionToken(token *ReEncryptionToken) error {
	if !token.IsActive {
		return fmt.Errorf("token is not active")
	}

	if time.Now().After(token.ExpiresAt) {
		return fmt.Errorf("token has expired")
	}

	// Additional validation logic would go here
	// In a full implementation, this would verify the cryptographic validity

	return nil
}

// ReEncrypt performs proxy re-encryption using a token
func (p *PREService) ReEncrypt(ciphertext []byte, token *ReEncryptionToken) ([]byte, error) {
	// Validate token
	if err := p.ValidateReEncryptionToken(token); err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Get source user's key for decryption
	fromKey, err := p.keyStore.GetActiveKey(token.FromUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get source key: %w", err)
	}

	// Decrypt with source key (via HSM)
	plaintext, err := p.hsmClient.Decrypt(fromKey.HSMKeyID, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with source key: %w", err)
	}

	// Get target user's public key
	toKey, err := p.keyStore.GetActiveKey(token.ToUserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get target key: %w", err)
	}

	// Parse target public key
	targetPubKey, err := p.parsePublicKey(toKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target public key: %w", err)
	}

	// Re-encrypt for target user
	reEncrypted, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, targetPubKey, plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encrypt: %w", err)
	}

	return reEncrypted, nil
}

// generateTokenData creates the cryptographic token data for PRE
func (p *PREService) generateTokenData(fromKey, toKey *EncryptionKey, resourceID string) (string, error) {
	// In a full PRE implementation, this would generate proper re-encryption keys
	// For this implementation, we create a signed token containing the key relationship
	
	tokenPayload := fmt.Sprintf("%s:%s:%s:%d", fromKey.ID, toKey.ID, resourceID, time.Now().Unix())
	
	// Sign the token with the source key
	signature, err := p.hsmClient.Sign(fromKey.HSMKeyID, []byte(tokenPayload))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Combine payload and signature
	tokenData := fmt.Sprintf("%s.%s", 
		base64.StdEncoding.EncodeToString([]byte(tokenPayload)),
		base64.StdEncoding.EncodeToString(signature))

	return tokenData, nil
}

// parsePublicKey parses a PEM-encoded public key
func (p *PREService) parsePublicKey(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return rsaPublicKey, nil
}

// RevokeReEncryptionToken revokes a re-encryption token
func (p *PREService) RevokeReEncryptionToken(tokenID string) error {
	// In a full implementation, this would mark the token as revoked
	// and update the token store
	return nil
}

// GetUserPublicKey retrieves a user's public key
func (p *PREService) GetUserPublicKey(userID string) (string, error) {
	key, err := p.keyStore.GetActiveKey(userID)
	if err != nil {
		return "", fmt.Errorf("failed to get user key: %w", err)
	}

	return key.PublicKey, nil
}