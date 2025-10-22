package encryption

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/medrex/dlt-emr/pkg/logger"
)

// DatabaseKeyStore implements KeyStore using PostgreSQL
type DatabaseKeyStore struct {
	db     *sql.DB
	logger logger.Logger
}

// NewDatabaseKeyStore creates a new database-backed key store
func NewDatabaseKeyStore(db *sql.DB, logger logger.Logger) *DatabaseKeyStore {
	return &DatabaseKeyStore{
		db:     db,
		logger: logger,
	}
}

// StoreKey stores an encryption key in the database
func (ks *DatabaseKeyStore) StoreKey(key *EncryptionKey) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		INSERT INTO encryption_keys (
			id, key_type, encrypted_key, key_version, hsm_key_id, 
			created_at, expires_at, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

	// For this implementation, we store the HSM key ID as the encrypted_key
	// In production, this would be properly encrypted
	encryptedKeyData := []byte(key.HSMKeyID)

	_, err := ks.db.ExecContext(ctx, query,
		key.ID,
		key.KeyType,
		encryptedKeyData,
		key.KeyVersion,
		key.HSMKeyID,
		key.CreatedAt,
		key.ExpiresAt,
		key.IsActive,
	)

	if err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

	ks.logger.Info("Stored encryption key", "keyID", key.ID, "userID", key.UserID)
	return nil
}

// GetKey retrieves an encryption key by ID
func (ks *DatabaseKeyStore) GetKey(keyID string) (*EncryptionKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		SELECT id, key_type, encrypted_key, key_version, hsm_key_id,
			   created_at, expires_at, is_active
		FROM encryption_keys 
		WHERE id = $1`

	var key EncryptionKey
	var encryptedKeyData []byte
	var expiresAt sql.NullTime

	err := ks.db.QueryRowContext(ctx, query, keyID).Scan(
		&key.ID,
		&key.KeyType,
		&encryptedKeyData,
		&key.KeyVersion,
		&key.HSMKeyID,
		&key.CreatedAt,
		&expiresAt,
		&key.IsActive,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("key not found: %s", keyID)
		}
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	if expiresAt.Valid {
		key.ExpiresAt = &expiresAt.Time
	}

	return &key, nil
}

// GetActiveKey retrieves the active encryption key for a user
func (ks *DatabaseKeyStore) GetActiveKey(userID string) (*EncryptionKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First, get the user's key from the users table
	userQuery := `
		SELECT encryption_key_id 
		FROM users 
		WHERE id = $1 AND is_active = true`

	var keyID string
	err := ks.db.QueryRowContext(ctx, userQuery, userID).Scan(&keyID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no active user found: %s", userID)
		}
		return nil, fmt.Errorf("failed to get user key ID: %w", err)
	}

	// Get the encryption key
	key, err := ks.GetKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user's encryption key: %w", err)
	}

	key.UserID = userID
	return key, nil
}

// RevokeKey revokes an encryption key
func (ks *DatabaseKeyStore) RevokeKey(keyID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query := `
		UPDATE encryption_keys 
		SET is_active = false 
		WHERE id = $1`

	result, err := ks.db.ExecContext(ctx, query, keyID)
	if err != nil {
		return fmt.Errorf("failed to revoke key: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("key not found: %s", keyID)
	}

	ks.logger.Info("Revoked encryption key", "keyID", keyID)
	return nil
}

// ListUserKeys lists all keys for a user
func (ks *DatabaseKeyStore) ListUserKeys(userID string) ([]*EncryptionKey, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `
		SELECT ek.id, ek.key_type, ek.encrypted_key, ek.key_version, 
			   ek.hsm_key_id, ek.created_at, ek.expires_at, ek.is_active
		FROM encryption_keys ek
		JOIN users u ON u.encryption_key_id = ek.id
		WHERE u.id = $1
		ORDER BY ek.created_at DESC`

	rows, err := ks.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user keys: %w", err)
	}
	defer rows.Close()

	var keys []*EncryptionKey
	for rows.Next() {
		var key EncryptionKey
		var encryptedKeyData []byte
		var expiresAt sql.NullTime

		err := rows.Scan(
			&key.ID,
			&key.KeyType,
			&encryptedKeyData,
			&key.KeyVersion,
			&key.HSMKeyID,
			&key.CreatedAt,
			&expiresAt,
			&key.IsActive,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan key row: %w", err)
		}

		if expiresAt.Valid {
			key.ExpiresAt = &expiresAt.Time
		}

		key.UserID = userID
		keys = append(keys, &key)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating key rows: %w", err)
	}

	return keys, nil
}

// CleanupExpiredKeys removes expired keys from the database
func (ks *DatabaseKeyStore) CleanupExpiredKeys() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	query := `
		UPDATE encryption_keys 
		SET is_active = false 
		WHERE expires_at < NOW() AND is_active = true`

	result, err := ks.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired keys: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected > 0 {
		ks.logger.Info("Cleaned up expired keys", "count", rowsAffected)
	}

	return nil
}