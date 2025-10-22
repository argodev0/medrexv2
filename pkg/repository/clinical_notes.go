package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/medrex/dlt-emr/pkg/encryption"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// ClinicalNotesRepository handles encrypted clinical notes operations
type ClinicalNotesRepository struct {
	db        *sql.DB
	encryptor *encryption.AESEncryption
	logger    logger.Logger
}

// NewClinicalNotesRepository creates a new clinical notes repository
func NewClinicalNotesRepository(db *sql.DB, encryptor *encryption.AESEncryption, logger logger.Logger) *ClinicalNotesRepository {
	return &ClinicalNotesRepository{
		db:        db,
		encryptor: encryptor,
		logger:    logger,
	}
}

// Create creates a new clinical note with encrypted content
func (r *ClinicalNotesRepository) Create(ctx context.Context, note *types.ClinicalNote, authorID string) (*types.ClinicalNote, error) {
	// Generate new note ID
	note.ID = uuid.New().String()
	note.AuthorID = authorID
	note.CreatedAt = time.Now()
	note.UpdatedAt = time.Now()
	note.Version = 1

	// Encrypt note content
	encryptedContent, err := r.encryptor.Encrypt([]byte(note.Content))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt note content: %w", err)
	}

	// Generate content hash for blockchain storage
	contentHash := encryption.HashData([]byte(note.Content))

	// Encrypt metadata if present
	var encryptedMetadata []byte
	if note.Metadata != nil {
		metadataJSON, err := json.Marshal(note.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}

		encryptedMetadata, err = r.encryptor.Encrypt(metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt metadata: %w", err)
		}
	}

	// Generate encryption key ID (in production, managed by PRE service)
	encryptionKeyID := uuid.New().String()

	// Insert into database
	query := `
		INSERT INTO clinical_notes (
			id, patient_id, author_id, note_type, encrypted_content,
			content_hash, encrypted_metadata, encryption_key_id,
			created_at, updated_at, version, is_deleted
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at, updated_at`

	err = r.db.QueryRowContext(ctx, query,
		note.ID,
		note.PatientID,
		note.AuthorID,
		note.NoteType,
		encryptedContent,
		contentHash,
		encryptedMetadata,
		encryptionKeyID,
		note.CreatedAt,
		note.UpdatedAt,
		note.Version,
		false, // is_deleted
	).Scan(&note.ID, &note.CreatedAt, &note.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create clinical note: %w", err)
	}

	// Set the hash for return
	note.Hash = contentHash

	r.logger.Info("Created clinical note", "noteID", note.ID, "patientID", note.PatientID, "authorID", authorID)
	return note, nil
}

// GetByID retrieves a clinical note by ID with decrypted content
func (r *ClinicalNotesRepository) GetByID(ctx context.Context, noteID string) (*types.ClinicalNote, error) {
	query := `
		SELECT id, patient_id, author_id, note_type, encrypted_content,
			   content_hash, encrypted_metadata, encryption_key_id,
			   blockchain_tx_id, created_at, updated_at, version, is_deleted
		FROM clinical_notes 
		WHERE id = $1 AND is_deleted = false`

	var note types.ClinicalNote
	var encryptedContent, encryptedMetadata []byte
	var encryptionKeyID string
	var blockchainTxID sql.NullString

	err := r.db.QueryRowContext(ctx, query, noteID).Scan(
		&note.ID,
		&note.PatientID,
		&note.AuthorID,
		&note.NoteType,
		&encryptedContent,
		&note.Hash,
		&encryptedMetadata,
		&encryptionKeyID,
		&blockchainTxID,
		&note.CreatedAt,
		&note.UpdatedAt,
		&note.Version,
		&note.IsDeleted,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("clinical note not found: %s", noteID)
		}
		return nil, fmt.Errorf("failed to get clinical note: %w", err)
	}

	// Decrypt content
	contentBytes, err := r.encryptor.Decrypt(encryptedContent)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt note content: %w", err)
	}
	note.Content = string(contentBytes)

	// Decrypt metadata if present
	if len(encryptedMetadata) > 0 {
		metadataBytes, err := r.encryptor.Decrypt(encryptedMetadata)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt metadata: %w", err)
		}

		var metadata map[string]string
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
		note.Metadata = metadata
	}

	// Set blockchain transaction ID if present
	if blockchainTxID.Valid {
		note.BlockchainTxID = blockchainTxID.String
	}

	// Verify content integrity
	expectedHash := encryption.HashData([]byte(note.Content))
	if expectedHash != note.Hash {
		r.logger.Warn("Content integrity check failed", "noteID", noteID)
		return nil, fmt.Errorf("content integrity verification failed")
	}

	return &note, nil
}

// GetByPatientID retrieves all clinical notes for a patient
func (r *ClinicalNotesRepository) GetByPatientID(ctx context.Context, patientID string, filters *types.ClinicalNoteFilters) ([]*types.ClinicalNote, error) {
	query := `
		SELECT id, patient_id, author_id, note_type, content_hash,
			   blockchain_tx_id, created_at, updated_at, version
		FROM clinical_notes 
		WHERE patient_id = $1 AND is_deleted = false`
	
	args := []interface{}{patientID}
	argIndex := 2

	// Apply filters
	if filters != nil {
		if filters.NoteType != "" {
			query += fmt.Sprintf(" AND note_type = $%d", argIndex)
			args = append(args, filters.NoteType)
			argIndex++
		}

		if filters.AuthorID != "" {
			query += fmt.Sprintf(" AND author_id = $%d", argIndex)
			args = append(args, filters.AuthorID)
			argIndex++
		}

		if !filters.CreatedAfter.IsZero() {
			query += fmt.Sprintf(" AND created_at >= $%d", argIndex)
			args = append(args, filters.CreatedAfter)
			argIndex++
		}

		if !filters.CreatedBefore.IsZero() {
			query += fmt.Sprintf(" AND created_at <= $%d", argIndex)
			args = append(args, filters.CreatedBefore)
			argIndex++
		}
	}

	query += " ORDER BY created_at DESC"

	if filters != nil && filters.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filters.Limit)
		argIndex++
	}

	if filters != nil && filters.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filters.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get clinical notes: %w", err)
	}
	defer rows.Close()

	var notes []*types.ClinicalNote
	for rows.Next() {
		var note types.ClinicalNote
		var blockchainTxID sql.NullString

		err := rows.Scan(
			&note.ID,
			&note.PatientID,
			&note.AuthorID,
			&note.NoteType,
			&note.Hash,
			&blockchainTxID,
			&note.CreatedAt,
			&note.UpdatedAt,
			&note.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan clinical note row: %w", err)
		}

		if blockchainTxID.Valid {
			note.BlockchainTxID = blockchainTxID.String
		}

		// For list operations, we don't decrypt content by default
		// Content can be retrieved with GetByID
		notes = append(notes, &note)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating clinical note rows: %w", err)
	}

	return notes, nil
}

// Update updates a clinical note (creates new version)
func (r *ClinicalNotesRepository) Update(ctx context.Context, noteID string, updates *types.ClinicalNoteUpdates, updatedBy string) (*types.ClinicalNote, error) {
	// Get existing note
	existing, err := r.GetByID(ctx, noteID)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing note: %w", err)
	}

	// Check if updater is authorized (should be original author or authorized user)
	if existing.AuthorID != updatedBy {
		// In production, check additional authorization rules
		r.logger.Warn("Unauthorized note update attempt", "noteID", noteID, "updatedBy", updatedBy, "originalAuthor", existing.AuthorID)
	}

	// Create new version
	newNote := &types.ClinicalNote{
		PatientID: existing.PatientID,
		AuthorID:  existing.AuthorID,
		NoteType:  existing.NoteType,
		Content:   existing.Content,
		Metadata:  existing.Metadata,
		Version:   existing.Version + 1,
	}

	// Apply updates
	if updates.Content != "" {
		newNote.Content = updates.Content
	}
	if updates.Metadata != nil {
		newNote.Metadata = updates.Metadata
	}

	// Encrypt updated content
	encryptedContent, err := r.encryptor.Encrypt([]byte(newNote.Content))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt updated content: %w", err)
	}

	// Generate new content hash
	contentHash := encryption.HashData([]byte(newNote.Content))

	// Encrypt metadata if present
	var encryptedMetadata []byte
	if newNote.Metadata != nil {
		metadataJSON, err := json.Marshal(newNote.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}

		encryptedMetadata, err = r.encryptor.Encrypt(metadataJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt metadata: %w", err)
		}
	}

	// Generate new encryption key ID
	encryptionKeyID := uuid.New().String()

	// Insert new version
	newNote.ID = uuid.New().String()
	newNote.CreatedAt = time.Now()
	newNote.UpdatedAt = time.Now()
	newNote.Hash = contentHash

	query := `
		INSERT INTO clinical_notes (
			id, patient_id, author_id, note_type, encrypted_content,
			content_hash, encrypted_metadata, encryption_key_id,
			created_at, updated_at, version, is_deleted
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, created_at, updated_at`

	err = r.db.QueryRowContext(ctx, query,
		newNote.ID,
		newNote.PatientID,
		newNote.AuthorID,
		newNote.NoteType,
		encryptedContent,
		contentHash,
		encryptedMetadata,
		encryptionKeyID,
		newNote.CreatedAt,
		newNote.UpdatedAt,
		newNote.Version,
		false, // is_deleted
	).Scan(&newNote.ID, &newNote.CreatedAt, &newNote.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create note version: %w", err)
	}

	r.logger.Info("Updated clinical note", "noteID", newNote.ID, "originalNoteID", noteID, "version", newNote.Version)
	return newNote, nil
}

// Delete soft deletes a clinical note
func (r *ClinicalNotesRepository) Delete(ctx context.Context, noteID string, deletedBy string) error {
	query := `
		UPDATE clinical_notes 
		SET is_deleted = true, updated_at = $1
		WHERE id = $2 AND is_deleted = false`

	result, err := r.db.ExecContext(ctx, query, time.Now(), noteID)
	if err != nil {
		return fmt.Errorf("failed to delete clinical note: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("clinical note not found or already deleted: %s", noteID)
	}

	r.logger.Info("Deleted clinical note", "noteID", noteID, "deletedBy", deletedBy)
	return nil
}

// Search searches clinical notes with encrypted content matching
func (r *ClinicalNotesRepository) Search(ctx context.Context, criteria *types.ClinicalNoteSearchCriteria) ([]*types.ClinicalNote, error) {
	// Note: Full-text search on encrypted content is complex
	// This implementation provides basic metadata-based search
	// For content search, consider using searchable encryption or client-side decryption

	query := `
		SELECT id, patient_id, author_id, note_type, content_hash,
			   blockchain_tx_id, created_at, updated_at, version
		FROM clinical_notes 
		WHERE is_deleted = false`
	
	args := []interface{}{}
	argIndex := 1

	if criteria.PatientID != "" {
		query += fmt.Sprintf(" AND patient_id = $%d", argIndex)
		args = append(args, criteria.PatientID)
		argIndex++
	}

	if criteria.AuthorID != "" {
		query += fmt.Sprintf(" AND author_id = $%d", argIndex)
		args = append(args, criteria.AuthorID)
		argIndex++
	}

	if criteria.NoteType != "" {
		query += fmt.Sprintf(" AND note_type = $%d", argIndex)
		args = append(args, criteria.NoteType)
		argIndex++
	}

	if !criteria.CreatedAfter.IsZero() {
		query += fmt.Sprintf(" AND created_at >= $%d", argIndex)
		args = append(args, criteria.CreatedAfter)
		argIndex++
	}

	if !criteria.CreatedBefore.IsZero() {
		query += fmt.Sprintf(" AND created_at <= $%d", argIndex)
		args = append(args, criteria.CreatedBefore)
		argIndex++
	}

	query += " ORDER BY created_at DESC"

	if criteria.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, criteria.Limit)
		argIndex++
	}

	if criteria.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, criteria.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to search clinical notes: %w", err)
	}
	defer rows.Close()

	var notes []*types.ClinicalNote
	for rows.Next() {
		var note types.ClinicalNote
		var blockchainTxID sql.NullString

		err := rows.Scan(
			&note.ID,
			&note.PatientID,
			&note.AuthorID,
			&note.NoteType,
			&note.Hash,
			&blockchainTxID,
			&note.CreatedAt,
			&note.UpdatedAt,
			&note.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan clinical note row: %w", err)
		}

		if blockchainTxID.Valid {
			note.BlockchainTxID = blockchainTxID.String
		}

		notes = append(notes, &note)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating clinical note rows: %w", err)
	}

	return notes, nil
}

// UpdateBlockchainTxID updates the blockchain transaction ID for a note
func (r *ClinicalNotesRepository) UpdateBlockchainTxID(ctx context.Context, noteID, txID string) error {
	query := `
		UPDATE clinical_notes 
		SET blockchain_tx_id = $1, updated_at = $2
		WHERE id = $3`

	result, err := r.db.ExecContext(ctx, query, txID, time.Now(), noteID)
	if err != nil {
		return fmt.Errorf("failed to update blockchain tx ID: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("clinical note not found: %s", noteID)
	}

	r.logger.Info("Updated blockchain transaction ID", "noteID", noteID, "txID", txID)
	return nil
}