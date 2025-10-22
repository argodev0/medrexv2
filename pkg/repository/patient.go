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

// PatientRepository handles encrypted patient data operations
type PatientRepository struct {
	db        *sql.DB
	encryptor *encryption.AESEncryption
	logger    logger.Logger
}

// NewPatientRepository creates a new patient repository
func NewPatientRepository(db *sql.DB, encryptor *encryption.AESEncryption, logger logger.Logger) *PatientRepository {
	return &PatientRepository{
		db:        db,
		encryptor: encryptor,
		logger:    logger,
	}
}

// Create creates a new patient record with encrypted PHI
func (r *PatientRepository) Create(ctx context.Context, patient *types.Patient, createdBy string) (*types.Patient, error) {
	// Generate new patient ID
	patient.ID = uuid.New().String()
	patient.CreatedAt = time.Now()
	patient.UpdatedAt = time.Now()

	// Encrypt demographics
	demographicsJSON, err := json.Marshal(patient.Demographics)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal demographics: %w", err)
	}

	encryptedDemographics, err := r.encryptor.Encrypt(demographicsJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt demographics: %w", err)
	}

	// Encrypt insurance if present
	var encryptedInsurance []byte
	var insuranceJSON []byte
	if patient.Insurance != nil {
		insuranceJSON, err = json.Marshal(patient.Insurance)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal insurance: %w", err)
		}

		encryptedInsurance, err = r.encryptor.Encrypt(insuranceJSON)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt insurance: %w", err)
		}
	}

	// Generate hash for blockchain storage
	combinedData := append(demographicsJSON, insuranceJSON...)
	dataHash := encryption.HashData(combinedData)

	// Generate encryption key ID (in production, this would be managed by PRE service)
	encryptionKeyID := uuid.New().String()

	// Insert into database
	query := `
		INSERT INTO patients (
			id, mrn, encrypted_demographics, encrypted_insurance, 
			data_hash, encryption_key_id, created_at, updated_at, 
			created_by, updated_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at, updated_at`

	err = r.db.QueryRowContext(ctx, query,
		patient.ID,
		patient.MRN,
		encryptedDemographics,
		encryptedInsurance,
		dataHash,
		encryptionKeyID,
		patient.CreatedAt,
		patient.UpdatedAt,
		createdBy,
		createdBy,
	).Scan(&patient.ID, &patient.CreatedAt, &patient.UpdatedAt)

	if err != nil {
		return nil, fmt.Errorf("failed to create patient: %w", err)
	}

	r.logger.Info("Created patient record", "patientID", patient.ID, "mrn", patient.MRN)
	return patient, nil
}

// GetByID retrieves a patient by ID with decrypted PHI
func (r *PatientRepository) GetByID(ctx context.Context, patientID string) (*types.Patient, error) {
	query := `
		SELECT id, mrn, encrypted_demographics, encrypted_insurance, 
			   data_hash, encryption_key_id, created_at, updated_at,
			   created_by, updated_by
		FROM patients 
		WHERE id = $1`

	var patient types.Patient
	var encryptedDemographics, encryptedInsurance []byte
	var dataHash, encryptionKeyID, createdBy, updatedBy string

	err := r.db.QueryRowContext(ctx, query, patientID).Scan(
		&patient.ID,
		&patient.MRN,
		&encryptedDemographics,
		&encryptedInsurance,
		&dataHash,
		&encryptionKeyID,
		&patient.CreatedAt,
		&patient.UpdatedAt,
		&createdBy,
		&updatedBy,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("patient not found: %s", patientID)
		}
		return nil, fmt.Errorf("failed to get patient: %w", err)
	}

	// Decrypt demographics
	demographicsJSON, err := r.encryptor.Decrypt(encryptedDemographics)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt demographics: %w", err)
	}

	var demographics types.Demographics
	if err := json.Unmarshal(demographicsJSON, &demographics); err != nil {
		return nil, fmt.Errorf("failed to unmarshal demographics: %w", err)
	}
	patient.Demographics = &demographics

	// Decrypt insurance if present
	if len(encryptedInsurance) > 0 {
		insuranceJSON, err := r.encryptor.Decrypt(encryptedInsurance)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt insurance: %w", err)
		}

		var insurance types.Insurance
		if err := json.Unmarshal(insuranceJSON, &insurance); err != nil {
			return nil, fmt.Errorf("failed to unmarshal insurance: %w", err)
		}
		patient.Insurance = &insurance
	}

	// Verify data integrity
	combinedData := append(demographicsJSON, []byte{}...)
	if patient.Insurance != nil {
		insuranceJSON, _ := json.Marshal(patient.Insurance)
		combinedData = append(demographicsJSON, insuranceJSON...)
	}
	
	expectedHash := encryption.HashData(combinedData)
	if expectedHash != dataHash {
		r.logger.Warn("Data integrity check failed", "patientID", patientID)
		return nil, fmt.Errorf("data integrity verification failed")
	}

	return &patient, nil
}

// GetByMRN retrieves a patient by Medical Record Number
func (r *PatientRepository) GetByMRN(ctx context.Context, mrn string) (*types.Patient, error) {
	query := `
		SELECT id
		FROM patients 
		WHERE mrn = $1`

	var patientID string
	err := r.db.QueryRowContext(ctx, query, mrn).Scan(&patientID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("patient not found with MRN: %s", mrn)
		}
		return nil, fmt.Errorf("failed to get patient by MRN: %w", err)
	}

	return r.GetByID(ctx, patientID)
}

// Update updates a patient record with encrypted PHI
func (r *PatientRepository) Update(ctx context.Context, patientID string, updates map[string]interface{}, updatedBy string) error {
	// Get existing patient for comparison
	existing, err := r.GetByID(ctx, patientID)
	if err != nil {
		return fmt.Errorf("failed to get existing patient: %w", err)
	}

	// Apply updates
	if demographics, ok := updates["demographics"]; ok {
		if demo, ok := demographics.(*types.Demographics); ok {
			existing.Demographics = demo
		}
	}
	if insurance, ok := updates["insurance"]; ok {
		if ins, ok := insurance.(*types.Insurance); ok {
			existing.Insurance = ins
		}
	}

	// Encrypt updated data
	demographicsJSON, err := json.Marshal(existing.Demographics)
	if err != nil {
		return fmt.Errorf("failed to marshal demographics: %w", err)
	}

	encryptedDemographics, err := r.encryptor.Encrypt(demographicsJSON)
	if err != nil {
		return fmt.Errorf("failed to encrypt demographics: %w", err)
	}

	var encryptedInsurance []byte
	var insuranceJSON []byte
	if existing.Insurance != nil {
		insuranceJSON, err = json.Marshal(existing.Insurance)
		if err != nil {
			return fmt.Errorf("failed to marshal insurance: %w", err)
		}

		encryptedInsurance, err = r.encryptor.Encrypt(insuranceJSON)
		if err != nil {
			return fmt.Errorf("failed to encrypt insurance: %w", err)
		}
	}

	// Generate new hash
	combinedData := append(demographicsJSON, insuranceJSON...)
	dataHash := encryption.HashData(combinedData)

	// Update database
	query := `
		UPDATE patients 
		SET encrypted_demographics = $1, encrypted_insurance = $2, 
			data_hash = $3, updated_at = $4, updated_by = $5
		WHERE id = $6`

	result, err := r.db.ExecContext(ctx, query,
		encryptedDemographics,
		encryptedInsurance,
		dataHash,
		time.Now(),
		updatedBy,
		patientID,
	)

	if err != nil {
		return fmt.Errorf("failed to update patient: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("patient not found: %s", patientID)
	}

	r.logger.Info("Updated patient record", "patientID", patientID)
	return nil
}

// Delete soft deletes a patient record
func (r *PatientRepository) Delete(ctx context.Context, patientID string, deletedBy string) error {
	// In a real implementation, we would soft delete or archive
	// For now, we'll just log the deletion request
	r.logger.Info("Patient deletion requested", "patientID", patientID, "deletedBy", deletedBy)
	
	// In production, implement proper soft delete with audit trail
	return fmt.Errorf("patient deletion not implemented - use archive instead")
}

// Search searches for patients based on criteria
func (r *PatientRepository) Search(ctx context.Context, criteria map[string]interface{}, limit, offset int) ([]*types.Patient, error) {
	// Build dynamic query based on search criteria
	query := `
		SELECT id, mrn, created_at, updated_at
		FROM patients 
		WHERE 1=1`
	
	args := []interface{}{}
	argIndex := 1

	if mrn, ok := criteria["mrn"].(string); ok && mrn != "" {
		query += fmt.Sprintf(" AND mrn ILIKE $%d", argIndex)
		args = append(args, "%"+mrn+"%")
		argIndex++
	}

	if firstName, ok := criteria["first_name"].(string); ok && firstName != "" {
		// Note: This would require decrypting demographics for search, which is complex
		// In production, consider using searchable encryption or indexed fields
		r.logger.Warn("First name search not implemented due to encryption")
	}

	if lastName, ok := criteria["last_name"].(string); ok && lastName != "" {
		// Note: This would require decrypting demographics for search, which is complex
		r.logger.Warn("Last name search not implemented due to encryption")
	}

	query += " ORDER BY created_at DESC"

	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, limit)
		argIndex++
	}

	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to search patients: %w", err)
	}
	defer rows.Close()

	var patients []*types.Patient
	for rows.Next() {
		var patient types.Patient
		err := rows.Scan(
			&patient.ID,
			&patient.MRN,
			&patient.CreatedAt,
			&patient.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan patient row: %w", err)
		}

		// For search results, we only return basic info
		// Full patient data requires separate GetByID call
		patients = append(patients, &patient)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating patient rows: %w", err)
	}

	return patients, nil
}

// VerifyDataIntegrity verifies the integrity of patient data against blockchain hash
func (r *PatientRepository) VerifyDataIntegrity(ctx context.Context, patientID string, blockchainHash string) (bool, error) {
	patient, err := r.GetByID(ctx, patientID)
	if err != nil {
		return false, fmt.Errorf("failed to get patient: %w", err)
	}

	// Recalculate hash from current data
	demographicsJSON, _ := json.Marshal(patient.Demographics)
	var insuranceJSON []byte
	if patient.Insurance != nil {
		insuranceJSON, _ = json.Marshal(patient.Insurance)
	}
	
	combinedData := append(demographicsJSON, insuranceJSON...)
	currentHash := encryption.HashData(combinedData)

	// Compare with blockchain hash
	isValid := currentHash == blockchainHash
	
	if !isValid {
		r.logger.Warn("Data integrity verification failed", 
			"patientID", patientID, 
			"currentHash", currentHash, 
			"blockchainHash", blockchainHash)
	}

	return isValid, nil
}