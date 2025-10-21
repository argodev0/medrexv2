package service

import (
	"context"
	"fmt"

	"github.com/medrex/dlt-emr/pkg/encryption"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/repository"
	"github.com/medrex/dlt-emr/pkg/types"
)

// DataAccessService provides secure data access with encryption and blockchain integration
type DataAccessService struct {
	patientRepo      repository.PatientRepositoryInterface
	clinicalNotesRepo repository.ClinicalNotesRepositoryInterface
	auditLogRepo     repository.AuditLogRepositoryInterface
	preService       *encryption.PREService
	encryptor        *encryption.AESEncryption
	logger           *logger.Logger
}

// NewDataAccessService creates a new data access service
func NewDataAccessService(
	patientRepo repository.PatientRepositoryInterface,
	clinicalNotesRepo repository.ClinicalNotesRepositoryInterface,
	auditLogRepo repository.AuditLogRepositoryInterface,
	preService *encryption.PREService,
	encryptor *encryption.AESEncryption,
	logger *logger.Logger,
) *DataAccessService {
	return &DataAccessService{
		patientRepo:       patientRepo,
		clinicalNotesRepo: clinicalNotesRepo,
		auditLogRepo:      auditLogRepo,
		preService:        preService,
		encryptor:         encryptor,
		logger:            logger,
	}
}

// CreatePatient creates a new patient with encrypted PHI and audit logging
func (s *DataAccessService) CreatePatient(ctx context.Context, patient *types.Patient, createdBy string) (*types.Patient, error) {
	// Create audit log entry
	auditEntry := &types.AuditLogEntry{
		UserID:     createdBy,
		Action:     "CREATE_PATIENT",
		ResourceType: "patient",
		Success:    false,
		Details: map[string]interface{}{
			"mrn": patient.MRN,
		},
	}

	// Create patient record
	createdPatient, err := s.patientRepo.Create(ctx, patient, createdBy)
	if err != nil {
		auditEntry.ErrorMessage = err.Error()
		s.auditLogRepo.Create(ctx, auditEntry)
		return nil, fmt.Errorf("failed to create patient: %w", err)
	}

	// Update audit entry with success
	auditEntry.Success = true
	auditEntry.ResourceID = createdPatient.ID
	s.auditLogRepo.Create(ctx, auditEntry)

	s.logger.Info("Patient created successfully", "patientID", createdPatient.ID, "createdBy", createdBy)
	return createdPatient, nil
}

// GetPatientWithAuthorization retrieves patient data with access control validation
func (s *DataAccessService) GetPatientWithAuthorization(ctx context.Context, patientID, userID string, accessToken *encryption.ReEncryptionToken) (*types.Patient, error) {
	// Validate access token if provided
	if accessToken != nil {
		if err := s.preService.ValidateReEncryptionToken(accessToken); err != nil {
			s.logUnauthorizedAccess(ctx, userID, "GET_PATIENT", patientID, "Invalid access token")
			return nil, fmt.Errorf("access denied: %w", err)
		}
	}

	// Create audit log entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "GET_PATIENT",
		ResourceType: "patient",
		ResourceID:   patientID,
		Success:      false,
	}

	// Retrieve patient data
	patient, err := s.patientRepo.GetByID(ctx, patientID)
	if err != nil {
		auditEntry.ErrorMessage = err.Error()
		s.auditLogRepo.Create(ctx, auditEntry)
		return nil, fmt.Errorf("failed to get patient: %w", err)
	}

	// Update audit entry with success
	auditEntry.Success = true
	s.auditLogRepo.Create(ctx, auditEntry)

	s.logger.Info("Patient retrieved successfully", "patientID", patientID, "userID", userID)
	return patient, nil
}

// CreateClinicalNote creates a new clinical note with encryption and blockchain hash
func (s *DataAccessService) CreateClinicalNote(ctx context.Context, note *types.ClinicalNote, authorID string) (*types.ClinicalNote, error) {
	// Create audit log entry
	auditEntry := &types.AuditLogEntry{
		UserID:       authorID,
		Action:       "CREATE_CLINICAL_NOTE",
		ResourceType: "clinical_note",
		Success:      false,
		Details: map[string]interface{}{
			"patient_id": note.PatientID,
			"note_type":  note.NoteType,
		},
	}

	// Create clinical note
	createdNote, err := s.clinicalNotesRepo.Create(ctx, note, authorID)
	if err != nil {
		auditEntry.ErrorMessage = err.Error()
		s.auditLogRepo.Create(ctx, auditEntry)
		return nil, fmt.Errorf("failed to create clinical note: %w", err)
	}

	// Update audit entry with success
	auditEntry.Success = true
	auditEntry.ResourceID = createdNote.ID
	auditEntry.Details["content_hash"] = createdNote.Hash
	s.auditLogRepo.Create(ctx, auditEntry)

	s.logger.Info("Clinical note created successfully", "noteID", createdNote.ID, "authorID", authorID)
	return createdNote, nil
}

// GetClinicalNoteWithAuthorization retrieves clinical note with access control
func (s *DataAccessService) GetClinicalNoteWithAuthorization(ctx context.Context, noteID, userID string, accessToken *encryption.ReEncryptionToken) (*types.ClinicalNote, error) {
	// Validate access token if provided
	if accessToken != nil {
		if err := s.preService.ValidateReEncryptionToken(accessToken); err != nil {
			s.logUnauthorizedAccess(ctx, userID, "GET_CLINICAL_NOTE", noteID, "Invalid access token")
			return nil, fmt.Errorf("access denied: %w", err)
		}
	}

	// Create audit log entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "GET_CLINICAL_NOTE",
		ResourceType: "clinical_note",
		ResourceID:   noteID,
		Success:      false,
	}

	// Retrieve clinical note
	note, err := s.clinicalNotesRepo.GetByID(ctx, noteID)
	if err != nil {
		auditEntry.ErrorMessage = err.Error()
		s.auditLogRepo.Create(ctx, auditEntry)
		return nil, fmt.Errorf("failed to get clinical note: %w", err)
	}

	// Update audit entry with success
	auditEntry.Success = true
	auditEntry.Details = map[string]interface{}{
		"patient_id":   note.PatientID,
		"content_hash": note.Hash,
	}
	s.auditLogRepo.Create(ctx, auditEntry)

	s.logger.Info("Clinical note retrieved successfully", "noteID", noteID, "userID", userID)
	return note, nil
}

// VerifyDataIntegrity verifies data integrity against blockchain hashes
func (s *DataAccessService) VerifyDataIntegrity(ctx context.Context, resourceType, resourceID, blockchainHash, userID string) (bool, error) {
	// Create audit log entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "VERIFY_DATA_INTEGRITY",
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Success:      false,
		Details: map[string]interface{}{
			"blockchain_hash": blockchainHash,
		},
	}

	var isValid bool
	var err error

	switch resourceType {
	case "patient":
		isValid, err = s.patientRepo.VerifyDataIntegrity(ctx, resourceID, blockchainHash)
	case "clinical_note":
		// For clinical notes, we verify by comparing the stored hash
		note, noteErr := s.clinicalNotesRepo.GetByID(ctx, resourceID)
		if noteErr != nil {
			err = noteErr
		} else {
			isValid = note.Hash == blockchainHash
		}
	default:
		err = fmt.Errorf("unsupported resource type for integrity verification: %s", resourceType)
	}

	if err != nil {
		auditEntry.ErrorMessage = err.Error()
		s.auditLogRepo.Create(ctx, auditEntry)
		return false, fmt.Errorf("failed to verify data integrity: %w", err)
	}

	// Update audit entry with result
	auditEntry.Success = true
	auditEntry.Details["integrity_valid"] = isValid
	s.auditLogRepo.Create(ctx, auditEntry)

	if !isValid {
		s.logger.Warn("Data integrity verification failed", 
			"resourceType", resourceType, 
			"resourceID", resourceID, 
			"userID", userID)
	}

	return isValid, nil
}

// CreateReEncryptionToken creates a token for proxy re-encryption
func (s *DataAccessService) CreateReEncryptionToken(ctx context.Context, fromUserID, toUserID, resourceID string, requesterID string) (*encryption.ReEncryptionToken, error) {
	// Create audit log entry
	auditEntry := &types.AuditLogEntry{
		UserID:       requesterID,
		Action:       "CREATE_RE_ENCRYPTION_TOKEN",
		ResourceType: "re_encryption_token",
		Success:      false,
		Details: map[string]interface{}{
			"from_user_id": fromUserID,
			"to_user_id":   toUserID,
			"resource_id":  resourceID,
		},
	}

	// Create re-encryption token (24 hour expiry)
	token, err := s.preService.CreateReEncryptionToken(fromUserID, toUserID, resourceID, 24*60*60*1000000000) // 24 hours in nanoseconds
	if err != nil {
		auditEntry.ErrorMessage = err.Error()
		s.auditLogRepo.Create(ctx, auditEntry)
		return nil, fmt.Errorf("failed to create re-encryption token: %w", err)
	}

	// Update audit entry with success
	auditEntry.Success = true
	auditEntry.ResourceID = token.ID
	s.auditLogRepo.Create(ctx, auditEntry)

	s.logger.Info("Re-encryption token created", "tokenID", token.ID, "requesterID", requesterID)
	return token, nil
}

// SearchPatientsWithAuthorization searches patients with proper access control
func (s *DataAccessService) SearchPatientsWithAuthorization(ctx context.Context, criteria *types.PatientSearchCriteria, userID string) ([]*types.Patient, error) {
	// Create audit log entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "SEARCH_PATIENTS",
		ResourceType: "patient",
		Success:      false,
		Details: map[string]interface{}{
			"search_criteria": criteria,
		},
	}

	// Perform search
	patients, err := s.patientRepo.Search(ctx, criteria)
	if err != nil {
		auditEntry.ErrorMessage = err.Error()
		s.auditLogRepo.Create(ctx, auditEntry)
		return nil, fmt.Errorf("failed to search patients: %w", err)
	}

	// Update audit entry with success
	auditEntry.Success = true
	auditEntry.Details["results_count"] = len(patients)
	s.auditLogRepo.Create(ctx, auditEntry)

	s.logger.Info("Patient search completed", "resultsCount", len(patients), "userID", userID)
	return patients, nil
}

// logUnauthorizedAccess logs unauthorized access attempts
func (s *DataAccessService) logUnauthorizedAccess(ctx context.Context, userID, action, resourceID, reason string) {
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       action,
		ResourceType: "unauthorized_access",
		ResourceID:   resourceID,
		Success:      false,
		ErrorMessage: reason,
		Details: map[string]interface{}{
			"access_denied_reason": reason,
		},
	}

	s.auditLogRepo.Create(ctx, auditEntry)
	s.logger.Warn("Unauthorized access attempt", "userID", userID, "action", action, "resourceID", resourceID, "reason", reason)
}