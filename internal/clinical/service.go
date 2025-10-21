package clinical

import (
	"context"
	"fmt"
	"time"

	"github.com/medrex/dlt-emr/internal/iam"
	"github.com/medrex/dlt-emr/pkg/encryption"
	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/repository"
	"github.com/medrex/dlt-emr/pkg/types"
)

// ClinicalNotesService implements the clinical notes management service
type ClinicalNotesService struct {
	repository      *repository.ClinicalNotesRepository
	patientRepo     *repository.PatientRepository
	encryptionSvc   interfaces.EncryptionService
	blockchainClient interfaces.BlockchainClient
	preService      *encryption.PREService
	logger          *logger.Logger
}

// NewClinicalNotesService creates a new clinical notes service
func NewClinicalNotesService(
	repo *repository.ClinicalNotesRepository,
	patientRepo *repository.PatientRepository,
	encSvc interfaces.EncryptionService,
	bcClient interfaces.BlockchainClient,
	preService *encryption.PREService,
	logger *logger.Logger,
) *ClinicalNotesService {
	return &ClinicalNotesService{
		repository:      repo,
		patientRepo:     patientRepo,
		encryptionSvc:   encSvc,
		blockchainClient: bcClient,
		preService:      preService,
		logger:          logger,
	}
}

// CreateNote creates a new clinical note with encryption and blockchain integration
func (s *ClinicalNotesService) CreateNote(note *types.ClinicalNote, userID string) (*types.ClinicalNote, error) {
	ctx := context.Background()
	
	s.logger.Info("Creating clinical note", "patientID", note.PatientID, "userID", userID)

	// Validate access via AccessPolicy chaincode
	allowed, err := s.blockchainClient.CheckAccess(userID, note.PatientID, "create_note")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for note creation", "userID", userID, "patientID", note.PatientID)
		return nil, fmt.Errorf("access denied: insufficient permissions to create note")
	}

	// Verify patient exists
	patient, err := s.patientRepo.GetByID(ctx, note.PatientID)
	if err != nil {
		s.logger.Error("Failed to verify patient", "patientID", note.PatientID, "error", err)
		return nil, fmt.Errorf("patient verification failed: %w", err)
	}

	if patient == nil {
		return nil, fmt.Errorf("patient not found: %s", note.PatientID)
	}

	// Create encrypted note in repository
	createdNote, err := s.repository.Create(ctx, note, userID)
	if err != nil {
		s.logger.Error("Failed to create note in repository", "error", err)
		return nil, fmt.Errorf("note creation failed: %w", err)
	}

	// Store PHI hash on blockchain
	phiHash := &types.PHIHash{
		ID:        createdNote.ID,
		PatientID: createdNote.PatientID,
		Hash:      createdNote.Hash,
		Algorithm: "SHA-256",
		CreatedBy: userID,
		CreatedAt: time.Now(),
	}

	if err := s.blockchainClient.StorePHIHash(phiHash); err != nil {
		s.logger.Error("Failed to store PHI hash on blockchain", "noteID", createdNote.ID, "error", err)
		// Note: In production, consider rollback strategy
		return nil, fmt.Errorf("blockchain hash storage failed: %w", err)
	}

	// Log audit entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "create_clinical_note",
		ResourceID:   createdNote.ID,
		ResourceType: "clinical_note",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"patient_id": createdNote.PatientID,
			"note_type":  createdNote.NoteType,
			"hash":       createdNote.Hash,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit entry", "noteID", createdNote.ID, "error", err)
		// Continue execution - audit logging failure shouldn't block operation
	}

	s.logger.Info("Clinical note created successfully", "noteID", createdNote.ID, "patientID", createdNote.PatientID)
	return createdNote, nil
}

// GetNote retrieves a clinical note with access control validation
func (s *ClinicalNotesService) GetNote(noteID, userID string) (*types.ClinicalNote, error) {
	ctx := context.Background()
	
	s.logger.Info("Retrieving clinical note", "noteID", noteID, "userID", userID)

	// Get note metadata first (without decrypted content)
	note, err := s.repository.GetByID(ctx, noteID)
	if err != nil {
		s.logger.Error("Failed to retrieve note", "noteID", noteID, "error", err)
		return nil, fmt.Errorf("note retrieval failed: %w", err)
	}

	// Validate access via AccessPolicy chaincode
	allowed, err := s.blockchainClient.CheckAccess(userID, note.PatientID, "read_note")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for note retrieval", "userID", userID, "noteID", noteID)
		
		// Log unauthorized access attempt
		auditEntry := &types.AuditLogEntry{
			UserID:       userID,
			Action:       "read_clinical_note",
			ResourceID:   noteID,
			ResourceType: "clinical_note",
			Timestamp:    time.Now(),
			Success:      false,
			Details: map[string]interface{}{
				"reason": "access_denied",
			},
		}
		s.blockchainClient.LogActivity(auditEntry)
		
		return nil, fmt.Errorf("access denied: insufficient permissions to read note")
	}

	// Verify data integrity using blockchain hash
	if err := s.VerifyDataIntegrity(noteID); err != nil {
		s.logger.Error("Data integrity verification failed", "noteID", noteID, "error", err)
		return nil, fmt.Errorf("data integrity verification failed: %w", err)
	}

	// Log successful access
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "read_clinical_note",
		ResourceID:   noteID,
		ResourceType: "clinical_note",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"patient_id": note.PatientID,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit entry", "noteID", noteID, "error", err)
	}

	s.logger.Info("Clinical note retrieved successfully", "noteID", noteID, "userID", userID)
	return note, nil
}

// UpdateNote updates a clinical note with proper access control
func (s *ClinicalNotesService) UpdateNote(noteID string, updates *types.ClinicalNoteUpdates, userID string) error {
	ctx := context.Background()
	
	s.logger.Info("Updating clinical note", "noteID", noteID, "userID", userID)

	// Get existing note to check patient ID
	existingNote, err := s.repository.GetByID(ctx, noteID)
	if err != nil {
		return fmt.Errorf("failed to get existing note: %w", err)
	}

	// Validate access via AccessPolicy chaincode
	allowed, err := s.blockchainClient.CheckAccess(userID, existingNote.PatientID, "update_note")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for note update", "userID", userID, "noteID", noteID)
		
		// Log unauthorized access attempt
		auditEntry := &types.AuditLogEntry{
			UserID:       userID,
			Action:       "update_clinical_note",
			ResourceID:   noteID,
			ResourceType: "clinical_note",
			Timestamp:    time.Now(),
			Success:      false,
			Details: map[string]interface{}{
				"reason": "access_denied",
			},
		}
		s.blockchainClient.LogActivity(auditEntry)
		
		return fmt.Errorf("access denied: insufficient permissions to update note")
	}

	// Update note in repository (creates new version)
	updatedNote, err := s.repository.Update(ctx, noteID, updates, userID)
	if err != nil {
		s.logger.Error("Failed to update note", "noteID", noteID, "error", err)
		return fmt.Errorf("note update failed: %w", err)
	}

	// Store new PHI hash on blockchain
	phiHash := &types.PHIHash{
		ID:        updatedNote.ID,
		PatientID: updatedNote.PatientID,
		Hash:      updatedNote.Hash,
		Algorithm: "SHA-256",
		CreatedBy: userID,
		CreatedAt: time.Now(),
	}

	if err := s.blockchainClient.StorePHIHash(phiHash); err != nil {
		s.logger.Error("Failed to store updated PHI hash", "noteID", updatedNote.ID, "error", err)
		return fmt.Errorf("blockchain hash storage failed: %w", err)
	}

	// Log audit entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "update_clinical_note",
		ResourceID:   updatedNote.ID,
		ResourceType: "clinical_note",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"patient_id":     updatedNote.PatientID,
			"original_note":  noteID,
			"new_version":    updatedNote.Version,
			"new_hash":       updatedNote.Hash,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit entry", "noteID", updatedNote.ID, "error", err)
	}

	s.logger.Info("Clinical note updated successfully", "noteID", noteID, "newNoteID", updatedNote.ID, "version", updatedNote.Version)
	return nil
}

// DeleteNote soft deletes a clinical note
func (s *ClinicalNotesService) DeleteNote(noteID, userID string) error {
	ctx := context.Background()
	
	s.logger.Info("Deleting clinical note", "noteID", noteID, "userID", userID)

	// Get existing note to check patient ID
	existingNote, err := s.repository.GetByID(ctx, noteID)
	if err != nil {
		return fmt.Errorf("failed to get existing note: %w", err)
	}

	// Validate access via AccessPolicy chaincode
	allowed, err := s.blockchainClient.CheckAccess(userID, existingNote.PatientID, "delete_note")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for note deletion", "userID", userID, "noteID", noteID)
		
		// Log unauthorized access attempt
		auditEntry := &types.AuditLogEntry{
			UserID:       userID,
			Action:       "delete_clinical_note",
			ResourceID:   noteID,
			ResourceType: "clinical_note",
			Timestamp:    time.Now(),
			Success:      false,
			Details: map[string]interface{}{
				"reason": "access_denied",
			},
		}
		s.blockchainClient.LogActivity(auditEntry)
		
		return fmt.Errorf("access denied: insufficient permissions to delete note")
	}

	// Soft delete note in repository
	if err := s.repository.Delete(ctx, noteID, userID); err != nil {
		s.logger.Error("Failed to delete note", "noteID", noteID, "error", err)
		return fmt.Errorf("note deletion failed: %w", err)
	}

	// Log audit entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "delete_clinical_note",
		ResourceID:   noteID,
		ResourceType: "clinical_note",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"patient_id": existingNote.PatientID,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit entry", "noteID", noteID, "error", err)
	}

	s.logger.Info("Clinical note deleted successfully", "noteID", noteID, "userID", userID)
	return nil
}

// VerifyDataIntegrity verifies note integrity using blockchain hash
func (s *ClinicalNotesService) VerifyDataIntegrity(noteID string) error {
	ctx := context.Background()
	
	// Get note from database
	note, err := s.repository.GetByID(ctx, noteID)
	if err != nil {
		return fmt.Errorf("failed to get note: %w", err)
	}

	// Get PHI hash from blockchain
	phiHash, err := s.blockchainClient.GetPHIHash(noteID)
	if err != nil {
		return fmt.Errorf("failed to get blockchain hash: %w", err)
	}

	if phiHash == nil {
		return fmt.Errorf("no blockchain hash found for note: %s", noteID)
	}

	// Compare hashes
	if note.Hash != phiHash.Hash {
		s.logger.Error("Hash mismatch detected", "noteID", noteID, "dbHash", note.Hash, "blockchainHash", phiHash.Hash)
		return fmt.Errorf("data integrity verification failed: hash mismatch")
	}

	// Verify current content hash
	currentHash := encryption.HashData([]byte(note.Content))
	if currentHash != note.Hash {
		s.logger.Error("Content hash verification failed", "noteID", noteID, "expectedHash", note.Hash, "actualHash", currentHash)
		return fmt.Errorf("content integrity verification failed")
	}

	return nil
}

// GenerateHash generates SHA-256 hash for content
func (s *ClinicalNotesService) GenerateHash(content string) (string, error) {
	return encryption.HashData([]byte(content)), nil
}

// SearchNotes searches clinical notes with role-based filtering
func (s *ClinicalNotesService) SearchNotes(criteria *types.SearchCriteria, userID string) ([]*types.ClinicalNote, error) {
	ctx := context.Background()
	
	s.logger.Info("Searching clinical notes", "userID", userID, "patientID", criteria.PatientID)

	// If searching for specific patient, validate access
	if criteria.PatientID != "" {
		allowed, err := s.blockchainClient.CheckAccess(userID, criteria.PatientID, "read_note")
		if err != nil {
			s.logger.Error("Failed to check access for patient", "patientID", criteria.PatientID, "error", err)
			return nil, fmt.Errorf("access validation failed: %w", err)
		}

		if !allowed {
			s.logger.Warn("Access denied for patient notes search", "userID", userID, "patientID", criteria.PatientID)
			
			// Log unauthorized access attempt
			auditEntry := &types.AuditLogEntry{
				UserID:       userID,
				Action:       "search_clinical_notes",
				ResourceID:   criteria.PatientID,
				ResourceType: "patient",
				Timestamp:    time.Now(),
				Success:      false,
				Details: map[string]interface{}{
					"reason": "access_denied",
				},
			}
			s.blockchainClient.LogActivity(auditEntry)
			
			return nil, fmt.Errorf("access denied: insufficient permissions to search patient notes")
		}
	}

	// Convert search criteria to repository format
	searchCriteria := &types.ClinicalNoteSearchCriteria{
		PatientID:     criteria.PatientID,
		AuthorID:      criteria.AuthorID,
		NoteType:      criteria.NoteType,
		CreatedAfter:  criteria.FromDate,
		CreatedBefore: criteria.ToDate,
		Limit:         criteria.Limit,
		Offset:        criteria.Offset,
	}

	// Search notes in repository
	notes, err := s.repository.Search(ctx, searchCriteria)
	if err != nil {
		s.logger.Error("Failed to search notes", "error", err)
		return nil, fmt.Errorf("note search failed: %w", err)
	}

	// Filter results based on user access (for multi-patient searches)
	var filteredNotes []*types.ClinicalNote
	for _, note := range notes {
		// Check access for each note's patient
		allowed, err := s.blockchainClient.CheckAccess(userID, note.PatientID, "read_note")
		if err != nil {
			s.logger.Warn("Failed to check access for note", "noteID", note.ID, "error", err)
			continue
		}

		if allowed {
			filteredNotes = append(filteredNotes, note)
		}
	}

	// Log search activity
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "search_clinical_notes",
		ResourceID:   criteria.PatientID,
		ResourceType: "clinical_note",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"results_count": len(filteredNotes),
			"search_criteria": map[string]interface{}{
				"patient_id": criteria.PatientID,
				"note_type":  criteria.NoteType,
				"from_date":  criteria.FromDate,
				"to_date":    criteria.ToDate,
			},
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log search audit entry", "error", err)
	}

	s.logger.Info("Clinical notes search completed", "userID", userID, "resultsCount", len(filteredNotes))
	return filteredNotes, nil
}

// GetPatientNotes retrieves all notes for a specific patient
func (s *ClinicalNotesService) GetPatientNotes(patientID, userID string) ([]*types.ClinicalNote, error) {
	ctx := context.Background()
	
	s.logger.Info("Getting patient notes", "patientID", patientID, "userID", userID)

	// Validate access via AccessPolicy chaincode
	allowed, err := s.blockchainClient.CheckAccess(userID, patientID, "read_note")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for patient notes", "userID", userID, "patientID", patientID)
		
		// Log unauthorized access attempt
		auditEntry := &types.AuditLogEntry{
			UserID:       userID,
			Action:       "get_patient_notes",
			ResourceID:   patientID,
			ResourceType: "patient",
			Timestamp:    time.Now(),
			Success:      false,
			Details: map[string]interface{}{
				"reason": "access_denied",
			},
		}
		s.blockchainClient.LogActivity(auditEntry)
		
		return nil, fmt.Errorf("access denied: insufficient permissions to read patient notes")
	}

	// Get notes from repository
	notes, err := s.repository.GetByPatientID(ctx, patientID, nil)
	if err != nil {
		s.logger.Error("Failed to get patient notes", "patientID", patientID, "error", err)
		return nil, fmt.Errorf("failed to retrieve patient notes: %w", err)
	}

	// Log successful access
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "get_patient_notes",
		ResourceID:   patientID,
		ResourceType: "patient",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"notes_count": len(notes),
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit entry", "error", err)
	}

	s.logger.Info("Patient notes retrieved successfully", "patientID", patientID, "notesCount", len(notes))
	return notes, nil
}

// CreatePatient creates a new patient record
func (s *ClinicalNotesService) CreatePatient(patient *types.Patient, userID string) (*types.Patient, error) {
	ctx := context.Background()
	
	s.logger.Info("Creating patient", "userID", userID)

	// Validate access to create patients
	allowed, err := s.blockchainClient.CheckAccess(userID, "patients", "create")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for patient creation", "userID", userID)
		return nil, fmt.Errorf("access denied: insufficient permissions to create patient")
	}

	// Create patient in repository
	createdPatient, err := s.patientRepo.Create(ctx, patient, userID)
	if err != nil {
		s.logger.Error("Failed to create patient", "error", err)
		return nil, fmt.Errorf("patient creation failed: %w", err)
	}

	// Log audit entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "create_patient",
		ResourceID:   createdPatient.ID,
		ResourceType: "patient",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"mrn": createdPatient.MRN,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit entry", "patientID", createdPatient.ID, "error", err)
	}

	s.logger.Info("Patient created successfully", "patientID", createdPatient.ID, "mrn", createdPatient.MRN)
	return createdPatient, nil
}

// GetPatient retrieves a patient by ID
func (s *ClinicalNotesService) GetPatient(patientID, userID string) (*types.Patient, error) {
	ctx := context.Background()
	
	s.logger.Info("Getting patient", "patientID", patientID, "userID", userID)

	// Validate access via AccessPolicy chaincode
	allowed, err := s.blockchainClient.CheckAccess(userID, patientID, "read")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for patient retrieval", "userID", userID, "patientID", patientID)
		
		// Log unauthorized access attempt
		auditEntry := &types.AuditLogEntry{
			UserID:       userID,
			Action:       "get_patient",
			ResourceID:   patientID,
			ResourceType: "patient",
			Timestamp:    time.Now(),
			Success:      false,
			Details: map[string]interface{}{
				"reason": "access_denied",
			},
		}
		s.blockchainClient.LogActivity(auditEntry)
		
		return nil, fmt.Errorf("access denied: insufficient permissions to read patient")
	}

	// Get patient from repository
	patient, err := s.patientRepo.GetByID(ctx, patientID)
	if err != nil {
		s.logger.Error("Failed to get patient", "patientID", patientID, "error", err)
		return nil, fmt.Errorf("patient retrieval failed: %w", err)
	}

	// Log successful access
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "get_patient",
		ResourceID:   patientID,
		ResourceType: "patient",
		Timestamp:    time.Now(),
		Success:      true,
		Details:      map[string]interface{}{},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit entry", "patientID", patientID, "error", err)
	}

	s.logger.Info("Patient retrieved successfully", "patientID", patientID)
	return patient, nil
}

// UpdatePatient updates patient information
func (s *ClinicalNotesService) UpdatePatient(patientID string, updates map[string]interface{}, userID string) error {
	ctx := context.Background()
	
	s.logger.Info("Updating patient", "patientID", patientID, "userID", userID)

	// Validate access via AccessPolicy chaincode
	allowed, err := s.blockchainClient.CheckAccess(userID, patientID, "update")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for patient update", "userID", userID, "patientID", patientID)
		
		// Log unauthorized access attempt
		auditEntry := &types.AuditLogEntry{
			UserID:       userID,
			Action:       "update_patient",
			ResourceID:   patientID,
			ResourceType: "patient",
			Timestamp:    time.Now(),
			Success:      false,
			Details: map[string]interface{}{
				"reason": "access_denied",
			},
		}
		s.blockchainClient.LogActivity(auditEntry)
		
		return fmt.Errorf("access denied: insufficient permissions to update patient")
	}

	// Update patient in repository
	if err := s.patientRepo.Update(ctx, patientID, updates, userID); err != nil {
		s.logger.Error("Failed to update patient", "patientID", patientID, "error", err)
		return fmt.Errorf("patient update failed: %w", err)
	}

	// Log audit entry
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "update_patient",
		ResourceID:   patientID,
		ResourceType: "patient",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"updated_fields": getUpdatedFields(updates),
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit entry", "patientID", patientID, "error", err)
	}

	s.logger.Info("Patient updated successfully", "patientID", patientID)
	return nil
}

// SearchPatients searches for patients with role-based filtering
func (s *ClinicalNotesService) SearchPatients(criteria map[string]interface{}, userID string) ([]*types.Patient, error) {
	ctx := context.Background()
	
	s.logger.Info("Searching patients", "userID", userID)

	// Validate access to search patients
	allowed, err := s.blockchainClient.CheckAccess(userID, "patients", "search")
	if err != nil {
		s.logger.Error("Failed to check access", "error", err)
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for patient search", "userID", userID)
		return nil, fmt.Errorf("access denied: insufficient permissions to search patients")
	}

	// Extract limit and offset from criteria
	limit, _ := criteria["limit"].(int)
	offset, _ := criteria["offset"].(int)
	if limit == 0 {
		limit = 50 // Default limit
	}

	// Search patients in repository
	patients, err := s.patientRepo.Search(ctx, criteria, limit, offset)
	if err != nil {
		s.logger.Error("Failed to search patients", "error", err)
		return nil, fmt.Errorf("patient search failed: %w", err)
	}

	// Log search activity
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "search_patients",
		ResourceID:   "patients",
		ResourceType: "patient",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"results_count":   len(patients),
			"search_criteria": criteria,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log search audit entry", "error", err)
	}

	s.logger.Info("Patient search completed", "userID", userID, "resultsCount", len(patients))
	return patients, nil
}

// getUpdatedFields extracts field names from update map for audit logging
func getUpdatedFields(updates map[string]interface{}) []string {
	var fields []string
	for field := range updates {
		fields = append(fields, field)
	}
	return fields
}

// GetAuditTrail retrieves audit trail for a resource
func (s *ClinicalNotesService) GetAuditTrail(resourceID, userID string) ([]*types.AuditLogEntry, error) {
	s.logger.Info("Getting audit trail", "resourceID", resourceID, "userID", userID)

	// Validate access to audit logs
	allowed, err := s.blockchainClient.CheckAccess(userID, resourceID, "read_audit")
	if err != nil {
		s.logger.Error("Failed to check audit access", "error", err)
		return nil, fmt.Errorf("audit access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for audit trail", "userID", userID, "resourceID", resourceID)
		return nil, fmt.Errorf("access denied: insufficient permissions to read audit trail")
	}

	// Get audit trail from blockchain
	entries, err := s.blockchainClient.GetAuditTrail(resourceID)
	if err != nil {
		s.logger.Error("Failed to get audit trail", "resourceID", resourceID, "error", err)
		return nil, fmt.Errorf("audit trail retrieval failed: %w", err)
	}

	// Log audit trail access
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "read_audit_trail",
		ResourceID:   resourceID,
		ResourceType: "audit_log",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"entries_count": len(entries),
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log audit trail access", "error", err)
	}

	return entries, nil
}

// ValidateUserAccess validates user access with detailed role checking
func (s *ClinicalNotesService) ValidateUserAccess(userID, resourceID, action, requiredRole string) (bool, error) {
	s.logger.Info("Validating user access", "userID", userID, "resourceID", resourceID, "action", action, "requiredRole", requiredRole)

	// First validate user role
	if requiredRole != "" {
		roleValid, err := s.blockchainClient.ValidateUserRole(userID, requiredRole)
		if err != nil {
			return false, fmt.Errorf("role validation failed: %w", err)
		}

		if !roleValid {
			s.logger.Warn("User role validation failed", "userID", userID, "requiredRole", requiredRole)
			return false, nil
		}
	}

	// Then check specific access permissions
	allowed, err := s.blockchainClient.CheckAccess(userID, resourceID, action)
	if err != nil {
		return false, fmt.Errorf("access check failed: %w", err)
	}

	return allowed, nil
}

// CreateAccessPolicy creates a new access policy
func (s *ClinicalNotesService) CreateAccessPolicy(policy *types.AccessPolicy, userID string) error {
	s.logger.Info("Creating access policy", "policyID", policy.ID, "userID", userID)

	// Validate admin access
	allowed, err := s.blockchainClient.CheckAccess(userID, "access_policies", "create")
	if err != nil {
		return fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for policy creation", "userID", userID)
		return fmt.Errorf("access denied: insufficient permissions to create access policy")
	}

	// Set policy metadata
	policy.CreatedBy = userID
	policy.CreatedAt = time.Now()

	// Create policy on blockchain
	if err := s.blockchainClient.CreateAccessPolicy(policy); err != nil {
		s.logger.Error("Failed to create access policy", "error", err)
		return fmt.Errorf("access policy creation failed: %w", err)
	}

	// Log policy creation
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "create_access_policy",
		ResourceID:   policy.ID,
		ResourceType: "access_policy",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"resource_type": policy.ResourceType,
			"user_role":     policy.UserRole,
			"actions":       policy.Actions,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log policy creation", "error", err)
	}

	s.logger.Info("Access policy created successfully", "policyID", policy.ID)
	return nil
}

// GetComplianceReport generates compliance report
func (s *ClinicalNotesService) GetComplianceReport(startDate, endDate time.Time, resourceType, userID string) (map[string]interface{}, error) {
	s.logger.Info("Generating compliance report", "startDate", startDate, "endDate", endDate, "resourceType", resourceType, "userID", userID)

	// Validate admin access for compliance reports
	allowed, err := s.blockchainClient.CheckAccess(userID, "compliance_reports", "read")
	if err != nil {
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for compliance report", "userID", userID)
		return nil, fmt.Errorf("access denied: insufficient permissions to generate compliance report")
	}

	// Get compliance report from blockchain
	report, err := s.blockchainClient.GetComplianceReport(startDate, endDate, resourceType)
	if err != nil {
		s.logger.Error("Failed to get compliance report", "error", err)
		return nil, fmt.Errorf("compliance report generation failed: %w", err)
	}

	// Log report generation
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "generate_compliance_report",
		ResourceID:   fmt.Sprintf("report_%s_%s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
		ResourceType: "compliance_report",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"start_date":    startDate,
			"end_date":      endDate,
			"resource_type": resourceType,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log report generation", "error", err)
	}

	return report, nil
}

// CreateReEncryptionToken creates a PRE token for secure data sharing
func (s *ClinicalNotesService) CreateReEncryptionToken(fromUserID, toUserID, resourceID string, expiresIn time.Duration, requestingUserID string) (*types.AccessToken, error) {
	s.logger.Info("Creating re-encryption token", "fromUserID", fromUserID, "toUserID", toUserID, "resourceID", resourceID, "requestingUserID", requestingUserID)

	// Validate that requesting user has permission to create tokens for the resource
	allowed, err := s.blockchainClient.CheckAccess(requestingUserID, resourceID, "share")
	if err != nil {
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for token creation", "requestingUserID", requestingUserID, "resourceID", resourceID)
		return nil, fmt.Errorf("access denied: insufficient permissions to create re-encryption token")
	}

	// Create token via blockchain
	token, err := s.blockchainClient.CreateReEncryptionToken(fromUserID, toUserID, resourceID, expiresIn)
	if err != nil {
		s.logger.Error("Failed to create re-encryption token", "error", err)
		return nil, fmt.Errorf("re-encryption token creation failed: %w", err)
	}

	s.logger.Info("Re-encryption token created successfully", "tokenID", token.ID)
	return token, nil
}

// RevokeAccessToken revokes an access token
func (s *ClinicalNotesService) RevokeAccessToken(tokenID, userID string) error {
	s.logger.Info("Revoking access token", "tokenID", tokenID, "userID", userID)

	// Validate permission to revoke tokens
	allowed, err := s.blockchainClient.CheckAccess(userID, tokenID, "revoke")
	if err != nil {
		return fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for token revocation", "userID", userID, "tokenID", tokenID)
		return fmt.Errorf("access denied: insufficient permissions to revoke access token")
	}

	// Revoke token via blockchain
	if err := s.blockchainClient.RevokeAccessToken(tokenID, userID); err != nil {
		s.logger.Error("Failed to revoke access token", "error", err)
		return fmt.Errorf("access token revocation failed: %w", err)
	}

	s.logger.Info("Access token revoked successfully", "tokenID", tokenID)
	return nil
}

// ValidateDataIntegrityBatch validates integrity for multiple notes
func (s *ClinicalNotesService) ValidateDataIntegrityBatch(noteIDs []string, userID string) (map[string]bool, error) {
	s.logger.Info("Validating data integrity for batch", "noteCount", len(noteIDs), "userID", userID)

	results := make(map[string]bool)
	
	for _, noteID := range noteIDs {
		valid := true
		if err := s.VerifyDataIntegrity(noteID); err != nil {
			s.logger.Warn("Data integrity check failed", "noteID", noteID, "error", err)
			valid = false
		}
		results[noteID] = valid
	}

	// Log batch integrity check
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "validate_data_integrity_batch",
		ResourceID:   fmt.Sprintf("batch_%d_notes", len(noteIDs)),
		ResourceType: "clinical_note",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"note_count": len(noteIDs),
			"results":    results,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log batch integrity check", "error", err)
	}

	return results, nil
}