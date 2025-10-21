package clinical

import (
	"context"
	"testing"
	"time"

	"github.com/medrex/dlt-emr/pkg/encryption"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/repository"
	"github.com/medrex/dlt-emr/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClinicalNotesRepository mocks the clinical notes repository
type MockClinicalNotesRepository struct {
	mock.Mock
}

func (m *MockClinicalNotesRepository) Create(ctx context.Context, note *types.ClinicalNote, authorID string) (*types.ClinicalNote, error) {
	args := m.Called(ctx, note, authorID)
	return args.Get(0).(*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalNotesRepository) GetByID(ctx context.Context, noteID string) (*types.ClinicalNote, error) {
	args := m.Called(ctx, noteID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalNotesRepository) Update(ctx context.Context, noteID string, updates *types.ClinicalNoteUpdates, updatedBy string) (*types.ClinicalNote, error) {
	args := m.Called(ctx, noteID, updates, updatedBy)
	return args.Get(0).(*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalNotesRepository) Delete(ctx context.Context, noteID string, deletedBy string) error {
	args := m.Called(ctx, noteID, deletedBy)
	return args.Error(0)
}

func (m *MockClinicalNotesRepository) Search(ctx context.Context, criteria *types.ClinicalNoteSearchCriteria) ([]*types.ClinicalNote, error) {
	args := m.Called(ctx, criteria)
	return args.Get(0).([]*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalNotesRepository) GetByPatientID(ctx context.Context, patientID string, filters *types.ClinicalNoteFilters) ([]*types.ClinicalNote, error) {
	args := m.Called(ctx, patientID, filters)
	return args.Get(0).([]*types.ClinicalNote), args.Error(1)
}

// MockPatientRepository mocks the patient repository
type MockPatientRepository struct {
	mock.Mock
}

func (m *MockPatientRepository) GetByID(ctx context.Context, patientID string) (*types.Patient, error) {
	args := m.Called(ctx, patientID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.Patient), args.Error(1)
}

func (m *MockPatientRepository) Create(ctx context.Context, patient *types.Patient, createdBy string) (*types.Patient, error) {
	args := m.Called(ctx, patient, createdBy)
	return args.Get(0).(*types.Patient), args.Error(1)
}

func (m *MockPatientRepository) Update(ctx context.Context, patientID string, updates map[string]interface{}, updatedBy string) error {
	args := m.Called(ctx, patientID, updates, updatedBy)
	return args.Error(0)
}

func (m *MockPatientRepository) Search(ctx context.Context, criteria map[string]interface{}, limit, offset int) ([]*types.Patient, error) {
	args := m.Called(ctx, criteria, limit, offset)
	return args.Get(0).([]*types.Patient), args.Error(1)
}

// MockEncryptionService mocks the encryption service
type MockEncryptionService struct {
	mock.Mock
}

func (m *MockEncryptionService) Encrypt(plaintext string) (string, error) {
	args := m.Called(plaintext)
	return args.String(0), args.Error(1)
}

func (m *MockEncryptionService) Decrypt(ciphertext string) (string, error) {
	args := m.Called(ciphertext)
	return args.String(0), args.Error(1)
}

func (m *MockEncryptionService) GenerateKey() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockEncryptionService) RotateKey(oldKey, newKey string) error {
	args := m.Called(oldKey, newKey)
	return args.Error(0)
}

func (m *MockEncryptionService) GenerateReEncryptionToken(fromKey, toKey string) (string, error) {
	args := m.Called(fromKey, toKey)
	return args.String(0), args.Error(1)
}

func (m *MockEncryptionService) ReEncrypt(ciphertext, token string) (string, error) {
	args := m.Called(ciphertext, token)
	return args.String(0), args.Error(1)
}

func (m *MockEncryptionService) GenerateHash(data string) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *MockEncryptionService) VerifyHash(data, hash string) (bool, error) {
	args := m.Called(data, hash)
	return args.Bool(0), args.Error(1)
}

// MockBlockchainClient mocks the blockchain client
type MockBlockchainClient struct {
	mock.Mock
}

func (m *MockBlockchainClient) CheckAccess(userID, resourceID, action string) (bool, error) {
	args := m.Called(userID, resourceID, action)
	return args.Bool(0), args.Error(1)
}

func (m *MockBlockchainClient) GetAccessToken(userID, resourceID string) (*types.AccessToken, error) {
	args := m.Called(userID, resourceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.AccessToken), args.Error(1)
}

func (m *MockBlockchainClient) LogActivity(entry *types.AuditLogEntry) error {
	args := m.Called(entry)
	return args.Error(0)
}

func (m *MockBlockchainClient) GetAuditTrail(resourceID string) ([]*types.AuditLogEntry, error) {
	args := m.Called(resourceID)
	return args.Get(0).([]*types.AuditLogEntry), args.Error(1)
}

func (m *MockBlockchainClient) StorePHIHash(hash *types.PHIHash) error {
	args := m.Called(hash)
	return args.Error(0)
}

func (m *MockBlockchainClient) GetPHIHash(resourceID string) (*types.PHIHash, error) {
	args := m.Called(resourceID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.PHIHash), args.Error(1)
}

func (m *MockBlockchainClient) SubmitTransaction(chaincode, function string, args []string) (*types.ChaincodeTxResult, error) {
	mockArgs := m.Called(chaincode, function, args)
	return mockArgs.Get(0).(*types.ChaincodeTxResult), mockArgs.Error(1)
}

func (m *MockBlockchainClient) QueryChaincode(chaincode, function string, args []string) ([]byte, error) {
	mockArgs := m.Called(chaincode, function, args)
	return mockArgs.Get(0).([]byte), mockArgs.Error(1)
}

// Test setup helper
func setupTestService() (*ClinicalNotesService, *MockClinicalNotesRepository, *MockPatientRepository, *MockEncryptionService, *MockBlockchainClient) {
	mockRepo := &MockClinicalNotesRepository{}
	mockPatientRepo := &MockPatientRepository{}
	mockEncryption := &MockEncryptionService{}
	mockBlockchain := &MockBlockchainClient{}
	mockPRE := &encryption.PREService{}
	logger := logger.New("debug")

	service := NewClinicalNotesService(
		mockRepo,
		mockPatientRepo,
		mockEncryption,
		mockBlockchain,
		mockPRE,
		logger,
	)

	return service, mockRepo, mockPatientRepo, mockEncryption, mockBlockchain
}

// Test CreateNote functionality
func TestClinicalNotesService_CreateNote(t *testing.T) {
	service, mockRepo, mockPatientRepo, _, mockBlockchain := setupTestService()

	t.Run("successful note creation", func(t *testing.T) {
		// Setup test data
		note := &types.ClinicalNote{
			PatientID: "patient-123",
			Content:   "Test clinical note content",
			NoteType:  "progress_note",
			Metadata: map[string]string{
				"department": "cardiology",
			},
		}
		userID := "user-123"

		// Setup mocks
		mockBlockchain.On("CheckAccess", userID, note.PatientID, "create_note").Return(true, nil)
		
		patient := &types.Patient{
			ID:  "patient-123",
			MRN: "MRN-123",
		}
		mockPatientRepo.On("GetByID", mock.Anything, note.PatientID).Return(patient, nil)

		createdNote := &types.ClinicalNote{
			ID:        "note-123",
			PatientID: note.PatientID,
			Content:   note.Content,
			NoteType:  note.NoteType,
			Hash:      "test-hash",
			CreatedAt: time.Now(),
		}
		mockRepo.On("Create", mock.Anything, note, userID).Return(createdNote, nil)

		phiHash := &types.PHIHash{
			ID:        createdNote.ID,
			PatientID: createdNote.PatientID,
			Hash:      createdNote.Hash,
		}
		mockBlockchain.On("StorePHIHash", mock.MatchedBy(func(h *types.PHIHash) bool {
			return h.ID == phiHash.ID && h.PatientID == phiHash.PatientID
		})).Return(nil)

		mockBlockchain.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := service.CreateNote(note, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, createdNote.ID, result.ID)
		assert.Equal(t, createdNote.PatientID, result.PatientID)

		// Verify all mocks were called
		mockBlockchain.AssertExpectations(t)
		mockPatientRepo.AssertExpectations(t)
		mockRepo.AssertExpectations(t)
	})

	t.Run("access denied", func(t *testing.T) {
		note := &types.ClinicalNote{
			PatientID: "patient-123",
			Content:   "Test content",
			NoteType:  "progress_note",
		}
		userID := "user-123"

		// Setup mock to deny access
		mockBlockchain.On("CheckAccess", userID, note.PatientID, "create_note").Return(false, nil)

		// Execute test
		result, err := service.CreateNote(note, userID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "access denied")

		mockBlockchain.AssertExpectations(t)
	})

	t.Run("patient not found", func(t *testing.T) {
		note := &types.ClinicalNote{
			PatientID: "nonexistent-patient",
			Content:   "Test content",
			NoteType:  "progress_note",
		}
		userID := "user-123"

		// Setup mocks
		mockBlockchain.On("CheckAccess", userID, note.PatientID, "create_note").Return(true, nil)
		mockPatientRepo.On("GetByID", mock.Anything, note.PatientID).Return(nil, assert.AnError)

		// Execute test
		result, err := service.CreateNote(note, userID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "patient verification failed")

		mockBlockchain.AssertExpectations(t)
		mockPatientRepo.AssertExpectations(t)
	})
}

// Test GetNote functionality
func TestClinicalNotesService_GetNote(t *testing.T) {
	service, mockRepo, _, _, mockBlockchain := setupTestService()

	t.Run("successful note retrieval", func(t *testing.T) {
		noteID := "note-123"
		userID := "user-123"

		// Setup test data
		note := &types.ClinicalNote{
			ID:        noteID,
			PatientID: "patient-123",
			Content:   "Test content",
			Hash:      "test-hash",
		}

		// Setup mocks
		mockRepo.On("GetByID", mock.Anything, noteID).Return(note, nil)
		mockBlockchain.On("CheckAccess", userID, note.PatientID, "read_note").Return(true, nil)

		// Mock data integrity verification
		phiHash := &types.PHIHash{
			ID:   noteID,
			Hash: note.Hash,
		}
		mockBlockchain.On("GetPHIHash", noteID).Return(phiHash, nil)
		mockBlockchain.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := service.GetNote(noteID, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, noteID, result.ID)

		mockRepo.AssertExpectations(t)
		mockBlockchain.AssertExpectations(t)
	})

	t.Run("access denied", func(t *testing.T) {
		noteID := "note-123"
		userID := "user-123"

		note := &types.ClinicalNote{
			ID:        noteID,
			PatientID: "patient-123",
		}

		// Setup mocks
		mockRepo.On("GetByID", mock.Anything, noteID).Return(note, nil)
		mockBlockchain.On("CheckAccess", userID, note.PatientID, "read_note").Return(false, nil)
		mockBlockchain.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := service.GetNote(noteID, userID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "access denied")

		mockRepo.AssertExpectations(t)
		mockBlockchain.AssertExpectations(t)
	})
}

// Test UpdateNote functionality
func TestClinicalNotesService_UpdateNote(t *testing.T) {
	service, mockRepo, _, _, mockBlockchain := setupTestService()

	t.Run("successful note update", func(t *testing.T) {
		noteID := "note-123"
		userID := "user-123"
		updates := &types.ClinicalNoteUpdates{
			Content: "Updated content",
		}

		// Setup test data
		existingNote := &types.ClinicalNote{
			ID:        noteID,
			PatientID: "patient-123",
		}

		updatedNote := &types.ClinicalNote{
			ID:        "note-124", // New version gets new ID
			PatientID: existingNote.PatientID,
			Content:   updates.Content,
			Hash:      "updated-hash",
			Version:   2,
		}

		// Setup mocks
		mockRepo.On("GetByID", mock.Anything, noteID).Return(existingNote, nil)
		mockBlockchain.On("CheckAccess", userID, existingNote.PatientID, "update_note").Return(true, nil)
		mockRepo.On("Update", mock.Anything, noteID, updates, userID).Return(updatedNote, nil)

		phiHash := &types.PHIHash{
			ID:   updatedNote.ID,
			Hash: updatedNote.Hash,
		}
		mockBlockchain.On("StorePHIHash", mock.MatchedBy(func(h *types.PHIHash) bool {
			return h.ID == phiHash.ID && h.Hash == phiHash.Hash
		})).Return(nil)
		mockBlockchain.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		err := service.UpdateNote(noteID, updates, userID)

		// Assertions
		assert.NoError(t, err)

		mockRepo.AssertExpectations(t)
		mockBlockchain.AssertExpectations(t)
	})
}

// Test DeleteNote functionality
func TestClinicalNotesService_DeleteNote(t *testing.T) {
	service, mockRepo, _, _, mockBlockchain := setupTestService()

	t.Run("successful note deletion", func(t *testing.T) {
		noteID := "note-123"
		userID := "user-123"

		existingNote := &types.ClinicalNote{
			ID:        noteID,
			PatientID: "patient-123",
		}

		// Setup mocks
		mockRepo.On("GetByID", mock.Anything, noteID).Return(existingNote, nil)
		mockBlockchain.On("CheckAccess", userID, existingNote.PatientID, "delete_note").Return(true, nil)
		mockRepo.On("Delete", mock.Anything, noteID, userID).Return(nil)
		mockBlockchain.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		err := service.DeleteNote(noteID, userID)

		// Assertions
		assert.NoError(t, err)

		mockRepo.AssertExpectations(t)
		mockBlockchain.AssertExpectations(t)
	})
}

// Test VerifyDataIntegrity functionality
func TestClinicalNotesService_VerifyDataIntegrity(t *testing.T) {
	service, mockRepo, _, _, mockBlockchain := setupTestService()

	t.Run("successful integrity verification", func(t *testing.T) {
		noteID := "note-123"
		content := "Test content"
		hash := encryption.HashData([]byte(content))

		note := &types.ClinicalNote{
			ID:      noteID,
			Content: content,
			Hash:    hash,
		}

		phiHash := &types.PHIHash{
			ID:   noteID,
			Hash: hash,
		}

		// Setup mocks
		mockRepo.On("GetByID", mock.Anything, noteID).Return(note, nil)
		mockBlockchain.On("GetPHIHash", noteID).Return(phiHash, nil)

		// Execute test
		err := service.VerifyDataIntegrity(noteID)

		// Assertions
		assert.NoError(t, err)

		mockRepo.AssertExpectations(t)
		mockBlockchain.AssertExpectations(t)
	})

	t.Run("integrity verification failure - hash mismatch", func(t *testing.T) {
		noteID := "note-123"

		note := &types.ClinicalNote{
			ID:      noteID,
			Content: "Test content",
			Hash:    "original-hash",
		}

		phiHash := &types.PHIHash{
			ID:   noteID,
			Hash: "different-hash", // Mismatch
		}

		// Setup mocks
		mockRepo.On("GetByID", mock.Anything, noteID).Return(note, nil)
		mockBlockchain.On("GetPHIHash", noteID).Return(phiHash, nil)

		// Execute test
		err := service.VerifyDataIntegrity(noteID)

		// Assertions
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "hash mismatch")

		mockRepo.AssertExpectations(t)
		mockBlockchain.AssertExpectations(t)
	})
}

// Test SearchNotes functionality
func TestClinicalNotesService_SearchNotes(t *testing.T) {
	service, mockRepo, _, _, mockBlockchain := setupTestService()

	t.Run("successful search with patient ID", func(t *testing.T) {
		userID := "user-123"
		criteria := &types.SearchCriteria{
			PatientID: "patient-123",
			NoteType:  "progress_note",
		}

		notes := []*types.ClinicalNote{
			{
				ID:        "note-1",
				PatientID: "patient-123",
				NoteType:  "progress_note",
			},
			{
				ID:        "note-2",
				PatientID: "patient-123",
				NoteType:  "progress_note",
			},
		}

		searchCriteria := &types.ClinicalNoteSearchCriteria{
			PatientID: criteria.PatientID,
			NoteType:  criteria.NoteType,
		}

		// Setup mocks
		mockBlockchain.On("CheckAccess", userID, criteria.PatientID, "read_note").Return(true, nil)
		mockRepo.On("Search", mock.Anything, mock.MatchedBy(func(sc *types.ClinicalNoteSearchCriteria) bool {
			return sc.PatientID == searchCriteria.PatientID && sc.NoteType == searchCriteria.NoteType
		})).Return(notes, nil)
		mockBlockchain.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := service.SearchNotes(criteria, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result, 2)

		mockRepo.AssertExpectations(t)
		mockBlockchain.AssertExpectations(t)
	})

	t.Run("access denied for patient search", func(t *testing.T) {
		userID := "user-123"
		criteria := &types.SearchCriteria{
			PatientID: "patient-123",
		}

		// Setup mock to deny access
		mockBlockchain.On("CheckAccess", userID, criteria.PatientID, "read_note").Return(false, nil)
		mockBlockchain.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := service.SearchNotes(criteria, userID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "access denied")

		mockBlockchain.AssertExpectations(t)
	})
}