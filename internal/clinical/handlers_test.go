package clinical

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClinicalService mocks the clinical service for handler tests
type MockClinicalService struct {
	mock.Mock
}

func (m *MockClinicalService) CreateNote(note *types.ClinicalNote, userID string) (*types.ClinicalNote, error) {
	args := m.Called(note, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalService) GetNote(noteID, userID string) (*types.ClinicalNote, error) {
	args := m.Called(noteID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalService) UpdateNote(noteID string, updates *types.ClinicalNoteUpdates, userID string) error {
	args := m.Called(noteID, updates, userID)
	return args.Error(0)
}

func (m *MockClinicalService) DeleteNote(noteID, userID string) error {
	args := m.Called(noteID, userID)
	return args.Error(0)
}

func (m *MockClinicalService) SearchNotes(criteria *types.SearchCriteria, userID string) ([]*types.ClinicalNote, error) {
	args := m.Called(criteria, userID)
	return args.Get(0).([]*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalService) GetPatientNotes(patientID, userID string) ([]*types.ClinicalNote, error) {
	args := m.Called(patientID, userID)
	return args.Get(0).([]*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalService) CreatePatient(patient *types.Patient, userID string) (*types.Patient, error) {
	args := m.Called(patient, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.Patient), args.Error(1)
}

func (m *MockClinicalService) GetPatient(patientID, userID string) (*types.Patient, error) {
	args := m.Called(patientID, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.Patient), args.Error(1)
}

func (m *MockClinicalService) UpdatePatient(patientID string, updates map[string]interface{}, userID string) error {
	args := m.Called(patientID, updates, userID)
	return args.Error(0)
}

func (m *MockClinicalService) SearchPatients(criteria map[string]interface{}, userID string) ([]*types.Patient, error) {
	args := m.Called(criteria, userID)
	return args.Get(0).([]*types.Patient), args.Error(1)
}

func (m *MockClinicalService) VerifyDataIntegrity(noteID string) error {
	args := m.Called(noteID)
	return args.Error(0)
}

func (m *MockClinicalService) GenerateHash(content string) (string, error) {
	args := m.Called(content)
	return args.String(0), args.Error(1)
}

func setupTestHandlers() (*Handlers, *MockClinicalService) {
	mockService := &MockClinicalService{}
	logger := logger.New("debug")
	
	// Create a real service with mocked dependencies for the handlers
	service := &ClinicalNotesService{}
	handlers := NewHandlers(service, logger)
	
	return handlers, mockService
}

func TestHandlers_CreateNote(t *testing.T) {
	handlers, mockService := setupTestHandlers()

	t.Run("successful note creation", func(t *testing.T) {
		note := &types.ClinicalNote{
			PatientID: "patient-123",
			Content:   "Test clinical note",
			NoteType:  "progress_note",
		}

		createdNote := &types.ClinicalNote{
			ID:        "note-123",
			PatientID: note.PatientID,
			Content:   note.Content,
			NoteType:  note.NoteType,
			CreatedAt: time.Now(),
		}

		// Setup mock
		mockService.On("CreateNote", mock.MatchedBy(func(n *types.ClinicalNote) bool {
			return n.PatientID == note.PatientID && n.Content == note.Content
		}), "test-user").Return(createdNote, nil)

		// Create request
		body, _ := json.Marshal(note)
		req := httptest.NewRequest("POST", "/notes", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.CreateNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusCreated, rr.Code)
		
		var response types.ClinicalNote
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, createdNote.ID, response.ID)

		mockService.AssertExpectations(t)
	})

	t.Run("missing user ID", func(t *testing.T) {
		note := &types.ClinicalNote{
			PatientID: "patient-123",
			Content:   "Test note",
			NoteType:  "progress_note",
		}

		body, _ := json.Marshal(note)
		req := httptest.NewRequest("POST", "/notes", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		// No X-User-ID header
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.CreateNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusUnauthorized, rr.Code)
	})

	t.Run("invalid JSON payload", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/notes", bytes.NewBufferString("invalid json"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.CreateNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("missing required fields", func(t *testing.T) {
		note := &types.ClinicalNote{
			// Missing PatientID, Content, and NoteType
		}

		body, _ := json.Marshal(note)
		req := httptest.NewRequest("POST", "/notes", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.CreateNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, rr.Code)
		
		var errorResponse map[string]interface{}
		json.Unmarshal(rr.Body.Bytes(), &errorResponse)
		assert.Contains(t, errorResponse["error"].(map[string]interface{})["message"], "Patient ID is required")
	})

	t.Run("service error", func(t *testing.T) {
		note := &types.ClinicalNote{
			PatientID: "patient-123",
			Content:   "Test note",
			NoteType:  "progress_note",
		}

		// Setup mock to return error
		mockService.On("CreateNote", mock.Anything, "test-user").Return(nil, assert.AnError)

		body, _ := json.Marshal(note)
		req := httptest.NewRequest("POST", "/notes", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.CreateNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusInternalServerError, rr.Code)

		mockService.AssertExpectations(t)
	})
}

func TestHandlers_GetNote(t *testing.T) {
	handlers, mockService := setupTestHandlers()

	t.Run("successful note retrieval", func(t *testing.T) {
		noteID := "note-123"
		note := &types.ClinicalNote{
			ID:        noteID,
			PatientID: "patient-123",
			Content:   "Test note content",
			NoteType:  "progress_note",
		}

		// Setup mock
		mockService.On("GetNote", noteID, "test-user").Return(note, nil)

		// Create request with URL parameters
		req := httptest.NewRequest("GET", "/notes/"+noteID, nil)
		req.Header.Set("X-User-ID", "test-user")
		req = mux.SetURLVars(req, map[string]string{"noteID": noteID})
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.GetNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response types.ClinicalNote
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, note.ID, response.ID)

		mockService.AssertExpectations(t)
	})

	t.Run("access denied", func(t *testing.T) {
		noteID := "note-123"

		// Setup mock to return access denied error
		mockService.On("GetNote", noteID, "test-user").Return(nil, 
			assert.AnError) // Using a generic error for simplicity

		req := httptest.NewRequest("GET", "/notes/"+noteID, nil)
		req.Header.Set("X-User-ID", "test-user")
		req = mux.SetURLVars(req, map[string]string{"noteID": noteID})
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.GetNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusInternalServerError, rr.Code)

		mockService.AssertExpectations(t)
	})
}

func TestHandlers_UpdateNote(t *testing.T) {
	handlers, mockService := setupTestHandlers()

	t.Run("successful note update", func(t *testing.T) {
		noteID := "note-123"
		updates := &types.ClinicalNoteUpdates{
			Content: "Updated content",
		}

		// Setup mock
		mockService.On("UpdateNote", noteID, mock.MatchedBy(func(u *types.ClinicalNoteUpdates) bool {
			return u.Content == updates.Content
		}), "test-user").Return(nil)

		body, _ := json.Marshal(updates)
		req := httptest.NewRequest("PUT", "/notes/"+noteID, bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "test-user")
		req = mux.SetURLVars(req, map[string]string{"noteID": noteID})
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.UpdateNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response map[string]string
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Note updated successfully", response["message"])

		mockService.AssertExpectations(t)
	})
}

func TestHandlers_DeleteNote(t *testing.T) {
	handlers, mockService := setupTestHandlers()

	t.Run("successful note deletion", func(t *testing.T) {
		noteID := "note-123"

		// Setup mock
		mockService.On("DeleteNote", noteID, "test-user").Return(nil)

		req := httptest.NewRequest("DELETE", "/notes/"+noteID, nil)
		req.Header.Set("X-User-ID", "test-user")
		req = mux.SetURLVars(req, map[string]string{"noteID": noteID})
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.DeleteNote(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response map[string]string
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "Note deleted successfully", response["message"])

		mockService.AssertExpectations(t)
	})
}

func TestHandlers_SearchNotes(t *testing.T) {
	handlers, mockService := setupTestHandlers()

	t.Run("successful notes search", func(t *testing.T) {
		notes := []*types.ClinicalNote{
			{ID: "note-1", PatientID: "patient-123", NoteType: "progress_note"},
			{ID: "note-2", PatientID: "patient-123", NoteType: "progress_note"},
		}

		// Setup mock
		mockService.On("SearchNotes", mock.MatchedBy(func(c *types.SearchCriteria) bool {
			return c.PatientID == "patient-123" && c.NoteType == "progress_note"
		}), "test-user").Return(notes, nil)

		req := httptest.NewRequest("GET", "/notes/search?patient_id=patient-123&note_type=progress_note", nil)
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.SearchNotes(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, float64(2), response["count"])

		mockService.AssertExpectations(t)
	})

	t.Run("search with date filters", func(t *testing.T) {
		notes := []*types.ClinicalNote{
			{ID: "note-1", CreatedAt: time.Now()},
		}

		// Setup mock
		mockService.On("SearchNotes", mock.MatchedBy(func(c *types.SearchCriteria) bool {
			return !c.FromDate.IsZero() && !c.ToDate.IsZero()
		}), "test-user").Return(notes, nil)

		req := httptest.NewRequest("GET", "/notes/search?from_date=2023-01-01&to_date=2023-12-31", nil)
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.SearchNotes(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)

		mockService.AssertExpectations(t)
	})

	t.Run("search with pagination", func(t *testing.T) {
		notes := []*types.ClinicalNote{
			{ID: "note-1"},
		}

		// Setup mock
		mockService.On("SearchNotes", mock.MatchedBy(func(c *types.SearchCriteria) bool {
			return c.Limit == 10 && c.Offset == 20
		}), "test-user").Return(notes, nil)

		req := httptest.NewRequest("GET", "/notes/search?limit=10&offset=20", nil)
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.SearchNotes(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)

		mockService.AssertExpectations(t)
	})
}

func TestHandlers_VerifyIntegrity(t *testing.T) {
	handlers, mockService := setupTestHandlers()

	t.Run("successful integrity verification", func(t *testing.T) {
		noteID := "note-123"

		// Setup mock
		mockService.On("VerifyDataIntegrity", noteID).Return(nil)

		req := httptest.NewRequest("GET", "/notes/"+noteID+"/integrity", nil)
		req.Header.Set("X-User-ID", "test-user")
		req = mux.SetURLVars(req, map[string]string{"noteID": noteID})
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.VerifyIntegrity(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.True(t, response["valid"].(bool))

		mockService.AssertExpectations(t)
	})

	t.Run("integrity verification failure", func(t *testing.T) {
		noteID := "note-123"

		// Setup mock to return error
		mockService.On("VerifyDataIntegrity", noteID).Return(assert.AnError)

		req := httptest.NewRequest("GET", "/notes/"+noteID+"/integrity", nil)
		req.Header.Set("X-User-ID", "test-user")
		req = mux.SetURLVars(req, map[string]string{"noteID": noteID})
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.VerifyIntegrity(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.False(t, response["valid"].(bool))
		assert.NotEmpty(t, response["reason"])

		mockService.AssertExpectations(t)
	})
}

func TestHandlers_CreatePatient(t *testing.T) {
	handlers, mockService := setupTestHandlers()

	t.Run("successful patient creation", func(t *testing.T) {
		patient := &types.Patient{
			MRN: "MRN-123",
			Demographics: &types.Demographics{
				FirstName: "John",
				LastName:  "Doe",
			},
		}

		createdPatient := &types.Patient{
			ID:           "patient-123",
			MRN:          patient.MRN,
			Demographics: patient.Demographics,
			CreatedAt:    time.Now(),
		}

		// Setup mock
		mockService.On("CreatePatient", mock.MatchedBy(func(p *types.Patient) bool {
			return p.MRN == patient.MRN
		}), "test-user").Return(createdPatient, nil)

		body, _ := json.Marshal(patient)
		req := httptest.NewRequest("POST", "/patients", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.CreatePatient(rr, req)

		// Assertions
		assert.Equal(t, http.StatusCreated, rr.Code)
		
		var response types.Patient
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, createdPatient.ID, response.ID)

		mockService.AssertExpectations(t)
	})

	t.Run("missing MRN", func(t *testing.T) {
		patient := &types.Patient{
			Demographics: &types.Demographics{
				FirstName: "John",
				LastName:  "Doe",
			},
		}

		body, _ := json.Marshal(patient)
		req := httptest.NewRequest("POST", "/patients", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.CreatePatient(rr, req)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})

	t.Run("missing demographics", func(t *testing.T) {
		patient := &types.Patient{
			MRN: "MRN-123",
		}

		body, _ := json.Marshal(patient)
		req := httptest.NewRequest("POST", "/patients", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-User-ID", "test-user")
		
		rr := httptest.NewRecorder()

		// Execute
		handlers.CreatePatient(rr, req)

		// Assertions
		assert.Equal(t, http.StatusBadRequest, rr.Code)
	})
}

func TestHandlers_HealthCheck(t *testing.T) {
	handlers, _ := setupTestHandlers()

	t.Run("health check", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		rr := httptest.NewRecorder()

		// Execute
		handlers.HealthCheck(rr, req)

		// Assertions
		assert.Equal(t, http.StatusOK, rr.Code)
		
		var response map[string]interface{}
		err := json.Unmarshal(rr.Body.Bytes(), &response)
		assert.NoError(t, err)
		assert.Equal(t, "healthy", response["status"])
		assert.Equal(t, "clinical-notes-service", response["service"])
		assert.NotEmpty(t, response["timestamp"])
	})
}

func TestHandlers_GetUserID(t *testing.T) {
	handlers, _ := setupTestHandlers()

	t.Run("user ID from X-User-ID header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("X-User-ID", "test-user-123")

		userID := handlers.getUserID(req)
		assert.Equal(t, "test-user-123", userID)
	})

	t.Run("user ID from Authorization header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer jwt-token")

		userID := handlers.getUserID(req)
		assert.Equal(t, "mock_user_id", userID) // Mock implementation returns this
	})

	t.Run("no user ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)

		userID := handlers.getUserID(req)
		assert.Empty(t, userID)
	})
}