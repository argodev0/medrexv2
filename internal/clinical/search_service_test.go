package clinical

import (
	"testing"
	"time"

	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockClinicalNotesService mocks the clinical notes service for search tests
type MockClinicalNotesService struct {
	mock.Mock
}

func (m *MockClinicalNotesService) SearchNotes(criteria *types.SearchCriteria, userID string) ([]*types.ClinicalNote, error) {
	args := m.Called(criteria, userID)
	return args.Get(0).([]*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalNotesService) GetPatientNotes(patientID, userID string) ([]*types.ClinicalNote, error) {
	args := m.Called(patientID, userID)
	return args.Get(0).([]*types.ClinicalNote), args.Error(1)
}

func (m *MockClinicalNotesService) ValidateDataIntegrityBatch(noteIDs []string, userID string) (map[string]bool, error) {
	args := m.Called(noteIDs, userID)
	return args.Get(0).(map[string]bool), args.Error(1)
}

func setupTestSearchService() (*SearchService, *MockClinicalNotesService, *MockBlockchainClient) {
	mockClinicalService := &MockClinicalNotesService{}
	mockBlockchainClient := &MockBlockchainClient{}
	logger := logger.New("debug")

	searchService := NewSearchService(mockClinicalService, mockBlockchainClient, logger)

	return searchService, mockClinicalService, mockBlockchainClient
}

func TestSearchService_AdvancedSearch(t *testing.T) {
	searchService, mockClinicalService, mockBlockchainClient := setupTestSearchService()

	t.Run("successful advanced search", func(t *testing.T) {
		userID := "user-123"
		criteria := &AdvancedSearchCriteria{
			PatientID: "patient-123",
			NoteType:  "progress_note",
			Keywords:  []string{"cardiology"},
			Limit:     10,
			SortBy:    "created_at",
			SortOrder: "desc",
		}

		// Mock notes data
		notes := []*types.ClinicalNote{
			{
				ID:        "note-1",
				PatientID: "patient-123",
				NoteType:  "progress_note",
				CreatedAt: time.Now().Add(-1 * time.Hour),
				Metadata: map[string]string{
					"department": "cardiology",
					"keywords":   "cardiology consultation",
				},
			},
			{
				ID:        "note-2",
				PatientID: "patient-123",
				NoteType:  "progress_note",
				CreatedAt: time.Now().Add(-2 * time.Hour),
				Metadata: map[string]string{
					"department": "cardiology",
					"keywords":   "cardiology follow-up",
				},
			},
		}

		// Setup mocks
		mockBlockchainClient.On("CheckAccess", userID, "clinical_notes", "search").Return(true, nil)
		
		basicCriteria := &types.SearchCriteria{
			PatientID: criteria.PatientID,
			NoteType:  criteria.NoteType,
			Limit:     criteria.Limit,
		}
		mockClinicalService.On("SearchNotes", mock.MatchedBy(func(c *types.SearchCriteria) bool {
			return c.PatientID == basicCriteria.PatientID && c.NoteType == basicCriteria.NoteType
		}), userID).Return(notes, nil)

		mockBlockchainClient.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := searchService.AdvancedSearch(criteria, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Notes, 2)
		assert.Equal(t, 2, result.TotalCount)
		assert.False(t, result.HasMore)
		assert.Contains(t, result.FilteredBy, "keywords")
		assert.True(t, result.SearchTime > 0)

		// Verify sorting (most recent first)
		assert.True(t, result.Notes[0].CreatedAt.After(result.Notes[1].CreatedAt))

		mockClinicalService.AssertExpectations(t)
		mockBlockchainClient.AssertExpectations(t)
	})

	t.Run("access denied for search", func(t *testing.T) {
		userID := "user-123"
		criteria := &AdvancedSearchCriteria{
			PatientID: "patient-123",
		}

		// Setup mock to deny access
		mockBlockchainClient.On("CheckAccess", userID, "clinical_notes", "search").Return(false, nil)

		// Execute test
		result, err := searchService.AdvancedSearch(criteria, userID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "access denied")

		mockBlockchainClient.AssertExpectations(t)
	})

	t.Run("search with pagination", func(t *testing.T) {
		userID := "user-123"
		criteria := &AdvancedSearchCriteria{
			Limit:  1,
			Offset: 0,
		}

		// Create more notes than the limit
		notes := []*types.ClinicalNote{
			{ID: "note-1", CreatedAt: time.Now().Add(-1 * time.Hour)},
			{ID: "note-2", CreatedAt: time.Now().Add(-2 * time.Hour)},
			{ID: "note-3", CreatedAt: time.Now().Add(-3 * time.Hour)},
		}

		// Setup mocks
		mockBlockchainClient.On("CheckAccess", userID, "clinical_notes", "search").Return(true, nil)
		mockClinicalService.On("SearchNotes", mock.Anything, userID).Return(notes, nil)
		mockBlockchainClient.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := searchService.AdvancedSearch(criteria, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Notes, 1) // Limited by pagination
		assert.Equal(t, 3, result.TotalCount) // Total before pagination
		assert.True(t, result.HasMore) // More results available

		mockClinicalService.AssertExpectations(t)
		mockBlockchainClient.AssertExpectations(t)
	})
}

func TestSearchService_SearchByPatientWithAggregation(t *testing.T) {
	searchService, mockClinicalService, mockBlockchainClient := setupTestSearchService()

	t.Run("successful patient data aggregation", func(t *testing.T) {
		patientID := "patient-123"
		userID := "user-123"

		// Mock notes data with variety
		notes := []*types.ClinicalNote{
			{
				ID:        "note-1",
				PatientID: patientID,
				AuthorID:  "doctor-1",
				NoteType:  "progress_note",
				CreatedAt: time.Now().Add(-1 * time.Hour),
			},
			{
				ID:        "note-2",
				PatientID: patientID,
				AuthorID:  "doctor-1",
				NoteType:  "progress_note",
				CreatedAt: time.Now().Add(-2 * time.Hour),
			},
			{
				ID:        "note-3",
				PatientID: patientID,
				AuthorID:  "doctor-2",
				NoteType:  "consultation_note",
				CreatedAt: time.Now().Add(-3 * time.Hour),
			},
		}

		// Setup mocks
		mockBlockchainClient.On("CheckAccess", userID, patientID, "read_aggregated").Return(true, nil)
		mockClinicalService.On("GetPatientNotes", patientID, userID).Return(notes, nil)
		mockBlockchainClient.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		aggregation, err := searchService.SearchByPatientWithAggregation(patientID, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, aggregation)
		assert.Equal(t, patientID, aggregation.PatientID)
		assert.Equal(t, 3, aggregation.TotalNotes)
		
		// Check aggregation by type
		assert.Equal(t, 2, aggregation.NotesByType["progress_note"])
		assert.Equal(t, 1, aggregation.NotesByType["consultation_note"])
		
		// Check aggregation by author
		assert.Equal(t, 2, aggregation.NotesByAuthor["doctor-1"])
		assert.Equal(t, 1, aggregation.NotesByAuthor["doctor-2"])
		
		// Check recent activity (should be sorted by creation date)
		assert.Len(t, aggregation.RecentActivity, 3)
		assert.Equal(t, "note-1", aggregation.RecentActivity[0].ID) // Most recent
		
		// Check summary
		assert.Equal(t, "progress_note", aggregation.Summary["most_common_note_type"])
		assert.Equal(t, "doctor-1", aggregation.Summary["most_active_author"])
		assert.Equal(t, 2, aggregation.Summary["unique_authors"])
		assert.Equal(t, 2, aggregation.Summary["unique_note_types"])

		mockClinicalService.AssertExpectations(t)
		mockBlockchainClient.AssertExpectations(t)
	})

	t.Run("access denied for patient aggregation", func(t *testing.T) {
		patientID := "patient-123"
		userID := "user-123"

		// Setup mock to deny access
		mockBlockchainClient.On("CheckAccess", userID, patientID, "read_aggregated").Return(false, nil)

		// Execute test
		aggregation, err := searchService.SearchByPatientWithAggregation(patientID, userID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, aggregation)
		assert.Contains(t, err.Error(), "access denied")

		mockBlockchainClient.AssertExpectations(t)
	})

	t.Run("empty patient notes", func(t *testing.T) {
		patientID := "patient-123"
		userID := "user-123"

		// Setup mocks with empty notes
		mockBlockchainClient.On("CheckAccess", userID, patientID, "read_aggregated").Return(true, nil)
		mockClinicalService.On("GetPatientNotes", patientID, userID).Return([]*types.ClinicalNote{}, nil)
		mockBlockchainClient.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		aggregation, err := searchService.SearchByPatientWithAggregation(patientID, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, aggregation)
		assert.Equal(t, patientID, aggregation.PatientID)
		assert.Equal(t, 0, aggregation.TotalNotes)
		assert.Empty(t, aggregation.NotesByType)
		assert.Empty(t, aggregation.NotesByAuthor)
		assert.Empty(t, aggregation.RecentActivity)

		mockClinicalService.AssertExpectations(t)
		mockBlockchainClient.AssertExpectations(t)
	})
}

func TestSearchService_SearchWithDataIntegrityVerification(t *testing.T) {
	searchService, mockClinicalService, mockBlockchainClient := setupTestSearchService()

	t.Run("successful search with integrity verification", func(t *testing.T) {
		userID := "user-123"
		criteria := &AdvancedSearchCriteria{
			PatientID: "patient-123",
		}

		notes := []*types.ClinicalNote{
			{ID: "note-1", PatientID: "patient-123"},
			{ID: "note-2", PatientID: "patient-123"},
		}

		integrityResults := map[string]bool{
			"note-1": true,
			"note-2": false, // One note has integrity issues
		}

		// Setup mocks
		mockBlockchainClient.On("CheckAccess", userID, "clinical_notes", "search").Return(true, nil)
		mockClinicalService.On("SearchNotes", mock.Anything, userID).Return(notes, nil)
		mockClinicalService.On("ValidateDataIntegrityBatch", []string{"note-1", "note-2"}, userID).Return(integrityResults, nil)
		mockBlockchainClient.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, integrity, err := searchService.SearchWithDataIntegrityVerification(criteria, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, integrity)
		assert.Len(t, result.Notes, 2)
		assert.True(t, integrity["note-1"])
		assert.False(t, integrity["note-2"])

		mockClinicalService.AssertExpectations(t)
		mockBlockchainClient.AssertExpectations(t)
	})

	t.Run("search with integrity verification failure", func(t *testing.T) {
		userID := "user-123"
		criteria := &AdvancedSearchCriteria{
			PatientID: "patient-123",
		}

		notes := []*types.ClinicalNote{
			{ID: "note-1", PatientID: "patient-123"},
		}

		// Setup mocks
		mockBlockchainClient.On("CheckAccess", userID, "clinical_notes", "search").Return(true, nil)
		mockClinicalService.On("SearchNotes", mock.Anything, userID).Return(notes, nil)
		mockClinicalService.On("ValidateDataIntegrityBatch", []string{"note-1"}, userID).Return(map[string]bool{}, assert.AnError)
		mockBlockchainClient.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, integrity, err := searchService.SearchWithDataIntegrityVerification(criteria, userID)

		// Assertions - should continue with search results even if integrity check fails
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotNil(t, integrity)
		assert.Len(t, result.Notes, 1)
		assert.Empty(t, integrity) // Empty due to integrity check failure

		mockClinicalService.AssertExpectations(t)
		mockBlockchainClient.AssertExpectations(t)
	})
}

func TestSearchService_SearchByTimeRange(t *testing.T) {
	searchService, mockClinicalService, mockBlockchainClient := setupTestSearchService()

	t.Run("successful time range search", func(t *testing.T) {
		userID := "user-123"
		userRole := "consulting_doctor"
		startDate := time.Now().AddDate(0, 0, -7) // 7 days ago
		endDate := time.Now()

		notes := []*types.ClinicalNote{
			{ID: "note-1", CreatedAt: time.Now().Add(-1 * time.Hour)},
			{ID: "note-2", CreatedAt: time.Now().Add(-2 * time.Hour)},
		}

		// Setup mocks
		mockBlockchainClient.On("CheckAccess", userID, "clinical_notes", "search").Return(true, nil)
		mockClinicalService.On("SearchNotes", mock.MatchedBy(func(c *types.SearchCriteria) bool {
			return c.CreatedAfter.Equal(startDate) && c.CreatedBefore.Equal(endDate)
		}), userID).Return(notes, nil)
		mockBlockchainClient.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := searchService.SearchByTimeRange(startDate, endDate, userRole, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Notes, 2)

		mockClinicalService.AssertExpectations(t)
		mockBlockchainClient.AssertExpectations(t)
	})
}

func TestSearchService_SearchByAuthor(t *testing.T) {
	searchService, mockClinicalService, mockBlockchainClient := setupTestSearchService()

	t.Run("successful author search", func(t *testing.T) {
		authorID := "doctor-123"
		userID := "user-123"

		notes := []*types.ClinicalNote{
			{ID: "note-1", AuthorID: authorID},
			{ID: "note-2", AuthorID: authorID},
		}

		// Setup mocks
		mockBlockchainClient.On("CheckAccess", userID, authorID, "read_authored_notes").Return(true, nil)
		mockClinicalService.On("SearchNotes", mock.MatchedBy(func(c *types.SearchCriteria) bool {
			return c.AuthorID == authorID
		}), userID).Return(notes, nil)
		mockBlockchainClient.On("LogActivity", mock.AnythingOfType("*types.AuditLogEntry")).Return(nil)

		// Execute test
		result, err := searchService.SearchByAuthor(authorID, userID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, result.Notes, 2)

		mockClinicalService.AssertExpectations(t)
		mockBlockchainClient.AssertExpectations(t)
	})

	t.Run("access denied for author search", func(t *testing.T) {
		authorID := "doctor-123"
		userID := "user-123"

		// Setup mock to deny access
		mockBlockchainClient.On("CheckAccess", userID, authorID, "read_authored_notes").Return(false, nil)

		// Execute test
		result, err := searchService.SearchByAuthor(authorID, userID)

		// Assertions
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "access denied")

		mockBlockchainClient.AssertExpectations(t)
	})
}

// Test helper functions
func TestSearchService_HelperFunctions(t *testing.T) {
	searchService, _, _ := setupTestSearchService()

	t.Run("test matchesKeywords", func(t *testing.T) {
		note := &types.ClinicalNote{
			Metadata: map[string]string{
				"keywords":    "cardiology consultation",
				"description": "Patient consultation for heart condition",
			},
		}

		// Test matching keywords
		assert.True(t, searchService.matchesKeywords(note, []string{"cardiology"}))
		assert.True(t, searchService.matchesKeywords(note, []string{"consultation"}))
		assert.True(t, searchService.matchesKeywords(note, []string{"heart"}))
		
		// Test non-matching keywords
		assert.False(t, searchService.matchesKeywords(note, []string{"neurology"}))
		
		// Test multiple keywords (all must match)
		assert.True(t, searchService.matchesKeywords(note, []string{"cardiology", "consultation"}))
		assert.False(t, searchService.matchesKeywords(note, []string{"cardiology", "neurology"}))
		
		// Test note without metadata
		noteWithoutMetadata := &types.ClinicalNote{}
		assert.False(t, searchService.matchesKeywords(noteWithoutMetadata, []string{"cardiology"}))
	})

	t.Run("test matchesTags", func(t *testing.T) {
		note := &types.ClinicalNote{
			Metadata: map[string]string{
				"tags": "urgent, follow-up, cardiology",
			},
		}

		// Test matching tags
		assert.True(t, searchService.matchesTags(note, []string{"urgent"}))
		assert.True(t, searchService.matchesTags(note, []string{"follow-up"}))
		assert.True(t, searchService.matchesTags(note, []string{"cardiology"}))
		
		// Test non-matching tags
		assert.False(t, searchService.matchesTags(note, []string{"routine"}))
		
		// Test multiple tags (all must match)
		assert.True(t, searchService.matchesTags(note, []string{"urgent", "cardiology"}))
		assert.False(t, searchService.matchesTags(note, []string{"urgent", "routine"}))
	})

	t.Run("test matchesDepartment", func(t *testing.T) {
		note := &types.ClinicalNote{
			Metadata: map[string]string{
				"department": "Cardiology",
			},
		}

		// Test matching department (case insensitive)
		assert.True(t, searchService.matchesDepartment(note, "cardiology"))
		assert.True(t, searchService.matchesDepartment(note, "Cardiology"))
		assert.True(t, searchService.matchesDepartment(note, "CARDIOLOGY"))
		
		// Test non-matching department
		assert.False(t, searchService.matchesDepartment(note, "neurology"))
	})

	t.Run("test applySorting", func(t *testing.T) {
		now := time.Now()
		notes := []*types.ClinicalNote{
			{ID: "note-1", CreatedAt: now.Add(-2 * time.Hour)},
			{ID: "note-2", CreatedAt: now.Add(-1 * time.Hour)},
			{ID: "note-3", CreatedAt: now.Add(-3 * time.Hour)},
		}

		// Test descending sort (default)
		sorted := searchService.applySorting(notes, "created_at", "desc")
		assert.Equal(t, "note-2", sorted[0].ID) // Most recent
		assert.Equal(t, "note-1", sorted[1].ID)
		assert.Equal(t, "note-3", sorted[2].ID) // Oldest

		// Test ascending sort
		sorted = searchService.applySorting(notes, "created_at", "asc")
		assert.Equal(t, "note-3", sorted[0].ID) // Oldest
		assert.Equal(t, "note-1", sorted[1].ID)
		assert.Equal(t, "note-2", sorted[2].ID) // Most recent
	})

	t.Run("test applyPagination", func(t *testing.T) {
		notes := []*types.ClinicalNote{
			{ID: "note-1"},
			{ID: "note-2"},
			{ID: "note-3"},
			{ID: "note-4"},
			{ID: "note-5"},
		}

		// Test first page
		paginated, hasMore := searchService.applyPagination(notes, 2, 0)
		assert.Len(t, paginated, 2)
		assert.Equal(t, "note-1", paginated[0].ID)
		assert.Equal(t, "note-2", paginated[1].ID)
		assert.True(t, hasMore)

		// Test second page
		paginated, hasMore = searchService.applyPagination(notes, 2, 2)
		assert.Len(t, paginated, 2)
		assert.Equal(t, "note-3", paginated[0].ID)
		assert.Equal(t, "note-4", paginated[1].ID)
		assert.True(t, hasMore)

		// Test last page
		paginated, hasMore = searchService.applyPagination(notes, 2, 4)
		assert.Len(t, paginated, 1)
		assert.Equal(t, "note-5", paginated[0].ID)
		assert.False(t, hasMore)

		// Test beyond available data
		paginated, hasMore = searchService.applyPagination(notes, 2, 10)
		assert.Len(t, paginated, 0)
		assert.False(t, hasMore)
	})

	t.Run("test getMostCommonKey", func(t *testing.T) {
		counts := map[string]int{
			"progress_note":     5,
			"consultation_note": 3,
			"discharge_summary": 8,
		}

		mostCommon := searchService.getMostCommonKey(counts)
		assert.Equal(t, "discharge_summary", mostCommon)

		// Test empty map
		empty := map[string]int{}
		mostCommon = searchService.getMostCommonKey(empty)
		assert.Equal(t, "", mostCommon)
	})

	t.Run("test removeDuplicates", func(t *testing.T) {
		slice := []string{"a", "b", "a", "c", "b", "d"}
		unique := searchService.removeDuplicates(slice)
		
		assert.Len(t, unique, 4)
		assert.Contains(t, unique, "a")
		assert.Contains(t, unique, "b")
		assert.Contains(t, unique, "c")
		assert.Contains(t, unique, "d")
	})
}