package clinical

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// SearchService provides advanced search and retrieval capabilities
type SearchService struct {
	clinicalService  *ClinicalNotesService
	blockchainClient *BlockchainClient
	logger           *logger.Logger
}

// NewSearchService creates a new search service
func NewSearchService(clinicalService *ClinicalNotesService, blockchainClient *BlockchainClient, logger *logger.Logger) *SearchService {
	return &SearchService{
		clinicalService:  clinicalService,
		blockchainClient: blockchainClient,
		logger:           logger,
	}
}

// AdvancedSearchCriteria represents advanced search parameters
type AdvancedSearchCriteria struct {
	// Basic filters
	PatientID     string    `json:"patient_id,omitempty"`
	AuthorID      string    `json:"author_id,omitempty"`
	NoteType      string    `json:"note_type,omitempty"`
	CreatedAfter  time.Time `json:"created_after,omitempty"`
	CreatedBefore time.Time `json:"created_before,omitempty"`
	
	// Advanced filters
	Keywords      []string  `json:"keywords,omitempty"`
	Tags          []string  `json:"tags,omitempty"`
	Department    string    `json:"department,omitempty"`
	Specialty     string    `json:"specialty,omitempty"`
	Priority      string    `json:"priority,omitempty"`
	
	// Content filters (metadata-based since content is encrypted)
	HasAttachments bool     `json:"has_attachments,omitempty"`
	MinLength      int      `json:"min_length,omitempty"`
	MaxLength      int      `json:"max_length,omitempty"`
	
	// Pagination and sorting
	Limit         int      `json:"limit,omitempty"`
	Offset        int      `json:"offset,omitempty"`
	SortBy        string   `json:"sort_by,omitempty"`
	SortOrder     string   `json:"sort_order,omitempty"`
	
	// Role-based filtering
	UserRole      string   `json:"user_role,omitempty"`
	AccessLevel   string   `json:"access_level,omitempty"`
}

// SearchResult represents search results with metadata
type SearchResult struct {
	Notes       []*types.ClinicalNote `json:"notes"`
	TotalCount  int                   `json:"total_count"`
	FilteredBy  []string              `json:"filtered_by"`
	SearchTime  time.Duration         `json:"search_time"`
	HasMore     bool                  `json:"has_more"`
}

// PatientDataAggregation represents aggregated patient data
type PatientDataAggregation struct {
	PatientID       string                 `json:"patient_id"`
	TotalNotes      int                    `json:"total_notes"`
	NotesByType     map[string]int         `json:"notes_by_type"`
	NotesByAuthor   map[string]int         `json:"notes_by_author"`
	DateRange       DateRange              `json:"date_range"`
	RecentActivity  []*types.ClinicalNote  `json:"recent_activity"`
	Summary         map[string]interface{} `json:"summary"`
}

// DateRange represents a date range
type DateRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// AdvancedSearch performs advanced search with role-based filtering
func (s *SearchService) AdvancedSearch(criteria *AdvancedSearchCriteria, userID string) (*SearchResult, error) {
	startTime := time.Now()
	s.logger.Info("Performing advanced search", "userID", userID, "criteria", criteria)

	// Validate user access for search
	allowed, err := s.blockchainClient.CheckAccess(userID, "clinical_notes", "search")
	if err != nil {
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for advanced search", "userID", userID)
		return nil, fmt.Errorf("access denied: insufficient permissions for advanced search")
	}

	// Convert to basic search criteria
	basicCriteria := s.convertToBasicCriteria(criteria)

	// Perform initial search
	notes, err := s.clinicalService.SearchNotes(basicCriteria, userID)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	// Apply advanced filters
	filteredNotes, appliedFilters := s.applyAdvancedFilters(notes, criteria, userID)

	// Apply sorting
	sortedNotes := s.applySorting(filteredNotes, criteria.SortBy, criteria.SortOrder)

	// Apply pagination
	paginatedNotes, hasMore := s.applyPagination(sortedNotes, criteria.Limit, criteria.Offset)

	// Create result
	result := &SearchResult{
		Notes:       paginatedNotes,
		TotalCount:  len(filteredNotes),
		FilteredBy:  appliedFilters,
		SearchTime:  time.Since(startTime),
		HasMore:     hasMore,
	}

	// Log search activity
	s.logSearchActivity(userID, criteria, result)

	s.logger.Info("Advanced search completed", "userID", userID, "resultsCount", len(paginatedNotes), "totalCount", result.TotalCount)
	return result, nil
}

// SearchByPatientWithAggregation searches notes for a patient with data aggregation
func (s *SearchService) SearchByPatientWithAggregation(patientID, userID string) (*PatientDataAggregation, error) {
	s.logger.Info("Searching patient data with aggregation", "patientID", patientID, "userID", userID)

	// Validate access to patient data
	allowed, err := s.blockchainClient.CheckAccess(userID, patientID, "read_aggregated")
	if err != nil {
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for patient data aggregation", "userID", userID, "patientID", patientID)
		return nil, fmt.Errorf("access denied: insufficient permissions for patient data aggregation")
	}

	// Get all notes for patient
	notes, err := s.clinicalService.GetPatientNotes(patientID, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get patient notes: %w", err)
	}

	// Aggregate data
	aggregation := s.aggregatePatientData(patientID, notes)

	// Log aggregation activity
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "aggregate_patient_data",
		ResourceID:   patientID,
		ResourceType: "patient",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"total_notes": aggregation.TotalNotes,
			"note_types":  len(aggregation.NotesByType),
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log aggregation activity", "error", err)
	}

	return aggregation, nil
}

// SearchWithDataIntegrityVerification searches notes and verifies data integrity
func (s *SearchService) SearchWithDataIntegrityVerification(criteria *AdvancedSearchCriteria, userID string) (*SearchResult, map[string]bool, error) {
	s.logger.Info("Searching with data integrity verification", "userID", userID)

	// Perform search
	result, err := s.AdvancedSearch(criteria, userID)
	if err != nil {
		return nil, nil, fmt.Errorf("search failed: %w", err)
	}

	// Verify integrity for all found notes
	noteIDs := make([]string, len(result.Notes))
	for i, note := range result.Notes {
		noteIDs[i] = note.ID
	}

	integrityResults, err := s.clinicalService.ValidateDataIntegrityBatch(noteIDs, userID)
	if err != nil {
		s.logger.Error("Failed to verify data integrity", "error", err)
		// Continue with search results even if integrity check fails
		integrityResults = make(map[string]bool)
	}

	return result, integrityResults, nil
}

// SearchByTimeRange searches notes within a specific time range with role-based filtering
func (s *SearchService) SearchByTimeRange(startDate, endDate time.Time, userRole, userID string) (*SearchResult, error) {
	s.logger.Info("Searching by time range", "startDate", startDate, "endDate", endDate, "userRole", userRole, "userID", userID)

	criteria := &AdvancedSearchCriteria{
		CreatedAfter:  startDate,
		CreatedBefore: endDate,
		UserRole:      userRole,
		SortBy:        "created_at",
		SortOrder:     "desc",
	}

	return s.AdvancedSearch(criteria, userID)
}

// SearchByAuthor searches notes by author with access control
func (s *SearchService) SearchByAuthor(authorID, userID string) (*SearchResult, error) {
	s.logger.Info("Searching by author", "authorID", authorID, "userID", userID)

	// Check if user can access notes by this author
	allowed, err := s.blockchainClient.CheckAccess(userID, authorID, "read_authored_notes")
	if err != nil {
		return nil, fmt.Errorf("access validation failed: %w", err)
	}

	if !allowed {
		s.logger.Warn("Access denied for author notes search", "userID", userID, "authorID", authorID)
		return nil, fmt.Errorf("access denied: insufficient permissions to search notes by author")
	}

	criteria := &AdvancedSearchCriteria{
		AuthorID:  authorID,
		SortBy:    "created_at",
		SortOrder: "desc",
	}

	return s.AdvancedSearch(criteria, userID)
}

// convertToBasicCriteria converts advanced criteria to basic search criteria
func (s *SearchService) convertToBasicCriteria(criteria *AdvancedSearchCriteria) *types.SearchCriteria {
	return &types.SearchCriteria{
		PatientID: criteria.PatientID,
		AuthorID:  criteria.AuthorID,
		NoteType:  criteria.NoteType,
		FromDate:  criteria.CreatedAfter,
		ToDate:    criteria.CreatedBefore,
		Limit:     criteria.Limit,
		Offset:    criteria.Offset,
	}
}

// applyAdvancedFilters applies advanced filtering logic
func (s *SearchService) applyAdvancedFilters(notes []*types.ClinicalNote, criteria *AdvancedSearchCriteria, userID string) ([]*types.ClinicalNote, []string) {
	var filtered []*types.ClinicalNote
	var appliedFilters []string

	for _, note := range notes {
		include := true

		// Apply keyword filtering (metadata-based since content is encrypted)
		if len(criteria.Keywords) > 0 && include {
			if !s.matchesKeywords(note, criteria.Keywords) {
				include = false
			} else {
				appliedFilters = append(appliedFilters, "keywords")
			}
		}

		// Apply tag filtering
		if len(criteria.Tags) > 0 && include {
			if !s.matchesTags(note, criteria.Tags) {
				include = false
			} else {
				appliedFilters = append(appliedFilters, "tags")
			}
		}

		// Apply department filtering
		if criteria.Department != "" && include {
			if !s.matchesDepartment(note, criteria.Department) {
				include = false
			} else {
				appliedFilters = append(appliedFilters, "department")
			}
		}

		// Apply role-based filtering
		if criteria.UserRole != "" && include {
			if !s.matchesUserRole(note, criteria.UserRole, userID) {
				include = false
			} else {
				appliedFilters = append(appliedFilters, "user_role")
			}
		}

		if include {
			filtered = append(filtered, note)
		}
	}

	// Remove duplicate filter names
	appliedFilters = s.removeDuplicates(appliedFilters)

	return filtered, appliedFilters
}

// matchesKeywords checks if note metadata matches keywords
func (s *SearchService) matchesKeywords(note *types.ClinicalNote, keywords []string) bool {
	if note.Metadata == nil {
		return false
	}

	// Search in metadata values
	for _, keyword := range keywords {
		found := false
		for _, value := range note.Metadata {
			if strings.Contains(strings.ToLower(value), strings.ToLower(keyword)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// matchesTags checks if note has specified tags
func (s *SearchService) matchesTags(note *types.ClinicalNote, tags []string) bool {
	if note.Metadata == nil {
		return false
	}

	noteTags, exists := note.Metadata["tags"]
	if !exists {
		return false
	}

	noteTagList := strings.Split(noteTags, ",")
	for _, tag := range tags {
		found := false
		for _, noteTag := range noteTagList {
			if strings.TrimSpace(strings.ToLower(noteTag)) == strings.ToLower(tag) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// matchesDepartment checks if note belongs to specified department
func (s *SearchService) matchesDepartment(note *types.ClinicalNote, department string) bool {
	if note.Metadata == nil {
		return false
	}

	noteDepartment, exists := note.Metadata["department"]
	if !exists {
		return false
	}

	return strings.EqualFold(noteDepartment, department)
}

// matchesUserRole checks if user role allows access to note
func (s *SearchService) matchesUserRole(note *types.ClinicalNote, userRole, userID string) bool {
	// Implement role-based filtering logic
	// This would typically check against access policies
	
	// For now, implement basic role-based filtering
	switch userRole {
	case "patient":
		// Patients can only see their own notes
		return note.Metadata != nil && note.Metadata["patient_id"] == userID
	case "mbbs_student":
		// Students have limited access
		return note.Metadata != nil && note.Metadata["access_level"] != "restricted"
	case "consulting_doctor":
		// Doctors have broader access
		return true
	default:
		return true
	}
}

// applySorting sorts notes based on criteria
func (s *SearchService) applySorting(notes []*types.ClinicalNote, sortBy, sortOrder string) []*types.ClinicalNote {
	if sortBy == "" {
		sortBy = "created_at"
	}
	if sortOrder == "" {
		sortOrder = "desc"
	}

	// Create a copy to avoid modifying original slice
	sorted := make([]*types.ClinicalNote, len(notes))
	copy(sorted, notes)

	// Simple sorting implementation
	// In production, use a more sophisticated sorting library
	if sortBy == "created_at" {
		if sortOrder == "desc" {
			// Sort by creation date descending
			for i := 0; i < len(sorted)-1; i++ {
				for j := i + 1; j < len(sorted); j++ {
					if sorted[i].CreatedAt.Before(sorted[j].CreatedAt) {
						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
		} else {
			// Sort by creation date ascending
			for i := 0; i < len(sorted)-1; i++ {
				for j := i + 1; j < len(sorted); j++ {
					if sorted[i].CreatedAt.After(sorted[j].CreatedAt) {
						sorted[i], sorted[j] = sorted[j], sorted[i]
					}
				}
			}
		}
	}

	return sorted
}

// applyPagination applies pagination to results
func (s *SearchService) applyPagination(notes []*types.ClinicalNote, limit, offset int) ([]*types.ClinicalNote, bool) {
	if limit <= 0 {
		limit = 50 // Default limit
	}

	if offset < 0 {
		offset = 0
	}

	total := len(notes)
	start := offset
	end := offset + limit

	if start >= total {
		return []*types.ClinicalNote{}, false
	}

	if end > total {
		end = total
	}

	hasMore := end < total
	return notes[start:end], hasMore
}

// aggregatePatientData aggregates patient data from notes
func (s *SearchService) aggregatePatientData(patientID string, notes []*types.ClinicalNote) *PatientDataAggregation {
	aggregation := &PatientDataAggregation{
		PatientID:     patientID,
		TotalNotes:    len(notes),
		NotesByType:   make(map[string]int),
		NotesByAuthor: make(map[string]int),
		Summary:       make(map[string]interface{}),
	}

	if len(notes) == 0 {
		return aggregation
	}

	// Find date range
	earliest := notes[0].CreatedAt
	latest := notes[0].CreatedAt

	// Aggregate data
	for _, note := range notes {
		// Count by type
		aggregation.NotesByType[note.NoteType]++

		// Count by author
		aggregation.NotesByAuthor[note.AuthorID]++

		// Update date range
		if note.CreatedAt.Before(earliest) {
			earliest = note.CreatedAt
		}
		if note.CreatedAt.After(latest) {
			latest = note.CreatedAt
		}
	}

	aggregation.DateRange = DateRange{
		Start: earliest,
		End:   latest,
	}

	// Get recent activity (last 10 notes)
	recentCount := 10
	if len(notes) < recentCount {
		recentCount = len(notes)
	}

	// Sort notes by creation date (most recent first)
	sortedNotes := s.applySorting(notes, "created_at", "desc")
	aggregation.RecentActivity = sortedNotes[:recentCount]

	// Generate summary
	aggregation.Summary = map[string]interface{}{
		"most_common_note_type": s.getMostCommonKey(aggregation.NotesByType),
		"most_active_author":    s.getMostCommonKey(aggregation.NotesByAuthor),
		"notes_per_day":         float64(aggregation.TotalNotes) / aggregation.DateRange.End.Sub(aggregation.DateRange.Start).Hours() * 24,
		"unique_authors":        len(aggregation.NotesByAuthor),
		"unique_note_types":     len(aggregation.NotesByType),
	}

	return aggregation
}

// getMostCommonKey returns the key with the highest value in a map
func (s *SearchService) getMostCommonKey(m map[string]int) string {
	maxKey := ""
	maxValue := 0

	for key, value := range m {
		if value > maxValue {
			maxValue = value
			maxKey = key
		}
	}

	return maxKey
}

// removeDuplicates removes duplicate strings from slice
func (s *SearchService) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// logSearchActivity logs search activity for audit
func (s *SearchService) logSearchActivity(userID string, criteria *AdvancedSearchCriteria, result *SearchResult) {
	auditEntry := &types.AuditLogEntry{
		UserID:       userID,
		Action:       "advanced_search",
		ResourceID:   "clinical_notes",
		ResourceType: "clinical_note",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"search_criteria": criteria,
			"results_count":   len(result.Notes),
			"total_count":     result.TotalCount,
			"search_time_ms":  result.SearchTime.Milliseconds(),
			"filters_applied": result.FilteredBy,
		},
	}

	if err := s.blockchainClient.LogActivity(auditEntry); err != nil {
		s.logger.Error("Failed to log search activity", "error", err)
	}
}