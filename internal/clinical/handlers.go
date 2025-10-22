package clinical

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Handlers handles HTTP requests for clinical notes service
type Handlers struct {
	service *ClinicalNotesService
	logger  logger.Logger
}

// NewHandlers creates new HTTP handlers
func NewHandlers(service *ClinicalNotesService, logger logger.Logger) *Handlers {
	return &Handlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers HTTP routes
func (h *Handlers) RegisterRoutes(router *mux.Router) {
	// Clinical notes routes
	router.HandleFunc("/notes", h.CreateNote).Methods("POST")
	router.HandleFunc("/notes/{noteID}", h.GetNote).Methods("GET")
	router.HandleFunc("/notes/{noteID}", h.UpdateNote).Methods("PUT")
	router.HandleFunc("/notes/{noteID}", h.DeleteNote).Methods("DELETE")
	router.HandleFunc("/notes/search", h.SearchNotes).Methods("GET")
	router.HandleFunc("/notes/{noteID}/integrity", h.VerifyIntegrity).Methods("GET")

	// Patient routes
	router.HandleFunc("/patients", h.CreatePatient).Methods("POST")
	router.HandleFunc("/patients/{patientID}", h.GetPatient).Methods("GET")
	router.HandleFunc("/patients/{patientID}", h.UpdatePatient).Methods("PUT")
	router.HandleFunc("/patients/{patientID}/notes", h.GetPatientNotes).Methods("GET")
	router.HandleFunc("/patients/search", h.SearchPatients).Methods("GET")

	// Health check
	router.HandleFunc("/health", h.HealthCheck).Methods("GET")
}

// CreateNote handles clinical note creation
func (h *Handlers) CreateNote(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	var note types.ClinicalNote
	if err := json.NewDecoder(r.Body).Decode(&note); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	// Validate required fields
	if note.PatientID == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Patient ID is required")
		return
	}

	if note.Content == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Note content is required")
		return
	}

	if note.NoteType == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Note type is required")
		return
	}

	// Get RBAC attributes from headers
	rbacAttrs := h.getRBACAttributes(r)
	
	// Add RBAC attributes to note context
	note.Metadata = make(map[string]string)
	for key, value := range rbacAttrs {
		note.Metadata["rbac_"+key] = value
	}

	createdNote, err := h.service.CreateNote(&note, userID)
	if err != nil {
		h.logger.Error("Failed to create note", "error", err, "userID", userID)
		
		// Handle RBAC-specific errors
		if rbacErr, ok := err.(*rbac.RBACError); ok {
			statusCode := h.getRBACErrorStatusCode(rbacErr.Type)
			h.writeError(w, statusCode, string(rbacErr.Type), rbacErr.Message)
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "creation_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusCreated, createdNote)
}

// GetNote handles clinical note retrieval
func (h *Handlers) GetNote(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	noteID := vars["noteID"]

	note, err := h.service.GetNote(noteID, userID)
	if err != nil {
		h.logger.Error("Failed to get note", "error", err, "noteID", noteID, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to read note" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "retrieval_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, note)
}

// UpdateNote handles clinical note updates
func (h *Handlers) UpdateNote(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	noteID := vars["noteID"]

	var updates types.ClinicalNoteUpdates
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if err := h.service.UpdateNote(noteID, &updates, userID); err != nil {
		h.logger.Error("Failed to update note", "error", err, "noteID", noteID, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to update note" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Note updated successfully"})
}

// DeleteNote handles clinical note deletion
func (h *Handlers) DeleteNote(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	noteID := vars["noteID"]

	if err := h.service.DeleteNote(noteID, userID); err != nil {
		h.logger.Error("Failed to delete note", "error", err, "noteID", noteID, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to delete note" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "deletion_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Note deleted successfully"})
}

// SearchNotes handles clinical note search
func (h *Handlers) SearchNotes(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	// Parse query parameters
	criteria := &types.SearchCriteria{
		PatientID: r.URL.Query().Get("patient_id"),
		AuthorID:  r.URL.Query().Get("author_id"),
		NoteType:  r.URL.Query().Get("note_type"),
	}

	// Parse date filters
	if fromDate := r.URL.Query().Get("from_date"); fromDate != "" {
		if parsed, err := time.Parse("2006-01-02", fromDate); err == nil {
			criteria.FromDate = parsed
		}
	}

	if toDate := r.URL.Query().Get("to_date"); toDate != "" {
		if parsed, err := time.Parse("2006-01-02", toDate); err == nil {
			criteria.ToDate = parsed
		}
	}

	// Parse pagination
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if parsed, err := strconv.Atoi(limit); err == nil && parsed > 0 {
			criteria.Limit = parsed
		}
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		if parsed, err := strconv.Atoi(offset); err == nil && parsed >= 0 {
			criteria.Offset = parsed
		}
	}

	notes, err := h.service.SearchNotes(criteria, userID)
	if err != nil {
		h.logger.Error("Failed to search notes", "error", err, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to search patient notes" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "search_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"notes": notes,
		"count": len(notes),
	})
}

// VerifyIntegrity handles data integrity verification
func (h *Handlers) VerifyIntegrity(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	noteID := vars["noteID"]

	if err := h.service.VerifyDataIntegrity(noteID); err != nil {
		h.logger.Error("Data integrity verification failed", "error", err, "noteID", noteID)
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"valid":  false,
			"reason": err.Error(),
		})
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"valid": true,
	})
}

// CreatePatient handles patient creation
func (h *Handlers) CreatePatient(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	var patient types.Patient
	if err := json.NewDecoder(r.Body).Decode(&patient); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	// Validate required fields
	if patient.MRN == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "MRN is required")
		return
	}

	if patient.Demographics == nil {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Demographics are required")
		return
	}

	createdPatient, err := h.service.CreatePatient(&patient, userID)
	if err != nil {
		h.logger.Error("Failed to create patient", "error", err, "userID", userID)
		h.writeError(w, http.StatusInternalServerError, "creation_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusCreated, createdPatient)
}

// GetPatient handles patient retrieval
func (h *Handlers) GetPatient(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	patientID := vars["patientID"]

	patient, err := h.service.GetPatient(patientID, userID)
	if err != nil {
		h.logger.Error("Failed to get patient", "error", err, "patientID", patientID, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to read patient" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "retrieval_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, patient)
}

// UpdatePatient handles patient updates
func (h *Handlers) UpdatePatient(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	patientID := vars["patientID"]

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if err := h.service.UpdatePatient(patientID, updates, userID); err != nil {
		h.logger.Error("Failed to update patient", "error", err, "patientID", patientID, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to update patient" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Patient updated successfully"})
}

// GetPatientNotes handles patient notes retrieval
func (h *Handlers) GetPatientNotes(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	patientID := vars["patientID"]

	notes, err := h.service.GetPatientNotes(patientID, userID)
	if err != nil {
		h.logger.Error("Failed to get patient notes", "error", err, "patientID", patientID, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to read patient notes" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "retrieval_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"notes": notes,
		"count": len(notes),
	})
}

// SearchPatients handles patient search
func (h *Handlers) SearchPatients(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	// Parse query parameters
	criteria := make(map[string]interface{})
	
	if mrn := r.URL.Query().Get("mrn"); mrn != "" {
		criteria["mrn"] = mrn
	}
	
	if firstName := r.URL.Query().Get("first_name"); firstName != "" {
		criteria["first_name"] = firstName
	}
	
	if lastName := r.URL.Query().Get("last_name"); lastName != "" {
		criteria["last_name"] = lastName
	}

	// Parse pagination
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if parsed, err := strconv.Atoi(limit); err == nil && parsed > 0 {
			criteria["limit"] = parsed
		}
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		if parsed, err := strconv.Atoi(offset); err == nil && parsed >= 0 {
			criteria["offset"] = parsed
		}
	}

	patients, err := h.service.SearchPatients(criteria, userID)
	if err != nil {
		h.logger.Error("Failed to search patients", "error", err, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to search patients" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "search_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"patients": patients,
		"count":    len(patients),
	})
}

// HealthCheck handles health check requests
func (h *Handlers) HealthCheck(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"service":   "clinical-notes-service",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// getUserID extracts user ID from request context or headers
func (h *Handlers) getUserID(r *http.Request) string {
	// Check RBAC headers first (set by API Gateway RBAC middleware)
	if userID := r.Header.Get("X-RBAC-User-ID"); userID != "" {
		return userID
	}

	// Check the X-User-ID header
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}

	// Check Authorization header for JWT token
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		// In production, decode JWT token and extract user ID
		// For now, return a mock user ID
		return "mock_user_id"
	}

	return ""
}

// getRBACAttributes extracts RBAC attributes from request headers
func (h *Handlers) getRBACAttributes(r *http.Request) map[string]string {
	attributes := make(map[string]string)

	// Extract RBAC information set by API Gateway
	if role := r.Header.Get("X-RBAC-Role"); role != "" {
		attributes["role"] = role
	}

	if scope := r.Header.Get("X-RBAC-Scope"); scope != "" {
		attributes["scope"] = scope
	}

	if conditions := r.Header.Get("X-RBAC-Conditions"); conditions != "" {
		attributes["conditions"] = conditions
	}

	if rbacAttrs := r.Header.Get("X-RBAC-Attributes"); rbacAttrs != "" {
		attributes["rbac_attributes"] = rbacAttrs
	}

	return attributes
}

// getRBACErrorStatusCode maps RBAC error types to HTTP status codes
func (h *Handlers) getRBACErrorStatusCode(errorType rbac.RBACErrorType) int {
	switch errorType {
	case rbac.ErrorTypeInsufficientPrivileges:
		return http.StatusForbidden
	case rbac.ErrorTypeInvalidRole:
		return http.StatusUnauthorized
	case rbac.ErrorTypeAttributeValidation:
		return http.StatusBadRequest
	case rbac.ErrorTypeSupervisionRequired:
		return http.StatusPreconditionRequired
	case rbac.ErrorTypeCertificateInvalid:
		return http.StatusUnauthorized
	case rbac.ErrorTypePolicyViolation:
		return http.StatusForbidden
	case rbac.ErrorTypeTimeRestriction:
		return http.StatusForbidden
	case rbac.ErrorTypeEmergencyOverride:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// writeJSON writes JSON response
func (h *Handlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes error response
func (h *Handlers) writeError(w http.ResponseWriter, status int, code, message string) {
	errorResponse := map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
		"timestamp": time.Now().Format(time.RFC3339),
	}
	
	h.writeJSON(w, status, errorResponse)
}

// GetAuditTrail handles audit trail retrieval
func (h *Handlers) GetAuditTrail(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	resourceID := vars["resourceID"]

	entries, err := h.service.GetAuditTrail(resourceID, userID)
	if err != nil {
		h.logger.Error("Failed to get audit trail", "error", err, "resourceID", resourceID, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to read audit trail" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "retrieval_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"audit_entries": entries,
		"count":         len(entries),
	})
}

// CreateAccessPolicy handles access policy creation
func (h *Handlers) CreateAccessPolicy(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	var policy types.AccessPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	// Validate required fields
	if policy.ID == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Policy ID is required")
		return
	}

	if policy.ResourceType == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Resource type is required")
		return
	}

	if policy.UserRole == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "User role is required")
		return
	}

	if len(policy.Actions) == 0 {
		h.writeError(w, http.StatusBadRequest, "validation_error", "At least one action is required")
		return
	}

	if err := h.service.CreateAccessPolicy(&policy, userID); err != nil {
		h.logger.Error("Failed to create access policy", "error", err, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to create access policy" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "creation_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusCreated, map[string]string{"message": "Access policy created successfully"})
}

// GetComplianceReport handles compliance report generation
func (h *Handlers) GetComplianceReport(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	// Parse query parameters
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	resourceType := r.URL.Query().Get("resource_type")

	if startDateStr == "" || endDateStr == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "start_date and end_date are required")
		return
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Invalid start_date format (YYYY-MM-DD)")
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Invalid end_date format (YYYY-MM-DD)")
		return
	}

	if resourceType == "" {
		resourceType = "clinical_note" // Default resource type
	}

	report, err := h.service.GetComplianceReport(startDate, endDate, resourceType, userID)
	if err != nil {
		h.logger.Error("Failed to generate compliance report", "error", err, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to generate compliance report" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "report_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, report)
}

// CreateReEncryptionToken handles PRE token creation
func (h *Handlers) CreateReEncryptionToken(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	var request struct {
		FromUserID string `json:"from_user_id"`
		ToUserID   string `json:"to_user_id"`
		ResourceID string `json:"resource_id"`
		ExpiresIn  int    `json:"expires_in"` // Duration in hours
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	// Validate required fields
	if request.FromUserID == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "from_user_id is required")
		return
	}

	if request.ToUserID == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "to_user_id is required")
		return
	}

	if request.ResourceID == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "resource_id is required")
		return
	}

	if request.ExpiresIn <= 0 {
		request.ExpiresIn = 24 // Default to 24 hours
	}

	expiresIn := time.Duration(request.ExpiresIn) * time.Hour

	token, err := h.service.CreateReEncryptionToken(request.FromUserID, request.ToUserID, request.ResourceID, expiresIn, userID)
	if err != nil {
		h.logger.Error("Failed to create re-encryption token", "error", err, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to create re-encryption token" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "creation_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusCreated, token)
}

// RevokeAccessToken handles access token revocation
func (h *Handlers) RevokeAccessToken(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	tokenID := vars["tokenID"]

	if err := h.service.RevokeAccessToken(tokenID, userID); err != nil {
		h.logger.Error("Failed to revoke access token", "error", err, "tokenID", tokenID, "userID", userID)
		
		if err.Error() == "access denied: insufficient permissions to revoke access token" {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "revocation_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Access token revoked successfully"})
}

// ValidateDataIntegrityBatch handles batch integrity validation
func (h *Handlers) ValidateDataIntegrityBatch(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	var request struct {
		NoteIDs []string `json:"note_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	if len(request.NoteIDs) == 0 {
		h.writeError(w, http.StatusBadRequest, "validation_error", "note_ids array cannot be empty")
		return
	}

	if len(request.NoteIDs) > 100 {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Maximum 100 notes can be validated at once")
		return
	}

	results, err := h.service.ValidateDataIntegrityBatch(request.NoteIDs, userID)
	if err != nil {
		h.logger.Error("Failed to validate data integrity batch", "error", err, "userID", userID)
		h.writeError(w, http.StatusInternalServerError, "validation_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
		"summary": h.generateIntegritySummary(results),
	})
}

// generateIntegritySummary creates a summary of integrity validation results
func (h *Handlers) generateIntegritySummary(results map[string]bool) map[string]interface{} {
	total := len(results)
	valid := 0
	invalid := 0

	for _, isValid := range results {
		if isValid {
			valid++
		} else {
			invalid++
		}
	}

	return map[string]interface{}{
		"total":   total,
		"valid":   valid,
		"invalid": invalid,
		"success_rate": float64(valid) / float64(total) * 100,
	}
}

// Update RegisterRoutes to include new endpoints
func (h *Handlers) RegisterRoutesEnhanced(router *mux.Router) {
	// Call original RegisterRoutes
	h.RegisterRoutes(router)

	// Add new blockchain integration routes
	router.HandleFunc("/audit/{resourceID}", h.GetAuditTrail).Methods("GET")
	router.HandleFunc("/policies", h.CreateAccessPolicy).Methods("POST")
	router.HandleFunc("/compliance/report", h.GetComplianceReport).Methods("GET")
	router.HandleFunc("/tokens/re-encryption", h.CreateReEncryptionToken).Methods("POST")
	router.HandleFunc("/tokens/{tokenID}/revoke", h.RevokeAccessToken).Methods("POST")
	router.HandleFunc("/integrity/batch", h.ValidateDataIntegrityBatch).Methods("POST")
}

// AdvancedSearch handles advanced search requests
func (h *Handlers) AdvancedSearch(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	// Parse search criteria from request body
	var criteria AdvancedSearchCriteria
	if err := json.NewDecoder(r.Body).Decode(&criteria); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	// Create search service
	searchService := NewSearchService(h.service, h.service.blockchainClient.(*BlockchainClient), h.logger)

	// Perform search
	result, err := searchService.AdvancedSearch(&criteria, userID)
	if err != nil {
		h.logger.Error("Advanced search failed", "error", err, "userID", userID)
		
		if strings.Contains(err.Error(), "access denied") {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "search_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// SearchByPatientWithAggregation handles patient data aggregation requests
func (h *Handlers) SearchByPatientWithAggregation(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	patientID := vars["patientID"]

	// Create search service
	searchService := NewSearchService(h.service, h.service.blockchainClient.(*BlockchainClient), h.logger)

	// Get aggregated data
	aggregation, err := searchService.SearchByPatientWithAggregation(patientID, userID)
	if err != nil {
		h.logger.Error("Patient data aggregation failed", "error", err, "patientID", patientID, "userID", userID)
		
		if strings.Contains(err.Error(), "access denied") {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "aggregation_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, aggregation)
}

// SearchWithIntegrityVerification handles search with data integrity verification
func (h *Handlers) SearchWithIntegrityVerification(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	// Parse search criteria
	var criteria AdvancedSearchCriteria
	if err := json.NewDecoder(r.Body).Decode(&criteria); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON payload")
		return
	}

	// Create search service
	searchService := NewSearchService(h.service, h.service.blockchainClient.(*BlockchainClient), h.logger)

	// Perform search with integrity verification
	result, integrityResults, err := searchService.SearchWithDataIntegrityVerification(&criteria, userID)
	if err != nil {
		h.logger.Error("Search with integrity verification failed", "error", err, "userID", userID)
		
		if strings.Contains(err.Error(), "access denied") {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "search_failed", err.Error())
		return
	}

	response := map[string]interface{}{
		"search_result":      result,
		"integrity_results":  integrityResults,
		"integrity_summary":  h.generateIntegritySummary(integrityResults),
	}

	h.writeJSON(w, http.StatusOK, response)
}

// SearchByTimeRange handles time range search requests
func (h *Handlers) SearchByTimeRange(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	// Parse query parameters
	startDateStr := r.URL.Query().Get("start_date")
	endDateStr := r.URL.Query().Get("end_date")
	userRole := r.URL.Query().Get("user_role")

	if startDateStr == "" || endDateStr == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "start_date and end_date are required")
		return
	}

	startDate, err := time.Parse("2006-01-02", startDateStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Invalid start_date format (YYYY-MM-DD)")
		return
	}

	endDate, err := time.Parse("2006-01-02", endDateStr)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Invalid end_date format (YYYY-MM-DD)")
		return
	}

	// Create search service
	searchService := NewSearchService(h.service, h.service.blockchainClient.(*BlockchainClient), h.logger)

	// Perform time range search
	result, err := searchService.SearchByTimeRange(startDate, endDate, userRole, userID)
	if err != nil {
		h.logger.Error("Time range search failed", "error", err, "userID", userID)
		
		if strings.Contains(err.Error(), "access denied") {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "search_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// SearchByAuthor handles author-based search requests
func (h *Handlers) SearchByAuthor(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	vars := mux.Vars(r)
	authorID := vars["authorID"]

	// Create search service
	searchService := NewSearchService(h.service, h.service.blockchainClient.(*BlockchainClient), h.logger)

	// Perform author search
	result, err := searchService.SearchByAuthor(authorID, userID)
	if err != nil {
		h.logger.Error("Author search failed", "error", err, "authorID", authorID, "userID", userID)
		
		if strings.Contains(err.Error(), "access denied") {
			h.writeError(w, http.StatusForbidden, "access_denied", err.Error())
			return
		}
		
		h.writeError(w, http.StatusInternalServerError, "search_failed", err.Error())
		return
	}

	h.writeJSON(w, http.StatusOK, result)
}

// GetSearchSuggestions handles search suggestion requests
func (h *Handlers) GetSearchSuggestions(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		h.writeError(w, http.StatusUnauthorized, "unauthorized", "User ID not found in request")
		return
	}

	query := r.URL.Query().Get("q")
	category := r.URL.Query().Get("category") // note_type, author, department, etc.

	if query == "" {
		h.writeError(w, http.StatusBadRequest, "validation_error", "Query parameter 'q' is required")
		return
	}

	// Generate suggestions based on category
	suggestions := h.generateSearchSuggestions(query, category, userID)

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"query":       query,
		"category":    category,
		"suggestions": suggestions,
	})
}

// generateSearchSuggestions generates search suggestions
func (h *Handlers) generateSearchSuggestions(query, category, userID string) []string {
	// In a real implementation, this would query the database for suggestions
	// For now, return mock suggestions based on category
	
	switch category {
	case "note_type":
		return h.filterSuggestions([]string{
			"progress_note", "discharge_summary", "consultation_note",
			"procedure_note", "lab_result", "radiology_report",
			"nursing_note", "medication_administration", "vital_signs",
		}, query)
	
	case "department":
		return h.filterSuggestions([]string{
			"cardiology", "neurology", "orthopedics", "pediatrics",
			"emergency", "surgery", "internal_medicine", "radiology",
			"pathology", "pharmacy", "nursing", "administration",
		}, query)
	
	case "specialty":
		return h.filterSuggestions([]string{
			"cardiothoracic_surgery", "interventional_cardiology",
			"pediatric_neurology", "orthopedic_surgery", "emergency_medicine",
			"internal_medicine", "family_medicine", "psychiatry",
		}, query)
	
	default:
		return h.filterSuggestions([]string{
			"patient", "diagnosis", "treatment", "medication",
			"procedure", "consultation", "follow_up", "discharge",
		}, query)
	}
}

// filterSuggestions filters suggestions based on query
func (h *Handlers) filterSuggestions(suggestions []string, query string) []string {
	var filtered []string
	queryLower := strings.ToLower(query)
	
	for _, suggestion := range suggestions {
		if strings.Contains(strings.ToLower(suggestion), queryLower) {
			filtered = append(filtered, suggestion)
		}
	}
	
	// Limit to 10 suggestions
	if len(filtered) > 10 {
		filtered = filtered[:10]
	}
	
	return filtered
}

// Update RegisterRoutes to include search endpoints
func (h *Handlers) RegisterSearchRoutes(router *mux.Router) {
	// Advanced search routes
	router.HandleFunc("/search/advanced", h.AdvancedSearch).Methods("POST")
	router.HandleFunc("/search/patients/{patientID}/aggregate", h.SearchByPatientWithAggregation).Methods("GET")
	router.HandleFunc("/search/with-integrity", h.SearchWithIntegrityVerification).Methods("POST")
	router.HandleFunc("/search/time-range", h.SearchByTimeRange).Methods("GET")
	router.HandleFunc("/search/author/{authorID}", h.SearchByAuthor).Methods("GET")
	router.HandleFunc("/search/suggestions", h.GetSearchSuggestions).Methods("GET")
}

// Update the main RegisterRoutes method to include all routes
func (h *Handlers) RegisterAllRoutes(router *mux.Router) {
	// Register original routes
	h.RegisterRoutes(router)
	
	// Register enhanced blockchain routes
	h.RegisterRoutesEnhanced(router)
	
	// Register search routes
	h.RegisterSearchRoutes(router)
}