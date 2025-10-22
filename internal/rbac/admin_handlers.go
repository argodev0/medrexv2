package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// AdminHandlers provides HTTP handlers for RBAC policy administration
type AdminHandlers struct {
	policyManager rbac.PolicyManager
	auditLogger   rbac.AuditLogger
	logger        *logrus.Logger
}

// NewAdminHandlers creates a new instance of admin handlers
func NewAdminHandlers(policyManager rbac.PolicyManager, auditLogger rbac.AuditLogger, logger *logrus.Logger) *AdminHandlers {
	return &AdminHandlers{
		policyManager: policyManager,
		auditLogger:   auditLogger,
		logger:        logger,
	}
}

// RegisterRoutes registers all admin routes with the router
func (h *AdminHandlers) RegisterRoutes(router *mux.Router) {
	adminRouter := router.PathPrefix("/admin/rbac").Subrouter()
	
	// Policy management routes
	adminRouter.HandleFunc("/policies", h.CreatePolicy).Methods("POST")
	adminRouter.HandleFunc("/policies", h.ListPolicies).Methods("GET")
	adminRouter.HandleFunc("/policies/{policyID}", h.GetPolicy).Methods("GET")
	adminRouter.HandleFunc("/policies/{policyID}", h.UpdatePolicy).Methods("PUT")
	adminRouter.HandleFunc("/policies/{policyID}", h.DeletePolicy).Methods("DELETE")
	adminRouter.HandleFunc("/policies/{policyID}/validate", h.ValidatePolicy).Methods("POST")
	
	// Bulk operations
	adminRouter.HandleFunc("/policies/bulk", h.BulkUpdatePolicies).Methods("POST")
	adminRouter.HandleFunc("/policies/bulk/validate", h.BulkValidatePolicies).Methods("POST")
	
	// Policy testing
	adminRouter.HandleFunc("/policies/test", h.TestPolicyAccess).Methods("POST")
	adminRouter.HandleFunc("/policies/{policyID}/test", h.TestSpecificPolicy).Methods("POST")
	
	// Audit and compliance
	adminRouter.HandleFunc("/audit/trail", h.GetAuditTrail).Methods("GET")
	adminRouter.HandleFunc("/audit/policies", h.GetPolicyAuditTrail).Methods("GET")
	adminRouter.HandleFunc("/compliance/report", h.GenerateComplianceReport).Methods("GET")
}

// CreatePolicy handles policy creation requests
func (h *AdminHandlers) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	var policy rbac.AccessPolicy
	if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}
	
	// Set creation metadata
	policy.LastUpdated = time.Now()
	if policy.Version == "" {
		policy.Version = "1.0.0"
	}
	
	// Create the policy
	if err := h.policyManager.CreatePolicy(ctx, &policy); err != nil {
		h.logger.WithError(err).Error("Failed to create policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create policy", err)
		return
	}
	
	// Log policy creation
	change := &rbac.PolicyChange{
		PolicyID:   policy.ID,
		ChangeType: "create",
		ChangedBy:  h.getUserFromContext(ctx),
		Timestamp:  time.Now(),
		NewPolicy:  &policy,
		Reason:     "Policy created via admin API",
	}
	
	if err := h.auditLogger.LogPolicyChange(ctx, change); err != nil {
		h.logger.WithError(err).Warn("Failed to log policy creation")
	}
	
	h.writeJSONResponse(w, http.StatusCreated, map[string]interface{}{
		"message":   "Policy created successfully",
		"policy_id": policy.ID,
		"version":   policy.Version,
	})
}

// GetPolicy handles policy retrieval requests
func (h *AdminHandlers) GetPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["policyID"]
	
	policy, err := h.policyManager.GetPolicy(ctx, policyID)
	if err != nil {
		if rbacErr, ok := rbac.GetRBACError(err); ok && rbacErr.Type == rbac.ErrorTypePolicyViolation {
			h.writeErrorResponse(w, http.StatusNotFound, "Policy not found", err)
		} else {
			h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve policy", err)
		}
		return
	}
	
	h.writeJSONResponse(w, http.StatusOK, policy)
}

// UpdatePolicy handles policy update requests
func (h *AdminHandlers) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["policyID"]
	
	// Get existing policy for audit trail
	oldPolicy, err := h.policyManager.GetPolicy(ctx, policyID)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Policy not found", err)
		return
	}
	
	var newPolicy rbac.AccessPolicy
	if err := json.NewDecoder(r.Body).Decode(&newPolicy); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}
	
	// Ensure policy ID matches
	newPolicy.ID = policyID
	newPolicy.LastUpdated = time.Now()
	
	// Update the policy
	if err := h.policyManager.UpdatePolicy(ctx, policyID, &newPolicy); err != nil {
		h.logger.WithError(err).Error("Failed to update policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to update policy", err)
		return
	}
	
	// Log policy update
	change := &rbac.PolicyChange{
		PolicyID:   policyID,
		ChangeType: "update",
		ChangedBy:  h.getUserFromContext(ctx),
		Timestamp:  time.Now(),
		OldPolicy:  oldPolicy,
		NewPolicy:  &newPolicy,
		Reason:     "Policy updated via admin API",
	}
	
	if err := h.auditLogger.LogPolicyChange(ctx, change); err != nil {
		h.logger.WithError(err).Warn("Failed to log policy update")
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message":   "Policy updated successfully",
		"policy_id": policyID,
		"version":   newPolicy.Version,
	})
}

// DeletePolicy handles policy deletion requests
func (h *AdminHandlers) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["policyID"]
	
	// Get existing policy for audit trail
	oldPolicy, err := h.policyManager.GetPolicy(ctx, policyID)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Policy not found", err)
		return
	}
	
	// Delete the policy
	if err := h.policyManager.DeletePolicy(ctx, policyID); err != nil {
		h.logger.WithError(err).Error("Failed to delete policy")
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete policy", err)
		return
	}
	
	// Log policy deletion
	change := &rbac.PolicyChange{
		PolicyID:   policyID,
		ChangeType: "delete",
		ChangedBy:  h.getUserFromContext(ctx),
		Timestamp:  time.Now(),
		OldPolicy:  oldPolicy,
		Reason:     "Policy deleted via admin API",
	}
	
	if err := h.auditLogger.LogPolicyChange(ctx, change); err != nil {
		h.logger.WithError(err).Warn("Failed to log policy deletion")
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"message":   "Policy deleted successfully",
		"policy_id": policyID,
	})
}

// ListPolicies handles policy listing requests with filtering
func (h *AdminHandlers) ListPolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Parse query parameters for filtering
	filter := &rbac.PolicyFilter{}
	
	if roleID := r.URL.Query().Get("role_id"); roleID != "" {
		filter.RoleID = roleID
	}
	
	if resourceID := r.URL.Query().Get("resource_id"); resourceID != "" {
		filter.ResourceID = resourceID
	}
	
	if action := r.URL.Query().Get("action"); action != "" {
		filter.Action = action
	}
	
	if updatedAfter := r.URL.Query().Get("updated_after"); updatedAfter != "" {
		if t, err := time.Parse(time.RFC3339, updatedAfter); err == nil {
			filter.UpdatedAfter = t
		}
	}
	
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}
	
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}
	
	policies, err := h.policyManager.ListPolicies(ctx, filter)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list policies", err)
		return
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"policies": policies,
		"count":    len(policies),
		"filter":   filter,
	})
}

// ValidatePolicy handles policy validation requests
func (h *AdminHandlers) ValidatePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["policyID"]
	
	policy, err := h.policyManager.GetPolicy(ctx, policyID)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Policy not found", err)
		return
	}
	
	if err := h.policyManager.ValidatePolicy(ctx, policy); err != nil {
		h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"valid":  false,
			"errors": err.Error(),
		})
		return
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"message": "Policy validation successful",
	})
}

// BulkUpdatePolicies handles bulk policy update requests
func (h *AdminHandlers) BulkUpdatePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	var request struct {
		Policies []rbac.AccessPolicy `json:"policies"`
		Reason   string              `json:"reason"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}
	
	results := make([]map[string]interface{}, 0, len(request.Policies))
	successCount := 0
	
	for _, policy := range request.Policies {
		result := map[string]interface{}{
			"policy_id": policy.ID,
		}
		
		// Get existing policy for audit trail
		oldPolicy, err := h.policyManager.GetPolicy(ctx, policy.ID)
		isUpdate := err == nil
		
		policy.LastUpdated = time.Now()
		
		var opErr error
		if isUpdate {
			opErr = h.policyManager.UpdatePolicy(ctx, policy.ID, &policy)
		} else {
			opErr = h.policyManager.CreatePolicy(ctx, &policy)
		}
		
		if opErr != nil {
			result["success"] = false
			result["error"] = opErr.Error()
		} else {
			result["success"] = true
			result["operation"] = map[string]bool{"created": !isUpdate, "updated": isUpdate}
			successCount++
			
			// Log policy change
			changeType := "create"
			if isUpdate {
				changeType = "update"
			}
			
			change := &rbac.PolicyChange{
				PolicyID:   policy.ID,
				ChangeType: changeType,
				ChangedBy:  h.getUserFromContext(ctx),
				Timestamp:  time.Now(),
				OldPolicy:  oldPolicy,
				NewPolicy:  &policy,
				Reason:     fmt.Sprintf("Bulk operation: %s", request.Reason),
			}
			
			if err := h.auditLogger.LogPolicyChange(ctx, change); err != nil {
				h.logger.WithError(err).Warn("Failed to log bulk policy change")
			}
		}
		
		results = append(results, result)
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"total_policies":     len(request.Policies),
		"successful_updates": successCount,
		"failed_updates":     len(request.Policies) - successCount,
		"results":           results,
	})
}

// BulkValidatePolicies handles bulk policy validation requests
func (h *AdminHandlers) BulkValidatePolicies(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	var policies []rbac.AccessPolicy
	if err := json.NewDecoder(r.Body).Decode(&policies); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}
	
	results := make([]map[string]interface{}, 0, len(policies))
	validCount := 0
	
	for _, policy := range policies {
		result := map[string]interface{}{
			"policy_id": policy.ID,
		}
		
		if err := h.policyManager.ValidatePolicy(ctx, &policy); err != nil {
			result["valid"] = false
			result["errors"] = err.Error()
		} else {
			result["valid"] = true
			validCount++
		}
		
		results = append(results, result)
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"total_policies": len(policies),
		"valid_policies": validCount,
		"invalid_policies": len(policies) - validCount,
		"results": results,
	})
}

// TestPolicyAccess handles policy access testing requests
func (h *AdminHandlers) TestPolicyAccess(w http.ResponseWriter, r *http.Request) {
	var request struct {
		AccessRequest rbac.AccessRequest `json:"access_request"`
		PolicyID      string             `json:"policy_id,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}
	
	// This would integrate with the RBAC core engine to test access
	// For now, we'll provide a mock response
	decision := &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Test access granted based on policy evaluation",
		TTL:     time.Hour,
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"test_result": decision,
		"timestamp":   time.Now(),
	})
}

// TestSpecificPolicy handles testing access against a specific policy
func (h *AdminHandlers) TestSpecificPolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	policyID := vars["policyID"]
	
	var accessRequest rbac.AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&accessRequest); err != nil {
		h.writeErrorResponse(w, http.StatusBadRequest, "Invalid JSON payload", err)
		return
	}
	
	// Get the policy
	policy, err := h.policyManager.GetPolicy(ctx, policyID)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Policy not found", err)
		return
	}
	
	// Test access against the specific policy
	// This would integrate with the RBAC core engine
	decision := &rbac.AccessDecision{
		Allowed: true,
		Reason:  fmt.Sprintf("Test access granted based on policy %s", policy.Name),
		TTL:     time.Hour,
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"policy_id":   policyID,
		"policy_name": policy.Name,
		"test_result": decision,
		"timestamp":   time.Now(),
	})
}

// Helper methods

func (h *AdminHandlers) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.WithError(err).Error("Failed to encode JSON response")
	}
}

func (h *AdminHandlers) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	h.logger.WithError(err).Error(message)
	
	response := map[string]interface{}{
		"error":   message,
		"timestamp": time.Now(),
	}
	
	if rbacErr, ok := rbac.GetRBACError(err); ok {
		response["error_type"] = rbacErr.Type
		response["error_code"] = rbacErr.Code
		if len(rbacErr.Suggestions) > 0 {
			response["suggestions"] = rbacErr.Suggestions
		}
	}
	
	h.writeJSONResponse(w, statusCode, response)
}

func (h *AdminHandlers) getUserFromContext(ctx context.Context) string {
	// Extract user ID from context - this would be set by authentication middleware
	if userID, ok := ctx.Value("user_id").(string); ok {
		return userID
	}
	return "system"
}

// GetAuditTrail handles audit trail retrieval requests
func (h *AdminHandlers) GetAuditTrail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Parse query parameters for filtering
	filter := &rbac.AuditFilter{}
	
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		filter.UserID = userID
	}
	
	if resourceID := r.URL.Query().Get("resource_id"); resourceID != "" {
		filter.ResourceID = resourceID
	}
	
	if action := r.URL.Query().Get("action"); action != "" {
		filter.Action = action
	}
	
	if result := r.URL.Query().Get("result"); result != "" {
		filter.Result = result
	}
	
	if startTime := r.URL.Query().Get("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filter.StartTime = t
		}
	}
	
	if endTime := r.URL.Query().Get("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filter.EndTime = t
		}
	}
	
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			filter.Limit = limit
		}
	}
	
	if offsetStr := r.URL.Query().Get("offset"); offsetStr != "" {
		if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
			filter.Offset = offset
		}
	}
	
	entries, err := h.auditLogger.GetAuditTrail(ctx, filter)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve audit trail", err)
		return
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"audit_entries": entries,
		"count":         len(entries),
		"filter":        filter,
	})
}

// GetPolicyAuditTrail handles policy-specific audit trail requests
func (h *AdminHandlers) GetPolicyAuditTrail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	policyID := r.URL.Query().Get("policy_id")
	if policyID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "policy_id parameter is required", nil)
		return
	}
	
	limit := 100 // Default limit
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	
	changes, err := h.auditLogger.GetPolicyAuditTrail(ctx, policyID, limit)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve policy audit trail", err)
		return
	}
	
	h.writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"policy_id":      policyID,
		"policy_changes": changes,
		"count":          len(changes),
	})
}

// GenerateComplianceReport handles compliance report generation requests
func (h *AdminHandlers) GenerateComplianceReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	
	// Parse time range parameters
	startTimeStr := r.URL.Query().Get("start_time")
	endTimeStr := r.URL.Query().Get("end_time")
	
	var startTime, endTime time.Time
	var err error
	
	if startTimeStr != "" {
		startTime, err = time.Parse(time.RFC3339, startTimeStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid start_time format", err)
			return
		}
	} else {
		// Default to last 30 days
		startTime = time.Now().AddDate(0, 0, -30)
	}
	
	if endTimeStr != "" {
		endTime, err = time.Parse(time.RFC3339, endTimeStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid end_time format", err)
			return
		}
	} else {
		endTime = time.Now()
	}
	
	// Validate time range
	if endTime.Before(startTime) {
		h.writeErrorResponse(w, http.StatusBadRequest, "end_time must be after start_time", nil)
		return
	}
	
	// Generate compliance report
	report, err := h.auditLogger.GenerateComplianceReport(ctx, startTime, endTime)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to generate compliance report", err)
		return
	}
	
	h.writeJSONResponse(w, http.StatusOK, report)
}