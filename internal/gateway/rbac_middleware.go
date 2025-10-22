package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/medrex/dlt-emr/pkg/types"
)

// RBACMiddleware handles RBAC validation for API Gateway requests
type RBACMiddleware struct {
	rbacEngine rbac.RBACCoreEngine
	logger     interface {
		Info(msg string, fields ...interface{})
		Error(msg string, fields ...interface{})
		Warn(msg string, fields ...interface{})
	}
}

// NewRBACMiddleware creates a new RBAC middleware instance
func NewRBACMiddleware(rbacEngine rbac.RBACCoreEngine, logger interface {
	Info(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
}) *RBACMiddleware {
	return &RBACMiddleware{
		rbacEngine: rbacEngine,
		logger:     logger,
	}
}

// rbacMiddleware validates RBAC permissions for incoming requests
func (s *Service) rbacMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip RBAC for health checks, admin endpoints, and landing page
		if r.URL.Path == "/" || r.URL.Path == "/health" || r.URL.Path == "/metrics" || strings.HasPrefix(r.URL.Path, "/admin/") {
			next.ServeHTTP(w, r)
			return
		}

		// Get user claims from context (set by auth middleware)
		claims, ok := r.Context().Value("user_claims").(*UserClaims)
		if !ok {
			s.writeErrorResponse(w, http.StatusUnauthorized, "user claims not found in context")
			return
		}

		// Extract resource and action from request
		resourceID, action := s.extractResourceAndAction(r)
		if resourceID == "" || action == "" {
			s.logger.Warn("Unable to extract resource or action from request",
				"path", r.URL.Path,
				"method", r.Method,
				"user_id", claims.UserID,
			)
			s.writeErrorResponse(w, http.StatusBadRequest, "unable to determine resource or action")
			return
		}

		// Create RBAC access request
		accessReq := &rbac.AccessRequest{
			UserID:     claims.UserID,
			ResourceID: resourceID,
			Action:     action,
			Context: map[string]string{
				"ip_address":  r.RemoteAddr,
				"user_agent":  r.UserAgent(),
				"request_id":  r.Header.Get("X-Request-ID"),
				"service":     s.extractServiceName(r.URL.Path),
			},
			Attributes: s.extractUserAttributes(claims, r),
			Timestamp:  time.Now(),
		}

		// Validate access using RBAC engine
		decision, err := s.rbacEngine.ValidateAccess(r.Context(), accessReq)
		if err != nil {
			s.logger.Error("RBAC validation failed",
				"error", err,
				"user_id", claims.UserID,
				"resource", resourceID,
				"action", action,
			)
			s.writeErrorResponse(w, http.StatusInternalServerError, "access validation failed")
			return
		}

		// Check if access is allowed
		if !decision.Allowed {
			s.logger.Warn("Access denied by RBAC",
				"user_id", claims.UserID,
				"resource", resourceID,
				"action", action,
				"reason", decision.Reason,
			)
			
			// Return appropriate error based on reason
			statusCode := s.getStatusCodeFromRBACReason(decision.Reason)
			errorResponse := &types.MedrexError{
				Type:    types.ErrorTypeAuthorization,
				Code:    "RBAC_ACCESS_DENIED",
				Message: decision.Reason,
				Details: map[string]interface{}{
					"resource":    resourceID,
					"action":      action,
					"conditions":  decision.Conditions,
					"suggestions": s.generateAccessSuggestions(decision),
				},
			}
			
			s.writeJSONResponse(w, statusCode, errorResponse)
			return
		}

		// Add RBAC decision to request context for downstream services
		ctx := context.WithValue(r.Context(), "rbac_decision", decision)
		ctx = context.WithValue(ctx, "rbac_attributes", decision.Attributes)
		r = r.WithContext(ctx)

		// Log successful access
		s.logger.Info("RBAC access granted",
			"user_id", claims.UserID,
			"resource", resourceID,
			"action", action,
			"granted_role", decision.Attributes["granted_role"],
			"scope", decision.Attributes["permission_scope"],
		)

		next.ServeHTTP(w, r)
	})
}

// extractResourceAndAction extracts resource ID and action from HTTP request
func (s *Service) extractResourceAndAction(r *http.Request) (string, string) {
	// Extract service name from path
	serviceName := s.extractServiceName(r.URL.Path)
	if serviceName == "" {
		return "", ""
	}

	// Map HTTP method to RBAC action
	action := s.mapHTTPMethodToAction(r.Method)
	if action == "" {
		return "", ""
	}

	// Extract resource ID based on service and path
	resourceID := s.extractResourceID(serviceName, r.URL.Path, r)
	
	return resourceID, action
}

// mapHTTPMethodToAction maps HTTP methods to RBAC actions
func (s *Service) mapHTTPMethodToAction(method string) string {
	switch strings.ToUpper(method) {
	case "GET":
		return rbac.ActionRead
	case "POST":
		return rbac.ActionCreate
	case "PUT", "PATCH":
		return rbac.ActionUpdate
	case "DELETE":
		return rbac.ActionDelete
	default:
		return ""
	}
}

// extractResourceID extracts resource identifier from request path and parameters
func (s *Service) extractResourceID(serviceName, path string, r *http.Request) string {
	// Remove service prefix from path
	cleanPath := strings.TrimPrefix(path, "/api/v1/"+serviceName)
	pathParts := strings.Split(strings.Trim(cleanPath, "/"), "/")

	switch serviceName {
	case "clinical-notes":
		// Clinical Notes Service resources
		if len(pathParts) >= 1 {
			switch pathParts[0] {
			case "patients":
				if len(pathParts) >= 2 {
					return rbac.ResourcePatientEHR + ":" + pathParts[1]
				}
				return rbac.ResourcePatientEHR
			case "notes":
				if len(pathParts) >= 2 {
					return rbac.ResourceClinicalNote + ":" + pathParts[1]
				}
				return rbac.ResourceClinicalNote
			case "orders":
				if len(pathParts) >= 2 {
					return rbac.ResourceCPOEOrder + ":" + pathParts[1]
				}
				return rbac.ResourceCPOEOrder
			}
		}
		return rbac.ResourcePatientEHR

	case "iam":
		// IAM Service resources
		if len(pathParts) >= 1 {
			switch pathParts[0] {
			case "users":
				if len(pathParts) >= 2 {
					return rbac.ResourceUserManagement + ":" + pathParts[1]
				}
				return rbac.ResourceUserManagement
			case "roles":
				return rbac.ResourceRoleManagement
			case "certificates":
				if len(pathParts) >= 2 {
					return rbac.ResourceCertificate + ":" + pathParts[1]
				}
				return rbac.ResourceCertificate
			}
		}
		return rbac.ResourceUserManagement

	case "scheduling":
		// Scheduling Service resources
		if len(pathParts) >= 1 {
			switch pathParts[0] {
			case "appointments":
				if len(pathParts) >= 2 {
					return rbac.ResourceAppointment + ":" + pathParts[1]
				}
				return rbac.ResourceAppointment
			case "calendar":
				return rbac.ResourceCalendar
			}
		}
		return rbac.ResourceAppointment

	case "mobile-workflow":
		// Mobile Workflow Service resources
		if len(pathParts) >= 1 {
			switch pathParts[0] {
			case "workflows":
				if len(pathParts) >= 2 {
					return rbac.ResourceWorkflow + ":" + pathParts[1]
				}
				return rbac.ResourceWorkflow
			case "barcode":
				return rbac.ResourceBarcodeScanner
			case "sync":
				return rbac.ResourceOfflineSync
			}
		}
		return rbac.ResourceWorkflow

	default:
		// Generic resource mapping
		if len(pathParts) >= 1 {
			resourceType := pathParts[0]
			if len(pathParts) >= 2 {
				return resourceType + ":" + pathParts[1]
			}
			return resourceType
		}
		return serviceName
	}
}

// extractUserAttributes extracts user attributes from claims and request context
func (s *Service) extractUserAttributes(claims *UserClaims, r *http.Request) map[string]string {
	attributes := make(map[string]string)

	// Extract attributes from JWT claims
	if claims.Role != "" {
		attributes["role"] = string(claims.Role)
	}
	if claims.Specialty != "" {
		attributes["specialty"] = claims.Specialty
	}
	if claims.Department != "" {
		attributes["department"] = claims.Department
	}
	if claims.WardAssignment != "" {
		attributes["ward_assignment"] = claims.WardAssignment
	}

	// Extract boolean attributes
	if claims.IsTrainee {
		attributes["is_trainee"] = "true"
	}
	if claims.IsSupervisor {
		attributes["is_supervisor"] = "true"
	}

	// Extract contextual attributes from request
	if patientID := r.Header.Get("X-Patient-ID"); patientID != "" {
		attributes["patient_id"] = patientID
	}
	if dataType := r.Header.Get("X-Data-Type"); dataType != "" {
		attributes["data_type"] = dataType
	}
	if orderType := r.Header.Get("X-Order-Type"); orderType != "" {
		attributes["order_type"] = orderType
	}
	if dataCategory := r.Header.Get("X-Data-Category"); dataCategory != "" {
		attributes["data_category"] = dataCategory
	}

	// Extract query parameters that might be relevant for RBAC
	query := r.URL.Query()
	if scope := query.Get("scope"); scope != "" {
		attributes["requested_scope"] = scope
	}
	if filter := query.Get("filter"); filter != "" {
		attributes["data_filter"] = filter
	}

	return attributes
}

// getStatusCodeFromRBACReason maps RBAC denial reasons to HTTP status codes
func (s *Service) getStatusCodeFromRBACReason(reason string) int {
	switch {
	case strings.Contains(reason, "Insufficient privileges"):
		return http.StatusForbidden
	case strings.Contains(reason, "No roles assigned"):
		return http.StatusUnauthorized
	case strings.Contains(reason, "time restrictions"):
		return http.StatusForbidden
	case strings.Contains(reason, "Supervision required"):
		return http.StatusPreconditionRequired
	case strings.Contains(reason, "conditions not met"):
		return http.StatusPreconditionFailed
	default:
		return http.StatusForbidden
	}
}

// generateAccessSuggestions generates helpful suggestions for denied access
func (s *Service) generateAccessSuggestions(decision *rbac.AccessDecision) []string {
	var suggestions []string

	if strings.Contains(decision.Reason, "Supervision required") {
		suggestions = append(suggestions, "Request supervisor approval for this action")
		suggestions = append(suggestions, "Contact your supervising physician")
	}

	if strings.Contains(decision.Reason, "time restrictions") {
		suggestions = append(suggestions, "Try again during allowed hours")
		suggestions = append(suggestions, "Contact administrator for emergency access")
	}

	if strings.Contains(decision.Reason, "Insufficient privileges") {
		suggestions = append(suggestions, "Contact administrator to request additional permissions")
		suggestions = append(suggestions, "Verify you are accessing the correct resource")
	}

	if len(decision.Conditions) > 0 {
		for _, condition := range decision.Conditions {
			switch condition {
			case "requires_supervisor_approval":
				suggestions = append(suggestions, "Obtain supervisor approval before proceeding")
			case "de_identified_only":
				suggestions = append(suggestions, "Access de-identified training data instead")
			case "demographics_only":
				suggestions = append(suggestions, "Limit access to demographic information only")
			}
		}
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "Contact system administrator for assistance")
	}

	return suggestions
}

// RBACRequestInfo contains RBAC-related information for downstream services
type RBACRequestInfo struct {
	UserID         string            `json:"user_id"`
	Role           string            `json:"role"`
	GrantedScope   string            `json:"granted_scope"`
	Attributes     map[string]string `json:"attributes"`
	Conditions     []string          `json:"conditions"`
	DecisionTTL    time.Duration     `json:"decision_ttl"`
}

// GetRBACInfoFromContext extracts RBAC information from request context
func GetRBACInfoFromContext(ctx context.Context) (*RBACRequestInfo, bool) {
	decision, ok := ctx.Value("rbac_decision").(*rbac.AccessDecision)
	if !ok {
		return nil, false
	}

	attributes, _ := ctx.Value("rbac_attributes").(map[string]string)
	claims, _ := ctx.Value("user_claims").(*UserClaims)

	info := &RBACRequestInfo{
		GrantedScope: decision.Attributes["permission_scope"],
		Attributes:   attributes,
		Conditions:   decision.Conditions,
		DecisionTTL:  decision.TTL,
	}

	if claims != nil {
		info.UserID = claims.UserID
		info.Role = string(claims.Role)
	}

	return info, true
}

// ValidateRoleBasedRouting validates if user can access specific service endpoints
func (s *Service) ValidateRoleBasedRouting(userRole, serviceName, endpoint string) bool {
	// Define role-based service access rules
	serviceAccess := map[string][]string{
		"clinical-notes": {
			rbac.RoleConsultingDoctor,
			rbac.RoleMDStudent,
			rbac.RoleMBBSStudent,
			rbac.RoleNurse,
			rbac.RoleClinicalStaff,
			rbac.RoleLabTechnician,
		},
		"iam": {
			rbac.RoleAdministrator,
			rbac.RoleConsultingDoctor,
			rbac.RoleReceptionist,
		},
		"scheduling": {
			rbac.RolePatient,
			rbac.RoleReceptionist,
			rbac.RoleConsultingDoctor,
			rbac.RoleNurse,
			rbac.RoleClinicalStaff,
		},
		"mobile-workflow": {
			rbac.RoleNurse,
			rbac.RoleLabTechnician,
			rbac.RoleClinicalStaff,
			rbac.RoleConsultingDoctor,
		},
	}

	allowedRoles, exists := serviceAccess[serviceName]
	if !exists {
		// If service not defined, allow all authenticated users
		return true
	}

	for _, allowedRole := range allowedRoles {
		if userRole == allowedRole {
			return true
		}
	}

	return false
}

// AddRBACHeaders adds RBAC-related headers to downstream service requests
func (s *Service) AddRBACHeaders(r *http.Request, rbacInfo *RBACRequestInfo) {
	if rbacInfo == nil {
		return
	}

	// Add RBAC information as headers for downstream services
	r.Header.Set("X-RBAC-User-ID", rbacInfo.UserID)
	r.Header.Set("X-RBAC-Role", rbacInfo.Role)
	r.Header.Set("X-RBAC-Scope", rbacInfo.GrantedScope)

	// Add attributes as JSON header
	if len(rbacInfo.Attributes) > 0 {
		if attributesJSON, err := json.Marshal(rbacInfo.Attributes); err == nil {
			r.Header.Set("X-RBAC-Attributes", string(attributesJSON))
		}
	}

	// Add conditions as JSON header
	if len(rbacInfo.Conditions) > 0 {
		if conditionsJSON, err := json.Marshal(rbacInfo.Conditions); err == nil {
			r.Header.Set("X-RBAC-Conditions", string(conditionsJSON))
		}
	}

	// Add decision TTL
	if rbacInfo.DecisionTTL > 0 {
		r.Header.Set("X-RBAC-TTL", fmt.Sprintf("%.0f", rbacInfo.DecisionTTL.Seconds()))
	}
}