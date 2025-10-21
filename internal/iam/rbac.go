package iam

import (
	"fmt"

	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// RBACManager implements role-based access control
type RBACManager struct {
	logger          logger.Logger
	accessPolicyCC  AccessPolicyChaincode
	permissionMatrix map[types.UserRole]map[string][]string
}

// AccessPolicyChaincode interface for chaincode interactions
type AccessPolicyChaincode interface {
	ValidateAccess(userID, resource, action string, userRole types.UserRole) (bool, error)
	GetAccessPolicy(resource string, userRole types.UserRole) (*AccessPolicy, error)
	CreateAccessPolicy(policy *AccessPolicy) error
	UpdateAccessPolicy(policyID string, updates map[string]interface{}) error
}

// AccessPolicy represents an access control policy
type AccessPolicy struct {
	ID           string            `json:"id"`
	ResourceType string            `json:"resource_type"`
	UserRole     types.UserRole    `json:"user_role"`
	Actions      []string          `json:"actions"`
	Conditions   map[string]string `json:"conditions"`
	CreatedBy    string            `json:"created_by"`
	CreatedAt    string            `json:"created_at"`
}

// NewRBACManager creates a new RBAC manager
func NewRBACManager(log logger.Logger, accessPolicyCC AccessPolicyChaincode) *RBACManager {
	rbac := &RBACManager{
		logger:         log,
		accessPolicyCC: accessPolicyCC,
	}
	
	rbac.initializePermissionMatrix()
	return rbac
}

// ValidatePermissions validates if a user has permission to perform an action on a resource
func (r *RBACManager) ValidatePermissions(userID, resource, action string) (bool, error) {
	r.logger.Info("Validating permissions", "user_id", userID, "resource", resource, "action", action)

	// Get user role (this would typically come from the user context)
	userRole, err := r.getUserRole(userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user role: %w", err)
	}

	// Check local permission matrix first
	if allowed := r.checkLocalPermissions(userRole, resource, action); !allowed {
		r.logger.Warn("Permission denied by local matrix", "user_role", userRole, "resource", resource, "action", action)
		return false, nil
	}

	// Validate against AccessPolicy chaincode for real-time validation
	allowed, err := r.accessPolicyCC.ValidateAccess(userID, resource, action, userRole)
	if err != nil {
		r.logger.Error("Failed to validate access via chaincode", "error", err)
		return false, fmt.Errorf("chaincode validation failed: %w", err)
	}

	if !allowed {
		r.logger.Warn("Permission denied by chaincode", "user_id", userID, "resource", resource, "action", action)
		return false, nil
	}

	r.logger.Info("Permission granted", "user_id", userID, "resource", resource, "action", action)
	return true, nil
}

// GetUserPermissions returns all permissions for a user
func (r *RBACManager) GetUserPermissions(userID string) ([]string, error) {
	userRole, err := r.getUserRole(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user role: %w", err)
	}

	var permissions []string
	if rolePerms, exists := r.permissionMatrix[userRole]; exists {
		for resource, actions := range rolePerms {
			for _, action := range actions {
				permissions = append(permissions, fmt.Sprintf("%s:%s", resource, action))
			}
		}
	}

	return permissions, nil
}

// checkLocalPermissions checks permissions against the local matrix
func (r *RBACManager) checkLocalPermissions(userRole types.UserRole, resource, action string) bool {
	rolePerms, exists := r.permissionMatrix[userRole]
	if !exists {
		return false
	}

	actions, exists := rolePerms[resource]
	if !exists {
		return false
	}

	for _, allowedAction := range actions {
		if allowedAction == action || allowedAction == "*" {
			return true
		}
	}

	return false
}

// getUserRole retrieves user role (placeholder implementation)
func (r *RBACManager) getUserRole(userID string) (types.UserRole, error) {
	// In a real implementation, this would query the user repository
	// For now, return a default role for demonstration
	return types.RoleConsultingDoctor, nil
}

// initializePermissionMatrix sets up the RBAC permission matrix
func (r *RBACManager) initializePermissionMatrix() {
	r.permissionMatrix = map[types.UserRole]map[string][]string{
		types.RolePatient: {
			"patient_records": {"read"},
			"appointments":    {"read", "create", "update"},
			"billing":         {"read"},
			"communication":   {"read", "create"},
		},
		types.RoleMBBSStudent: {
			"patient_records": {"read"}, // Read-only access to de-identified data
			"training_data":   {"read"},
			"appointments":    {"read"},
		},
		types.RoleMDStudent: {
			"patient_records": {"read", "create"}, // Requires co-signature for create
			"cpoe_orders":     {"create"},         // Requires co-signature
			"appointments":    {"read", "create", "update"},
			"training_data":   {"read"},
		},
		types.RoleConsultingDoctor: {
			"patient_records": {"read", "create", "update", "delete"},
			"cpoe_orders":     {"read", "create", "update", "delete", "co_sign"},
			"appointments":    {"read", "create", "update", "delete"},
			"research_data":   {"read", "create", "update"},
			"financial_data":  {"read"},
			"staff_management": {"read", "update"},
		},
		types.RoleNurse: {
			"patient_records":     {"read", "update"},
			"medication_admin":    {"read", "create", "update"},
			"vital_signs":         {"read", "create", "update"},
			"appointments":        {"read", "update"},
			"patient_communication": {"read", "create"},
		},
		types.RoleLabTechnician: {
			"lab_results":     {"read", "create", "update"},
			"patient_records": {"read"}, // Limited to lab-related data
			"appointments":    {"read"},
			"equipment_logs":  {"read", "create", "update"},
		},
		types.RoleReceptionist: {
			"appointments":        {"read", "create", "update", "delete"},
			"patient_demographics": {"read", "update"},
			"billing":             {"read", "create", "update"},
			"insurance":           {"read", "update"},
		},
		types.RoleClinicalStaff: {
			"patient_records": {"read", "update"},
			"appointments":    {"read", "create", "update"},
			"clinical_notes":  {"read", "create", "update"},
			"vital_signs":     {"read", "create", "update"},
		},
		types.RoleAdministrator: {
			"*": {"*"}, // Full access to all resources
		},
	}
}

// CreateAccessPolicy creates a new access policy in the chaincode
func (r *RBACManager) CreateAccessPolicy(resourceType string, userRole types.UserRole, actions []string, conditions map[string]string, createdBy string) error {
	policy := &AccessPolicy{
		ID:           fmt.Sprintf("%s_%s_%d", resourceType, userRole, len(actions)),
		ResourceType: resourceType,
		UserRole:     userRole,
		Actions:      actions,
		Conditions:   conditions,
		CreatedBy:    createdBy,
		CreatedAt:    "2023-12-01T00:00:00Z", // Would use actual timestamp
	}

	err := r.accessPolicyCC.CreateAccessPolicy(policy)
	if err != nil {
		return fmt.Errorf("failed to create access policy: %w", err)
	}

	r.logger.Info("Access policy created", "policy_id", policy.ID, "resource", resourceType, "role", userRole)
	return nil
}

// UpdateAccessPolicy updates an existing access policy
func (r *RBACManager) UpdateAccessPolicy(policyID string, updates map[string]interface{}) error {
	err := r.accessPolicyCC.UpdateAccessPolicy(policyID, updates)
	if err != nil {
		return fmt.Errorf("failed to update access policy: %w", err)
	}

	r.logger.Info("Access policy updated", "policy_id", policyID)
	return nil
}

// ValidateResourceAccess validates access to a specific resource with conditions
func (r *RBACManager) ValidateResourceAccess(userID, resourceType, resourceID, action string, context map[string]string) (bool, error) {
	userRole, err := r.getUserRole(userID)
	if err != nil {
		return false, fmt.Errorf("failed to get user role: %w", err)
	}

	// Get access policy from chaincode
	policy, err := r.accessPolicyCC.GetAccessPolicy(resourceType, userRole)
	if err != nil {
		return false, fmt.Errorf("failed to get access policy: %w", err)
	}

	if policy == nil {
		r.logger.Warn("No access policy found", "resource_type", resourceType, "user_role", userRole)
		return false, nil
	}

	// Check if action is allowed
	actionAllowed := false
	for _, allowedAction := range policy.Actions {
		if allowedAction == action || allowedAction == "*" {
			actionAllowed = true
			break
		}
	}

	if !actionAllowed {
		return false, nil
	}

	// Validate conditions
	if !r.validateConditions(policy.Conditions, context) {
		r.logger.Warn("Access denied due to condition validation", "policy_id", policy.ID)
		return false, nil
	}

	return true, nil
}

// validateConditions validates policy conditions against context
func (r *RBACManager) validateConditions(conditions map[string]string, context map[string]string) bool {
	for key, expectedValue := range conditions {
		if actualValue, exists := context[key]; !exists || actualValue != expectedValue {
			return false
		}
	}
	return true
}

// GetRolePermissions returns all permissions for a specific role
func (r *RBACManager) GetRolePermissions(role types.UserRole) map[string][]string {
	if perms, exists := r.permissionMatrix[role]; exists {
		return perms
	}
	return make(map[string][]string)
}

// IsActionAllowed checks if a specific action is allowed for a role on a resource
func (r *RBACManager) IsActionAllowed(role types.UserRole, resource, action string) bool {
	return r.checkLocalPermissions(role, resource, action)
}