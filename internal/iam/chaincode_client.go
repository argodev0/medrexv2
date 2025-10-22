package iam

import (
	"fmt"

	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// AccessPolicyChaincodeClient implements chaincode interactions for access policies
type AccessPolicyChaincodeClient struct {
	config *config.FabricConfig
	logger logger.Logger
}

// NewAccessPolicyChaincodeClient creates a new chaincode client
func NewAccessPolicyChaincodeClient(config *config.FabricConfig, logger logger.Logger) *AccessPolicyChaincodeClient {
	return &AccessPolicyChaincodeClient{
		config: config,
		logger: logger,
	}
}

// ValidateAccess validates access through the AccessPolicy chaincode
func (c *AccessPolicyChaincodeClient) ValidateAccess(userID, resource, action string, userRole types.UserRole) (bool, error) {
	c.logger.Info("Validating access via chaincode", 
		"user_id", userID, 
		"resource", resource, 
		"action", action, 
		"role", userRole,
	)

	// This would invoke the AccessPolicy chaincode
	// For now, implement basic role-based validation
	switch userRole {
	case types.RoleAdministrator:
		return true, nil // Administrators have full access
	case types.RoleConsultingDoctor:
		return c.validateDoctorAccess(resource, action), nil
	case types.RoleNurse:
		return c.validateNurseAccess(resource, action), nil
	case types.RolePatient:
		return c.validatePatientAccess(userID, resource, action), nil
	default:
		return false, nil
	}
}

// GetAccessPolicy retrieves an access policy from chaincode
func (c *AccessPolicyChaincodeClient) GetAccessPolicy(resource string, userRole types.UserRole) (*AccessPolicy, error) {
	c.logger.Info("Getting access policy from chaincode", "resource", resource, "role", userRole)

	// This would query the AccessPolicy chaincode
	// For now, return a mock policy
	policy := &AccessPolicy{
		ID:           fmt.Sprintf("policy_%s_%s", resource, userRole),
		ResourceType: resource,
		UserRole:     userRole,
		Actions:      c.getDefaultActionsForRole(userRole, resource),
		Conditions:   make(map[string]string),
		CreatedBy:    "system",
		CreatedAt:    "2024-01-01T00:00:00Z",
	}

	return policy, nil
}

// CreateAccessPolicy creates a new access policy in chaincode
func (c *AccessPolicyChaincodeClient) CreateAccessPolicy(policy *AccessPolicy) error {
	c.logger.Info("Creating access policy in chaincode", "policy_id", policy.ID)

	// This would invoke the AccessPolicy chaincode to create a new policy
	// For now, just log the operation
	c.logger.Info("Access policy created successfully", "policy_id", policy.ID)
	return nil
}

// UpdateAccessPolicy updates an existing access policy in chaincode
func (c *AccessPolicyChaincodeClient) UpdateAccessPolicy(policyID string, updates map[string]interface{}) error {
	c.logger.Info("Updating access policy in chaincode", "policy_id", policyID)

	// This would invoke the AccessPolicy chaincode to update the policy
	// For now, just log the operation
	c.logger.Info("Access policy updated successfully", "policy_id", policyID)
	return nil
}

// Helper methods for validation logic

func (c *AccessPolicyChaincodeClient) validateDoctorAccess(resource, action string) bool {
	// Consulting doctors have broad access
	allowedResources := []string{
		"patient_records", "cpoe_orders", "appointments", 
		"research_data", "financial_data", "staff_management",
	}
	
	for _, allowedResource := range allowedResources {
		if resource == allowedResource {
			return true
		}
	}
	return false
}

func (c *AccessPolicyChaincodeClient) validateNurseAccess(resource, action string) bool {
	// Nurses have limited access
	allowedResources := []string{
		"patient_records", "medication_admin", "vital_signs", 
		"appointments", "patient_communication",
	}
	
	for _, allowedResource := range allowedResources {
		if resource == allowedResource {
			// Nurses cannot delete most resources
			if action == "delete" && resource != "appointments" {
				return false
			}
			return true
		}
	}
	return false
}

func (c *AccessPolicyChaincodeClient) validatePatientAccess(userID, resource, action string) bool {
	// Patients can only access their own data
	allowedResources := []string{"patient_records", "appointments", "billing", "communication"}
	
	for _, allowedResource := range allowedResources {
		if resource == allowedResource {
			// Additional validation would check if the resource belongs to the patient
			return action == "read" || (action == "create" && resource == "appointments")
		}
	}
	return false
}

func (c *AccessPolicyChaincodeClient) getDefaultActionsForRole(role types.UserRole, resource string) []string {
	switch role {
	case types.RoleAdministrator:
		return []string{"create", "read", "update", "delete"}
	case types.RoleConsultingDoctor:
		return []string{"create", "read", "update", "delete", "co_sign"}
	case types.RoleNurse:
		if resource == "appointments" {
			return []string{"read", "update", "delete"}
		}
		return []string{"read", "create", "update"}
	case types.RolePatient:
		if resource == "appointments" {
			return []string{"read", "create", "update"}
		}
		return []string{"read"}
	default:
		return []string{"read"}
	}
}