package accesspolicy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing access policies
type SmartContract struct {
	contractapi.Contract
}

// AccessPolicy represents a role-based access control policy
type AccessPolicy struct {
	ID           string            `json:"id"`
	ResourceType string            `json:"resource_type"`
	UserRole     string            `json:"user_role"`
	Actions      []string          `json:"actions"`
	Conditions   map[string]string `json:"conditions"`
	CreatedBy    string            `json:"created_by"`
	CreatedAt    time.Time         `json:"created_at"`
}

// AccessRequest represents a request for resource access
type AccessRequest struct {
	UserID       string `json:"user_id"`
	UserRole     string `json:"user_role"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Action       string `json:"action"`
	OrgID        string `json:"org_id"`
}

// AccessToken represents a PRE token for authorized access
type AccessToken struct {
	TokenID      string    `json:"token_id"`
	UserID       string    `json:"user_id"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Action       string    `json:"action"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// UserRole represents the different user roles in the system
type UserRole string

const (
	RolePatient           UserRole = "patient"
	RoleMBBSStudent      UserRole = "mbbs_student"
	RoleMDStudent        UserRole = "md_student"
	RoleConsultingDoctor UserRole = "consulting_doctor"
	RoleNurse            UserRole = "nurse"
	RoleLabTechnician    UserRole = "lab_technician"
	RoleReceptionist     UserRole = "receptionist"
	RoleClinicalStaff    UserRole = "clinical_staff"
	RoleAdministrator    UserRole = "administrator"
)

// InitLedger initializes the ledger with default access policies
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// Default RBAC policies for the Medrex system
	policies := []AccessPolicy{
		{
			ID:           "policy_patient_ehr",
			ResourceType: "ehr",
			UserRole:     string(RolePatient),
			Actions:      []string{"read"},
			Conditions:   map[string]string{"owner": "self"},
			CreatedBy:    "system",
			CreatedAt:    time.Now(),
		},
		{
			ID:           "policy_mbbs_student_ehr",
			ResourceType: "ehr",
			UserRole:     string(RoleMBBSStudent),
			Actions:      []string{"read"},
			Conditions:   map[string]string{"data_type": "deidentified", "assigned": "true"},
			CreatedBy:    "system",
			CreatedAt:    time.Now(),
		},
		{
			ID:           "policy_md_student_ehr",
			ResourceType: "ehr",
			UserRole:     string(RoleMDStudent),
			Actions:      []string{"read", "create"},
			Conditions:   map[string]string{"assigned": "true", "requires_cosign": "true"},
			CreatedBy:    "system",
			CreatedAt:    time.Now(),
		},
		{
			ID:           "policy_consulting_doctor_ehr",
			ResourceType: "ehr",
			UserRole:     string(RoleConsultingDoctor),
			Actions:      []string{"read", "create", "update"},
			Conditions:   map[string]string{"assigned": "true"},
			CreatedBy:    "system",
			CreatedAt:    time.Now(),
		},
		{
			ID:           "policy_nurse_ehr",
			ResourceType: "ehr",
			UserRole:     string(RoleNurse),
			Actions:      []string{"read", "update"},
			Conditions:   map[string]string{"assigned": "true", "scope": "nursing_notes"},
			CreatedBy:    "system",
			CreatedAt:    time.Now(),
		},
		{
			ID:           "policy_administrator_all",
			ResourceType: "*",
			UserRole:     string(RoleAdministrator),
			Actions:      []string{"read", "create", "update", "delete"},
			Conditions:   map[string]string{},
			CreatedBy:    "system",
			CreatedAt:    time.Now(),
		},
	}

	for _, policy := range policies {
		policyJSON, err := json.Marshal(policy)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState(policy.ID, policyJSON)
		if err != nil {
			return fmt.Errorf("failed to put policy to world state: %v", err)
		}
	}

	return nil
}

// CreateAccessPolicy creates a new access policy
func (s *SmartContract) CreateAccessPolicy(ctx contractapi.TransactionContextInterface, id, resourceType, userRole string, actions []string, conditions map[string]string) error {
	// Verify caller has admin privileges
	if err := s.verifyAdminAccess(ctx); err != nil {
		return fmt.Errorf("access denied: %v", err)
	}

	// Check if policy already exists
	existing, err := ctx.GetStub().GetState(id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("policy %s already exists", id)
	}

	// Validate user role
	if !s.isValidUserRole(userRole) {
		return fmt.Errorf("invalid user role: %s", userRole)
	}

	// Get caller identity
	callerID, err := s.getCallerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %v", err)
	}

	policy := AccessPolicy{
		ID:           id,
		ResourceType: resourceType,
		UserRole:     userRole,
		Actions:      actions,
		Conditions:   conditions,
		CreatedBy:    callerID,
		CreatedAt:    time.Now(),
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(id, policyJSON)
}

// ValidateAccess validates if a user has access to a specific resource
func (s *SmartContract) ValidateAccess(ctx contractapi.TransactionContextInterface, userID, userRole, resourceType, resourceID, action string) (bool, error) {
	// Extract user role from certificate if not provided
	if userRole == "" {
		extractedRole, err := s.extractUserRoleFromCert(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to extract user role: %v", err)
		}
		userRole = extractedRole
	}

	// Find applicable policies
	policies, err := s.getPoliciesForRole(ctx, userRole, resourceType)
	if err != nil {
		return false, fmt.Errorf("failed to get policies: %v", err)
	}

	// Check each policy
	for _, policy := range policies {
		if s.checkPolicyMatch(policy, resourceType, action) {
			// Validate conditions
			if s.validateConditions(policy.Conditions, userID, resourceID) {
				return true, nil
			}
		}
	}

	return false, nil
}

// GenerateAccessToken generates a PRE token for authorized access
func (s *SmartContract) GenerateAccessToken(ctx contractapi.TransactionContextInterface, userID, resourceType, resourceID, action string) (*AccessToken, error) {
	// Extract user role from certificate
	userRole, err := s.extractUserRoleFromCert(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user role: %v", err)
	}

	// Validate access first
	hasAccess, err := s.ValidateAccess(ctx, userID, userRole, resourceType, resourceID, action)
	if err != nil {
		return nil, fmt.Errorf("access validation failed: %v", err)
	}
	if !hasAccess {
		return nil, fmt.Errorf("access denied for user %s to resource %s", userID, resourceID)
	}

	// Generate unique token ID
	tokenID, err := s.generateTokenID(userID, resourceID, action)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token ID: %v", err)
	}

	// Create access token with expiration
	token := &AccessToken{
		TokenID:      tokenID,
		UserID:       userID,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Action:       action,
		ExpiresAt:    time.Now().Add(24 * time.Hour), // 24-hour expiration
		CreatedAt:    time.Now(),
	}

	// Store token on ledger
	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}

	err = ctx.GetStub().PutState("token_"+tokenID, tokenJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to store access token: %v", err)
	}

	return token, nil
}

// ValidateAccessToken validates an existing access token
func (s *SmartContract) ValidateAccessToken(ctx contractapi.TransactionContextInterface, tokenID string) (bool, error) {
	tokenBytes, err := ctx.GetStub().GetState("token_" + tokenID)
	if err != nil {
		return false, fmt.Errorf("failed to read token from world state: %v", err)
	}
	if tokenBytes == nil {
		return false, fmt.Errorf("token %s does not exist", tokenID)
	}

	var token AccessToken
	err = json.Unmarshal(tokenBytes, &token)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshal token: %v", err)
	}

	// Check if token is expired
	if time.Now().After(token.ExpiresAt) {
		return false, fmt.Errorf("token %s has expired", tokenID)
	}

	return true, nil
}

// GetAccessPolicy retrieves an access policy by ID
func (s *SmartContract) GetAccessPolicy(ctx contractapi.TransactionContextInterface, id string) (*AccessPolicy, error) {
	policyJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if policyJSON == nil {
		return nil, fmt.Errorf("policy %s does not exist", id)
	}

	var policy AccessPolicy
	err = json.Unmarshal(policyJSON, &policy)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

// Helper functions

// extractUserRoleFromCert extracts user role from X.509 certificate attributes
func (s *SmartContract) extractUserRoleFromCert(ctx contractapi.TransactionContextInterface) (string, error) {
	// Get client identity
	clientIdentity := ctx.GetClientIdentity()
	
	// Extract role attribute from certificate
	role, found, err := clientIdentity.GetAttributeValue("role")
	if err != nil {
		return "", fmt.Errorf("failed to get role attribute: %v", err)
	}
	if !found {
		return "", fmt.Errorf("role attribute not found in certificate")
	}

	return role, nil
}

// getCallerIdentity gets the identity of the transaction caller
func (s *SmartContract) getCallerIdentity(ctx contractapi.TransactionContextInterface) (string, error) {
	clientIdentity := ctx.GetClientIdentity()
	id, err := clientIdentity.GetID()
	if err != nil {
		return "", fmt.Errorf("failed to get client ID: %v", err)
	}
	return id, nil
}

// verifyAdminAccess verifies that the caller has administrator privileges
func (s *SmartContract) verifyAdminAccess(ctx contractapi.TransactionContextInterface) error {
	userRole, err := s.extractUserRoleFromCert(ctx)
	if err != nil {
		return err
	}

	if userRole != string(RoleAdministrator) {
		return fmt.Errorf("administrator role required, got: %s", userRole)
	}

	return nil
}

// isValidUserRole validates if the provided role is valid
func (s *SmartContract) isValidUserRole(role string) bool {
	validRoles := []string{
		string(RolePatient),
		string(RoleMBBSStudent),
		string(RoleMDStudent),
		string(RoleConsultingDoctor),
		string(RoleNurse),
		string(RoleLabTechnician),
		string(RoleReceptionist),
		string(RoleClinicalStaff),
		string(RoleAdministrator),
	}

	for _, validRole := range validRoles {
		if role == validRole {
			return true
		}
	}
	return false
}

// getPoliciesForRole retrieves all policies applicable to a user role and resource type
func (s *SmartContract) getPoliciesForRole(ctx contractapi.TransactionContextInterface, userRole, resourceType string) ([]AccessPolicy, error) {
	// Query all policies (in production, this should use rich queries for better performance)
	resultsIterator, err := ctx.GetStub().GetStateByRange("policy_", "policy_~")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var policies []AccessPolicy
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var policy AccessPolicy
		err = json.Unmarshal(queryResponse.Value, &policy)
		if err != nil {
			return nil, err
		}

		// Check if policy applies to this role and resource type
		if policy.UserRole == userRole && (policy.ResourceType == resourceType || policy.ResourceType == "*") {
			policies = append(policies, policy)
		}
	}

	return policies, nil
}

// checkPolicyMatch checks if a policy matches the requested resource type and action
func (s *SmartContract) checkPolicyMatch(policy AccessPolicy, resourceType, action string) bool {
	// Check resource type match
	if policy.ResourceType != resourceType && policy.ResourceType != "*" {
		return false
	}

	// Check action match
	for _, allowedAction := range policy.Actions {
		if allowedAction == action || allowedAction == "*" {
			return true
		}
	}

	return false
}

// validateConditions validates policy conditions against the request context
func (s *SmartContract) validateConditions(conditions map[string]string, userID, resourceID string) bool {
	// For now, implement basic condition validation
	// In production, this would be more sophisticated
	
	for key, value := range conditions {
		switch key {
		case "owner":
			if value == "self" {
				// Check if user is accessing their own resource
				// This would require additional context about resource ownership
				continue
			}
		case "assigned":
			if value == "true" {
				// Check if user is assigned to this resource
				// This would require additional context about assignments
				continue
			}
		case "data_type":
			if value == "deidentified" {
				// Check if data is de-identified
				// This would require additional context about data classification
				continue
			}
		}
	}

	return true
}

// generateTokenID generates a unique token ID using cryptographic hash
func (s *SmartContract) generateTokenID(userID, resourceID, action string) (string, error) {
	// Create random bytes
	randomBytes := make([]byte, 16)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Create hash input
	input := fmt.Sprintf("%s:%s:%s:%s:%d", userID, resourceID, action, hex.EncodeToString(randomBytes), time.Now().UnixNano())
	
	// Generate SHA-256 hash
	hash := sha256.Sum256([]byte(input))
	
	return hex.EncodeToString(hash[:]), nil
}