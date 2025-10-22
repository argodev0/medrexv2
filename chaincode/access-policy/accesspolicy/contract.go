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

// SBEPolicy represents a State-Based Endorsement policy
type SBEPolicy struct {
	ID                    string                  `json:"id"`
	Name                  string                  `json:"name"`
	ResourceType          string                  `json:"resource_type"`
	TriggerConditions     []TriggerCondition      `json:"trigger_conditions"`
	RequiredEndorsers     []EndorserRequirement   `json:"required_endorsers"`
	TimeoutDuration       int64                   `json:"timeout_duration"` // Duration in seconds
	EscalationPolicy      string                  `json:"escalation_policy"`
	EmergencyOverride     bool                    `json:"emergency_override"`
	CreatedBy             string                  `json:"created_by"`
	CreatedAt             time.Time               `json:"created_at"`
	Version               int                     `json:"version"`
}

// TriggerCondition defines when an SBE policy should be triggered
type TriggerCondition struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
}

// EndorserRequirement defines requirements for endorsers in SBE policies
type EndorserRequirement struct {
	Role        string            `json:"role"`
	Attributes  map[string]string `json:"attributes"`
	MinCount    int               `json:"min_count"`
	MaxCount    int               `json:"max_count"`
}

// SupervisionWorkflow represents a trainee supervision workflow
type SupervisionWorkflow struct {
	ID              string                 `json:"id"`
	TraineeID       string                 `json:"trainee_id"`
	SupervisorID    string                 `json:"supervisor_id"`
	ResourceID      string                 `json:"resource_id"`
	WorkflowType    string                 `json:"workflow_type"`
	Status          string                 `json:"status"` // "pending", "in_progress", "completed", "expired", "overridden"
	RequiredActions []SupervisionAction    `json:"required_actions"`
	CompletedActions []CompletedAction     `json:"completed_actions"`
	CreatedAt       time.Time              `json:"created_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// SupervisionAction represents an action required in a supervision workflow
type SupervisionAction struct {
	Type        string            `json:"type"`        // "review", "approve", "co_sign"
	Description string            `json:"description"`
	Required    bool              `json:"required"`
	Attributes  map[string]string `json:"attributes"`
}

// CompletedAction represents a completed supervision action
type CompletedAction struct {
	Action      SupervisionAction `json:"action"`
	CompletedBy string            `json:"completed_by"`
	CompletedAt time.Time         `json:"completed_at"`
	Signature   string            `json:"signature"`
	Comments    string            `json:"comments,omitempty"`
}

// EndorsementRecord represents an endorsement for SBE policy
type EndorsementRecord struct {
	ID           string    `json:"id"`
	ResourceID   string    `json:"resource_id"`
	PolicyID     string    `json:"policy_id"`
	EndorserID   string    `json:"endorser_id"`
	EndorserRole string    `json:"endorser_role"`
	Signature    string    `json:"signature"`
	Timestamp    time.Time `json:"timestamp"`
	Comments     string    `json:"comments,omitempty"`
}

// ABACPolicy represents an Attribute-Based Access Control policy
type ABACPolicy struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	ResourceType string               `json:"resource_type"`
	Rules       []ABACRule            `json:"rules"`
	Conditions  []AttributeCondition  `json:"conditions"`
	Effect      string                `json:"effect"` // "allow" or "deny"
	Priority    int                   `json:"priority"`
	CreatedBy   string                `json:"created_by"`
	CreatedAt   time.Time             `json:"created_at"`
}

// ABACRule represents a rule in an ABAC policy
type ABACRule struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"` // "equals", "not_equals", "contains", "in", "not_in"
	Value     interface{} `json:"value"`
	Required  bool        `json:"required"`
}

// AttributeCondition represents contextual conditions for ABAC
type AttributeCondition struct {
	Type        string      `json:"type"`        // "time", "location", "patient_assignment", "ward_assignment"
	Constraint  string      `json:"constraint"`  // "business_hours", "ward_match", "assigned_patients"
	Value       interface{} `json:"value"`
}

// UserAttributes represents extracted user attributes from certificate
type UserAttributes struct {
	Role           string `json:"role"`
	Specialty      string `json:"specialty,omitempty"`
	IsTrainee      bool   `json:"is_trainee"`
	IsSupervisor   bool   `json:"is_supervisor"`
	WardAssignment string `json:"ward_assignment,omitempty"`
	LabOrg         string `json:"lab_org,omitempty"`
	Department     string `json:"department,omitempty"`
	Level          int    `json:"level"`
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

// InitLedger initializes the ledger with default access policies and ABAC policies
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
			ID:           "policy_lab_technician_results",
			ResourceType: "lab_results",
			UserRole:     string(RoleLabTechnician),
			Actions:      []string{"create", "read", "update"},
			Conditions:   map[string]string{"lab_org": "match"},
			CreatedBy:    "system",
			CreatedAt:    time.Now(),
		},
		{
			ID:           "policy_clinical_staff_specialized",
			ResourceType: "specialized_service",
			UserRole:     string(RoleClinicalStaff),
			Actions:      []string{"create", "read", "update"},
			Conditions:   map[string]string{"specialty": "match"},
			CreatedBy:    "system",
			CreatedAt:    time.Now(),
		},
		{
			ID:           "policy_receptionist_registration",
			ResourceType: "patient_registration",
			UserRole:     string(RoleReceptionist),
			Actions:      []string{"create", "read", "update"},
			Conditions:   map[string]string{},
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

	// Store RBAC policies
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

	// Default ABAC policies
	abacPolicies := []ABACPolicy{
		{
			ID:           "abac_ward_restriction",
			Name:         "Ward Assignment Restriction",
			ResourceType: "ehr",
			Rules: []ABACRule{
				{Attribute: "ward_assignment", Operator: "not_equals", Value: "", Required: true},
			},
			Conditions: []AttributeCondition{
				{Type: "ward_assignment", Constraint: "ward_match", Value: true},
			},
			Effect:    "allow",
			Priority:  100,
			CreatedBy: "system",
			CreatedAt: time.Now(),
		},
		{
			ID:           "abac_trainee_supervision",
			Name:         "Trainee Supervision Requirement",
			ResourceType: "cpoe_order",
			Rules: []ABACRule{
				{Attribute: "is_trainee", Operator: "equals", Value: true, Required: true},
			},
			Conditions: []AttributeCondition{},
			Effect:     "deny",
			Priority:   200,
			CreatedBy:  "system",
			CreatedAt:  time.Now(),
		},
		{
			ID:           "abac_business_hours",
			Name:         "Business Hours Access",
			ResourceType: "*",
			Rules:        []ABACRule{},
			Conditions: []AttributeCondition{
				{Type: "time", Constraint: "business_hours", Value: true},
			},
			Effect:    "allow",
			Priority:  50,
			CreatedBy: "system",
			CreatedAt: time.Now(),
		},
	}

	// Store ABAC policies
	for _, policy := range abacPolicies {
		policyJSON, err := json.Marshal(policy)
		if err != nil {
			return err
		}

		err = ctx.GetStub().PutState("abac_"+policy.ID, policyJSON)
		if err != nil {
			return fmt.Errorf("failed to put ABAC policy to world state: %v", err)
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

// ValidateAccess validates if a user has access to a specific resource using RBAC and ABAC
func (s *SmartContract) ValidateAccess(ctx contractapi.TransactionContextInterface, userID, userRole, resourceType, resourceID, action string) (bool, error) {
	// Extract user role from certificate if not provided
	if userRole == "" {
		extractedRole, err := s.extractUserRoleFromCert(ctx)
		if err != nil {
			return false, fmt.Errorf("failed to extract user role: %v", err)
		}
		userRole = extractedRole
	}

	// Extract user attributes from certificate for ABAC
	userAttributes, err := s.extractUserAttributesFromCert(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to extract user attributes: %v", err)
	}

	// Find applicable RBAC policies
	rbacPolicies, err := s.getPoliciesForRole(ctx, userRole, resourceType)
	if err != nil {
		return false, fmt.Errorf("failed to get RBAC policies: %v", err)
	}

	// Check RBAC policies first
	rbacAllowed := false
	for _, policy := range rbacPolicies {
		if s.checkPolicyMatch(policy, resourceType, action) {
			// Validate conditions
			if s.validateConditions(policy.Conditions, userID, resourceID) {
				rbacAllowed = true
				break
			}
		}
	}

	if !rbacAllowed {
		return false, nil
	}

	// Apply ABAC policies for additional attribute-based validation
	abacAllowed, err := s.validateABACPolicies(ctx, userAttributes, resourceType, resourceID, action)
	if err != nil {
		return false, fmt.Errorf("ABAC validation failed: %v", err)
	}

	return abacAllowed, nil
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

// CreateSBEPolicy creates a new State-Based Endorsement policy
func (s *SmartContract) CreateSBEPolicy(ctx contractapi.TransactionContextInterface, id, name, resourceType string, triggerConditions []TriggerCondition, requiredEndorsers []EndorserRequirement, timeoutDuration int64, escalationPolicy string, emergencyOverride bool) error {
	// Verify caller has admin privileges
	if err := s.verifyAdminAccess(ctx); err != nil {
		return fmt.Errorf("access denied: %v", err)
	}

	// Check if policy already exists
	existing, err := ctx.GetStub().GetState("sbe_" + id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("SBE policy %s already exists", id)
	}

	// Get caller identity
	callerID, err := s.getCallerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %v", err)
	}

	policy := SBEPolicy{
		ID:                id,
		Name:              name,
		ResourceType:      resourceType,
		TriggerConditions: triggerConditions,
		RequiredEndorsers: requiredEndorsers,
		TimeoutDuration:   timeoutDuration,
		EscalationPolicy:  escalationPolicy,
		EmergencyOverride: emergencyOverride,
		CreatedBy:         callerID,
		CreatedAt:         time.Now(),
		Version:           1,
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("sbe_"+id, policyJSON)
}

// ApplySBEPolicyToResource applies an SBE policy to a specific resource
func (s *SmartContract) ApplySBEPolicyToResource(ctx contractapi.TransactionContextInterface, resourceID, policyID string) error {
	// Verify caller has appropriate privileges
	userRole, err := s.extractUserRoleFromCert(ctx)
	if err != nil {
		return fmt.Errorf("failed to extract user role: %v", err)
	}

	// Only administrators and consulting doctors can apply SBE policies
	if userRole != string(RoleAdministrator) && userRole != string(RoleConsultingDoctor) {
		return fmt.Errorf("insufficient privileges to apply SBE policy")
	}

	// Verify the SBE policy exists
	policyBytes, err := ctx.GetStub().GetState("sbe_" + policyID)
	if err != nil {
		return fmt.Errorf("failed to read SBE policy: %v", err)
	}
	if policyBytes == nil {
		return fmt.Errorf("SBE policy %s does not exist", policyID)
	}

	// Create resource-policy mapping
	mapping := map[string]interface{}{
		"resource_id": resourceID,
		"policy_id":   policyID,
		"applied_by":  userRole,
		"applied_at":  time.Now(),
	}

	mappingJSON, err := json.Marshal(mapping)
	if err != nil {
		return err
	}

	// Store the mapping
	return ctx.GetStub().PutState("sbe_mapping_"+resourceID, mappingJSON)
}

// ValidateSupervisorEndorsement validates that a supervisor can endorse a resource
func (s *SmartContract) ValidateSupervisorEndorsement(ctx contractapi.TransactionContextInterface, resourceID, supervisorID string) (bool, error) {
	// Get applicable SBE policies for the resource
	policies, err := s.getApplicableSBEPolicies(ctx, resourceID)
	if err != nil {
		return false, fmt.Errorf("failed to get applicable SBE policies: %v", err)
	}

	// If no SBE policies apply, endorsement is valid
	if len(policies) == 0 {
		return true, nil
	}

	// Get supervisor's role and attributes from certificate
	supervisorRole, err := s.getUserRole(ctx, supervisorID)
	if err != nil {
		return false, fmt.Errorf("failed to get supervisor role: %v", err)
	}

	supervisorAttrs, err := s.getUserAttributes(ctx, supervisorID)
	if err != nil {
		return false, fmt.Errorf("failed to get supervisor attributes: %v", err)
	}

	// Check each applicable policy
	for _, policy := range policies {
		valid := s.validateEndorserForSBEPolicy(supervisorRole, supervisorAttrs, policy)
		if !valid {
			return false, fmt.Errorf("supervisor %s is not authorized to endorse under policy %s", supervisorID, policy.ID)
		}
	}

	// Additional validation: Check if supervisor has required attributes
	if supervisorRole == string(RoleConsultingDoctor) {
		if supervisorAttrs["is_supervisor"] != "true" {
			return false, fmt.Errorf("consulting doctor %s is not designated as a supervisor", supervisorID)
		}
	}

	return true, nil
}

// CheckSBEPolicyTrigger checks if an SBE policy should be triggered for a resource
func (s *SmartContract) CheckSBEPolicyTrigger(ctx contractapi.TransactionContextInterface, resourceID, resourceType string, userAttributes *UserAttributes) (bool, []string, error) {
	// Get all SBE policies for the resource type
	policies, err := s.getSBEPoliciesForResourceType(ctx, resourceType)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get SBE policies: %v", err)
	}

	var triggeredPolicies []string

	// Check each policy's trigger conditions
	for _, policy := range policies {
		triggered := true
		for _, condition := range policy.TriggerConditions {
			matches, err := s.evaluateTriggerCondition(condition, userAttributes)
			if err != nil {
				return false, nil, fmt.Errorf("failed to evaluate trigger condition: %v", err)
			}
			if !matches {
				triggered = false
				break
			}
		}

		if triggered {
			triggeredPolicies = append(triggeredPolicies, policy.ID)
		}
	}

	return len(triggeredPolicies) > 0, triggeredPolicies, nil
}

// evaluateTriggerCondition evaluates a single trigger condition
func (s *SmartContract) evaluateTriggerCondition(condition TriggerCondition, userAttributes *UserAttributes) (bool, error) {
	var userValue interface{}

	// Get user attribute value
	switch condition.Attribute {
	case "is_trainee":
		userValue = userAttributes.IsTrainee
	case "role":
		userValue = userAttributes.Role
	case "specialty":
		userValue = userAttributes.Specialty
	case "ward_assignment":
		userValue = userAttributes.WardAssignment
	case "department":
		userValue = userAttributes.Department
	default:
		return false, fmt.Errorf("unknown trigger attribute: %s", condition.Attribute)
	}

	// Evaluate based on operator
	switch condition.Operator {
	case "equals":
		return userValue == condition.Value, nil
	case "not_equals":
		return userValue != condition.Value, nil
	case "contains":
		userStr, ok := userValue.(string)
		if !ok {
			return false, nil
		}
		conditionStr, ok := condition.Value.(string)
		if !ok {
			return false, nil
		}
		return strings.Contains(userStr, conditionStr), nil
	default:
		return false, fmt.Errorf("unknown trigger operator: %s", condition.Operator)
	}
}

// getSBEPoliciesForResourceType retrieves all SBE policies for a resource type
func (s *SmartContract) getSBEPoliciesForResourceType(ctx contractapi.TransactionContextInterface, resourceType string) ([]SBEPolicy, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("sbe_", "sbe_~")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var policies []SBEPolicy
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var policy SBEPolicy
		err = json.Unmarshal(queryResponse.Value, &policy)
		if err != nil {
			return nil, err
		}

		// Check if policy applies to this resource type
		if policy.ResourceType == resourceType || policy.ResourceType == "*" {
			policies = append(policies, policy)
		}
	}

	return policies, nil
}

// HandleEmergencyOverride handles emergency override procedures with enhanced logging
func (s *SmartContract) HandleEmergencyOverride(ctx contractapi.TransactionContextInterface, resourceID, overrideReason, justification string) error {
	// Get caller identity and role
	callerID, err := s.getCallerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %v", err)
	}

	callerRole, err := s.extractUserRoleFromCert(ctx)
	if err != nil {
		return fmt.Errorf("failed to extract caller role: %v", err)
	}

	// Only consulting doctors and administrators can perform emergency overrides
	if callerRole != string(RoleConsultingDoctor) && callerRole != string(RoleAdministrator) {
		return fmt.Errorf("insufficient privileges for emergency override")
	}

	// Get applicable SBE policies
	policies, err := s.getApplicableSBEPolicies(ctx, resourceID)
	if err != nil {
		return fmt.Errorf("failed to get applicable SBE policies: %v", err)
	}

	// Check if emergency override is allowed by policies
	overrideAllowed := false
	for _, policy := range policies {
		if policy.EmergencyOverride {
			overrideAllowed = true
			break
		}
	}

	if !overrideAllowed {
		return fmt.Errorf("emergency override not permitted for this resource")
	}

	// Create emergency override record
	overrideRecord := map[string]interface{}{
		"resource_id":    resourceID,
		"override_by":    callerID,
		"override_role":  callerRole,
		"reason":         overrideReason,
		"justification":  justification,
		"timestamp":      time.Now(),
		"requires_audit": true,
	}

	recordJSON, err := json.Marshal(overrideRecord)
	if err != nil {
		return fmt.Errorf("failed to marshal override record: %v", err)
	}

	// Store override record with unique key
	overrideKey := fmt.Sprintf("emergency_override_%s_%d", resourceID, time.Now().UnixNano())
	err = ctx.GetStub().PutState(overrideKey, recordJSON)
	if err != nil {
		return fmt.Errorf("failed to store emergency override record: %v", err)
	}

	// Update any existing supervision workflows to overridden status
	err = s.updateWorkflowStatusToOverridden(ctx, resourceID, callerID, overrideReason)
	if err != nil {
		return fmt.Errorf("failed to update workflow status: %v", err)
	}

	return nil
}

// updateWorkflowStatusToOverridden updates supervision workflows to overridden status
func (s *SmartContract) updateWorkflowStatusToOverridden(ctx contractapi.TransactionContextInterface, resourceID, overrideBy, reason string) error {
	// Query all workflows for this resource
	resultsIterator, err := ctx.GetStub().GetStateByRange("workflow_", "workflow_~")
	if err != nil {
		return err
	}
	defer resultsIterator.Close()

	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return err
		}

		var workflow SupervisionWorkflow
		err = json.Unmarshal(queryResponse.Value, &workflow)
		if err != nil {
			continue // Skip invalid workflows
		}

		// Check if this workflow is for the overridden resource
		if workflow.ResourceID == resourceID && (workflow.Status == "pending" || workflow.Status == "in_progress") {
			// Update workflow status
			workflow.Status = "overridden"
			if workflow.Metadata == nil {
				workflow.Metadata = make(map[string]interface{})
			}
			workflow.Metadata["override_by"] = overrideBy
			workflow.Metadata["override_reason"] = reason
			workflow.Metadata["override_timestamp"] = time.Now()

			// Save updated workflow
			workflowJSON, err := json.Marshal(workflow)
			if err != nil {
				continue // Skip if can't marshal
			}

			err = ctx.GetStub().PutState(queryResponse.Key, workflowJSON)
			if err != nil {
				continue // Skip if can't save
			}
		}
	}

	return nil
}

// ValidateEndorsementRequirements validates that all endorsement requirements are met
func (s *SmartContract) ValidateEndorsementRequirements(ctx contractapi.TransactionContextInterface, resourceID string) (bool, []string, error) {
	// Get applicable SBE policies
	policies, err := s.getApplicableSBEPolicies(ctx, resourceID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get applicable SBE policies: %v", err)
	}

	if len(policies) == 0 {
		return true, nil, nil // No SBE policies, requirements met
	}

	var missingEndorsements []string

	// Check each policy's endorsement requirements
	for _, policy := range policies {
		for _, requirement := range policy.RequiredEndorsers {
			// Count existing endorsements for this requirement
			count, err := s.countEndorsementsForRequirement(ctx, resourceID, policy.ID, requirement)
			if err != nil {
				return false, nil, fmt.Errorf("failed to count endorsements: %v", err)
			}

			if count < requirement.MinCount {
				missingEndorsements = append(missingEndorsements, 
					fmt.Sprintf("Policy %s requires %d endorsements from role %s, but only %d found", 
						policy.ID, requirement.MinCount, requirement.Role, count))
			}
		}
	}

	return len(missingEndorsements) == 0, missingEndorsements, nil
}

// countEndorsementsForRequirement counts endorsements that meet a specific requirement
func (s *SmartContract) countEndorsementsForRequirement(ctx contractapi.TransactionContextInterface, resourceID, policyID string, requirement EndorserRequirement) (int, error) {
	// Query all endorsement records for this resource and policy
	resultsIterator, err := ctx.GetStub().GetStateByRange("endorsement_", "endorsement_~")
	if err != nil {
		return 0, err
	}
	defer resultsIterator.Close()

	count := 0
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return 0, err
		}

		var record EndorsementRecord
		err = json.Unmarshal(queryResponse.Value, &record)
		if err != nil {
			continue // Skip invalid records
		}

		// Check if this endorsement matches the requirement
		if record.ResourceID == resourceID && record.PolicyID == policyID && record.EndorserRole == requirement.Role {
			// Additional attribute validation could be added here
			count++
		}
	}

	return count, nil
}

// CreateSupervisionWorkflow creates a new supervision workflow
func (s *SmartContract) CreateSupervisionWorkflow(ctx contractapi.TransactionContextInterface, workflowID, traineeID, resourceID, workflowType string, requiredActions []SupervisionAction, expirationHours int) error {
	// Verify caller is a trainee or supervisor
	userRole, err := s.extractUserRoleFromCert(ctx)
	if err != nil {
		return fmt.Errorf("failed to extract user role: %v", err)
	}

	if userRole != string(RoleMDStudent) && userRole != string(RoleMBBSStudent) && userRole != string(RoleConsultingDoctor) {
		return fmt.Errorf("only trainees and supervisors can create supervision workflows")
	}

	// Check if workflow already exists
	existing, err := ctx.GetStub().GetState("workflow_" + workflowID)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("supervision workflow %s already exists", workflowID)
	}

	workflow := SupervisionWorkflow{
		ID:              workflowID,
		TraineeID:       traineeID,
		ResourceID:      resourceID,
		WorkflowType:    workflowType,
		Status:          "pending",
		RequiredActions: requiredActions,
		CompletedActions: []CompletedAction{},
		CreatedAt:       time.Now(),
		ExpiresAt:       time.Now().Add(time.Duration(expirationHours) * time.Hour),
		Metadata:        make(map[string]interface{}),
	}

	workflowJSON, err := json.Marshal(workflow)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("workflow_"+workflowID, workflowJSON)
}

// CompleteSupervisionAction completes a supervision action
func (s *SmartContract) CompleteSupervisionAction(ctx contractapi.TransactionContextInterface, workflowID, actionType, signature, comments string) error {
	// Get the workflow
	workflowBytes, err := ctx.GetStub().GetState("workflow_" + workflowID)
	if err != nil {
		return fmt.Errorf("failed to read workflow: %v", err)
	}
	if workflowBytes == nil {
		return fmt.Errorf("workflow %s does not exist", workflowID)
	}

	var workflow SupervisionWorkflow
	err = json.Unmarshal(workflowBytes, &workflow)
	if err != nil {
		return fmt.Errorf("failed to unmarshal workflow: %v", err)
	}

	// Check if workflow is still active
	if workflow.Status == "completed" || workflow.Status == "expired" {
		return fmt.Errorf("workflow %s is no longer active", workflowID)
	}

	// Get caller identity
	callerID, err := s.getCallerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %v", err)
	}

	// Find the required action
	var requiredAction *SupervisionAction
	for _, action := range workflow.RequiredActions {
		if action.Type == actionType {
			requiredAction = &action
			break
		}
	}

	if requiredAction == nil {
		return fmt.Errorf("action type %s is not required for this workflow", actionType)
	}

	// Create completed action
	completedAction := CompletedAction{
		Action:      *requiredAction,
		CompletedBy: callerID,
		CompletedAt: time.Now(),
		Signature:   signature,
		Comments:    comments,
	}

	// Add to completed actions
	workflow.CompletedActions = append(workflow.CompletedActions, completedAction)

	// Check if all required actions are completed
	if s.areAllRequiredActionsCompleted(workflow) {
		workflow.Status = "completed"
	} else {
		workflow.Status = "in_progress"
	}

	// Update workflow
	workflowJSON, err := json.Marshal(workflow)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("workflow_"+workflowID, workflowJSON)
}

// CreateEndorsementRecord creates an endorsement record for SBE policy
func (s *SmartContract) CreateEndorsementRecord(ctx contractapi.TransactionContextInterface, recordID, resourceID, policyID, signature, comments string) error {
	// Get caller identity and role
	callerID, err := s.getCallerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %v", err)
	}

	callerRole, err := s.extractUserRoleFromCert(ctx)
	if err != nil {
		return fmt.Errorf("failed to extract user role: %v", err)
	}

	// Validate supervisor endorsement
	valid, err := s.ValidateSupervisorEndorsement(ctx, resourceID, callerID)
	if err != nil {
		return fmt.Errorf("endorsement validation failed: %v", err)
	}
	if !valid {
		return fmt.Errorf("caller is not authorized to endorse this resource")
	}

	record := EndorsementRecord{
		ID:           recordID,
		ResourceID:   resourceID,
		PolicyID:     policyID,
		EndorserID:   callerID,
		EndorserRole: callerRole,
		Signature:    signature,
		Timestamp:    time.Now(),
		Comments:     comments,
	}

	recordJSON, err := json.Marshal(record)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("endorsement_"+recordID, recordJSON)
}

// GetSBEPolicy retrieves an SBE policy by ID
func (s *SmartContract) GetSBEPolicy(ctx contractapi.TransactionContextInterface, id string) (*SBEPolicy, error) {
	policyJSON, err := ctx.GetStub().GetState("sbe_" + id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if policyJSON == nil {
		return nil, fmt.Errorf("SBE policy %s does not exist", id)
	}

	var policy SBEPolicy
	err = json.Unmarshal(policyJSON, &policy)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

// GetSupervisionWorkflow retrieves a supervision workflow by ID
func (s *SmartContract) GetSupervisionWorkflow(ctx contractapi.TransactionContextInterface, id string) (*SupervisionWorkflow, error) {
	workflowJSON, err := ctx.GetStub().GetState("workflow_" + id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if workflowJSON == nil {
		return nil, fmt.Errorf("supervision workflow %s does not exist", id)
	}

	var workflow SupervisionWorkflow
	err = json.Unmarshal(workflowJSON, &workflow)
	if err != nil {
		return nil, err
	}

	return &workflow, nil
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

// getRoleHierarchyLevel returns the hierarchy level for a role (higher number = higher privilege)
func (s *SmartContract) getRoleHierarchyLevel(role string) int {
	roleHierarchy := map[string]int{
		string(RolePatient):           1,
		string(RoleMBBSStudent):      2,
		string(RoleMDStudent):        3,
		string(RoleReceptionist):     3,
		string(RoleLabTechnician):    4,
		string(RoleNurse):            4,
		string(RoleClinicalStaff):    5,
		string(RoleConsultingDoctor): 6,
		string(RoleAdministrator):    7,
	}

	if level, exists := roleHierarchy[role]; exists {
		return level
	}
	return 0
}

// canRoleAccessResource checks if a role can access a specific resource type
func (s *SmartContract) canRoleAccessResource(role, resourceType string) bool {
	// Define role-resource access matrix
	accessMatrix := map[string][]string{
		string(RolePatient): {"ehr", "appointment", "communication"},
		string(RoleMBBSStudent): {"ehr", "training_data"},
		string(RoleMDStudent): {"ehr", "cpoe_order", "clinical_notes"},
		string(RoleConsultingDoctor): {"ehr", "cpoe_order", "clinical_notes", "supervision", "specialized_service"},
		string(RoleNurse): {"ehr", "medication_administration", "nursing_notes"},
		string(RoleLabTechnician): {"lab_results", "lab_orders"},
		string(RoleReceptionist): {"patient_registration", "appointment", "demographics"},
		string(RoleClinicalStaff): {"specialized_service", "ehr"},
		string(RoleAdministrator): {"*"}, // Administrator can access all resources
	}

	allowedResources, exists := accessMatrix[role]
	if !exists {
		return false
	}

	// Check if role can access all resources
	for _, resource := range allowedResources {
		if resource == "*" || resource == resourceType {
			return true
		}
	}

	return false
}

// ValidateRoleHierarchy validates if a user can perform an action based on role hierarchy
func (s *SmartContract) ValidateRoleHierarchy(ctx contractapi.TransactionContextInterface, targetUserRole, requiredRole string) (bool, error) {
	// Get caller's role
	callerRole, err := s.extractUserRoleFromCert(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to extract caller role: %v", err)
	}

	// Get hierarchy levels
	callerLevel := s.getRoleHierarchyLevel(callerRole)
	targetLevel := s.getRoleHierarchyLevel(targetUserRole)
	requiredLevel := s.getRoleHierarchyLevel(requiredRole)

	// Caller must have at least the required level and be at or above target level
	return callerLevel >= requiredLevel && callerLevel >= targetLevel, nil
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

// getApplicableSBEPolicies retrieves SBE policies applicable to a resource
func (s *SmartContract) getApplicableSBEPolicies(ctx contractapi.TransactionContextInterface, resourceID string) ([]SBEPolicy, error) {
	// Get resource-policy mapping
	mappingBytes, err := ctx.GetStub().GetState("sbe_mapping_" + resourceID)
	if err != nil {
		return nil, fmt.Errorf("failed to read SBE mapping: %v", err)
	}
	if mappingBytes == nil {
		// No SBE policies apply to this resource
		return []SBEPolicy{}, nil
	}

	var mapping map[string]interface{}
	err = json.Unmarshal(mappingBytes, &mapping)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SBE mapping: %v", err)
	}

	policyID, ok := mapping["policy_id"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid policy ID in mapping")
	}

	// Get the SBE policy
	policy, err := s.GetSBEPolicy(ctx, policyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get SBE policy: %v", err)
	}

	return []SBEPolicy{*policy}, nil
}

// getUserRole gets a user's role (placeholder implementation)
func (s *SmartContract) getUserRole(ctx contractapi.TransactionContextInterface, userID string) (string, error) {
	// In a real implementation, this would query user data from the ledger
	// or from an external identity service
	// For now, return a placeholder based on userID patterns
	
	if strings.Contains(userID, "consulting") {
		return string(RoleConsultingDoctor), nil
	} else if strings.Contains(userID, "md_student") {
		return string(RoleMDStudent), nil
	} else if strings.Contains(userID, "mbbs_student") {
		return string(RoleMBBSStudent), nil
	}
	
	// Default to consulting doctor for supervisors
	return string(RoleConsultingDoctor), nil
}

// getUserAttributes gets a user's attributes (placeholder implementation)
func (s *SmartContract) getUserAttributes(ctx contractapi.TransactionContextInterface, userID string) (map[string]string, error) {
	// In a real implementation, this would extract attributes from the user's certificate
	// or query from an external service
	
	attributes := make(map[string]string)
	
	// Add placeholder attributes based on user role
	role, err := s.getUserRole(ctx, userID)
	if err != nil {
		return nil, err
	}
	
	attributes["role"] = role
	
	if role == string(RoleConsultingDoctor) {
		attributes["is_supervisor"] = "true"
		attributes["specialty"] = "internal_medicine" // placeholder
	}
	
	return attributes, nil
}

// validateEndorserForSBEPolicy validates if an endorser meets SBE policy requirements
func (s *SmartContract) validateEndorserForSBEPolicy(endorserRole string, endorserAttrs map[string]string, policy SBEPolicy) bool {
	// Check each endorser requirement in the policy
	for _, requirement := range policy.RequiredEndorsers {
		if requirement.Role == endorserRole {
			// Check attribute requirements
			for attrKey, attrValue := range requirement.Attributes {
				if endorserAttrs[attrKey] != attrValue {
					return false
				}
			}
			return true
		}
	}
	
	return false
}

// areAllRequiredActionsCompleted checks if all required actions in a workflow are completed
func (s *SmartContract) areAllRequiredActionsCompleted(workflow SupervisionWorkflow) bool {
	completedTypes := make(map[string]bool)
	for _, completed := range workflow.CompletedActions {
		completedTypes[completed.Action.Type] = true
	}

	for _, required := range workflow.RequiredActions {
		if required.Required && !completedTypes[required.Type] {
			return false
		}
	}

	return true
}

// CreateABACPolicy creates a new Attribute-Based Access Control policy
func (s *SmartContract) CreateABACPolicy(ctx contractapi.TransactionContextInterface, id, name, resourceType string, rules []ABACRule, conditions []AttributeCondition, effect string, priority int) error {
	// Verify caller has admin privileges
	if err := s.verifyAdminAccess(ctx); err != nil {
		return fmt.Errorf("access denied: %v", err)
	}

	// Check if policy already exists
	existing, err := ctx.GetStub().GetState("abac_" + id)
	if err != nil {
		return fmt.Errorf("failed to read from world state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("ABAC policy %s already exists", id)
	}

	// Validate effect
	if effect != "allow" && effect != "deny" {
		return fmt.Errorf("invalid effect: %s, must be 'allow' or 'deny'", effect)
	}

	// Get caller identity
	callerID, err := s.getCallerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("failed to get caller identity: %v", err)
	}

	policy := ABACPolicy{
		ID:           id,
		Name:         name,
		ResourceType: resourceType,
		Rules:        rules,
		Conditions:   conditions,
		Effect:       effect,
		Priority:     priority,
		CreatedBy:    callerID,
		CreatedAt:    time.Now(),
	}

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState("abac_"+id, policyJSON)
}

// extractUserAttributesFromCert extracts user attributes from X.509 certificate
func (s *SmartContract) extractUserAttributesFromCert(ctx contractapi.TransactionContextInterface) (*UserAttributes, error) {
	clientIdentity := ctx.GetClientIdentity()
	
	// Extract role attribute
	role, found, err := clientIdentity.GetAttributeValue("role")
	if err != nil {
		return nil, fmt.Errorf("failed to get role attribute: %v", err)
	}
	if !found {
		return nil, fmt.Errorf("role attribute not found in certificate")
	}

	attributes := &UserAttributes{
		Role: role,
	}

	// Extract optional attributes
	if specialty, found, _ := clientIdentity.GetAttributeValue("specialty"); found {
		attributes.Specialty = specialty
	}

	if isTrainee, found, _ := clientIdentity.GetAttributeValue("is_trainee"); found {
		attributes.IsTrainee = isTrainee == "true"
	}

	if isSupervisor, found, _ := clientIdentity.GetAttributeValue("is_supervisor"); found {
		attributes.IsSupervisor = isSupervisor == "true"
	}

	if wardAssignment, found, _ := clientIdentity.GetAttributeValue("ward_assignment"); found {
		attributes.WardAssignment = wardAssignment
	}

	if labOrg, found, _ := clientIdentity.GetAttributeValue("lab_org"); found {
		attributes.LabOrg = labOrg
	}

	if department, found, _ := clientIdentity.GetAttributeValue("department"); found {
		attributes.Department = department
	}

	return attributes, nil
}

// validateABACPolicies validates access using Attribute-Based Access Control policies
func (s *SmartContract) validateABACPolicies(ctx contractapi.TransactionContextInterface, userAttributes *UserAttributes, resourceType, resourceID, action string) (bool, error) {
	// Get all ABAC policies for the resource type
	abacPolicies, err := s.getABACPoliciesForResource(ctx, resourceType)
	if err != nil {
		return false, fmt.Errorf("failed to get ABAC policies: %v", err)
	}

	// If no ABAC policies exist, allow access (RBAC already validated)
	if len(abacPolicies) == 0 {
		return true, nil
	}

	// Sort policies by priority (higher priority first)
	for i := 0; i < len(abacPolicies)-1; i++ {
		for j := i + 1; j < len(abacPolicies); j++ {
			if abacPolicies[i].Priority < abacPolicies[j].Priority {
				abacPolicies[i], abacPolicies[j] = abacPolicies[j], abacPolicies[i]
			}
		}
	}

	// Evaluate policies in priority order
	for _, policy := range abacPolicies {
		matches, err := s.evaluateABACPolicy(policy, userAttributes, resourceID, action)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate ABAC policy %s: %v", policy.ID, err)
		}

		if matches {
			// Policy matches, return based on effect
			return policy.Effect == "allow", nil
		}
	}

	// No policies matched, default to allow (RBAC already validated)
	return true, nil
}

// getABACPoliciesForResource retrieves ABAC policies for a specific resource type
func (s *SmartContract) getABACPoliciesForResource(ctx contractapi.TransactionContextInterface, resourceType string) ([]ABACPolicy, error) {
	resultsIterator, err := ctx.GetStub().GetStateByRange("abac_", "abac_~")
	if err != nil {
		return nil, err
	}
	defer resultsIterator.Close()

	var policies []ABACPolicy
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var policy ABACPolicy
		err = json.Unmarshal(queryResponse.Value, &policy)
		if err != nil {
			return nil, err
		}

		// Check if policy applies to this resource type
		if policy.ResourceType == resourceType || policy.ResourceType == "*" {
			policies = append(policies, policy)
		}
	}

	return policies, nil
}

// evaluateABACPolicy evaluates a single ABAC policy against user attributes
func (s *SmartContract) evaluateABACPolicy(policy ABACPolicy, userAttributes *UserAttributes, resourceID, action string) (bool, error) {
	// Check all rules
	for _, rule := range policy.Rules {
		matches, err := s.evaluateABACRule(rule, userAttributes)
		if err != nil {
			return false, err
		}

		if rule.Required && !matches {
			return false, nil
		}
	}

	// Check all conditions
	for _, condition := range policy.Conditions {
		matches, err := s.evaluateAttributeCondition(condition, userAttributes, resourceID)
		if err != nil {
			return false, err
		}

		if !matches {
			return false, nil
		}
	}

	return true, nil
}

// evaluateABACRule evaluates a single ABAC rule
func (s *SmartContract) evaluateABACRule(rule ABACRule, userAttributes *UserAttributes) (bool, error) {
	var userValue interface{}

	// Get user attribute value
	switch rule.Attribute {
	case "role":
		userValue = userAttributes.Role
	case "specialty":
		userValue = userAttributes.Specialty
	case "is_trainee":
		userValue = userAttributes.IsTrainee
	case "is_supervisor":
		userValue = userAttributes.IsSupervisor
	case "ward_assignment":
		userValue = userAttributes.WardAssignment
	case "lab_org":
		userValue = userAttributes.LabOrg
	case "department":
		userValue = userAttributes.Department
	case "level":
		userValue = userAttributes.Level
	default:
		return false, fmt.Errorf("unknown attribute: %s", rule.Attribute)
	}

	// Evaluate based on operator
	switch rule.Operator {
	case "equals":
		return userValue == rule.Value, nil
	case "not_equals":
		return userValue != rule.Value, nil
	case "contains":
		userStr, ok := userValue.(string)
		if !ok {
			return false, nil
		}
		ruleStr, ok := rule.Value.(string)
		if !ok {
			return false, nil
		}
		return strings.Contains(userStr, ruleStr), nil
	case "in":
		ruleSlice, ok := rule.Value.([]interface{})
		if !ok {
			return false, nil
		}
		for _, v := range ruleSlice {
			if userValue == v {
				return true, nil
			}
		}
		return false, nil
	case "not_in":
		ruleSlice, ok := rule.Value.([]interface{})
		if !ok {
			return false, nil
		}
		for _, v := range ruleSlice {
			if userValue == v {
				return false, nil
			}
		}
		return true, nil
	default:
		return false, fmt.Errorf("unknown operator: %s", rule.Operator)
	}
}

// evaluateAttributeCondition evaluates contextual conditions
func (s *SmartContract) evaluateAttributeCondition(condition AttributeCondition, userAttributes *UserAttributes, resourceID string) (bool, error) {
	switch condition.Type {
	case "ward_assignment":
		if condition.Constraint == "ward_match" {
			// Check if user's ward assignment matches resource ward
			// This would require additional context about resource ward
			// For now, return true if user has ward assignment
			return userAttributes.WardAssignment != "", nil
		}
	case "patient_assignment":
		if condition.Constraint == "assigned_patients" {
			// Check if user is assigned to this patient
			// This would require additional context about patient assignments
			// For now, return true for supervisors and consulting doctors
			return userAttributes.IsSupervisor || userAttributes.Role == string(RoleConsultingDoctor), nil
		}
	case "time":
		if condition.Constraint == "business_hours" {
			// Check if current time is within business hours
			now := time.Now()
			hour := now.Hour()
			// Business hours: 8 AM to 6 PM
			return hour >= 8 && hour < 18, nil
		}
	}

	// Default to true for unknown conditions
	return true, nil
}

// GetABACPolicy retrieves an ABAC policy by ID
func (s *SmartContract) GetABACPolicy(ctx contractapi.TransactionContextInterface, id string) (*ABACPolicy, error) {
	policyJSON, err := ctx.GetStub().GetState("abac_" + id)
	if err != nil {
		return nil, fmt.Errorf("failed to read from world state: %v", err)
	}
	if policyJSON == nil {
		return nil, fmt.Errorf("ABAC policy %s does not exist", id)
	}

	var policy ABACPolicy
	err = json.Unmarshal(policyJSON, &policy)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}