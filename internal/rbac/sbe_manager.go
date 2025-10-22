package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// PolicyStorage defines the interface for SBE policy storage
type PolicyStorage interface {
	StorePolicyVersion(ctx context.Context, policy *rbac.SBEPolicy, version int) error
	GetPolicyVersion(ctx context.Context, policyID string, version int) (*rbac.SBEPolicy, error)
	GetLatestPolicy(ctx context.Context, policyID string) (*rbac.SBEPolicy, error)
	ListPolicyVersions(ctx context.Context, policyID string) ([]int, error)
	DeletePolicy(ctx context.Context, policyID string) error
	ListActivePolicies(ctx context.Context) ([]*rbac.SBEPolicy, error)
}

// InMemoryPolicyStorage provides in-memory storage for SBE policies
type InMemoryPolicyStorage struct {
	mu       sync.RWMutex
	policies map[string]map[int]*rbac.SBEPolicy // policyID -> version -> policy
	latest   map[string]int                     // policyID -> latest version
}

// NewInMemoryPolicyStorage creates a new in-memory policy storage
func NewInMemoryPolicyStorage() *InMemoryPolicyStorage {
	return &InMemoryPolicyStorage{
		policies: make(map[string]map[int]*rbac.SBEPolicy),
		latest:   make(map[string]int),
	}
}

// StorePolicyVersion stores a policy version
func (s *InMemoryPolicyStorage) StorePolicyVersion(ctx context.Context, policy *rbac.SBEPolicy, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.policies[policy.ID] == nil {
		s.policies[policy.ID] = make(map[int]*rbac.SBEPolicy)
	}

	// Deep copy the policy to avoid mutations
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to serialize policy: %w", err)
	}

	var policyCopy rbac.SBEPolicy
	if err := json.Unmarshal(policyBytes, &policyCopy); err != nil {
		return fmt.Errorf("failed to deserialize policy: %w", err)
	}

	s.policies[policy.ID][version] = &policyCopy
	s.latest[policy.ID] = version

	return nil
}

// GetPolicyVersion retrieves a specific policy version
func (s *InMemoryPolicyStorage) GetPolicyVersion(ctx context.Context, policyID string, version int) (*rbac.SBEPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions, exists := s.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	policy, exists := versions[version]
	if !exists {
		return nil, fmt.Errorf("policy %s version %d not found", policyID, version)
	}

	return policy, nil
}

// GetLatestPolicy retrieves the latest version of a policy
func (s *InMemoryPolicyStorage) GetLatestPolicy(ctx context.Context, policyID string) (*rbac.SBEPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	latestVersion, exists := s.latest[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	return s.policies[policyID][latestVersion], nil
}

// ListPolicyVersions lists all versions of a policy
func (s *InMemoryPolicyStorage) ListPolicyVersions(ctx context.Context, policyID string) ([]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions, exists := s.policies[policyID]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", policyID)
	}

	var versionList []int
	for version := range versions {
		versionList = append(versionList, version)
	}

	return versionList, nil
}

// DeletePolicy deletes all versions of a policy
func (s *InMemoryPolicyStorage) DeletePolicy(ctx context.Context, policyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.policies, policyID)
	delete(s.latest, policyID)

	return nil
}

// ListActivePolicies lists all active policies (latest versions)
func (s *InMemoryPolicyStorage) ListActivePolicies(ctx context.Context) ([]*rbac.SBEPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var activePolicies []*rbac.SBEPolicy
	for policyID, latestVersion := range s.latest {
		policy := s.policies[policyID][latestVersion]
		activePolicies = append(activePolicies, policy)
	}

	return activePolicies, nil
}

// SBEPolicyManager implements State-Based Endorsement policy management
type SBEPolicyManager struct {
	config   *Config
	logger   *logrus.Logger
	storage  PolicyStorage
	mu       sync.RWMutex
}

// NewSBEPolicyManager creates a new SBE policy manager
func NewSBEPolicyManager(config *Config, logger *logrus.Logger) (*SBEPolicyManager, error) {
	storage := NewInMemoryPolicyStorage()
	
	return &SBEPolicyManager{
		config:  config,
		logger:  logger,
		storage: storage,
	}, nil
}

// NewSBEPolicyManagerWithStorage creates a new SBE policy manager with custom storage
func NewSBEPolicyManagerWithStorage(config *Config, logger *logrus.Logger, storage PolicyStorage) (*SBEPolicyManager, error) {
	return &SBEPolicyManager{
		config:  config,
		logger:  logger,
		storage: storage,
	}, nil
}

// CreateSBEPolicy creates a new State-Based Endorsement policy
func (m *SBEPolicyManager) CreateSBEPolicy(ctx context.Context, policy *rbac.SBEPolicy) error {
	if err := m.validateSBEPolicy(policy); err != nil {
		return fmt.Errorf("invalid SBE policy: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if policy already exists
	if _, err := m.storage.GetLatestPolicy(ctx, policy.ID); err == nil {
		return fmt.Errorf("policy %s already exists", policy.ID)
	}

	// Store as version 1
	if err := m.storage.StorePolicyVersion(ctx, policy, 1); err != nil {
		return fmt.Errorf("failed to store policy: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"policy_id":     policy.ID,
		"policy_name":   policy.Name,
		"resource_type": policy.ResourceType,
		"version":       1,
	}).Info("Created SBE policy")

	return nil
}

// UpdateSBEPolicy updates an existing SBE policy with a new version
func (m *SBEPolicyManager) UpdateSBEPolicy(ctx context.Context, policy *rbac.SBEPolicy) error {
	if err := m.validateSBEPolicy(policy); err != nil {
		return fmt.Errorf("invalid SBE policy: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Get current versions to determine next version number
	versions, err := m.storage.ListPolicyVersions(ctx, policy.ID)
	if err != nil {
		return fmt.Errorf("policy %s not found: %w", policy.ID, err)
	}

	// Find the highest version number
	maxVersion := 0
	for _, version := range versions {
		if version > maxVersion {
			maxVersion = version
		}
	}

	nextVersion := maxVersion + 1

	// Store the new version
	if err := m.storage.StorePolicyVersion(ctx, policy, nextVersion); err != nil {
		return fmt.Errorf("failed to store policy version: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"policy_id":     policy.ID,
		"policy_name":   policy.Name,
		"resource_type": policy.ResourceType,
		"version":       nextVersion,
		"prev_version":  maxVersion,
	}).Info("Updated SBE policy")

	return nil
}

// GetSBEPolicy retrieves the latest version of an SBE policy
func (m *SBEPolicyManager) GetSBEPolicy(ctx context.Context, policyID string) (*rbac.SBEPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.storage.GetLatestPolicy(ctx, policyID)
}

// GetSBEPolicyVersion retrieves a specific version of an SBE policy
func (m *SBEPolicyManager) GetSBEPolicyVersion(ctx context.Context, policyID string, version int) (*rbac.SBEPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.storage.GetPolicyVersion(ctx, policyID, version)
}

// ListSBEPolicyVersions lists all versions of an SBE policy
func (m *SBEPolicyManager) ListSBEPolicyVersions(ctx context.Context, policyID string) ([]int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.storage.ListPolicyVersions(ctx, policyID)
}

// RollbackSBEPolicy rolls back an SBE policy to a previous version
func (m *SBEPolicyManager) RollbackSBEPolicy(ctx context.Context, policyID string, targetVersion int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get the target version policy
	targetPolicy, err := m.storage.GetPolicyVersion(ctx, policyID, targetVersion)
	if err != nil {
		return fmt.Errorf("failed to get target version %d: %w", targetVersion, err)
	}

	// Get current versions to determine next version number
	versions, err := m.storage.ListPolicyVersions(ctx, policyID)
	if err != nil {
		return fmt.Errorf("failed to list policy versions: %w", err)
	}

	// Find the highest version number
	maxVersion := 0
	for _, version := range versions {
		if version > maxVersion {
			maxVersion = version
		}
	}

	nextVersion := maxVersion + 1

	// Store the rollback as a new version (maintaining audit trail)
	if err := m.storage.StorePolicyVersion(ctx, targetPolicy, nextVersion); err != nil {
		return fmt.Errorf("failed to store rollback version: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"policy_id":      policyID,
		"target_version": targetVersion,
		"new_version":    nextVersion,
		"rolled_back_from": maxVersion,
	}).Info("Rolled back SBE policy")

	return nil
}

// DeleteSBEPolicy deletes an SBE policy and all its versions
func (m *SBEPolicyManager) DeleteSBEPolicy(ctx context.Context, policyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.storage.DeletePolicy(ctx, policyID); err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"policy_id": policyID,
	}).Info("Deleted SBE policy")

	return nil
}

// ListActiveSBEPolicies lists all active SBE policies
func (m *SBEPolicyManager) ListActiveSBEPolicies(ctx context.Context) ([]*rbac.SBEPolicy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.storage.ListActivePolicies(ctx)
}

// ApplySBEPolicy applies an SBE policy to a specific resource
func (m *SBEPolicyManager) ApplySBEPolicy(ctx context.Context, resourceID string, policy *rbac.SBEPolicy) error {
	m.logger.WithFields(logrus.Fields{
		"resource_id": resourceID,
		"policy_id":   policy.ID,
	}).Debug("Applying SBE policy to resource")

	// In a real implementation, this would:
	// 1. Store the policy application in the blockchain
	// 2. Set up the endorsement requirements for the resource
	// 3. Configure the chaincode to enforce the policy

	// For now, we'll just log the application
	m.logger.WithFields(logrus.Fields{
		"resource_id": resourceID,
		"policy_id":   policy.ID,
		"endorsers":   len(policy.RequiredEndorsers),
	}).Info("SBE policy applied to resource")

	return nil
}

// ValidateSupervisorEndorsement validates that a supervisor can endorse a resource
func (m *SBEPolicyManager) ValidateSupervisorEndorsement(ctx context.Context, resourceID, supervisorID string) error {
	m.logger.WithFields(logrus.Fields{
		"resource_id":   resourceID,
		"supervisor_id": supervisorID,
	}).Debug("Validating supervisor endorsement")

	// Get applicable SBE policies for the resource
	policies := m.getApplicablePolicies(resourceID)
	if len(policies) == 0 {
		// No SBE policies apply, endorsement is valid
		return nil
	}

	// Check each applicable policy
	for _, policy := range policies {
		valid, err := m.validateEndorserForPolicy(supervisorID, policy)
		if err != nil {
			return fmt.Errorf("failed to validate endorser for policy %s: %w", policy.ID, err)
		}

		if !valid {
			return rbac.NewRBACError(
				rbac.ErrorTypeSBEPolicyViolation,
				rbac.ErrorCodeSBEPolicyViolation,
				fmt.Sprintf("Supervisor %s is not authorized to endorse under policy %s", supervisorID, policy.ID),
			)
		}
	}

	m.logger.WithFields(logrus.Fields{
		"resource_id":   resourceID,
		"supervisor_id": supervisorID,
	}).Info("Supervisor endorsement validated successfully")

	return nil
}

// GetRequiredEndorsers returns the list of required endorsers for a resource
func (m *SBEPolicyManager) GetRequiredEndorsers(ctx context.Context, resourceID string) ([]string, error) {
	policies := m.getApplicablePolicies(resourceID)
	if len(policies) == 0 {
		return []string{}, nil
	}

	var allEndorsers []string
	for _, policy := range policies {
		for _, requirement := range policy.RequiredEndorsers {
			// In a real implementation, this would query the user database
			// to find users matching the endorser requirements
			endorsers := m.findEndorsersForRequirement(requirement)
			allEndorsers = append(allEndorsers, endorsers...)
		}
	}

	// Remove duplicates
	uniqueEndorsers := m.removeDuplicates(allEndorsers)

	m.logger.WithFields(logrus.Fields{
		"resource_id":      resourceID,
		"endorsers_count":  len(uniqueEndorsers),
		"policies_applied": len(policies),
	}).Debug("Retrieved required endorsers")

	return uniqueEndorsers, nil
}

// HandleEmergencyOverride handles emergency override requests
func (m *SBEPolicyManager) HandleEmergencyOverride(ctx context.Context, req *rbac.EmergencyOverrideRequest) error {
	m.logger.WithFields(logrus.Fields{
		"user_id":     req.UserID,
		"resource_id": req.ResourceID,
		"action":      req.Action,
		"reason":      req.Reason,
	}).Warn("Processing emergency override request")

	// Validate emergency override request
	if err := m.validateEmergencyOverride(req); err != nil {
		return fmt.Errorf("invalid emergency override request: %w", err)
	}

	// Check if emergency overrides are enabled for applicable policies
	policies := m.getApplicablePolicies(req.ResourceID)
	for _, policy := range policies {
		if !policy.EmergencyOverride {
			return rbac.NewRBACError(
				rbac.ErrorTypeEmergencyOverride,
				rbac.ErrorCodeEmergencyOverride,
				fmt.Sprintf("Emergency override not allowed for policy %s", policy.ID),
			)
		}
	}

	// In a real implementation, this would:
	// 1. Create an immutable audit record of the override
	// 2. Notify relevant supervisors and administrators
	// 3. Set up enhanced monitoring for the user
	// 4. Apply temporary elevated permissions with automatic expiry

	m.logger.WithFields(logrus.Fields{
		"user_id":       req.UserID,
		"resource_id":   req.ResourceID,
		"justification": req.Justification,
	}).Warn("Emergency override granted")

	return nil
}

// Helper methods

func (m *SBEPolicyManager) validateSBEPolicy(policy *rbac.SBEPolicy) error {
	var validationErrors rbac.ValidationErrors

	if policy.ID == "" {
		validationErrors.Add("id", policy.ID, "Policy ID is required")
	}

	if policy.Name == "" {
		validationErrors.Add("name", policy.Name, "Policy name is required")
	}

	if policy.ResourceType == "" {
		validationErrors.Add("resource_type", policy.ResourceType, "Resource type is required")
	}

	if len(policy.RequiredEndorsers) == 0 {
		validationErrors.Add("required_endorsers", "empty", "At least one endorser requirement is required")
	}

	if policy.TimeoutDuration <= 0 {
		validationErrors.Add("timeout_duration", policy.TimeoutDuration.String(), "Timeout duration must be positive")
	}

	// Validate endorser requirements
	for i, endorser := range policy.RequiredEndorsers {
		if endorser.Role == "" {
			validationErrors.Add(fmt.Sprintf("required_endorsers[%d].role", i), endorser.Role, "Endorser role is required")
		}

		if endorser.MinCount <= 0 {
			validationErrors.Add(fmt.Sprintf("required_endorsers[%d].min_count", i), fmt.Sprintf("%d", endorser.MinCount), "Minimum count must be positive")
		}

		if endorser.MaxCount > 0 && endorser.MaxCount < endorser.MinCount {
			validationErrors.Add(fmt.Sprintf("required_endorsers[%d].max_count", i), fmt.Sprintf("%d", endorser.MaxCount), "Maximum count must be greater than or equal to minimum count")
		}
	}

	if validationErrors.HasErrors() {
		return &validationErrors
	}

	return nil
}

func (m *SBEPolicyManager) getApplicablePolicies(resourceID string) []*rbac.SBEPolicy {
	var applicable []*rbac.SBEPolicy

	// Get all active policies
	activePolicies, err := m.storage.ListActivePolicies(context.Background())
	if err != nil {
		m.logger.WithError(err).Error("Failed to list active policies")
		return applicable
	}

	// Filter policies based on resource type and trigger conditions
	for _, policy := range activePolicies {
		if m.isPolicyApplicableToResource(policy, resourceID) {
			applicable = append(applicable, policy)
		}
	}

	return applicable
}

func (m *SBEPolicyManager) isPolicyApplicableToResource(policy *rbac.SBEPolicy, resourceID string) bool {
	// In a real implementation, this would:
	// 1. Extract resource type from resourceID
	// 2. Match against policy.ResourceType
	// 3. Evaluate trigger conditions against resource attributes
	// 4. Check effective date ranges
	
	// For now, assume all policies are applicable as a placeholder
	// This should be enhanced based on actual resource metadata
	return true
}

func (m *SBEPolicyManager) validateEndorserForPolicy(endorserID string, policy *rbac.SBEPolicy) (bool, error) {
	// In a real implementation, this would:
	// 1. Get the endorser's role and attributes
	// 2. Check against each endorser requirement in the policy
	// 3. Validate attribute constraints

	// For now, assume validation passes if the endorser ID is not empty
	return endorserID != "", nil
}

func (m *SBEPolicyManager) findEndorsersForRequirement(requirement rbac.EndorserRequirement) []string {
	// In a real implementation, this would query the user database
	// to find users with the specified role and attributes

	// For now, return placeholder endorsers
	var endorsers []string
	for i := 0; i < requirement.MinCount; i++ {
		endorsers = append(endorsers, fmt.Sprintf("%s_user_%d", requirement.Role, i+1))
	}

	return endorsers
}

func (m *SBEPolicyManager) removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var unique []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			unique = append(unique, item)
		}
	}

	return unique
}

func (m *SBEPolicyManager) validateEmergencyOverride(req *rbac.EmergencyOverrideRequest) error {
	var validationErrors rbac.ValidationErrors

	if req.UserID == "" {
		validationErrors.Add("user_id", req.UserID, "User ID is required")
	}

	if req.ResourceID == "" {
		validationErrors.Add("resource_id", req.ResourceID, "Resource ID is required")
	}

	if req.Action == "" {
		validationErrors.Add("action", req.Action, "Action is required")
	}

	if req.Reason == "" {
		validationErrors.Add("reason", req.Reason, "Reason is required")
	}

	if req.Justification == "" {
		validationErrors.Add("justification", req.Justification, "Justification is required")
	}

	if req.Timestamp.IsZero() {
		validationErrors.Add("timestamp", req.Timestamp.String(), "Timestamp is required")
	}

	// Check if the override request is too old (security measure)
	if time.Since(req.Timestamp) > time.Hour {
		validationErrors.Add("timestamp", req.Timestamp.String(), "Override request is too old")
	}

	if validationErrors.HasErrors() {
		return &validationErrors
	}

	return nil
}