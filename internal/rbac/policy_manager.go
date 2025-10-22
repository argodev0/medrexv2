package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// PolicyManager implements RBAC policy management functionality
type PolicyManager struct {
	config   *Config
	logger   *logrus.Logger
	policies map[string]*rbac.AccessPolicy
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager(config *Config, logger *logrus.Logger) (*PolicyManager, error) {
	return &PolicyManager{
		config:   config,
		logger:   logger,
		policies: make(map[string]*rbac.AccessPolicy),
	}, nil
}

// CreatePolicy creates a new access control policy
func (m *PolicyManager) CreatePolicy(ctx context.Context, policy *rbac.AccessPolicy) error {
	if err := m.ValidatePolicy(ctx, policy); err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}

	policy.LastUpdated = time.Now()
	m.policies[policy.ID] = policy

	m.logger.WithFields(logrus.Fields{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
		"version":     policy.Version,
	}).Info("Created access control policy")

	return nil
}

// UpdatePolicy updates an existing access control policy
func (m *PolicyManager) UpdatePolicy(ctx context.Context, policyID string, policy *rbac.AccessPolicy) error {
	if _, exists := m.policies[policyID]; !exists {
		return rbac.NewRBACError(
			rbac.ErrorTypePolicyViolation,
			rbac.ErrorCodePolicyViolation,
			fmt.Sprintf("Policy not found: %s", policyID),
		)
	}

	if err := m.ValidatePolicy(ctx, policy); err != nil {
		return fmt.Errorf("policy validation failed: %w", err)
	}

	policy.LastUpdated = time.Now()
	m.policies[policyID] = policy

	m.logger.WithFields(logrus.Fields{
		"policy_id":   policyID,
		"policy_name": policy.Name,
		"version":     policy.Version,
	}).Info("Updated access control policy")

	return nil
}

// DeletePolicy deletes an access control policy
func (m *PolicyManager) DeletePolicy(ctx context.Context, policyID string) error {
	if _, exists := m.policies[policyID]; !exists {
		return rbac.NewRBACError(
			rbac.ErrorTypePolicyViolation,
			rbac.ErrorCodePolicyViolation,
			fmt.Sprintf("Policy not found: %s", policyID),
		)
	}

	delete(m.policies, policyID)

	m.logger.WithField("policy_id", policyID).Info("Deleted access control policy")
	return nil
}

// GetPolicy retrieves an access control policy by ID
func (m *PolicyManager) GetPolicy(ctx context.Context, policyID string) (*rbac.AccessPolicy, error) {
	policy, exists := m.policies[policyID]
	if !exists {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypePolicyViolation,
			rbac.ErrorCodePolicyViolation,
			fmt.Sprintf("Policy not found: %s", policyID),
		)
	}

	return policy, nil
}

// ListPolicies lists access control policies based on filter criteria
func (m *PolicyManager) ListPolicies(ctx context.Context, filter *rbac.PolicyFilter) ([]*rbac.AccessPolicy, error) {
	var result []*rbac.AccessPolicy

	for _, policy := range m.policies {
		if m.matchesFilter(policy, filter) {
			result = append(result, policy)
		}
	}

	// Apply pagination
	if filter != nil {
		if filter.Offset > 0 && filter.Offset < len(result) {
			result = result[filter.Offset:]
		}
		if filter.Limit > 0 && filter.Limit < len(result) {
			result = result[:filter.Limit]
		}
	}

	return result, nil
}

// ValidatePolicy validates an access control policy
func (m *PolicyManager) ValidatePolicy(ctx context.Context, policy *rbac.AccessPolicy) error {
	var validationErrors rbac.ValidationErrors

	if policy.ID == "" {
		validationErrors.Add("id", policy.ID, "Policy ID is required")
	}

	if policy.Name == "" {
		validationErrors.Add("name", policy.Name, "Policy name is required")
	}

	if policy.Version == "" {
		validationErrors.Add("version", policy.Version, "Policy version is required")
	}

	// Validate roles
	if len(policy.Roles) == 0 {
		validationErrors.Add("roles", "empty", "At least one role must be defined")
	}

	for roleID, rolePerms := range policy.Roles {
		if rolePerms.RoleID != roleID {
			validationErrors.Add(fmt.Sprintf("roles[%s].role_id", roleID), rolePerms.RoleID, "Role ID mismatch")
		}

		// Validate permissions for the role
		if err := m.validateRolePermissions(rolePerms); err != nil {
			validationErrors.Add(fmt.Sprintf("roles[%s].permissions", roleID), "", err.Error())
		}
	}

	// Validate resources
	for resourceID, resource := range policy.Resources {
		if resource.ID != resourceID {
			validationErrors.Add(fmt.Sprintf("resources[%s].id", resourceID), resource.ID, "Resource ID mismatch")
		}

		if resource.Name == "" {
			validationErrors.Add(fmt.Sprintf("resources[%s].name", resourceID), resource.Name, "Resource name is required")
		}
	}

	// Validate actions
	for actionID, action := range policy.Actions {
		if action.ID != actionID {
			validationErrors.Add(fmt.Sprintf("actions[%s].id", actionID), action.ID, "Action ID mismatch")
		}

		if action.Name == "" {
			validationErrors.Add(fmt.Sprintf("actions[%s].name", actionID), action.Name, "Action name is required")
		}
	}

	if validationErrors.HasErrors() {
		return &validationErrors
	}

	return nil
}

// Helper methods

func (m *PolicyManager) matchesFilter(policy *rbac.AccessPolicy, filter *rbac.PolicyFilter) bool {
	if filter == nil {
		return true
	}

	// Filter by role ID
	if filter.RoleID != "" {
		if _, exists := policy.Roles[filter.RoleID]; !exists {
			return false
		}
	}

	// Filter by resource ID
	if filter.ResourceID != "" {
		if _, exists := policy.Resources[filter.ResourceID]; !exists {
			return false
		}
	}

	// Filter by action
	if filter.Action != "" {
		if _, exists := policy.Actions[filter.Action]; !exists {
			return false
		}
	}

	// Filter by update time
	if !filter.UpdatedAfter.IsZero() {
		if policy.LastUpdated.Before(filter.UpdatedAfter) {
			return false
		}
	}

	return true
}

func (m *PolicyManager) validateRolePermissions(rolePerms *rbac.RolePermissions) error {
	if len(rolePerms.Permissions) == 0 {
		return fmt.Errorf("role must have at least one permission")
	}

	for permID, perm := range rolePerms.Permissions {
		if perm.Resource == "" {
			return fmt.Errorf("permission %s: resource is required", permID)
		}

		if len(perm.Actions) == 0 {
			return fmt.Errorf("permission %s: at least one action is required", permID)
		}

		if perm.Scope == "" {
			return fmt.Errorf("permission %s: scope is required", permID)
		}

		// Validate scope values
		validScopes := []string{rbac.ScopeOwn, rbac.ScopeAssigned, rbac.ScopeWard, rbac.ScopeDept, rbac.ScopeAll}
		validScope := false
		for _, validScopeValue := range validScopes {
			if perm.Scope == validScopeValue {
				validScope = true
				break
			}
		}
		if !validScope {
			return fmt.Errorf("permission %s: invalid scope value: %s", permID, perm.Scope)
		}

		// Validate time restrictions if present
		if perm.TimeRestriction != nil {
			if err := m.validateTimeRestriction(perm.TimeRestriction); err != nil {
				return fmt.Errorf("permission %s: invalid time restriction: %w", permID, err)
			}
		}
	}

	// Validate constraints
	for i, constraint := range rolePerms.Constraints {
		if constraint.Attribute == "" {
			return fmt.Errorf("constraint %d: attribute is required", i)
		}

		if constraint.Operator == "" {
			return fmt.Errorf("constraint %d: operator is required", i)
		}

		// Validate operator
		validOperators := []string{
			rbac.OperatorEquals, rbac.OperatorNotEquals,
			rbac.OperatorContains, rbac.OperatorNotContains,
			rbac.OperatorIn, rbac.OperatorNotIn,
			rbac.OperatorGreaterThan, rbac.OperatorLessThan,
			rbac.OperatorMatches, rbac.OperatorNotMatches,
		}
		validOperator := false
		for _, validOp := range validOperators {
			if constraint.Operator == validOp {
				validOperator = true
				break
			}
		}
		if !validOperator {
			return fmt.Errorf("constraint %d: invalid operator: %s", i, constraint.Operator)
		}
	}

	return nil
}

func (m *PolicyManager) validateTimeRestriction(restriction *rbac.TimeRestriction) error {
	// Validate time format
	if restriction.StartTime != "" {
		if _, err := time.Parse(rbac.TimeFormatHourMinute, restriction.StartTime); err != nil {
			return fmt.Errorf("invalid start time format: %s", restriction.StartTime)
		}
	}

	if restriction.EndTime != "" {
		if _, err := time.Parse(rbac.TimeFormatHourMinute, restriction.EndTime); err != nil {
			return fmt.Errorf("invalid end time format: %s", restriction.EndTime)
		}
	}

	// Validate days of week
	for _, day := range restriction.DaysOfWeek {
		validDay := false
		for _, validDayValue := range rbac.Weekdays {
			if day == validDayValue {
				validDay = true
				break
			}
		}
		if !validDay {
			return fmt.Errorf("invalid day of week: %s", day)
		}
	}

	// Validate timezone
	if restriction.Timezone != "" {
		if _, err := time.LoadLocation(restriction.Timezone); err != nil {
			return fmt.Errorf("invalid timezone: %s", restriction.Timezone)
		}
	}

	return nil
}