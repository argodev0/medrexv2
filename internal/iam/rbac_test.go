package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Mock AccessPolicyChaincode for testing
type MockAccessPolicyChaincode struct {
	mock.Mock
}

func (m *MockAccessPolicyChaincode) ValidateAccess(userID, resource, action string, userRole types.UserRole) (bool, error) {
	args := m.Called(userID, resource, action, userRole)
	return args.Bool(0), args.Error(1)
}

func (m *MockAccessPolicyChaincode) GetAccessPolicy(resource string, userRole types.UserRole) (*AccessPolicy, error) {
	args := m.Called(resource, userRole)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AccessPolicy), args.Error(1)
}

func (m *MockAccessPolicyChaincode) CreateAccessPolicy(policy *AccessPolicy) error {
	args := m.Called(policy)
	return args.Error(0)
}

func (m *MockAccessPolicyChaincode) UpdateAccessPolicy(policyID string, updates map[string]interface{}) error {
	args := m.Called(policyID, updates)
	return args.Error(0)
}

// Test setup for RBAC
func setupRBACTest() (*RBACManager, *MockAccessPolicyChaincode) {
	log := logger.New("debug")
	mockChaincode := &MockAccessPolicyChaincode{}
	rbacManager := NewRBACManager(log, mockChaincode)
	return rbacManager, mockChaincode
}

// Test permission validation
func TestRBACManager_ValidatePermissions(t *testing.T) {
	rbacManager, mockChaincode := setupRBACTest()

	t.Run("consulting doctor can access patient records", func(t *testing.T) {
		userID := "doctor-id"
		resource := "patient_records"
		action := "read"

		// Mock chaincode response
		mockChaincode.On("ValidateAccess", userID, resource, action, types.RoleConsultingDoctor).Return(true, nil)

		// Execute
		allowed, err := rbacManager.ValidatePermissions(userID, resource, action)

		// Assert
		assert.NoError(t, err)
		assert.True(t, allowed)

		mockChaincode.AssertExpectations(t)
	})

	t.Run("patient cannot access other patient records", func(t *testing.T) {
		userID := "patient-id"
		resource := "patient_records"
		action := "read"

		// Mock chaincode response - denied
		mockChaincode.On("ValidateAccess", userID, resource, action, types.RoleConsultingDoctor).Return(false, nil)

		// Execute
		allowed, err := rbacManager.ValidatePermissions(userID, resource, action)

		// Assert
		assert.NoError(t, err)
		assert.False(t, allowed)

		mockChaincode.AssertExpectations(t)
	})

	t.Run("MBBS student has read-only access", func(t *testing.T) {
		userID := "student-id"
		resource := "patient_records"
		action := "read"

		// Mock chaincode response
		mockChaincode.On("ValidateAccess", userID, resource, action, types.RoleConsultingDoctor).Return(true, nil)

		// Execute
		allowed, err := rbacManager.ValidatePermissions(userID, resource, action)

		// Assert
		assert.NoError(t, err)
		assert.True(t, allowed)

		mockChaincode.AssertExpectations(t)
	})

	t.Run("MBBS student cannot create records", func(t *testing.T) {
		userID := "student-id"
		resource := "patient_records"
		action := "create"

		// Mock chaincode response - denied
		mockChaincode.On("ValidateAccess", userID, resource, action, types.RoleConsultingDoctor).Return(false, nil)

		// Execute
		allowed, err := rbacManager.ValidatePermissions(userID, resource, action)

		// Assert
		assert.NoError(t, err)
		assert.False(t, allowed)

		mockChaincode.AssertExpectations(t)
	})
}

// Test local permission matrix
func TestRBACManager_CheckLocalPermissions(t *testing.T) {
	rbacManager, _ := setupRBACTest()

	testCases := []struct {
		name     string
		role     types.UserRole
		resource string
		action   string
		expected bool
	}{
		{
			name:     "patient can read own records",
			role:     types.RolePatient,
			resource: "patient_records",
			action:   "read",
			expected: true,
		},
		{
			name:     "patient cannot delete records",
			role:     types.RolePatient,
			resource: "patient_records",
			action:   "delete",
			expected: false,
		},
		{
			name:     "consulting doctor has full access",
			role:     types.RoleConsultingDoctor,
			resource: "patient_records",
			action:   "delete",
			expected: true,
		},
		{
			name:     "nurse can administer medications",
			role:     types.RoleNurse,
			resource: "medication_admin",
			action:   "create",
			expected: true,
		},
		{
			name:     "lab technician can create lab results",
			role:     types.RoleLabTechnician,
			resource: "lab_results",
			action:   "create",
			expected: true,
		},
		{
			name:     "lab technician cannot access patient records",
			role:     types.RoleLabTechnician,
			resource: "patient_records",
			action:   "update",
			expected: false,
		},
		{
			name:     "administrator has wildcard access",
			role:     types.RoleAdministrator,
			resource: "any_resource",
			action:   "any_action",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := rbacManager.checkLocalPermissions(tc.role, tc.resource, tc.action)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test access policy management
func TestRBACManager_AccessPolicyManagement(t *testing.T) {
	rbacManager, mockChaincode := setupRBACTest()

	t.Run("create access policy", func(t *testing.T) {
		resourceType := "test_resource"
		userRole := types.RoleConsultingDoctor
		actions := []string{"read", "write"}
		conditions := map[string]string{"department": "cardiology"}
		createdBy := "admin-id"

		mockChaincode.On("CreateAccessPolicy", mock.AnythingOfType("*iam.AccessPolicy")).Return(nil)

		// Execute
		err := rbacManager.CreateAccessPolicy(resourceType, userRole, actions, conditions, createdBy)

		// Assert
		assert.NoError(t, err)

		mockChaincode.AssertExpectations(t)
	})

	t.Run("update access policy", func(t *testing.T) {
		policyID := "policy-123"
		updates := map[string]interface{}{
			"actions": []string{"read", "write", "delete"},
		}

		mockChaincode.On("UpdateAccessPolicy", policyID, updates).Return(nil)

		// Execute
		err := rbacManager.UpdateAccessPolicy(policyID, updates)

		// Assert
		assert.NoError(t, err)

		mockChaincode.AssertExpectations(t)
	})
}

// Test resource access validation with conditions
func TestRBACManager_ValidateResourceAccess(t *testing.T) {
	rbacManager, mockChaincode := setupRBACTest()

	t.Run("access granted with matching conditions", func(t *testing.T) {
		userID := "doctor-id"
		resourceType := "patient_records"
		resourceID := "patient-123"
		action := "read"
		context := map[string]string{
			"department": "cardiology",
			"shift":      "day",
		}

		policy := &AccessPolicy{
			ID:           "policy-1",
			ResourceType: resourceType,
			UserRole:     types.RoleConsultingDoctor,
			Actions:      []string{"read", "write"},
			Conditions: map[string]string{
				"department": "cardiology",
			},
		}

		mockChaincode.On("GetAccessPolicy", resourceType, types.RoleConsultingDoctor).Return(policy, nil)

		// Execute
		allowed, err := rbacManager.ValidateResourceAccess(userID, resourceType, resourceID, action, context)

		// Assert
		assert.NoError(t, err)
		assert.True(t, allowed)

		mockChaincode.AssertExpectations(t)
	})

	t.Run("access denied with mismatched conditions", func(t *testing.T) {
		userID := "doctor-id"
		resourceType := "patient_records"
		resourceID := "patient-123"
		action := "read"
		context := map[string]string{
			"department": "neurology", // Different department
		}

		policy := &AccessPolicy{
			ID:           "policy-1",
			ResourceType: resourceType,
			UserRole:     types.RoleConsultingDoctor,
			Actions:      []string{"read", "write"},
			Conditions: map[string]string{
				"department": "cardiology",
			},
		}

		mockChaincode.On("GetAccessPolicy", resourceType, types.RoleConsultingDoctor).Return(policy, nil)

		// Execute
		allowed, err := rbacManager.ValidateResourceAccess(userID, resourceType, resourceID, action, context)

		// Assert
		assert.NoError(t, err)
		assert.False(t, allowed)

		mockChaincode.AssertExpectations(t)
	})

	t.Run("access denied for unauthorized action", func(t *testing.T) {
		userID := "doctor-id"
		resourceType := "patient_records"
		resourceID := "patient-123"
		action := "delete" // Not in allowed actions
		context := map[string]string{
			"department": "cardiology",
		}

		policy := &AccessPolicy{
			ID:           "policy-1",
			ResourceType: resourceType,
			UserRole:     types.RoleConsultingDoctor,
			Actions:      []string{"read", "write"}, // delete not allowed
			Conditions: map[string]string{
				"department": "cardiology",
			},
		}

		mockChaincode.On("GetAccessPolicy", resourceType, types.RoleConsultingDoctor).Return(policy, nil)

		// Execute
		allowed, err := rbacManager.ValidateResourceAccess(userID, resourceType, resourceID, action, context)

		// Assert
		assert.NoError(t, err)
		assert.False(t, allowed)

		mockChaincode.AssertExpectations(t)
	})
}

// Test role permissions retrieval
func TestRBACManager_GetRolePermissions(t *testing.T) {
	rbacManager, _ := setupRBACTest()

	t.Run("get consulting doctor permissions", func(t *testing.T) {
		permissions := rbacManager.GetRolePermissions(types.RoleConsultingDoctor)

		// Assert
		assert.NotEmpty(t, permissions)
		assert.Contains(t, permissions, "patient_records")
		assert.Contains(t, permissions, "cpoe_orders")
		
		// Check specific actions
		patientRecordActions := permissions["patient_records"]
		assert.Contains(t, patientRecordActions, "read")
		assert.Contains(t, patientRecordActions, "create")
		assert.Contains(t, patientRecordActions, "update")
		assert.Contains(t, patientRecordActions, "delete")
	})

	t.Run("get MBBS student permissions", func(t *testing.T) {
		permissions := rbacManager.GetRolePermissions(types.RoleMBBSStudent)

		// Assert
		assert.NotEmpty(t, permissions)
		assert.Contains(t, permissions, "patient_records")
		assert.Contains(t, permissions, "training_data")
		
		// Check read-only access
		patientRecordActions := permissions["patient_records"]
		assert.Contains(t, patientRecordActions, "read")
		assert.NotContains(t, patientRecordActions, "create")
		assert.NotContains(t, patientRecordActions, "update")
		assert.NotContains(t, patientRecordActions, "delete")
	})

	t.Run("get administrator permissions", func(t *testing.T) {
		permissions := rbacManager.GetRolePermissions(types.RoleAdministrator)

		// Assert
		assert.NotEmpty(t, permissions)
		assert.Contains(t, permissions, "*")
		
		// Check wildcard access
		wildcardActions := permissions["*"]
		assert.Contains(t, wildcardActions, "*")
	})

	t.Run("get permissions for non-existent role", func(t *testing.T) {
		permissions := rbacManager.GetRolePermissions("non_existent_role")

		// Assert
		assert.Empty(t, permissions)
	})
}

// Test action validation
func TestRBACManager_IsActionAllowed(t *testing.T) {
	rbacManager, _ := setupRBACTest()

	testCases := []struct {
		name     string
		role     types.UserRole
		resource string
		action   string
		expected bool
	}{
		{
			name:     "nurse can update vital signs",
			role:     types.RoleNurse,
			resource: "vital_signs",
			action:   "update",
			expected: true,
		},
		{
			name:     "receptionist can create appointments",
			role:     types.RoleReceptionist,
			resource: "appointments",
			action:   "create",
			expected: true,
		},
		{
			name:     "receptionist cannot access clinical notes",
			role:     types.RoleReceptionist,
			resource: "clinical_notes",
			action:   "read",
			expected: false,
		},
		{
			name:     "clinical staff can update clinical notes",
			role:     types.RoleClinicalStaff,
			resource: "clinical_notes",
			action:   "update",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := rbacManager.IsActionAllowed(tc.role, tc.resource, tc.action)
			assert.Equal(t, tc.expected, result)
		})
	}
}