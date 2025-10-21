package accesspolicy

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/ledger/queryresult"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockTransactionContext provides a mock transaction context for testing
type MockTransactionContext struct {
	mock.Mock
}

func (m *MockTransactionContext) GetStub() shim.ChaincodeStubInterface {
	args := m.Called()
	return args.Get(0).(shim.ChaincodeStubInterface)
}

func (m *MockTransactionContext) GetClientIdentity() contractapi.ClientIdentity {
	args := m.Called()
	return args.Get(0).(contractapi.ClientIdentity)
}

// MockChaincodeStub provides a mock chaincode stub for testing
type MockChaincodeStub struct {
	mock.Mock
	State map[string][]byte
}

func (m *MockChaincodeStub) GetState(key string) ([]byte, error) {
	args := m.Called(key)
	if value, exists := m.State[key]; exists {
		return value, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockChaincodeStub) PutState(key string, value []byte) error {
	args := m.Called(key, value)
	if m.State == nil {
		m.State = make(map[string][]byte)
	}
	m.State[key] = value
	return args.Error(0)
}

func (m *MockChaincodeStub) GetStateByRange(startKey, endKey string) (shim.StateQueryIteratorInterface, error) {
	args := m.Called(startKey, endKey)
	return args.Get(0).(shim.StateQueryIteratorInterface), args.Error(1)
}

func (m *MockChaincodeStub) GetTxID() string {
	args := m.Called()
	return args.String(0)
}

// MockClientIdentity provides a mock client identity for testing
type MockClientIdentity struct {
	mock.Mock
}

func (m *MockClientIdentity) GetID() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockClientIdentity) GetAttributeValue(attrName string) (value string, found bool, err error) {
	args := m.Called(attrName)
	return args.String(0), args.Bool(1), args.Error(2)
}

// MockStateQueryIterator provides a mock state query iterator for testing
type MockStateQueryIterator struct {
	mock.Mock
	Results []*queryresult.KV
	Index   int
}

func (m *MockStateQueryIterator) HasNext() bool {
	return m.Index < len(m.Results)
}

func (m *MockStateQueryIterator) Next() (*queryresult.KV, error) {
	if m.Index >= len(m.Results) {
		return nil, fmt.Errorf("no more results")
	}
	result := m.Results[m.Index]
	m.Index++
	return result, nil
}

func (m *MockStateQueryIterator) Close() error {
	return nil
}

func TestSmartContract_InitLedger(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)
	clientIdentity := new(MockClientIdentity)

	ctx.On("GetStub").Return(stub)
	ctx.On("GetClientIdentity").Return(clientIdentity)
	clientIdentity.On("GetID").Return("admin", nil)
	stub.On("PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(nil)

	err := contract.InitLedger(ctx)
	assert.NoError(t, err)

	// Verify that policies were created
	stub.AssertNumberOfCalls(t, "PutState", 6) // 6 default policies
}

func TestSmartContract_CreateAccessPolicy(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)
	clientIdentity := new(MockClientIdentity)

	ctx.On("GetStub").Return(stub)
	ctx.On("GetClientIdentity").Return(clientIdentity)
	clientIdentity.On("GetID").Return("admin", nil)
	clientIdentity.On("GetAttributeValue", "role").Return("administrator", true, nil)
	stub.On("GetState", "test_policy").Return([]byte(nil), nil) // Policy doesn't exist
	stub.On("PutState", "test_policy", mock.AnythingOfType("[]uint8")).Return(nil)

	err := contract.CreateAccessPolicy(ctx, "test_policy", "ehr", "consulting_doctor", []string{"read", "write"}, map[string]string{"assigned": "true"})
	assert.NoError(t, err)

	stub.AssertCalled(t, "PutState", "test_policy", mock.AnythingOfType("[]uint8"))
}

func TestSmartContract_CreateAccessPolicy_Unauthorized(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)
	clientIdentity := new(MockClientIdentity)

	ctx.On("GetStub").Return(stub)
	ctx.On("GetClientIdentity").Return(clientIdentity)
	clientIdentity.On("GetAttributeValue", "role").Return("nurse", true, nil) // Not admin

	err := contract.CreateAccessPolicy(ctx, "test_policy", "ehr", "consulting_doctor", []string{"read", "write"}, map[string]string{"assigned": "true"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "access denied")
}

func TestSmartContract_ValidateAccess_Success(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)
	clientIdentity := new(MockClientIdentity)

	// Create a test policy
	policy := AccessPolicy{
		ID:           "policy_consulting_doctor_ehr",
		ResourceType: "ehr",
		UserRole:     "consulting_doctor",
		Actions:      []string{"read", "create", "update"},
		Conditions:   map[string]string{"assigned": "true"},
		CreatedBy:    "system",
		CreatedAt:    time.Now(),
	}
	policyJSON, _ := json.Marshal(policy)

	ctx.On("GetStub").Return(stub)
	ctx.On("GetClientIdentity").Return(clientIdentity)
	clientIdentity.On("GetAttributeValue", "role").Return("consulting_doctor", true, nil)
	
	// Mock state query iterator
	iterator := &MockStateQueryIterator{
		Results: []*queryresult.KV{
			{Key: "policy_consulting_doctor_ehr", Value: policyJSON},
		},
	}
	stub.On("GetStateByRange", "policy_", "policy_~").Return(iterator, nil)

	hasAccess, err := contract.ValidateAccess(ctx, "doctor1", "consulting_doctor", "ehr", "patient123", "read")
	assert.NoError(t, err)
	assert.True(t, hasAccess)
}

func TestSmartContract_ValidateAccess_Denied(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)
	clientIdentity := new(MockClientIdentity)

	// Create a test policy that doesn't allow delete action
	policy := AccessPolicy{
		ID:           "policy_nurse_ehr",
		ResourceType: "ehr",
		UserRole:     "nurse",
		Actions:      []string{"read", "update"},
		Conditions:   map[string]string{"assigned": "true", "scope": "nursing_notes"},
		CreatedBy:    "system",
		CreatedAt:    time.Now(),
	}
	policyJSON, _ := json.Marshal(policy)

	ctx.On("GetStub").Return(stub)
	ctx.On("GetClientIdentity").Return(clientIdentity)
	clientIdentity.On("GetAttributeValue", "role").Return("nurse", true, nil)
	
	// Mock state query iterator
	iterator := &MockStateQueryIterator{
		Results: []*queryresult.KV{
			{Key: "policy_nurse_ehr", Value: policyJSON},
		},
	}
	stub.On("GetStateByRange", "policy_", "policy_~").Return(iterator, nil)

	hasAccess, err := contract.ValidateAccess(ctx, "nurse1", "nurse", "ehr", "patient123", "delete")
	assert.NoError(t, err)
	assert.False(t, hasAccess)
}

func TestSmartContract_GenerateAccessToken(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)
	clientIdentity := new(MockClientIdentity)

	// Create a test policy
	policy := AccessPolicy{
		ID:           "policy_consulting_doctor_ehr",
		ResourceType: "ehr",
		UserRole:     "consulting_doctor",
		Actions:      []string{"read", "create", "update"},
		Conditions:   map[string]string{"assigned": "true"},
		CreatedBy:    "system",
		CreatedAt:    time.Now(),
	}
	policyJSON, _ := json.Marshal(policy)

	ctx.On("GetStub").Return(stub)
	ctx.On("GetClientIdentity").Return(clientIdentity)
	clientIdentity.On("GetAttributeValue", "role").Return("consulting_doctor", true, nil)
	
	// Mock state query iterator for access validation
	iterator := &MockStateQueryIterator{
		Results: []*queryresult.KV{
			{Key: "policy_consulting_doctor_ehr", Value: policyJSON},
		},
	}
	stub.On("GetStateByRange", "policy_", "policy_~").Return(iterator, nil)
	stub.On("PutState", mock.MatchedBy(func(key string) bool {
		return key[:6] == "token_"
	}), mock.AnythingOfType("[]uint8")).Return(nil)

	token, err := contract.GenerateAccessToken(ctx, "doctor1", "ehr", "patient123", "read")
	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.Equal(t, "doctor1", token.UserID)
	assert.Equal(t, "ehr", token.ResourceType)
	assert.Equal(t, "patient123", token.ResourceID)
	assert.Equal(t, "read", token.Action)
	assert.True(t, token.ExpiresAt.After(time.Now()))
}

func TestSmartContract_ValidateAccessToken(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	// Create a valid token
	token := AccessToken{
		TokenID:      "test_token_123",
		UserID:       "doctor1",
		ResourceType: "ehr",
		ResourceID:   "patient123",
		Action:       "read",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		CreatedAt:    time.Now(),
	}
	tokenJSON, _ := json.Marshal(token)

	ctx.On("GetStub").Return(stub)
	stub.On("GetState", "token_test_token_123").Return(tokenJSON, nil)

	isValid, err := contract.ValidateAccessToken(ctx, "test_token_123")
	assert.NoError(t, err)
	assert.True(t, isValid)
}

func TestSmartContract_ValidateAccessToken_Expired(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	// Create an expired token
	token := AccessToken{
		TokenID:      "expired_token_123",
		UserID:       "doctor1",
		ResourceType: "ehr",
		ResourceID:   "patient123",
		Action:       "read",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // Expired
		CreatedAt:    time.Now().Add(-2 * time.Hour),
	}
	tokenJSON, _ := json.Marshal(token)

	ctx.On("GetStub").Return(stub)
	stub.On("GetState", "token_expired_token_123").Return(tokenJSON, nil)

	isValid, err := contract.ValidateAccessToken(ctx, "expired_token_123")
	assert.Error(t, err)
	assert.False(t, isValid)
	assert.Contains(t, err.Error(), "expired")
}

func TestSmartContract_GetAccessPolicy(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	// Create a test policy
	policy := AccessPolicy{
		ID:           "test_policy",
		ResourceType: "ehr",
		UserRole:     "consulting_doctor",
		Actions:      []string{"read", "write"},
		Conditions:   map[string]string{"assigned": "true"},
		CreatedBy:    "admin",
		CreatedAt:    time.Now(),
	}
	policyJSON, _ := json.Marshal(policy)

	ctx.On("GetStub").Return(stub)
	stub.On("GetState", "test_policy").Return(policyJSON, nil)

	retrievedPolicy, err := contract.GetAccessPolicy(ctx, "test_policy")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedPolicy)
	assert.Equal(t, "test_policy", retrievedPolicy.ID)
	assert.Equal(t, "ehr", retrievedPolicy.ResourceType)
	assert.Equal(t, "consulting_doctor", retrievedPolicy.UserRole)
}

func TestSmartContract_IsValidUserRole(t *testing.T) {
	contract := new(SmartContract)

	// Test valid roles
	validRoles := []string{
		"patient", "mbbs_student", "md_student", "consulting_doctor",
		"nurse", "lab_technician", "receptionist", "clinical_staff", "administrator",
	}

	for _, role := range validRoles {
		assert.True(t, contract.isValidUserRole(role), "Role %s should be valid", role)
	}

	// Test invalid roles
	invalidRoles := []string{"invalid_role", "", "doctor", "admin"}
	for _, role := range invalidRoles {
		assert.False(t, contract.isValidUserRole(role), "Role %s should be invalid", role)
	}
}