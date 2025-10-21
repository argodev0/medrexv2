package auditlog

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

func (m *MockChaincodeStub) GetQueryResult(query string) (shim.StateQueryIteratorInterface, error) {
	args := m.Called(query)
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
	clientIdentity.On("GetID").Return("system", nil)
	stub.On("GetTxID").Return("init_tx_123")
	stub.On("PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(nil)

	err := contract.InitLedger(ctx)
	assert.NoError(t, err)

	// Verify that initialization entry was created
	stub.AssertCalled(t, "PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8"))
}

func TestSmartContract_LogUserLogin_Success(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	ctx.On("GetStub").Return(stub)
	stub.On("GetTxID").Return("login_tx_123")
	stub.On("PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(nil)

	err := contract.LogUserLogin(ctx, "doctor1", "consulting_doctor", "192.168.1.100", "Mozilla/5.0", true)
	assert.NoError(t, err)

	// Verify that audit entry was created
	stub.AssertCalled(t, "PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8"))
}

func TestSmartContract_LogUserLogin_Failure(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	ctx.On("GetStub").Return(stub)
	stub.On("GetTxID").Return("login_fail_tx_123")
	stub.On("PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(nil)

	err := contract.LogUserLogin(ctx, "invalid_user", "unknown", "192.168.1.100", "Mozilla/5.0", false)
	assert.NoError(t, err)

	// Verify that audit entry was created for failed login
	stub.AssertCalled(t, "PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8"))
}

func TestSmartContract_LogPHIAccess(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	ctx.On("GetStub").Return(stub)
	stub.On("GetTxID").Return("phi_access_tx_123")
	stub.On("PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(nil)

	additionalDetails := map[string]interface{}{
		"patient_id": "patient123",
		"record_type": "clinical_notes",
	}

	err := contract.LogPHIAccess(ctx, "doctor1", "consulting_doctor", "record456", "read", "192.168.1.100", true, additionalDetails)
	assert.NoError(t, err)

	// Verify that audit entry was created
	stub.AssertCalled(t, "PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8"))
}

func TestSmartContract_LogCPOEEntry(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	ctx.On("GetStub").Return(stub)
	stub.On("GetTxID").Return("cpoe_tx_123")
	stub.On("PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(nil)

	err := contract.LogCPOEEntry(ctx, "student1", "md_student", "order789", "medication", "patient123", true, true)
	assert.NoError(t, err)

	// Verify that audit entry was created
	stub.AssertCalled(t, "PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8"))
}

func TestSmartContract_LogSecurityViolation(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	ctx.On("GetStub").Return(stub)
	stub.On("GetTxID").Return("security_violation_tx_123")
	stub.On("PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8")).Return(nil)

	err := contract.LogSecurityViolation(ctx, "malicious_user", "unknown", "unauthorized_access", "Attempted to access restricted PHI", "192.168.1.200")
	assert.NoError(t, err)

	// Verify that audit entry was created
	stub.AssertCalled(t, "PutState", mock.AnythingOfType("string"), mock.AnythingOfType("[]uint8"))
}

func TestSmartContract_GetAuditEntry(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	// Create a test audit entry
	entry := AuditLogEntry{
		ID:           "audit_test123",
		UserID:       "doctor1",
		UserRole:     "consulting_doctor",
		Action:       "phi_access",
		ResourceID:   "patient123",
		ResourceType: "phi",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"event_type": "phi_access",
			"access_type": "read",
		},
		TxID:      "test_tx_123",
		Signature: "test_signature_hash",
	}
	entryJSON, _ := json.Marshal(entry)

	ctx.On("GetStub").Return(stub)
	stub.On("GetState", "audit_test123").Return(entryJSON, nil)

	retrievedEntry, err := contract.GetAuditEntry(ctx, "audit_test123")
	assert.NoError(t, err)
	assert.NotNil(t, retrievedEntry)
	assert.Equal(t, "audit_test123", retrievedEntry.ID)
	assert.Equal(t, "doctor1", retrievedEntry.UserID)
	assert.Equal(t, "consulting_doctor", retrievedEntry.UserRole)
	assert.Equal(t, "phi_access", retrievedEntry.Action)
	assert.True(t, retrievedEntry.Success)
}

func TestSmartContract_QueryAuditLogs(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	// Create test audit entries
	entry1 := AuditLogEntry{
		ID:           "audit_test1",
		UserID:       "doctor1",
		UserRole:     "consulting_doctor",
		Action:       "phi_access",
		ResourceID:   "patient123",
		ResourceType: "phi",
		Timestamp:    time.Now(),
		Success:      true,
		Details:      map[string]interface{}{"event_type": "phi_access"},
		TxID:         "test_tx_1",
		Signature:    "signature1",
	}

	entry2 := AuditLogEntry{
		ID:           "audit_test2",
		UserID:       "nurse1",
		UserRole:     "nurse",
		Action:       "phi_update",
		ResourceID:   "patient456",
		ResourceType: "phi",
		Timestamp:    time.Now(),
		Success:      true,
		Details:      map[string]interface{}{"event_type": "phi_update"},
		TxID:         "test_tx_2",
		Signature:    "signature2",
	}

	entry1JSON, _ := json.Marshal(entry1)
	entry2JSON, _ := json.Marshal(entry2)

	// Mock query iterator
	iterator := &MockStateQueryIterator{
		Results: []*queryresult.KV{
			{Key: "audit_test1", Value: entry1JSON},
			{Key: "audit_test2", Value: entry2JSON},
		},
	}

	ctx.On("GetStub").Return(stub)
	stub.On("GetQueryResult", mock.AnythingOfType("string")).Return(iterator, nil)

	filter := QueryFilter{
		ResourceType: "phi",
	}
	filterJSON, _ := json.Marshal(filter)

	entries, err := contract.QueryAuditLogs(ctx, string(filterJSON))
	assert.NoError(t, err)
	assert.Len(t, entries, 2)
	assert.Equal(t, "audit_test1", entries[0].ID)
	assert.Equal(t, "audit_test2", entries[1].ID)
}

func TestSmartContract_GetAuditTrailByUser(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	// Create test audit entry for specific user
	entry := AuditLogEntry{
		ID:           "audit_user_test",
		UserID:       "doctor1",
		UserRole:     "consulting_doctor",
		Action:       "user_login",
		ResourceID:   "doctor1",
		ResourceType: "user_session",
		Timestamp:    time.Now(),
		Success:      true,
		Details:      map[string]interface{}{"event_type": "user_login"},
		TxID:         "login_tx_123",
		Signature:    "login_signature",
	}
	entryJSON, _ := json.Marshal(entry)

	// Mock query iterator
	iterator := &MockStateQueryIterator{
		Results: []*queryresult.KV{
			{Key: "audit_user_test", Value: entryJSON},
		},
	}

	ctx.On("GetStub").Return(stub)
	stub.On("GetQueryResult", mock.AnythingOfType("string")).Return(iterator, nil)

	entries, err := contract.GetAuditTrailByUser(ctx, "doctor1", 0, 0)
	assert.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "doctor1", entries[0].UserID)
	assert.Equal(t, "user_login", entries[0].Action)
}

func TestSmartContract_VerifyAuditIntegrity(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	// Create a test audit entry
	entry := AuditLogEntry{
		ID:           "audit_integrity_test",
		UserID:       "doctor1",
		UserRole:     "consulting_doctor",
		Action:       "phi_access",
		ResourceID:   "patient123",
		ResourceType: "phi",
		Timestamp:    time.Now(),
		Success:      true,
		Details:      map[string]interface{}{"event_type": "phi_access"},
		TxID:         "integrity_tx_123",
	}

	// Generate signature for the entry
	signature, _ := contract.generateEntrySignature(entry)
	entry.Signature = signature

	entryJSON, _ := json.Marshal(entry)

	ctx.On("GetStub").Return(stub)
	stub.On("GetState", "audit_integrity_test").Return(entryJSON, nil)

	isValid, err := contract.VerifyAuditIntegrity(ctx, "audit_integrity_test")
	assert.NoError(t, err)
	assert.True(t, isValid)
}

func TestSmartContract_VerifyAuditIntegrity_Tampered(t *testing.T) {
	contract := new(SmartContract)
	ctx := new(MockTransactionContext)
	stub := new(MockChaincodeStub)

	// Create a test audit entry with tampered signature
	entry := AuditLogEntry{
		ID:           "audit_tampered_test",
		UserID:       "doctor1",
		UserRole:     "consulting_doctor",
		Action:       "phi_access",
		ResourceID:   "patient123",
		ResourceType: "phi",
		Timestamp:    time.Now(),
		Success:      true,
		Details:      map[string]interface{}{"event_type": "phi_access"},
		TxID:         "tampered_tx_123",
		Signature:    "invalid_signature_hash", // Tampered signature
	}

	entryJSON, _ := json.Marshal(entry)

	ctx.On("GetStub").Return(stub)
	stub.On("GetState", "audit_tampered_test").Return(entryJSON, nil)

	isValid, err := contract.VerifyAuditIntegrity(ctx, "audit_tampered_test")
	assert.NoError(t, err)
	assert.False(t, isValid)
}

func TestSmartContract_GenerateAuditID(t *testing.T) {
	contract := new(SmartContract)
	
	timestamp := time.Now()
	id1 := contract.generateAuditID("test_action", timestamp)
	id2 := contract.generateAuditID("test_action", timestamp)
	
	// Same inputs should generate same ID
	assert.Equal(t, id1, id2)
	assert.True(t, len(id1) > 0)
	assert.Contains(t, id1, "audit_")
	
	// Different inputs should generate different IDs
	id3 := contract.generateAuditID("different_action", timestamp)
	assert.NotEqual(t, id1, id3)
}

func TestSmartContract_GenerateEntrySignature(t *testing.T) {
	contract := new(SmartContract)
	
	entry := AuditLogEntry{
		ID:           "test_entry",
		UserID:       "doctor1",
		UserRole:     "consulting_doctor",
		Action:       "phi_access",
		ResourceID:   "patient123",
		ResourceType: "phi",
		Timestamp:    time.Now(),
		Success:      true,
		Details:      map[string]interface{}{"test": "data"},
		TxID:         "test_tx",
	}
	
	signature1, err1 := contract.generateEntrySignature(entry)
	signature2, err2 := contract.generateEntrySignature(entry)
	
	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.Equal(t, signature1, signature2) // Same entry should generate same signature
	assert.True(t, len(signature1) > 0)
	
	// Modified entry should generate different signature
	entry.UserID = "different_user"
	signature3, err3 := contract.generateEntrySignature(entry)
	assert.NoError(t, err3)
	assert.NotEqual(t, signature1, signature3)
}