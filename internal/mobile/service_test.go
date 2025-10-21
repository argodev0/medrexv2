package mobile

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Mock implementations for testing

type MockMobileRepository struct {
	mock.Mock
}

func (m *MockMobileRepository) CreateOrder(order *types.CPOEOrder) error {
	args := m.Called(order)
	return args.Error(0)
}

func (m *MockMobileRepository) GetOrderByID(id string) (*types.CPOEOrder, error) {
	args := m.Called(id)
	return args.Get(0).(*types.CPOEOrder), args.Error(1)
}

func (m *MockMobileRepository) UpdateOrder(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockMobileRepository) GetOrdersByUser(userID string, filters map[string]interface{}) ([]*types.CPOEOrder, error) {
	args := m.Called(userID, filters)
	return args.Get(0).([]*types.CPOEOrder), args.Error(1)
}

func (m *MockMobileRepository) GetPendingOrders(consultantID string) ([]*types.CPOEOrder, error) {
	args := m.Called(consultantID)
	return args.Get(0).([]*types.CPOEOrder), args.Error(1)
}

func (m *MockMobileRepository) CreateMedicationAdmin(admin *types.MedicationAdministration) error {
	args := m.Called(admin)
	return args.Error(0)
}

func (m *MockMobileRepository) GetMedicationAdminByID(id string) (*types.MedicationAdministration, error) {
	args := m.Called(id)
	return args.Get(0).(*types.MedicationAdministration), args.Error(1)
}

func (m *MockMobileRepository) GetMedicationSchedule(patientID string) ([]*types.MedicationAdministration, error) {
	args := m.Called(patientID)
	return args.Get(0).([]*types.MedicationAdministration), args.Error(1)
}

func (m *MockMobileRepository) UpdateMedicationAdmin(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockMobileRepository) CreateLabResult(result *types.LabResult) error {
	args := m.Called(result)
	return args.Error(0)
}

func (m *MockMobileRepository) GetLabResultByID(id string) (*types.LabResult, error) {
	args := m.Called(id)
	return args.Get(0).(*types.LabResult), args.Error(1)
}

func (m *MockMobileRepository) GetLabResults(patientID string, filters map[string]interface{}) ([]*types.LabResult, error) {
	args := m.Called(patientID, filters)
	return args.Get(0).([]*types.LabResult), args.Error(1)
}

func (m *MockMobileRepository) UpdateLabResult(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockMobileRepository) StoreOfflineData(data *types.OfflineData) error {
	args := m.Called(data)
	return args.Error(0)
}

func (m *MockMobileRepository) GetOfflineData(userID, deviceID string) (*types.OfflineData, error) {
	args := m.Called(userID, deviceID)
	return args.Get(0).(*types.OfflineData), args.Error(1)
}

func (m *MockMobileRepository) UpdateSyncStatus(userID, deviceID string, syncedAt string) error {
	args := m.Called(userID, deviceID, syncedAt)
	return args.Error(0)
}

func (m *MockMobileRepository) DeleteOfflineData(userID, deviceID string) error {
	args := m.Called(userID, deviceID)
	return args.Error(0)
}

type MockIAMService struct {
	mock.Mock
}

func (m *MockIAMService) RegisterUser(req *types.UserRegistrationRequest) (*types.User, error) {
	args := m.Called(req)
	return args.Get(0).(*types.User), args.Error(1)
}

func (m *MockIAMService) GetUser(userID string) (*types.User, error) {
	args := m.Called(userID)
	return args.Get(0).(*types.User), args.Error(1)
}

func (m *MockIAMService) UpdateUser(userID string, updates map[string]interface{}) error {
	args := m.Called(userID, updates)
	return args.Error(0)
}

func (m *MockIAMService) DeactivateUser(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockIAMService) AuthenticateUser(credentials *types.Credentials) (*types.AuthToken, error) {
	args := m.Called(credentials)
	return args.Get(0).(*types.AuthToken), args.Error(1)
}

func (m *MockIAMService) RefreshToken(token string) (*types.AuthToken, error) {
	args := m.Called(token)
	return args.Get(0).(*types.AuthToken), args.Error(1)
}

func (m *MockIAMService) RevokeToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockIAMService) ValidatePermissions(userID, resource, action string) (bool, error) {
	args := m.Called(userID, resource, action)
	return args.Bool(0), args.Error(1)
}

func (m *MockIAMService) GetUserPermissions(userID string) ([]string, error) {
	args := m.Called(userID)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockIAMService) EnrollWithFabricCA(userID string) (*types.X509Certificate, error) {
	args := m.Called(userID)
	return args.Get(0).(*types.X509Certificate), args.Error(1)
}

func (m *MockIAMService) RevokeCertificate(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockIAMService) RenewCertificate(userID string) (*types.X509Certificate, error) {
	args := m.Called(userID)
	return args.Get(0).(*types.X509Certificate), args.Error(1)
}

func (m *MockIAMService) EnableMFA(userID string) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

func (m *MockIAMService) VerifyMFA(userID, token string) (bool, error) {
	args := m.Called(userID, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockIAMService) DisableMFA(userID string) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockIAMService) Start(addr string) error {
	args := m.Called(addr)
	return args.Error(0)
}

func (m *MockIAMService) Stop() error {
	args := m.Called()
	return args.Error(0)
}

type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) LogEvent(userID, action, resourceID string, success bool, data map[string]interface{}) error {
	args := m.Called(userID, action, resourceID, success, data)
	return args.Error(0)
}

func (m *MockAuditService) GetAuditTrail(resourceID string) ([]*types.AuditLogEntry, error) {
	args := m.Called(resourceID)
	return args.Get(0).([]*types.AuditLogEntry), args.Error(1)
}

func (m *MockAuditService) GetUserAuditTrail(userID string, limit int) ([]*types.AuditLogEntry, error) {
	args := m.Called(userID, limit)
	return args.Get(0).([]*types.AuditLogEntry), args.Error(1)
}

// Test Suite Setup

func setupTestService() (*Service, *MockMobileRepository, *MockIAMService, *MockAuditService) {
	mockRepo := &MockMobileRepository{}
	mockIAM := &MockIAMService{}
	mockAudit := &MockAuditService{}

	service := NewService(
		mockRepo,
		nil, // barcodeService
		nil, // offlineSync
		nil, // workflowEngine
		mockIAM,
		mockAudit,
	)

	return service, mockRepo, mockIAM, mockAudit
}

// CPOE Workflow Tests

func TestCreateOrder_Success(t *testing.T) {
	service, mockRepo, mockIAM, mockAudit := setupTestService()

	// Setup test data
	userID := "user123"
	order := &types.CPOEOrder{
		PatientID: "patient123",
		OrderType: string(types.OrderTypeMedication),
		Details:   `{"medication_name": "Acetaminophen", "dose": "500mg", "route": "Oral", "frequency": "q6h"}`,
		Priority:  string(types.PriorityRoutine),
	}

	user := &types.User{
		ID:   userID,
		Role: types.RoleMDStudent,
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "cpoe_orders", "create").Return(true, nil)
	mockIAM.On("GetUser", userID).Return(user, nil)
	mockRepo.On("CreateOrder", mock.AnythingOfType("*types.CPOEOrder")).Return(nil)
	mockAudit.On("LogEvent", userID, "cpoe_order_created", mock.AnythingOfType("string"), true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	createdOrder, err := service.CreateOrder(order, userID)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, createdOrder)
	assert.NotEmpty(t, createdOrder.ID)
	assert.Equal(t, userID, createdOrder.OrderingMD)
	assert.Equal(t, string(types.OrderStatusDraft), createdOrder.Status)
	assert.True(t, createdOrder.RequiresCoSign) // MD student requires co-signature

	// Verify mocks
	mockIAM.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestCreateOrder_UnauthorizedUser(t *testing.T) {
	service, _, mockIAM, _ := setupTestService()

	userID := "user123"
	order := &types.CPOEOrder{
		PatientID: "patient123",
		OrderType: string(types.OrderTypeMedication),
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "cpoe_orders", "create").Return(false, nil)

	// Execute test
	createdOrder, err := service.CreateOrder(order, userID)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, createdOrder)
	assert.Contains(t, err.Error(), "does not have permission")

	// Verify mocks
	mockIAM.AssertExpectations(t)
}

func TestCreateOrder_InvalidMedicationOrder(t *testing.T) {
	service, _, mockIAM, _ := setupTestService()

	userID := "user123"
	order := &types.CPOEOrder{
		PatientID: "patient123",
		OrderType: string(types.OrderTypeMedication),
		Details:   `{"invalid": "data"}`, // Missing required fields
	}

	user := &types.User{
		ID:   userID,
		Role: types.RoleConsultingDoctor,
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "cpoe_orders", "create").Return(true, nil)
	mockIAM.On("GetUser", userID).Return(user, nil)

	// Execute test
	createdOrder, err := service.CreateOrder(order, userID)

	// Assertions
	assert.Error(t, err)
	assert.Nil(t, createdOrder)
	assert.Contains(t, err.Error(), "validation failed")

	// Verify mocks
	mockIAM.AssertExpectations(t)
}

func TestRequestCoSignature_Success(t *testing.T) {
	service, mockRepo, mockIAM, mockAudit := setupTestService()

	orderID := "order123"
	consultantID := "consultant123"
	
	order := &types.CPOEOrder{
		ID:             orderID,
		OrderingMD:     "student123",
		RequiresCoSign: true,
		Status:         string(types.OrderStatusDraft),
	}

	// Setup mocks
	mockRepo.On("GetOrderByID", orderID).Return(order, nil)
	mockIAM.On("ValidatePermissions", consultantID, "cpoe_orders", "co_sign").Return(true, nil)
	mockRepo.On("UpdateOrder", orderID, mock.AnythingOfType("map[string]interface {}")).Return(nil)
	mockAudit.On("LogEvent", order.OrderingMD, "co_signature_requested", orderID, true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.RequestCoSignature(orderID, consultantID)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockRepo.AssertExpectations(t)
	mockIAM.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestApproveOrder_Success(t *testing.T) {
	service, mockRepo, _, mockAudit := setupTestService()

	orderID := "order123"
	consultantID := "consultant123"
	
	order := &types.CPOEOrder{
		ID:           orderID,
		OrderingMD:   "student123",
		CoSigningMD:  consultantID,
		Status:       string(types.OrderStatusPending),
	}

	// Setup mocks
	mockRepo.On("GetOrderByID", orderID).Return(order, nil)
	mockRepo.On("UpdateOrder", orderID, mock.AnythingOfType("map[string]interface {}")).Return(nil)
	mockAudit.On("LogEvent", consultantID, "cpoe_order_approved", orderID, true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.ApproveOrder(orderID, consultantID)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestGetPendingCoSignatures_Success(t *testing.T) {
	service, mockRepo, mockIAM, _ := setupTestService()

	consultantID := "consultant123"
	expectedOrders := []*types.CPOEOrder{
		{
			ID:          "order1",
			CoSigningMD: consultantID,
			Status:      string(types.OrderStatusPending),
		},
		{
			ID:          "order2",
			CoSigningMD: consultantID,
			Status:      string(types.OrderStatusPending),
		},
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", consultantID, "cpoe_orders", "co_sign").Return(true, nil)
	mockRepo.On("GetPendingOrders", consultantID).Return(expectedOrders, nil)

	// Execute test
	orders, err := service.GetPendingCoSignatures(consultantID)

	// Assertions
	assert.NoError(t, err)
	assert.Len(t, orders, 2)
	assert.Equal(t, expectedOrders, orders)

	// Verify mocks
	mockIAM.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

// Medication Administration Tests

func TestRecordMedicationAdmin_Success(t *testing.T) {
	service, mockRepo, mockIAM, mockAudit := setupTestService()

	userID := "nurse123"
	admin := &types.MedicationAdministration{
		OrderID:      "order123",
		PatientID:    "patient123",
		MedicationID: "med123",
		Dose:         "500mg",
		Route:        "Oral",
	}

	order := &types.CPOEOrder{
		ID:        "order123",
		OrderType: string(types.OrderTypeMedication),
		Status:    string(types.OrderStatusApproved),
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "medication_admin", "create").Return(true, nil)
	mockRepo.On("GetOrderByID", "order123").Return(order, nil)
	mockRepo.On("CreateMedicationAdmin", mock.AnythingOfType("*types.MedicationAdministration")).Return(nil)
	mockAudit.On("LogEvent", userID, "medication_administered", mock.AnythingOfType("string"), true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.RecordMedicationAdmin(admin, userID)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockIAM.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestGetMedicationSchedule_Success(t *testing.T) {
	service, mockRepo, mockIAM, _ := setupTestService()

	userID := "nurse123"
	patientID := "patient123"
	expectedSchedule := []*types.MedicationAdministration{
		{
			ID:             "admin1",
			PatientID:      patientID,
			MedicationID:   "med1",
			AdministeredAt: time.Now(),
		},
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "medication_admin", "read").Return(true, nil)
	mockRepo.On("GetMedicationSchedule", patientID).Return(expectedSchedule, nil)

	// Execute test
	schedule, err := service.GetMedicationSchedule(patientID, userID)

	// Assertions
	assert.NoError(t, err)
	assert.Equal(t, expectedSchedule, schedule)

	// Verify mocks
	mockIAM.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
}

// Lab Results Tests

func TestEnterLabResult_Success(t *testing.T) {
	service, mockRepo, mockIAM, mockAudit := setupTestService()

	userID := "tech123"
	result := &types.LabResult{
		OrderID:   "order123",
		PatientID: "patient123",
		TestName:  "CBC",
		Result:    "Normal",
		Units:     "cells/uL",
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "lab_results", "create").Return(true, nil)
	mockRepo.On("CreateLabResult", mock.AnythingOfType("*types.LabResult")).Return(nil)
	mockAudit.On("LogEvent", userID, "lab_result_entered", mock.AnythingOfType("string"), true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.EnterLabResult(result, userID)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockIAM.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestEnterLabResult_InvalidData(t *testing.T) {
	service, _, mockIAM, _ := setupTestService()

	userID := "tech123"
	result := &types.LabResult{
		// Missing required fields
		OrderID: "order123",
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "lab_results", "create").Return(true, nil)

	// Execute test
	err := service.EnterLabResult(result, userID)

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")

	// Verify mocks
	mockIAM.AssertExpectations(t)
}

func TestVerifyLabResult_Success(t *testing.T) {
	service, mockRepo, mockIAM, mockAudit := setupTestService()

	userID := "tech123"
	resultID := "result123"

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "lab_results", "verify").Return(true, nil)
	mockRepo.On("UpdateLabResult", resultID, mock.AnythingOfType("map[string]interface {}")).Return(nil)
	mockAudit.On("LogEvent", userID, "lab_result_verified", resultID, true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.VerifyLabResult(resultID, userID)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockIAM.AssertExpectations(t)
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

// Mobile Configuration Tests

func TestGetMobileConfig_Success(t *testing.T) {
	service, _, mockIAM, _ := setupTestService()

	userID := "nurse123"
	user := &types.User{
		ID:   userID,
		Role: types.RoleNurse,
	}

	// Setup mocks
	mockIAM.On("GetUser", userID).Return(user, nil)

	// Execute test
	config, err := service.GetMobileConfig(userID)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, types.RoleNurse, config["user_role"])
	
	// Check nurse-specific configuration
	barcodeConfig := config["barcode_scanning"].(map[string]interface{})
	assert.True(t, barcodeConfig["enabled"].(bool))
	
	medicationConfig := config["medication_admin"].(map[string]interface{})
	assert.True(t, medicationConfig["can_administer"].(bool))

	// Verify mocks
	mockIAM.AssertExpectations(t)
}

func TestUpdateMobilePreferences_Success(t *testing.T) {
	service, _, _, mockAudit := setupTestService()

	userID := "user123"
	preferences := map[string]interface{}{
		"notifications": map[string]interface{}{
			"enabled": true,
			"sound":   true,
		},
		"display_settings": map[string]interface{}{
			"theme": "dark",
		},
	}

	// Setup mocks
	mockAudit.On("LogEvent", userID, "mobile_preferences_updated", userID, true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.UpdateMobilePreferences(userID, preferences)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockAudit.AssertExpectations(t)
}

func TestUpdateMobilePreferences_InvalidPreferences(t *testing.T) {
	service, _, _, _ := setupTestService()

	userID := "user123"
	preferences := map[string]interface{}{
		"invalid_key": "invalid_value",
	}

	// Execute test
	err := service.UpdateMobilePreferences(userID, preferences)

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid preference key")
}

// Helper Function Tests

func TestRequiresCoSignature(t *testing.T) {
	service, _, _, _ := setupTestService()

	testCases := []struct {
		role      types.UserRole
		orderType string
		expected  bool
	}{
		{types.RoleMBBSStudent, string(types.OrderTypeMedication), true},
		{types.RoleMBBSStudent, string(types.OrderTypeNursing), false},
		{types.RoleMDStudent, string(types.OrderTypeMedication), true},
		{types.RoleMDStudent, string(types.OrderTypeNursing), false},
		{types.RoleConsultingDoctor, string(types.OrderTypeMedication), false},
		{types.RoleNurse, string(types.OrderTypeNursing), false},
	}

	for _, tc := range testCases {
		result := service.requiresCoSignature(tc.role, tc.orderType)
		assert.Equal(t, tc.expected, result, 
			"Role: %s, OrderType: %s should require co-sign: %t", 
			tc.role, tc.orderType, tc.expected)
	}
}

func TestValidateMedicationOrder(t *testing.T) {
	service, _, _, _ := setupTestService()

	testCases := []struct {
		name        string
		order       *types.CPOEOrder
		expectError bool
	}{
		{
			name: "Valid medication order",
			order: &types.CPOEOrder{
				PatientID: "patient123",
				OrderType: string(types.OrderTypeMedication),
				Details:   `{"medication_name": "Acetaminophen", "dose": "500mg", "route": "Oral", "frequency": "q6h"}`,
			},
			expectError: false,
		},
		{
			name: "Missing medication name",
			order: &types.CPOEOrder{
				PatientID: "patient123",
				OrderType: string(types.OrderTypeMedication),
				Details:   `{"dose": "500mg", "route": "Oral", "frequency": "q6h"}`,
			},
			expectError: true,
		},
		{
			name: "Invalid JSON format",
			order: &types.CPOEOrder{
				PatientID: "patient123",
				OrderType: string(types.OrderTypeMedication),
				Details:   `invalid json`,
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := service.validateMedicationOrder(tc.order)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsHighRiskMedication(t *testing.T) {
	service, _, _, _ := setupTestService()

	testCases := []struct {
		medication string
		expected   bool
	}{
		{"warfarin", true},
		{"insulin", true},
		{"heparin", true},
		{"digoxin", true},
		{"acetaminophen", false},
		{"ibuprofen", false},
	}

	for _, tc := range testCases {
		result := service.isHighRiskMedication(tc.medication)
		assert.Equal(t, tc.expected, result, 
			"Medication %s should be high-risk: %t", tc.medication, tc.expected)
	}
}

// Benchmark Tests

func BenchmarkCreateOrder(b *testing.B) {
	service, mockRepo, mockIAM, mockAudit := setupTestService()

	userID := "user123"
	user := &types.User{
		ID:   userID,
		Role: types.RoleConsultingDoctor,
	}

	// Setup mocks
	mockIAM.On("ValidatePermissions", userID, "cpoe_orders", "create").Return(true, nil)
	mockIAM.On("GetUser", userID).Return(user, nil)
	mockRepo.On("CreateOrder", mock.AnythingOfType("*types.CPOEOrder")).Return(nil)
	mockAudit.On("LogEvent", userID, "cpoe_order_created", mock.AnythingOfType("string"), true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		order := &types.CPOEOrder{
			PatientID: "patient123",
			OrderType: string(types.OrderTypeMedication),
			Details:   `{"medication_name": "Acetaminophen", "dose": "500mg", "route": "Oral", "frequency": "q6h"}`,
		}
		service.CreateOrder(order, userID)
	}
}

func BenchmarkValidateMedicationOrder(b *testing.B) {
	service, _, _, _ := setupTestService()

	order := &types.CPOEOrder{
		PatientID: "patient123",
		OrderType: string(types.OrderTypeMedication),
		Details:   `{"medication_name": "Acetaminophen", "dose": "500mg", "route": "Oral", "frequency": "q6h"}`,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.validateMedicationOrder(order)
	}
}