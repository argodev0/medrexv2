package mobile

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Test Setup for Offline Sync Service

func setupOfflineSyncService() (*OfflineSyncService, *MockMobileRepository, *MockAuditService) {
	mockRepo := &MockMobileRepository{}
	mockAudit := &MockAuditService{}
	service := NewOfflineSyncService(mockRepo, mockAudit)
	return service, mockRepo, mockAudit
}

// Sync Operations Tests

func TestSyncUserData_Success(t *testing.T) {
	service, mockRepo, mockAudit := setupOfflineSyncService()

	userID := "user123"
	deviceID := "device456"
	
	offlineData := &types.OfflineData{
		UserID:   userID,
		DeviceID: deviceID,
		Orders: []types.CPOEOrder{
			{
				ID:        "order1",
				PatientID: "patient1",
				OrderingMD: userID,
				OrderType: string(types.OrderTypeMedication),
				Details:   `{"medication_name": "Acetaminophen"}`,
				Status:    string(types.OrderStatusDraft),
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
		},
		Scans: []types.ScanResult{
			{
				Code:      "P-PAT123-A1B2",
				Type:      "patient",
				IsValid:   true,
				ScannedAt: time.Now(),
				ScannedBy: userID,
			},
		},
		Notes: []types.ClinicalNote{
			{
				ID:        "note1",
				PatientID: "patient1",
				AuthorID:  userID,
				Content:   "Test note",
			},
		},
		LastSyncAt: time.Now().Add(-1 * time.Hour),
		SyncedAt:   time.Now(),
	}

	// Setup mocks
	mockRepo.On("GetOrderByID", "order1").Return((*types.CPOEOrder)(nil), assert.AnError) // Order doesn't exist
	mockRepo.On("CreateOrder", mock.AnythingOfType("*types.CPOEOrder")).Return(nil)
	mockRepo.On("StoreOfflineData", mock.AnythingOfType("*types.OfflineData")).Return(nil)
	mockAudit.On("LogEvent", userID, "barcode_scanned_offline", "P-PAT123-A1B2", true, mock.AnythingOfType("map[string]interface {}")).Return(nil)
	mockAudit.On("LogEvent", userID, "clinical_note_synced", "note1", true, mock.AnythingOfType("map[string]interface {}")).Return(nil)
	mockAudit.On("LogEvent", userID, "offline_data_synced", deviceID, true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.SyncUserData(userID, deviceID, offlineData)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

func TestSyncUserData_ValidationFailure(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	userID := "user123"
	deviceID := "device456"
	
	// Invalid offline data - missing required fields
	offlineData := &types.OfflineData{
		// Missing UserID and DeviceID
		Orders: []types.CPOEOrder{
			{
				// Missing required fields
				ID: "order1",
			},
		},
	}

	// Execute test
	err := service.SyncUserData(userID, deviceID, offlineData)

	// Assertions
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

func TestGetPendingSyncData_Success(t *testing.T) {
	service, mockRepo, _ := setupOfflineSyncService()

	userID := "user123"
	deviceID := "device456"
	
	existingData := &types.OfflineData{
		UserID:     userID,
		DeviceID:   deviceID,
		LastSyncAt: time.Now().Add(-1 * time.Hour),
		Orders:     []types.CPOEOrder{},
		Scans:      []types.ScanResult{},
		Notes:      []types.ClinicalNote{},
		CustomData: make(map[string]interface{}),
		SyncedAt:   time.Now(),
	}

	// Setup mocks
	mockRepo.On("GetOfflineData", userID, deviceID).Return(existingData, nil)

	// Execute test
	data, err := service.GetPendingSyncData(userID, deviceID)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, userID, data.UserID)
	assert.Equal(t, deviceID, data.DeviceID)

	// Verify mocks
	mockRepo.AssertExpectations(t)
}

func TestGetPendingSyncData_NoExistingData(t *testing.T) {
	service, mockRepo, _ := setupOfflineSyncService()

	userID := "user123"
	deviceID := "device456"

	// Setup mocks - no existing data
	mockRepo.On("GetOfflineData", userID, deviceID).Return((*types.OfflineData)(nil), assert.AnError)

	// Execute test
	data, err := service.GetPendingSyncData(userID, deviceID)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, data)
	assert.Equal(t, userID, data.UserID)
	assert.Equal(t, deviceID, data.DeviceID)
	assert.Empty(t, data.Orders)
	assert.Empty(t, data.Scans)
	assert.Empty(t, data.Notes)

	// Verify mocks
	mockRepo.AssertExpectations(t)
}

func TestMarkDataSynced_Success(t *testing.T) {
	service, mockRepo, mockAudit := setupOfflineSyncService()

	userID := "user123"
	deviceID := "device456"
	items := []string{"order1", "scan1", "note1"}

	// Setup mocks
	mockRepo.On("UpdateSyncStatus", userID, deviceID, mock.AnythingOfType("string")).Return(nil)
	mockAudit.On("LogEvent", userID, "sync_items_marked", deviceID, true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.MarkDataSynced(userID, deviceID, items)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockRepo.AssertExpectations(t)
	mockAudit.AssertExpectations(t)
}

// Data Validation Tests

func TestValidateOfflineData_Success(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	validData := &types.OfflineData{
		UserID:   "user123",
		DeviceID: "device456",
		Orders: []types.CPOEOrder{
			{
				ID:         "order1",
				PatientID:  "patient1",
				OrderingMD: "user123",
				OrderType:  string(types.OrderTypeMedication),
			},
		},
		Scans: []types.ScanResult{
			{
				Code:      "P-PAT123-A1B2",
				Type:      "patient",
				ScannedBy: "user123",
			},
		},
		Notes: []types.ClinicalNote{
			{
				ID:        "note1",
				PatientID: "patient1",
				AuthorID:  "user123",
			},
		},
	}

	isValid, errors, err := service.ValidateOfflineData(validData)

	assert.NoError(t, err)
	assert.True(t, isValid)
	assert.Empty(t, errors)
}

func TestValidateOfflineData_MissingRequiredFields(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	invalidData := &types.OfflineData{
		// Missing UserID and DeviceID
		Orders: []types.CPOEOrder{
			{
				// Missing required fields
				ID: "order1",
			},
		},
	}

	isValid, errors, err := service.ValidateOfflineData(invalidData)

	assert.NoError(t, err)
	assert.False(t, isValid)
	assert.NotEmpty(t, errors)
	assert.Contains(t, errors[0], "user_id is required")
	assert.Contains(t, errors[1], "device_id is required")
}

func TestValidateOfflineData_InvalidOrders(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	invalidData := &types.OfflineData{
		UserID:   "user123",
		DeviceID: "device456",
		Orders: []types.CPOEOrder{
			{
				ID: "order1",
				// Missing PatientID, OrderingMD, OrderType
			},
		},
	}

	isValid, errors, err := service.ValidateOfflineData(invalidData)

	assert.NoError(t, err)
	assert.False(t, isValid)
	assert.NotEmpty(t, errors)
	assert.Contains(t, errors[0], "patient_id is required")
	assert.Contains(t, errors[1], "ordering_md is required")
	assert.Contains(t, errors[2], "order_type is required")
}

func TestValidateOfflineData_DataSizeLimit(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	// Create data that exceeds size limit
	largeData := &types.OfflineData{
		UserID:   "user123",
		DeviceID: "device456",
		Orders:   make([]types.CPOEOrder, 500),
		Scans:    make([]types.ScanResult, 500),
		Notes:    make([]types.ClinicalNote, 100), // Total > 1000 items
	}

	isValid, errors, err := service.ValidateOfflineData(largeData)

	assert.NoError(t, err)
	assert.False(t, isValid)
	assert.NotEmpty(t, errors)
	assert.Contains(t, errors[len(errors)-1], "data size exceeds limit")
}

// Data Sanitization Tests

func TestSanitizeOfflineData_Success(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	originalData := &types.OfflineData{
		UserID:   "user123",
		DeviceID: "device456",
		Orders: []types.CPOEOrder{
			{
				ID:        "order1",
				PatientID: "patient1",
			},
		},
		Scans: []types.ScanResult{
			{
				Code: "P-PAT123-A1B2",
				Type: "patient",
			},
		},
		Notes: []types.ClinicalNote{
			{
				ID:        "note1",
				PatientID: "patient1",
			},
		},
		CustomData: map[string]interface{}{
			"preferences": map[string]interface{}{"theme": "dark"},
			"invalid_key": "should_be_removed",
		},
	}

	sanitizedData, err := service.SanitizeOfflineData(originalData)

	assert.NoError(t, err)
	assert.NotNil(t, sanitizedData)
	assert.Equal(t, originalData.UserID, sanitizedData.UserID)
	assert.Equal(t, originalData.DeviceID, sanitizedData.DeviceID)
	assert.Len(t, sanitizedData.Orders, 1)
	assert.Len(t, sanitizedData.Scans, 1)
	assert.Len(t, sanitizedData.Notes, 1)
	
	// Check that invalid custom data key was removed
	assert.Contains(t, sanitizedData.CustomData, "preferences")
	assert.NotContains(t, sanitizedData.CustomData, "invalid_key")
}

// Conflict Resolution Tests

func TestResolveConflicts_Success(t *testing.T) {
	service, _, mockAudit := setupOfflineSyncService()

	userID := "user123"
	conflicts := []map[string]interface{}{
		{
			"type":        "order_conflict",
			"resource_id": "order1",
			"conflict":    "version_mismatch",
		},
	}

	// Setup mocks
	mockAudit.On("LogEvent", userID, "sync_conflicts_resolved", userID, true, mock.AnythingOfType("map[string]interface {}")).Return(nil)

	// Execute test
	err := service.ResolveConflicts(userID, conflicts)

	// Assertions
	assert.NoError(t, err)

	// Verify mocks
	mockAudit.AssertExpectations(t)
}

func TestGetConflicts_Success(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	userID := "user123"
	deviceID := "device456"

	// Execute test
	conflicts, err := service.GetConflicts(userID, deviceID)

	// Assertions
	assert.NoError(t, err)
	assert.NotNil(t, conflicts)
	assert.Empty(t, conflicts) // Currently returns empty slice
}

// Helper Function Tests

func TestValidateOrder(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	testCases := []struct {
		name        string
		order       *types.CPOEOrder
		expectErrors bool
	}{
		{
			name: "Valid order",
			order: &types.CPOEOrder{
				ID:         "order1",
				PatientID:  "patient1",
				OrderingMD: "user1",
				OrderType:  string(types.OrderTypeMedication),
			},
			expectErrors: false,
		},
		{
			name: "Missing ID",
			order: &types.CPOEOrder{
				PatientID:  "patient1",
				OrderingMD: "user1",
				OrderType:  string(types.OrderTypeMedication),
			},
			expectErrors: true,
		},
		{
			name: "Missing PatientID",
			order: &types.CPOEOrder{
				ID:         "order1",
				OrderingMD: "user1",
				OrderType:  string(types.OrderTypeMedication),
			},
			expectErrors: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errors := service.validateOrder(tc.order)
			if tc.expectErrors {
				assert.NotEmpty(t, errors)
			} else {
				assert.Empty(t, errors)
			}
		})
	}
}

func TestValidateScan(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	testCases := []struct {
		name        string
		scan        *types.ScanResult
		expectErrors bool
	}{
		{
			name: "Valid scan",
			scan: &types.ScanResult{
				Code:      "P-PAT123-A1B2",
				Type:      "patient",
				ScannedBy: "user1",
			},
			expectErrors: false,
		},
		{
			name: "Missing code",
			scan: &types.ScanResult{
				Type:      "patient",
				ScannedBy: "user1",
			},
			expectErrors: true,
		},
		{
			name: "Missing type",
			scan: &types.ScanResult{
				Code:      "P-PAT123-A1B2",
				ScannedBy: "user1",
			},
			expectErrors: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errors := service.validateScan(tc.scan)
			if tc.expectErrors {
				assert.NotEmpty(t, errors)
			} else {
				assert.Empty(t, errors)
			}
		})
	}
}

func TestValidateNote(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	testCases := []struct {
		name        string
		note        *types.ClinicalNote
		expectErrors bool
	}{
		{
			name: "Valid note",
			note: &types.ClinicalNote{
				ID:        "note1",
				PatientID: "patient1",
				AuthorID:  "user1",
			},
			expectErrors: false,
		},
		{
			name: "Missing ID",
			note: &types.ClinicalNote{
				PatientID: "patient1",
				AuthorID:  "user1",
			},
			expectErrors: true,
		},
		{
			name: "Missing PatientID",
			note: &types.ClinicalNote{
				ID:       "note1",
				AuthorID: "user1",
			},
			expectErrors: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errors := service.validateNote(tc.note)
			if tc.expectErrors {
				assert.NotEmpty(t, errors)
			} else {
				assert.Empty(t, errors)
			}
		})
	}
}

func TestIsAllowedCustomDataKey(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	testCases := []struct {
		key      string
		expected bool
	}{
		{"preferences", true},
		{"settings", true},
		{"cache", true},
		{"invalid_key", false},
		{"malicious_data", false},
	}

	for _, tc := range testCases {
		result := service.isAllowedCustomDataKey(tc.key)
		assert.Equal(t, tc.expected, result, "Key %s should be allowed: %t", tc.key, tc.expected)
	}
}

func TestMergeOfflineData(t *testing.T) {
	service, _, _ := setupOfflineSyncService()

	existing := &types.OfflineData{
		UserID:   "user123",
		DeviceID: "device456",
		Orders: []types.CPOEOrder{
			{ID: "order1", PatientID: "patient1"},
		},
		Scans: []types.ScanResult{
			{Code: "scan1", Type: "patient"},
		},
		Notes: []types.ClinicalNote{
			{ID: "note1", PatientID: "patient1"},
		},
		CustomData: map[string]interface{}{
			"existing_key": "existing_value",
		},
	}

	new := &types.OfflineData{
		UserID:   "user123",
		DeviceID: "device456",
		Orders: []types.CPOEOrder{
			{ID: "order2", PatientID: "patient2"}, // New order
			{ID: "order1", PatientID: "patient1"}, // Duplicate order (should not duplicate)
		},
		Scans: []types.ScanResult{
			{Code: "scan2", Type: "medication"}, // New scan
		},
		Notes: []types.ClinicalNote{
			{ID: "note2", PatientID: "patient2"}, // New note
		},
		CustomData: map[string]interface{}{
			"new_key": "new_value",
		},
	}

	merged := service.mergeOfflineData(existing, new)

	assert.Equal(t, "user123", merged.UserID)
	assert.Equal(t, "device456", merged.DeviceID)
	assert.Len(t, merged.Orders, 2) // Should have 2 unique orders
	assert.Len(t, merged.Scans, 2)  // Should have 2 scans (scans are not deduplicated)
	assert.Len(t, merged.Notes, 2)  // Should have 2 unique notes
	assert.Len(t, merged.CustomData, 2) // Should have both custom data entries
	assert.Contains(t, merged.CustomData, "existing_key")
	assert.Contains(t, merged.CustomData, "new_key")
}

// Benchmark Tests

func BenchmarkValidateOfflineData(b *testing.B) {
	service, _, _ := setupOfflineSyncService()

	data := &types.OfflineData{
		UserID:   "user123",
		DeviceID: "device456",
		Orders: []types.CPOEOrder{
			{
				ID:         "order1",
				PatientID:  "patient1",
				OrderingMD: "user123",
				OrderType:  string(types.OrderTypeMedication),
			},
		},
		Scans: []types.ScanResult{
			{
				Code:      "P-PAT123-A1B2",
				Type:      "patient",
				ScannedBy: "user123",
			},
		},
		Notes: []types.ClinicalNote{
			{
				ID:        "note1",
				PatientID: "patient1",
				AuthorID:  "user123",
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.ValidateOfflineData(data)
	}
}

func BenchmarkSanitizeOfflineData(b *testing.B) {
	service, _, _ := setupOfflineSyncService()

	data := &types.OfflineData{
		UserID:   "user123",
		DeviceID: "device456",
		Orders: []types.CPOEOrder{
			{ID: "order1", PatientID: "patient1"},
		},
		Scans: []types.ScanResult{
			{Code: "scan1", Type: "patient"},
		},
		Notes: []types.ClinicalNote{
			{ID: "note1", PatientID: "patient1"},
		},
		CustomData: map[string]interface{}{
			"preferences": map[string]interface{}{"theme": "dark"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.SanitizeOfflineData(data)
	}
}