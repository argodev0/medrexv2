package mobile

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Mock PatientRepository for testing
type MockPatientRepository struct {
	mock.Mock
}

func (m *MockPatientRepository) GetByID(id string) (*types.Patient, error) {
	args := m.Called(id)
	return args.Get(0).(*types.Patient), args.Error(1)
}

func (m *MockPatientRepository) Create(patient *types.Patient) error {
	args := m.Called(patient)
	return args.Error(0)
}

func (m *MockPatientRepository) Update(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockPatientRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockPatientRepository) Search(criteria map[string]interface{}) ([]*types.Patient, error) {
	args := m.Called(criteria)
	return args.Get(0).([]*types.Patient), args.Error(1)
}

// Test Setup

func setupBarcodeService() (*BarcodeService, *MockPatientRepository) {
	mockPatientRepo := &MockPatientRepository{}
	service := NewBarcodeService(mockPatientRepo)
	return service, mockPatientRepo
}

// Barcode Decoding Tests

func TestDecodeBarcode_PatientWristband_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test patient wristband barcode
	barcode := "P-PAT123-A1B2"

	result, err := service.DecodeBarcode(barcode)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, barcode, result.Code)
	assert.Equal(t, "patient", result.Type)
	assert.True(t, result.IsValid)
	assert.Equal(t, "PAT123", result.Data["patient_id"])
	assert.Equal(t, "A1B2", result.Data["checksum"])
}

func TestDecodeBarcode_MedicationBarcode_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test medication barcode
	barcode := "M-MED456-LOT789-20241231"

	result, err := service.DecodeBarcode(barcode)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, barcode, result.Code)
	assert.Equal(t, "medication", result.Type)
	assert.True(t, result.IsValid)
	assert.Equal(t, "MED456", result.Data["medication_id"])
	assert.Equal(t, "LOT789", result.Data["lot_number"])
	assert.Equal(t, "20241231", result.Data["expiry_date"])
}

func TestDecodeBarcode_EquipmentBarcode_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test equipment barcode
	barcode := "E-EQP001-ROOM101"

	result, err := service.DecodeBarcode(barcode)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, barcode, result.Code)
	assert.Equal(t, "equipment", result.Type)
	assert.True(t, result.IsValid)
	assert.Equal(t, "EQP001", result.Data["equipment_id"])
	assert.Equal(t, "ROOM101", result.Data["location"])
}

func TestDecodeBarcode_SpecimenBarcode_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test specimen barcode
	barcode := "S-SPEC001-PAT123-CBC"

	result, err := service.DecodeBarcode(barcode)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, barcode, result.Code)
	assert.Equal(t, "specimen", result.Type)
	assert.True(t, result.IsValid)
	assert.Equal(t, "SPEC001", result.Data["specimen_id"])
	assert.Equal(t, "PAT123", result.Data["patient_id"])
	assert.Equal(t, "CBC", result.Data["test_type"])
}

func TestDecodeBarcode_UnknownFormat(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test unknown barcode format
	barcode := "UNKNOWN-FORMAT-123"

	result, err := service.DecodeBarcode(barcode)

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, barcode, result.Code)
	assert.Equal(t, "unknown", result.Type)
	assert.False(t, result.IsValid)
	assert.Contains(t, err.Error(), "unrecognized barcode format")
}

// Barcode Validation Tests

func TestValidateBarcode_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	barcode := "P-PAT123-A1B2"
	expectedType := "patient"

	isValid, err := service.ValidateBarcode(barcode, expectedType)

	assert.NoError(t, err)
	assert.True(t, isValid)
}

func TestValidateBarcode_TypeMismatch(t *testing.T) {
	service, _ := setupBarcodeService()

	barcode := "P-PAT123-A1B2" // Patient barcode
	expectedType := "medication"  // Expecting medication

	isValid, err := service.ValidateBarcode(barcode, expectedType)

	assert.Error(t, err)
	assert.False(t, isValid)
	assert.Contains(t, err.Error(), "barcode type mismatch")
}

// QR Code Tests

func TestDecodeQRCode_JSON_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test JSON format QR code
	qrCode := `{"patient_id": "PAT123", "medication_id": "MED456", "dose": "500mg"}`

	result, err := service.DecodeQRCode(qrCode)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, qrCode, result.Code)
	assert.Equal(t, "medication_admin", result.Type)
	assert.True(t, result.IsValid)
	assert.Equal(t, "PAT123", result.Data["patient_id"])
	assert.Equal(t, "MED456", result.Data["medication_id"])
	assert.Equal(t, "500mg", result.Data["dose"])
}

func TestDecodeQRCode_Delimited_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test delimited format QR code
	qrCode := "patient|patient_id=PAT123|name=John Doe|dob=1990-01-01"

	result, err := service.DecodeQRCode(qrCode)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, qrCode, result.Code)
	assert.Equal(t, "patient", result.Type)
	assert.True(t, result.IsValid)
	assert.Equal(t, "PAT123", result.Data["patient_id"])
	assert.Equal(t, "John Doe", result.Data["name"])
	assert.Equal(t, "1990-01-01", result.Data["dob"])
}

func TestDecodeQRCode_InvalidFormat(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test invalid QR code format
	qrCode := "invalid format"

	result, err := service.DecodeQRCode(qrCode)

	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, qrCode, result.Code)
	assert.False(t, result.IsValid)
	assert.Contains(t, err.Error(), "failed to parse QR code")
}

// Barcode Generation Tests

func TestGenerateBarcode_Code128_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	data := map[string]string{
		"patient_id": "PAT123",
	}

	barcode, err := service.GenerateBarcode(data, "code128")

	assert.NoError(t, err)
	assert.NotEmpty(t, barcode)
	assert.Contains(t, barcode, "PAT123")
}

func TestGenerateBarcode_UnsupportedFormat(t *testing.T) {
	service, _ := setupBarcodeService()

	data := map[string]string{
		"patient_id": "PAT123",
	}

	barcode, err := service.GenerateBarcode(data, "unsupported")

	assert.Error(t, err)
	assert.Empty(t, barcode)
	assert.Contains(t, err.Error(), "unsupported barcode format")
}

func TestGenerateQRCode_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	data := map[string]string{
		"patient_id": "PAT123",
		"name":       "John Doe",
	}

	qrCode, err := service.GenerateQRCode(data)

	assert.NoError(t, err)
	assert.NotEmpty(t, qrCode)
	
	// Verify it's valid JSON
	var parsedData map[string]string
	err = json.Unmarshal([]byte(qrCode), &parsedData)
	assert.NoError(t, err)
	assert.Equal(t, "PAT123", parsedData["patient_id"])
	assert.Equal(t, "John Doe", parsedData["name"])
}

// Medication Verification Tests

func TestVerifyMedicationBarcode_Success(t *testing.T) {
	service, mockPatientRepo := setupBarcodeService()

	barcode := "M-MED001-LOT123-20241231"
	patientID := "PAT123"

	patient := &types.Patient{
		ID: patientID,
	}

	// Setup mocks
	mockPatientRepo.On("GetByID", patientID).Return(patient, nil)

	isValid, medicationInfo, err := service.VerifyMedicationBarcode(barcode, patientID)

	assert.NoError(t, err)
	assert.True(t, isValid)
	assert.NotNil(t, medicationInfo)
	assert.Equal(t, "MED001", medicationInfo["medication_id"])
	assert.Equal(t, "LOT123", medicationInfo["lot_number"])

	// Verify mocks
	mockPatientRepo.AssertExpectations(t)
}

func TestVerifyMedicationBarcode_NotMedicationBarcode(t *testing.T) {
	service, _ := setupBarcodeService()

	barcode := "P-PAT123-A1B2" // Patient barcode, not medication
	patientID := "PAT123"

	isValid, medicationInfo, err := service.VerifyMedicationBarcode(barcode, patientID)

	assert.Error(t, err)
	assert.False(t, isValid)
	assert.Nil(t, medicationInfo)
	assert.Contains(t, err.Error(), "not a medication barcode")
}

func TestGetMedicationInfo_Success(t *testing.T) {
	service, _ := setupBarcodeService()

	barcode := "M-MED001-LOT123-20241231"

	medicationInfo, err := service.GetMedicationInfo(barcode)

	assert.NoError(t, err)
	assert.NotNil(t, medicationInfo)
	assert.Equal(t, "MED001", medicationInfo["medication_id"])
	assert.Equal(t, "LOT123", medicationInfo["lot_number"])
	assert.Equal(t, "20241231", medicationInfo["expiry_date"])
	
	// Check if additional medication details are included
	assert.Contains(t, medicationInfo, "name")
	assert.Contains(t, medicationInfo, "strength")
}

func TestGetMedicationInfo_KnownMedication(t *testing.T) {
	service, _ := setupBarcodeService()

	// Test with known medication ID
	barcode := "M-MED001-LOT123-20241231"

	medicationInfo, err := service.GetMedicationInfo(barcode)

	assert.NoError(t, err)
	assert.NotNil(t, medicationInfo)
	
	// Should have enhanced information for known medications
	assert.Equal(t, "Acetaminophen", medicationInfo["name"])
	assert.Equal(t, "500mg", medicationInfo["strength"])
	assert.Equal(t, "Tablet", medicationInfo["form"])
	assert.Equal(t, "Oral", medicationInfo["route"])
}

// Patient Verification Tests

func TestVerifyPatientWristband_Success(t *testing.T) {
	service, mockPatientRepo := setupBarcodeService()

	barcode := "P-PAT123-017B"
	patient := &types.Patient{
		ID: "PAT123",
	}

	// Setup mocks
	mockPatientRepo.On("GetByID", "PAT123").Return(patient, nil)

	isValid, returnedPatient, err := service.VerifyPatientWristband(barcode)

	assert.NoError(t, err)
	assert.True(t, isValid)
	assert.NotNil(t, returnedPatient)
	assert.Equal(t, "PAT123", returnedPatient.ID)

	// Verify mocks
	mockPatientRepo.AssertExpectations(t)
}

func TestVerifyPatientWristband_NotPatientBarcode(t *testing.T) {
	service, _ := setupBarcodeService()

	barcode := "M-MED001-LOT123-20241231" // Medication barcode, not patient

	isValid, patient, err := service.VerifyPatientWristband(barcode)

	assert.Error(t, err)
	assert.False(t, isValid)
	assert.Nil(t, patient)
	assert.Contains(t, err.Error(), "not a patient wristband")
}

func TestVerifyPatientWristband_PatientNotFound(t *testing.T) {
	service, mockPatientRepo := setupBarcodeService()

	barcode := "P-PAT999-A1B2"

	// Setup mocks - patient not found
	mockPatientRepo.On("GetByID", "PAT999").Return((*types.Patient)(nil), assert.AnError)

	isValid, patient, err := service.VerifyPatientWristband(barcode)

	assert.Error(t, err)
	assert.False(t, isValid)
	assert.Nil(t, patient)

	// Verify mocks
	mockPatientRepo.AssertExpectations(t)
}

// Helper Function Tests

func TestGenerateChecksum(t *testing.T) {
	service, _ := setupBarcodeService()

	testCases := []struct {
		input    string
		expected string
	}{
		{"PAT123", "017B"}, // Sum of ASCII values % 65536 in hex
		{"MED456", "0175"},
		{"", "0000"},
	}

	for _, tc := range testCases {
		result := service.generateChecksum(tc.input)
		assert.Equal(t, tc.expected, result, "Checksum for %s should be %s", tc.input, tc.expected)
	}
}

func TestIsHighRiskMedication_BarcodeService(t *testing.T) {
	service, _ := setupBarcodeService()

	testCases := []struct {
		medicationID string
		expected     bool
	}{
		{"MED003", true},  // High-risk medication
		{"MED004", true},  // High-risk medication
		{"MED005", true},  // High-risk medication
		{"MED001", false}, // Regular medication
		{"MED002", false}, // Regular medication
	}

	for _, tc := range testCases {
		result := service.isHighRiskMedication(tc.medicationID)
		assert.Equal(t, tc.expected, result, 
			"Medication %s should be high-risk: %t", tc.medicationID, tc.expected)
	}
}

func TestVerifyWristbandData(t *testing.T) {
	service, _ := setupBarcodeService()

	patient := &types.Patient{
		ID: "PAT123",
	}

	testCases := []struct {
		name         string
		wristbandData map[string]string
		expected     bool
	}{
		{
			name: "Valid wristband data",
			wristbandData: map[string]string{
				"patient_id": "PAT123",
				"checksum":   service.generateChecksum("PAT123"),
			},
			expected: true,
		},
		{
			name: "Invalid patient ID",
			wristbandData: map[string]string{
				"patient_id": "PAT999",
				"checksum":   service.generateChecksum("PAT123"),
			},
			expected: false,
		},
		{
			name: "Invalid checksum",
			wristbandData: map[string]string{
				"patient_id": "PAT123",
				"checksum":   "INVALID",
			},
			expected: false,
		},
		{
			name: "Missing checksum",
			wristbandData: map[string]string{
				"patient_id": "PAT123",
			},
			expected: true, // Should still pass without checksum
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := service.verifyWristbandData(tc.wristbandData, patient)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Benchmark Tests

func BenchmarkDecodeBarcode(b *testing.B) {
	service, _ := setupBarcodeService()
	barcode := "P-PAT123-A1B2"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.DecodeBarcode(barcode)
	}
}

func BenchmarkGenerateChecksum(b *testing.B) {
	service, _ := setupBarcodeService()
	input := "PAT123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.generateChecksum(input)
	}
}

func BenchmarkValidateBarcode(b *testing.B) {
	service, _ := setupBarcodeService()
	barcode := "P-PAT123-A1B2"
	expectedType := "patient"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		service.ValidateBarcode(barcode, expectedType)
	}
}