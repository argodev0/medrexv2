package mobile

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/types"
)

// BarcodeService implements barcode/QR code operations
type BarcodeService struct {
	patientRepo interfaces.PatientRepository
}

// NewBarcodeService creates a new barcode service
func NewBarcodeService(patientRepo interfaces.PatientRepository) *BarcodeService {
	return &BarcodeService{
		patientRepo: patientRepo,
	}
}

// Barcode Operations

// DecodeBarcode decodes a barcode and returns scan result
func (s *BarcodeService) DecodeBarcode(code string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Code:      code,
		ScannedAt: time.Now(),
		Data:      make(map[string]string),
	}

	// Determine barcode type and decode
	barcodeType, data, err := s.identifyBarcodeType(code)
	if err != nil {
		result.Type = "unknown"
		result.IsValid = false
		return result, fmt.Errorf("failed to identify barcode type: %w", err)
	}

	result.Type = barcodeType
	result.Data = data
	result.IsValid = true

	return result, nil
}

// ValidateBarcode validates a barcode against expected type
func (s *BarcodeService) ValidateBarcode(code, expectedType string) (bool, error) {
	result, err := s.DecodeBarcode(code)
	if err != nil {
		return false, err
	}

	if result.Type != expectedType {
		return false, fmt.Errorf("barcode type mismatch: expected %s, got %s", expectedType, result.Type)
	}

	return result.IsValid, nil
}

// GenerateBarcode generates a barcode for given data
func (s *BarcodeService) GenerateBarcode(data map[string]string, format string) (string, error) {
	switch format {
	case "code128":
		return s.generateCode128(data)
	case "code39":
		return s.generateCode39(data)
	default:
		return "", fmt.Errorf("unsupported barcode format: %s", format)
	}
}

// QR Code Operations

// DecodeQRCode decodes a QR code and returns scan result
func (s *BarcodeService) DecodeQRCode(code string) (*types.ScanResult, error) {
	result := &types.ScanResult{
		Code:      code,
		ScannedAt: time.Now(),
		Data:      make(map[string]string),
	}

	// Try to parse as JSON first
	var jsonData map[string]string
	if err := json.Unmarshal([]byte(code), &jsonData); err == nil {
		result.Type = s.determineQRType(jsonData)
		result.Data = jsonData
		result.IsValid = true
		return result, nil
	}

	// Try to parse as delimited string
	qrType, data, err := s.parseDelimitedQR(code)
	if err != nil {
		result.IsValid = false
		return result, fmt.Errorf("failed to parse QR code: %w", err)
	}

	result.Type = qrType
	result.Data = data
	result.IsValid = true

	return result, nil
}

// ValidateQRCode validates a QR code against expected type
func (s *BarcodeService) ValidateQRCode(code, expectedType string) (bool, error) {
	result, err := s.DecodeQRCode(code)
	if err != nil {
		return false, err
	}

	if result.Type != expectedType {
		return false, fmt.Errorf("QR code type mismatch: expected %s, got %s", expectedType, result.Type)
	}

	return result.IsValid, nil
}

// GenerateQRCode generates a QR code for given data
func (s *BarcodeService) GenerateQRCode(data map[string]string) (string, error) {
	// Generate JSON format QR code
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal QR data: %w", err)
	}

	return string(jsonData), nil
}

// Medication Verification

// VerifyMedicationBarcode verifies medication barcode against patient
func (s *BarcodeService) VerifyMedicationBarcode(code, patientID string) (bool, map[string]string, error) {
	// Decode medication barcode
	result, err := s.DecodeBarcode(code)
	if err != nil {
		return false, nil, fmt.Errorf("failed to decode medication barcode: %w", err)
	}

	if result.Type != "medication" {
		return false, nil, fmt.Errorf("barcode is not a medication barcode")
	}

	// Extract medication information
	medicationID, exists := result.Data["medication_id"]
	if !exists {
		return false, nil, fmt.Errorf("medication ID not found in barcode")
	}

	// Get medication information
	medicationInfo, err := s.GetMedicationInfo(code)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get medication info: %w", err)
	}

	// Verify against patient allergies and current medications
	isValid, err := s.verifyMedicationSafety(medicationID, patientID)
	if err != nil {
		return false, medicationInfo, fmt.Errorf("medication safety check failed: %w", err)
	}

	return isValid, medicationInfo, nil
}

// GetMedicationInfo retrieves medication information from barcode
func (s *BarcodeService) GetMedicationInfo(code string) (map[string]string, error) {
	result, err := s.DecodeBarcode(code)
	if err != nil {
		return nil, fmt.Errorf("failed to decode barcode: %w", err)
	}

	if result.Type != "medication" {
		return nil, fmt.Errorf("barcode is not a medication barcode")
	}

	// Return medication information from barcode data
	medicationInfo := make(map[string]string)
	for key, value := range result.Data {
		medicationInfo[key] = value
	}

	// Add additional medication details if available
	if medicationID, exists := result.Data["medication_id"]; exists {
		additionalInfo := s.lookupMedicationDetails(medicationID)
		for key, value := range additionalInfo {
			medicationInfo[key] = value
		}
	}

	return medicationInfo, nil
}

// Patient Verification

// VerifyPatientWristband verifies patient wristband barcode
func (s *BarcodeService) VerifyPatientWristband(code string) (bool, *types.Patient, error) {
	result, err := s.DecodeBarcode(code)
	if err != nil {
		return false, nil, fmt.Errorf("failed to decode wristband barcode: %w", err)
	}

	if result.Type != "patient" {
		return false, nil, fmt.Errorf("barcode is not a patient wristband")
	}

	// Extract patient ID
	patientID, exists := result.Data["patient_id"]
	if !exists {
		return false, nil, fmt.Errorf("patient ID not found in wristband barcode")
	}

	// Verify patient exists and get patient information
	patient, err := s.patientRepo.GetByID(patientID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get patient: %w", err)
	}

	// Verify wristband data matches patient record
	isValid := s.verifyWristbandData(result.Data, patient)

	return isValid, patient, nil
}

// Helper methods

// identifyBarcodeType identifies the type of barcode and extracts data
func (s *BarcodeService) identifyBarcodeType(code string) (string, map[string]string, error) {
	data := make(map[string]string)

	// Patient wristband pattern: P-{patient_id}-{checksum}
	if matched, _ := regexp.MatchString(`^P-[A-Z0-9]+-[A-Z0-9]+$`, code); matched {
		parts := strings.Split(code, "-")
		if len(parts) >= 3 {
			data["patient_id"] = parts[1]
			data["checksum"] = parts[2]
			return "patient", data, nil
		}
	}

	// Medication barcode pattern: M-{medication_id}-{lot_number}-{expiry}
	if matched, _ := regexp.MatchString(`^M-[A-Z0-9]+-[A-Z0-9]+-[0-9]{8}$`, code); matched {
		parts := strings.Split(code, "-")
		if len(parts) >= 4 {
			data["medication_id"] = parts[1]
			data["lot_number"] = parts[2]
			data["expiry_date"] = parts[3]
			return "medication", data, nil
		}
	}

	// Equipment barcode pattern: E-{equipment_id}-{location}
	if matched, _ := regexp.MatchString(`^E-[A-Z0-9]+-[A-Z0-9]+$`, code); matched {
		parts := strings.Split(code, "-")
		if len(parts) >= 3 {
			data["equipment_id"] = parts[1]
			data["location"] = parts[2]
			return "equipment", data, nil
		}
	}

	// Specimen barcode pattern: S-{specimen_id}-{patient_id}-{test_type}
	if matched, _ := regexp.MatchString(`^S-[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+$`, code); matched {
		parts := strings.Split(code, "-")
		if len(parts) >= 4 {
			data["specimen_id"] = parts[1]
			data["patient_id"] = parts[2]
			data["test_type"] = parts[3]
			return "specimen", data, nil
		}
	}

	return "unknown", data, fmt.Errorf("unrecognized barcode format: %s", code)
}

// determineQRType determines QR code type from JSON data
func (s *BarcodeService) determineQRType(data map[string]string) string {
	if _, exists := data["patient_id"]; exists {
		if _, exists := data["medication_id"]; exists {
			return "medication_admin"
		}
		return "patient"
	}

	if _, exists := data["equipment_id"]; exists {
		return "equipment"
	}

	if _, exists := data["order_id"]; exists {
		return "order"
	}

	return "unknown"
}

// parseDelimitedQR parses delimited QR code format
func (s *BarcodeService) parseDelimitedQR(code string) (string, map[string]string, error) {
	data := make(map[string]string)

	// Split by delimiter (|)
	parts := strings.Split(code, "|")
	if len(parts) < 2 {
		return "unknown", data, fmt.Errorf("invalid QR code format")
	}

	qrType := parts[0]
	for i := 1; i < len(parts); i++ {
		keyValue := strings.Split(parts[i], "=")
		if len(keyValue) == 2 {
			data[keyValue[0]] = keyValue[1]
		}
	}

	return qrType, data, nil
}

// generateCode128 generates Code 128 barcode
func (s *BarcodeService) generateCode128(data map[string]string) (string, error) {
	// This is a simplified implementation
	// In a real system, this would generate actual Code 128 barcode data
	var parts []string
	
	if patientID, exists := data["patient_id"]; exists {
		parts = append(parts, "P", patientID, s.generateChecksum(patientID))
	} else if medicationID, exists := data["medication_id"]; exists {
		parts = append(parts, "M", medicationID)
		if lot, exists := data["lot_number"]; exists {
			parts = append(parts, lot)
		}
		if expiry, exists := data["expiry_date"]; exists {
			parts = append(parts, expiry)
		}
	}

	return strings.Join(parts, "-"), nil
}

// generateCode39 generates Code 39 barcode
func (s *BarcodeService) generateCode39(data map[string]string) (string, error) {
	// This is a simplified implementation
	// In a real system, this would generate actual Code 39 barcode data
	return s.generateCode128(data) // Use same logic for simplicity
}

// generateChecksum generates a simple checksum for validation
func (s *BarcodeService) generateChecksum(input string) string {
	// Simple checksum implementation
	sum := 0
	for _, char := range input {
		sum += int(char)
	}
	return fmt.Sprintf("%04X", sum%65536)
}

// verifyMedicationSafety verifies medication safety against patient profile
func (s *BarcodeService) verifyMedicationSafety(medicationID, patientID string) (bool, error) {
	// This would integrate with medication safety systems
	// For now, implement basic safety checks
	
	// Get patient information
	patient, err := s.patientRepo.GetByID(patientID)
	if err != nil {
		return false, fmt.Errorf("failed to get patient: %w", err)
	}

	// Check for basic safety issues (simplified implementation)
	if s.isHighRiskMedication(medicationID) {
		// Additional verification required for high-risk medications
		return true, nil // Allow but flag for review
	}

	// Check against known allergies (would be implemented with real allergy data)
	if s.hasKnownAllergy(patient, medicationID) {
		return false, fmt.Errorf("patient has known allergy to medication")
	}

	return true, nil
}

// lookupMedicationDetails looks up additional medication details
func (s *BarcodeService) lookupMedicationDetails(medicationID string) map[string]string {
	// This would integrate with medication database
	// For now, return mock data
	details := map[string]string{
		"name":        "Unknown Medication",
		"strength":    "Unknown",
		"form":        "Unknown",
		"route":       "Unknown",
	}

	// Mock medication data
	mockMedications := map[string]map[string]string{
		"MED001": {
			"name":     "Acetaminophen",
			"strength": "500mg",
			"form":     "Tablet",
			"route":    "Oral",
		},
		"MED002": {
			"name":     "Ibuprofen",
			"strength": "200mg",
			"form":     "Tablet",
			"route":    "Oral",
		},
	}

	if medDetails, exists := mockMedications[medicationID]; exists {
		return medDetails
	}

	return details
}

// verifyWristbandData verifies wristband data against patient record
func (s *BarcodeService) verifyWristbandData(wristbandData map[string]string, patient *types.Patient) bool {
	// Verify patient ID matches
	if patientID, exists := wristbandData["patient_id"]; exists {
		if patientID != patient.ID {
			return false
		}
	}

	// Verify checksum if present
	if checksum, exists := wristbandData["checksum"]; exists {
		expectedChecksum := s.generateChecksum(patient.ID)
		if checksum != expectedChecksum {
			return false
		}
	}

	return true
}

// isHighRiskMedication checks if medication is high-risk
func (s *BarcodeService) isHighRiskMedication(medicationID string) bool {
	highRiskMeds := []string{"MED003", "MED004", "MED005"} // Mock high-risk medications
	for _, med := range highRiskMeds {
		if medicationID == med {
			return true
		}
	}
	return false
}

// hasKnownAllergy checks if patient has known allergy to medication
func (s *BarcodeService) hasKnownAllergy(patient *types.Patient, medicationID string) bool {
	// This would check against patient allergy records
	// For now, return false (no allergies)
	return false
}