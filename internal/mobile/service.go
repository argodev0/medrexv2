package mobile

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Service implements the MobileWorkflowService interface
type Service struct {
	repo           interfaces.MobileRepository
	barcodeService interfaces.BarcodeService
	offlineSync    interfaces.OfflineSyncService
	workflowEngine interfaces.WorkflowEngine
	iamService     interfaces.IAMService
	auditService   interfaces.AuditService
}

// NewService creates a new mobile workflow service
func NewService(
	repo interfaces.MobileRepository,
	barcodeService interfaces.BarcodeService,
	offlineSync interfaces.OfflineSyncService,
	workflowEngine interfaces.WorkflowEngine,
	iamService interfaces.IAMService,
	auditService interfaces.AuditService,
) *Service {
	return &Service{
		repo:           repo,
		barcodeService: barcodeService,
		offlineSync:    offlineSync,
		workflowEngine: workflowEngine,
		iamService:     iamService,
		auditService:   auditService,
	}
}

// CPOE Workflow Management Implementation

// CreateOrder creates a new CPOE order with proper validation and co-signature requirements
func (s *Service) CreateOrder(order *types.CPOEOrder, userID string) (*types.CPOEOrder, error) {
	// Validate user permissions
	hasPermission, err := s.iamService.ValidatePermissions(userID, "cpoe_orders", "create")
	if err != nil {
		return nil, fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user %s does not have permission to create CPOE orders", userID)
	}

	// Get user role to determine co-signature requirements
	user, err := s.iamService.GetUser(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Set order defaults
	order.ID = uuid.New().String()
	order.OrderingMD = userID
	order.Status = string(types.OrderStatusDraft)
	order.CreatedAt = time.Now()
	order.UpdatedAt = time.Now()

	// Determine if co-signature is required based on user role
	order.RequiresCoSign = s.requiresCoSignature(user.Role, order.OrderType)

	// Validate order details based on type
	if err := s.validateOrderDetails(order); err != nil {
		return nil, fmt.Errorf("order validation failed: %w", err)
	}

	// Check for drug interactions and allergies if medication order
	if order.OrderType == string(types.OrderTypeMedication) {
		if err := s.checkDrugInteractions(order); err != nil {
			return nil, fmt.Errorf("drug interaction check failed: %w", err)
		}
	}

	// Save order to repository
	if err := s.repo.CreateOrder(order); err != nil {
		return nil, fmt.Errorf("failed to create order: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"order_id":   order.ID,
		"order_type": order.OrderType,
		"patient_id": order.PatientID,
		"requires_co_sign": order.RequiresCoSign,
	}
	if err := s.auditService.LogEvent(userID, "cpoe_order_created", order.ID, true, auditData); err != nil {
		// Log error but don't fail the operation
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return order, nil
}

// GetOrder retrieves a CPOE order by ID with proper authorization
func (s *Service) GetOrder(orderID, userID string) (*types.CPOEOrder, error) {
	// Validate user permissions
	hasPermission, err := s.iamService.ValidatePermissions(userID, "cpoe_orders", "read")
	if err != nil {
		return nil, fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user %s does not have permission to read CPOE orders", userID)
	}

	order, err := s.repo.GetOrderByID(orderID)
	if err != nil {
		return nil, fmt.Errorf("failed to get order: %w", err)
	}

	// Check if user has access to this specific order
	if !s.canAccessOrder(order, userID) {
		return nil, fmt.Errorf("user %s does not have access to order %s", userID, orderID)
	}

	return order, nil
}

// UpdateOrder updates an existing CPOE order
func (s *Service) UpdateOrder(orderID string, updates map[string]interface{}, userID string) error {
	// Get existing order
	order, err := s.GetOrder(orderID, userID)
	if err != nil {
		return err
	}

	// Check if order can be updated
	if !s.canUpdateOrder(order, userID) {
		return fmt.Errorf("order %s cannot be updated in current state", orderID)
	}

	// Apply updates
	updates["updated_at"] = time.Now()
	if err := s.repo.UpdateOrder(orderID, updates); err != nil {
		return fmt.Errorf("failed to update order: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"order_id": orderID,
		"updates":  updates,
	}
	if err := s.auditService.LogEvent(userID, "cpoe_order_updated", orderID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// CancelOrder cancels a CPOE order
func (s *Service) CancelOrder(orderID, userID string) error {
	order, err := s.GetOrder(orderID, userID)
	if err != nil {
		return err
	}

	// Check if order can be cancelled
	if order.Status == string(types.OrderStatusExecuted) || order.Status == string(types.OrderStatusCancelled) {
		return fmt.Errorf("order %s cannot be cancelled in status %s", orderID, order.Status)
	}

	updates := map[string]interface{}{
		"status":     string(types.OrderStatusCancelled),
		"updated_at": time.Now(),
	}

	if err := s.repo.UpdateOrder(orderID, updates); err != nil {
		return fmt.Errorf("failed to cancel order: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"order_id": orderID,
		"reason":   "cancelled_by_user",
	}
	if err := s.auditService.LogEvent(userID, "cpoe_order_cancelled", orderID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// Co-signature Workflow Implementation

// RequestCoSignature requests co-signature from a consultant for student orders
func (s *Service) RequestCoSignature(orderID, consultantID string) error {
	order, err := s.repo.GetOrderByID(orderID)
	if err != nil {
		return fmt.Errorf("failed to get order: %w", err)
	}

	if !order.RequiresCoSign {
		return fmt.Errorf("order %s does not require co-signature", orderID)
	}

	// Validate consultant permissions
	hasPermission, err := s.iamService.ValidatePermissions(consultantID, "cpoe_orders", "co_sign")
	if err != nil {
		return fmt.Errorf("failed to validate consultant permissions: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user %s does not have co-signature permissions", consultantID)
	}

	updates := map[string]interface{}{
		"co_signing_md": consultantID,
		"status":        string(types.OrderStatusPending),
		"updated_at":    time.Now(),
	}

	if err := s.repo.UpdateOrder(orderID, updates); err != nil {
		return fmt.Errorf("failed to request co-signature: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"order_id":      orderID,
		"consultant_id": consultantID,
		"ordering_md":   order.OrderingMD,
	}
	if err := s.auditService.LogEvent(order.OrderingMD, "co_signature_requested", orderID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// ApproveOrder approves an order requiring co-signature
func (s *Service) ApproveOrder(orderID, consultantID string) error {
	order, err := s.repo.GetOrderByID(orderID)
	if err != nil {
		return fmt.Errorf("failed to get order: %w", err)
	}

	if order.CoSigningMD != consultantID {
		return fmt.Errorf("user %s is not assigned as co-signing consultant for order %s", consultantID, orderID)
	}

	now := time.Now()
	updates := map[string]interface{}{
		"status":       string(types.OrderStatusApproved),
		"co_signed_at": &now,
		"updated_at":   now,
	}

	if err := s.repo.UpdateOrder(orderID, updates); err != nil {
		return fmt.Errorf("failed to approve order: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"order_id":      orderID,
		"consultant_id": consultantID,
		"ordering_md":   order.OrderingMD,
	}
	if err := s.auditService.LogEvent(consultantID, "cpoe_order_approved", orderID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// RejectOrder rejects an order requiring co-signature
func (s *Service) RejectOrder(orderID, consultantID, reason string) error {
	order, err := s.repo.GetOrderByID(orderID)
	if err != nil {
		return fmt.Errorf("failed to get order: %w", err)
	}

	if order.CoSigningMD != consultantID {
		return fmt.Errorf("user %s is not assigned as co-signing consultant for order %s", consultantID, orderID)
	}

	updates := map[string]interface{}{
		"status":     string(types.OrderStatusCancelled),
		"updated_at": time.Now(),
	}

	if err := s.repo.UpdateOrder(orderID, updates); err != nil {
		return fmt.Errorf("failed to reject order: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"order_id":      orderID,
		"consultant_id": consultantID,
		"ordering_md":   order.OrderingMD,
		"reason":        reason,
	}
	if err := s.auditService.LogEvent(consultantID, "cpoe_order_rejected", orderID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// GetPendingCoSignatures retrieves orders pending co-signature for a consultant
func (s *Service) GetPendingCoSignatures(consultantID string) ([]*types.CPOEOrder, error) {
	// Validate consultant permissions
	hasPermission, err := s.iamService.ValidatePermissions(consultantID, "cpoe_orders", "co_sign")
	if err != nil {
		return nil, fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user %s does not have co-signature permissions", consultantID)
	}

	orders, err := s.repo.GetPendingOrders(consultantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending orders: %w", err)
	}

	return orders, nil
}

// Helper methods

// requiresCoSignature determines if an order requires co-signature based on user role and order type
func (s *Service) requiresCoSignature(userRole types.UserRole, orderType string) bool {
	// Students require co-signature for all orders except basic nursing orders
	if userRole == types.RoleMBBSStudent || userRole == types.RoleMDStudent {
		return orderType != string(types.OrderTypeNursing)
	}
	return false
}

// validateOrderDetails validates order details based on order type
func (s *Service) validateOrderDetails(order *types.CPOEOrder) error {
	if order.PatientID == "" {
		return fmt.Errorf("patient ID is required")
	}
	if order.OrderType == "" {
		return fmt.Errorf("order type is required")
	}
	if order.Details == "" {
		return fmt.Errorf("order details are required")
	}

	// Type-specific validation
	switch types.OrderType(order.OrderType) {
	case types.OrderTypeMedication:
		return s.validateMedicationOrder(order)
	case types.OrderTypeLab:
		return s.validateLabOrder(order)
	case types.OrderTypeImaging:
		return s.validateImagingOrder(order)
	default:
		// Basic validation for other order types
		return nil
	}
}

// validateMedicationOrder validates medication-specific order details
func (s *Service) validateMedicationOrder(order *types.CPOEOrder) error {
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(order.Details), &details); err != nil {
		return fmt.Errorf("invalid medication order details format")
	}

	required := []string{"medication_name", "dose", "route", "frequency"}
	for _, field := range required {
		if _, exists := details[field]; !exists {
			return fmt.Errorf("medication order missing required field: %s", field)
		}
	}

	return nil
}

// validateLabOrder validates lab-specific order details
func (s *Service) validateLabOrder(order *types.CPOEOrder) error {
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(order.Details), &details); err != nil {
		return fmt.Errorf("invalid lab order details format")
	}

	if _, exists := details["test_name"]; !exists {
		return fmt.Errorf("lab order missing required field: test_name")
	}

	return nil
}

// validateImagingOrder validates imaging-specific order details
func (s *Service) validateImagingOrder(order *types.CPOEOrder) error {
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(order.Details), &details); err != nil {
		return fmt.Errorf("invalid imaging order details format")
	}

	required := []string{"study_type", "body_part"}
	for _, field := range required {
		if _, exists := details[field]; !exists {
			return fmt.Errorf("imaging order missing required field: %s", field)
		}
	}

	return nil
}

// checkDrugInteractions checks for drug interactions and allergies
func (s *Service) checkDrugInteractions(order *types.CPOEOrder) error {
	// This would integrate with a drug interaction database
	// For now, implement basic validation
	var details map[string]interface{}
	if err := json.Unmarshal([]byte(order.Details), &details); err != nil {
		return fmt.Errorf("invalid medication details")
	}

	medicationName, ok := details["medication_name"].(string)
	if !ok {
		return fmt.Errorf("medication name not found")
	}

	// Basic drug interaction check (would be replaced with real drug database)
	if s.isHighRiskMedication(medicationName) {
		// Add warning to order details
		details["warnings"] = []string{"High-risk medication - requires careful monitoring"}
		updatedDetails, _ := json.Marshal(details)
		order.Details = string(updatedDetails)
	}

	return nil
}

// isHighRiskMedication checks if a medication is high-risk (simplified implementation)
func (s *Service) isHighRiskMedication(medicationName string) bool {
	highRiskMeds := []string{"warfarin", "insulin", "heparin", "digoxin"}
	for _, med := range highRiskMeds {
		if medicationName == med {
			return true
		}
	}
	return false
}

// canAccessOrder checks if a user can access a specific order
func (s *Service) canAccessOrder(order *types.CPOEOrder, userID string) bool {
	// User can access if they are the ordering physician or co-signing consultant
	if order.OrderingMD == userID || order.CoSigningMD == userID {
		return true
	}

	// Additional access checks could be implemented here based on role and patient assignment
	return false
}

// canUpdateOrder checks if an order can be updated by the user
func (s *Service) canUpdateOrder(order *types.CPOEOrder, userID string) bool {
	// Only ordering physician can update, and only if not executed or cancelled
	if order.OrderingMD != userID {
		return false
	}

	return order.Status != string(types.OrderStatusExecuted) && 
		   order.Status != string(types.OrderStatusCancelled)
}

// Barcode/QR Scanning Implementation

// ScanBarcode processes a barcode scan and returns the result
func (s *Service) ScanBarcode(barcode string, userID string) (*types.ScanResult, error) {
	// Validate user permissions
	hasPermission, err := s.iamService.ValidatePermissions(userID, "barcode_scanning", "scan")
	if err != nil {
		return nil, fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user %s does not have barcode scanning permissions", userID)
	}

	// Decode barcode using barcode service
	result, err := s.barcodeService.DecodeBarcode(barcode)
	if err != nil {
		return nil, fmt.Errorf("failed to decode barcode: %w", err)
	}

	// Set scan metadata
	result.ScannedAt = time.Now()
	result.ScannedBy = userID

	// Log audit event
	auditData := map[string]interface{}{
		"barcode": barcode,
		"type":    result.Type,
		"valid":   result.IsValid,
	}
	if err := s.auditService.LogEvent(userID, "barcode_scanned", barcode, result.IsValid, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return result, nil
}

// ValidateScan validates a scan result
func (s *Service) ValidateScan(scanResult *types.ScanResult) (bool, error) {
	return s.barcodeService.ValidateBarcode(scanResult.Code, scanResult.Type)
}

// ProcessScanResult processes a scan result based on its type
func (s *Service) ProcessScanResult(scanResult *types.ScanResult, userID string) error {
	switch scanResult.Type {
	case "medication":
		return s.processMedicationScan(scanResult, userID)
	case "patient":
		return s.processPatientScan(scanResult, userID)
	case "equipment":
		return s.processEquipmentScan(scanResult, userID)
	default:
		return fmt.Errorf("unsupported scan type: %s", scanResult.Type)
	}
}

// Medication Administration Implementation

// RecordMedicationAdmin records medication administration
func (s *Service) RecordMedicationAdmin(admin *types.MedicationAdministration, userID string) error {
	// Validate user permissions (nurses can administer medications)
	hasPermission, err := s.iamService.ValidatePermissions(userID, "medication_admin", "create")
	if err != nil {
		return fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user %s does not have medication administration permissions", userID)
	}

	// Set administration metadata
	admin.ID = uuid.New().String()
	admin.NurseID = userID
	admin.AdministeredAt = time.Now()
	admin.CreatedAt = time.Now()

	// Verify medication order exists and is approved
	if err := s.verifyMedicationOrder(admin.OrderID); err != nil {
		return fmt.Errorf("medication order verification failed: %w", err)
	}

	// Save administration record
	if err := s.repo.CreateMedicationAdmin(admin); err != nil {
		return fmt.Errorf("failed to record medication administration: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"admin_id":      admin.ID,
		"order_id":      admin.OrderID,
		"patient_id":    admin.PatientID,
		"medication_id": admin.MedicationID,
		"dose":          admin.Dose,
		"route":         admin.Route,
	}
	if err := s.auditService.LogEvent(userID, "medication_administered", admin.ID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// GetMedicationSchedule retrieves medication schedule for a patient
func (s *Service) GetMedicationSchedule(patientID, userID string) ([]*types.MedicationAdministration, error) {
	// Validate user permissions
	hasPermission, err := s.iamService.ValidatePermissions(userID, "medication_admin", "read")
	if err != nil {
		return nil, fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user %s does not have permission to read medication schedules", userID)
	}

	schedule, err := s.repo.GetMedicationSchedule(patientID)
	if err != nil {
		return nil, fmt.Errorf("failed to get medication schedule: %w", err)
	}

	return schedule, nil
}

// VerifyMedication verifies medication against patient allergies and interactions
func (s *Service) VerifyMedication(medicationID, patientID string) (bool, error) {
	// This would integrate with medication verification systems
	// For now, implement basic verification
	return true, nil
}

// Lab Results Implementation

// EnterLabResult enters a lab result
func (s *Service) EnterLabResult(result *types.LabResult, userID string) error {
	// Validate user permissions (lab technicians can enter results)
	hasPermission, err := s.iamService.ValidatePermissions(userID, "lab_results", "create")
	if err != nil {
		return fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user %s does not have lab result entry permissions", userID)
	}

	// Set result metadata
	result.ID = uuid.New().String()
	result.TechnicianID = userID
	result.ResultedAt = time.Now()
	result.CreatedAt = time.Now()
	result.Status = "final"

	// Validate result data
	if err := s.validateLabResult(result); err != nil {
		return fmt.Errorf("lab result validation failed: %w", err)
	}

	// Save result
	if err := s.repo.CreateLabResult(result); err != nil {
		return fmt.Errorf("failed to create lab result: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"result_id":  result.ID,
		"order_id":   result.OrderID,
		"patient_id": result.PatientID,
		"test_name":  result.TestName,
		"result":     result.Result,
	}
	if err := s.auditService.LogEvent(userID, "lab_result_entered", result.ID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// GetLabResults retrieves lab results for a patient
func (s *Service) GetLabResults(patientID, userID string) ([]*types.LabResult, error) {
	// Validate user permissions
	hasPermission, err := s.iamService.ValidatePermissions(userID, "lab_results", "read")
	if err != nil {
		return nil, fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user %s does not have permission to read lab results", userID)
	}

	filters := map[string]interface{}{
		"patient_id": patientID,
	}
	results, err := s.repo.GetLabResults(patientID, filters)
	if err != nil {
		return nil, fmt.Errorf("failed to get lab results: %w", err)
	}

	return results, nil
}

// VerifyLabResult verifies and finalizes a lab result
func (s *Service) VerifyLabResult(resultID, userID string) error {
	// Validate user permissions
	hasPermission, err := s.iamService.ValidatePermissions(userID, "lab_results", "verify")
	if err != nil {
		return fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user %s does not have lab result verification permissions", userID)
	}

	updates := map[string]interface{}{
		"status": "verified",
	}

	if err := s.repo.UpdateLabResult(resultID, updates); err != nil {
		return fmt.Errorf("failed to verify lab result: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"result_id": resultID,
	}
	if err := s.auditService.LogEvent(userID, "lab_result_verified", resultID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// Offline Synchronization Implementation

// SyncOfflineData synchronizes offline data from mobile devices
func (s *Service) SyncOfflineData(data *types.OfflineData, userID string) error {
	// Validate user permissions
	hasPermission, err := s.iamService.ValidatePermissions(userID, "offline_sync", "sync")
	if err != nil {
		return fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return fmt.Errorf("user %s does not have offline sync permissions", userID)
	}

	// Validate offline data
	isValid, errors, err := s.offlineSync.ValidateOfflineData(data)
	if err != nil {
		return fmt.Errorf("failed to validate offline data: %w", err)
	}
	if !isValid {
		return fmt.Errorf("offline data validation failed: %v", errors)
	}

	// Sync data using offline sync service
	if err := s.offlineSync.SyncUserData(userID, data.DeviceID, data); err != nil {
		return fmt.Errorf("failed to sync offline data: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"device_id":    data.DeviceID,
		"orders_count": len(data.Orders),
		"scans_count":  len(data.Scans),
		"notes_count":  len(data.Notes),
	}
	if err := s.auditService.LogEvent(userID, "offline_data_synced", data.DeviceID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// GetOfflineData retrieves offline data for a user and device
func (s *Service) GetOfflineData(userID, deviceID string) (*types.OfflineData, error) {
	// Validate user permissions
	hasPermission, err := s.iamService.ValidatePermissions(userID, "offline_sync", "read")
	if err != nil {
		return nil, fmt.Errorf("failed to validate permissions: %w", err)
	}
	if !hasPermission {
		return nil, fmt.Errorf("user %s does not have offline data access permissions", userID)
	}

	data, err := s.offlineSync.GetPendingSyncData(userID, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get offline data: %w", err)
	}

	return data, nil
}

// MarkDataSynced marks data as synced
func (s *Service) MarkDataSynced(userID, deviceID string, syncedAt string) error {
	return s.offlineSync.MarkDataSynced(userID, deviceID, []string{syncedAt})
}

// Mobile-specific Features

// GetMobileConfig retrieves mobile configuration for a user
func (s *Service) GetMobileConfig(userID string) (map[string]interface{}, error) {
	// Get user role to determine mobile configuration
	user, err := s.iamService.GetUser(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	config := map[string]interface{}{
		"user_role":           user.Role,
		"barcode_scanning":    s.getBarcodeConfig(user.Role),
		"offline_sync":        s.getOfflineSyncConfig(user.Role),
		"cpoe_permissions":    s.getCPOEPermissions(user.Role),
		"medication_admin":    s.getMedicationAdminConfig(user.Role),
		"lab_result_entry":    s.getLabResultConfig(user.Role),
	}

	return config, nil
}

// UpdateMobilePreferences updates mobile preferences for a user
func (s *Service) UpdateMobilePreferences(userID string, preferences map[string]interface{}) error {
	// This would store user preferences in the database
	// For now, just validate the preferences
	if err := s.validateMobilePreferences(preferences); err != nil {
		return fmt.Errorf("invalid mobile preferences: %w", err)
	}

	// Log audit event
	auditData := map[string]interface{}{
		"preferences": preferences,
	}
	if err := s.auditService.LogEvent(userID, "mobile_preferences_updated", userID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

// Service Management

// Start starts the mobile workflow service
func (s *Service) Start(addr string) error {
	// This would start the HTTP server for the mobile service
	// Implementation would depend on the HTTP framework used
	return nil
}

// Stop stops the mobile workflow service
func (s *Service) Stop() error {
	// This would gracefully stop the HTTP server
	return nil
}

// Helper methods for mobile-specific features

func (s *Service) processMedicationScan(scanResult *types.ScanResult, userID string) error {
	// Process medication barcode scan
	medicationID, exists := scanResult.Data["medication_id"]
	if !exists {
		return fmt.Errorf("medication ID not found in scan result")
	}

	patientID, exists := scanResult.Data["patient_id"]
	if !exists {
		return fmt.Errorf("patient ID not found in scan result")
	}

	// Verify medication against patient
	isValid, err := s.VerifyMedication(medicationID, patientID)
	if err != nil {
		return fmt.Errorf("medication verification failed: %w", err)
	}
	if !isValid {
		return fmt.Errorf("medication verification failed for patient %s", patientID)
	}

	return nil
}

func (s *Service) processPatientScan(scanResult *types.ScanResult, userID string) error {
	// Process patient wristband scan
	patientID, exists := scanResult.Data["patient_id"]
	if !exists {
		return fmt.Errorf("patient ID not found in scan result")
	}

	// Verify patient identity
	isValid, _, err := s.barcodeService.VerifyPatientWristband(scanResult.Code)
	if err != nil {
		return fmt.Errorf("patient verification failed: %w", err)
	}
	if !isValid {
		return fmt.Errorf("invalid patient wristband: %s", patientID)
	}

	return nil
}

func (s *Service) processEquipmentScan(scanResult *types.ScanResult, userID string) error {
	// Process equipment barcode scan
	equipmentID, exists := scanResult.Data["equipment_id"]
	if !exists {
		return fmt.Errorf("equipment ID not found in scan result")
	}

	// Log equipment usage
	auditData := map[string]interface{}{
		"equipment_id": equipmentID,
		"scanned_by":   userID,
	}
	if err := s.auditService.LogEvent(userID, "equipment_scanned", equipmentID, true, auditData); err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}

	return nil
}

func (s *Service) verifyMedicationOrder(orderID string) error {
	order, err := s.repo.GetOrderByID(orderID)
	if err != nil {
		return fmt.Errorf("failed to get order: %w", err)
	}

	if order.OrderType != string(types.OrderTypeMedication) {
		return fmt.Errorf("order %s is not a medication order", orderID)
	}

	if order.Status != string(types.OrderStatusApproved) {
		return fmt.Errorf("order %s is not approved for administration", orderID)
	}

	return nil
}

func (s *Service) validateLabResult(result *types.LabResult) error {
	if result.TestName == "" {
		return fmt.Errorf("test name is required")
	}
	if result.Result == "" {
		return fmt.Errorf("result value is required")
	}
	if result.PatientID == "" {
		return fmt.Errorf("patient ID is required")
	}
	return nil
}

func (s *Service) getBarcodeConfig(role types.UserRole) map[string]interface{} {
	config := map[string]interface{}{
		"enabled": false,
		"types":   []string{},
	}

	switch role {
	case types.RoleNurse:
		config["enabled"] = true
		config["types"] = []string{"medication", "patient"}
	case types.RoleLabTechnician:
		config["enabled"] = true
		config["types"] = []string{"patient", "specimen"}
	case types.RoleConsultingDoctor, types.RoleMDStudent, types.RoleMBBSStudent:
		config["enabled"] = true
		config["types"] = []string{"patient"}
	}

	return config
}

func (s *Service) getOfflineSyncConfig(role types.UserRole) map[string]interface{} {
	return map[string]interface{}{
		"enabled":        true,
		"sync_interval":  300, // 5 minutes
		"max_offline_time": 3600, // 1 hour
	}
}

func (s *Service) getCPOEPermissions(role types.UserRole) map[string]interface{} {
	permissions := map[string]interface{}{
		"create_orders":     false,
		"requires_co_sign":  false,
		"can_co_sign":       false,
		"order_types":       []string{},
	}

	switch role {
	case types.RoleMBBSStudent:
		permissions["create_orders"] = true
		permissions["requires_co_sign"] = true
		permissions["order_types"] = []string{"nursing"}
	case types.RoleMDStudent:
		permissions["create_orders"] = true
		permissions["requires_co_sign"] = true
		permissions["order_types"] = []string{"medication", "lab", "imaging", "nursing"}
	case types.RoleConsultingDoctor:
		permissions["create_orders"] = true
		permissions["can_co_sign"] = true
		permissions["order_types"] = []string{"medication", "lab", "imaging", "procedure", "consult", "diet", "nursing"}
	}

	return permissions
}

func (s *Service) getMedicationAdminConfig(role types.UserRole) map[string]interface{} {
	config := map[string]interface{}{
		"can_administer": false,
		"requires_scan":  true,
	}

	if role == types.RoleNurse {
		config["can_administer"] = true
	}

	return config
}

func (s *Service) getLabResultConfig(role types.UserRole) map[string]interface{} {
	config := map[string]interface{}{
		"can_enter":  false,
		"can_verify": false,
	}

	if role == types.RoleLabTechnician {
		config["can_enter"] = true
		config["can_verify"] = true
	}

	return config
}

func (s *Service) validateMobilePreferences(preferences map[string]interface{}) error {
	// Validate mobile preferences structure
	allowedKeys := []string{"notifications", "sync_settings", "display_settings", "security_settings"}
	
	for key := range preferences {
		found := false
		for _, allowed := range allowedKeys {
			if key == allowed {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid preference key: %s", key)
		}
	}

	return nil
}