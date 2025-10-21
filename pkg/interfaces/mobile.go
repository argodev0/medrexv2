package interfaces

import (
	"github.com/medrex/dlt-emr/pkg/types"
)

// MobileWorkflowService defines the interface for mobile-optimized workflows
type MobileWorkflowService interface {
	// CPOE operations
	CreateOrder(order *types.CPOEOrder, userID string) (*types.CPOEOrder, error)
	GetOrder(orderID, userID string) (*types.CPOEOrder, error)
	UpdateOrder(orderID string, updates map[string]interface{}, userID string) error
	CancelOrder(orderID, userID string) error
	
	// Co-signature workflow
	RequestCoSignature(orderID, consultantID string) error
	ApproveOrder(orderID, consultantID string) error
	RejectOrder(orderID, consultantID, reason string) error
	GetPendingCoSignatures(consultantID string) ([]*types.CPOEOrder, error)
	
	// Barcode/QR scanning
	ScanBarcode(barcode string, userID string) (*types.ScanResult, error)
	ValidateScan(scanResult *types.ScanResult) (bool, error)
	ProcessScanResult(scanResult *types.ScanResult, userID string) error
	
	// Medication administration
	RecordMedicationAdmin(admin *types.MedicationAdministration, userID string) error
	GetMedicationSchedule(patientID, userID string) ([]*types.MedicationAdministration, error)
	VerifyMedication(medicationID, patientID string) (bool, error)
	
	// Lab results
	EnterLabResult(result *types.LabResult, userID string) error
	GetLabResults(patientID, userID string) ([]*types.LabResult, error)
	VerifyLabResult(resultID, userID string) error
	
	// Offline synchronization
	SyncOfflineData(data *types.OfflineData, userID string) error
	GetOfflineData(userID, deviceID string) (*types.OfflineData, error)
	MarkDataSynced(userID, deviceID string, syncedAt string) error
	
	// Mobile-specific features
	GetMobileConfig(userID string) (map[string]interface{}, error)
	UpdateMobilePreferences(userID string, preferences map[string]interface{}) error
	
	// Service management
	Start(addr string) error
	Stop() error
}

// MobileRepository defines the interface for mobile workflow data persistence
type MobileRepository interface {
	// CPOE orders
	CreateOrder(order *types.CPOEOrder) error
	GetOrderByID(id string) (*types.CPOEOrder, error)
	UpdateOrder(id string, updates map[string]interface{}) error
	GetOrdersByUser(userID string, filters map[string]interface{}) ([]*types.CPOEOrder, error)
	GetPendingOrders(consultantID string) ([]*types.CPOEOrder, error)
	
	// Medication administration
	CreateMedicationAdmin(admin *types.MedicationAdministration) error
	GetMedicationAdminByID(id string) (*types.MedicationAdministration, error)
	GetMedicationSchedule(patientID string) ([]*types.MedicationAdministration, error)
	UpdateMedicationAdmin(id string, updates map[string]interface{}) error
	
	// Lab results
	CreateLabResult(result *types.LabResult) error
	GetLabResultByID(id string) (*types.LabResult, error)
	GetLabResults(patientID string, filters map[string]interface{}) ([]*types.LabResult, error)
	UpdateLabResult(id string, updates map[string]interface{}) error
	
	// Offline data
	StoreOfflineData(data *types.OfflineData) error
	GetOfflineData(userID, deviceID string) (*types.OfflineData, error)
	UpdateSyncStatus(userID, deviceID string, syncedAt string) error
	DeleteOfflineData(userID, deviceID string) error
}

// BarcodeService defines the interface for barcode/QR code operations
type BarcodeService interface {
	// Barcode operations
	DecodeBarcode(code string) (*types.ScanResult, error)
	ValidateBarcode(code, expectedType string) (bool, error)
	GenerateBarcode(data map[string]string, format string) (string, error)
	
	// QR code operations
	DecodeQRCode(code string) (*types.ScanResult, error)
	ValidateQRCode(code, expectedType string) (bool, error)
	GenerateQRCode(data map[string]string) (string, error)
	
	// Medication verification
	VerifyMedicationBarcode(code, patientID string) (bool, map[string]string, error)
	GetMedicationInfo(code string) (map[string]string, error)
	
	// Patient verification
	VerifyPatientWristband(code string) (bool, *types.Patient, error)
}

// OfflineSyncService defines the interface for offline data synchronization
type OfflineSyncService interface {
	// Sync operations
	SyncUserData(userID, deviceID string, data *types.OfflineData) error
	GetPendingSyncData(userID, deviceID string) (*types.OfflineData, error)
	MarkDataSynced(userID, deviceID string, items []string) error
	
	// Conflict resolution
	ResolveConflicts(userID string, conflicts []map[string]interface{}) error
	GetConflicts(userID, deviceID string) ([]map[string]interface{}, error)
	
	// Data validation
	ValidateOfflineData(data *types.OfflineData) (bool, []string, error)
	SanitizeOfflineData(data *types.OfflineData) (*types.OfflineData, error)
}

// WorkflowEngine defines the interface for mobile workflow management
type WorkflowEngine interface {
	// Workflow execution
	StartWorkflow(workflowType, userID string, params map[string]interface{}) (string, error)
	ContinueWorkflow(workflowID string, action string, data map[string]interface{}) error
	CompleteWorkflow(workflowID string) error
	CancelWorkflow(workflowID string, reason string) error
	
	// Workflow state
	GetWorkflowState(workflowID string) (map[string]interface{}, error)
	GetActiveWorkflows(userID string) ([]map[string]interface{}, error)
	
	// Workflow templates
	RegisterWorkflowTemplate(name string, template map[string]interface{}) error
	GetWorkflowTemplate(name string) (map[string]interface{}, error)
}