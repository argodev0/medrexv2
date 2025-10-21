package types

import "time"

// CPOEOrder represents a Computerized Provider Order Entry order
type CPOEOrder struct {
	ID            string    `json:"id" db:"id"`
	PatientID     string    `json:"patient_id" db:"patient_id"`
	OrderingMD    string    `json:"ordering_md" db:"ordering_md"`
	CoSigningMD   string    `json:"co_signing_md" db:"co_signing_md"`
	OrderType     string    `json:"order_type" db:"order_type"`
	Details       string    `json:"details" db:"details"`
	Status        string    `json:"status" db:"status"`
	Priority      string    `json:"priority" db:"priority"`
	RequiresCoSign bool     `json:"requires_co_sign" db:"requires_co_sign"`
	CoSignedAt    *time.Time `json:"co_signed_at" db:"co_signed_at"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time `json:"updated_at" db:"updated_at"`
}

// OrderStatus represents CPOE order status values
type OrderStatus string

const (
	OrderStatusDraft     OrderStatus = "draft"
	OrderStatusPending   OrderStatus = "pending"
	OrderStatusApproved  OrderStatus = "approved"
	OrderStatusExecuted  OrderStatus = "executed"
	OrderStatusCancelled OrderStatus = "cancelled"
	OrderStatusExpired   OrderStatus = "expired"
)

// OrderType represents CPOE order type values
type OrderType string

const (
	OrderTypeMedication OrderType = "medication"
	OrderTypeLab        OrderType = "lab"
	OrderTypeImaging    OrderType = "imaging"
	OrderTypeProcedure  OrderType = "procedure"
	OrderTypeConsult    OrderType = "consult"
	OrderTypeDiet       OrderType = "diet"
	OrderTypeNursing    OrderType = "nursing"
)

// OrderPriority represents order priority levels
type OrderPriority string

const (
	PriorityRoutine OrderPriority = "routine"
	PriorityUrgent  OrderPriority = "urgent"
	PriorityStat    OrderPriority = "stat"
	PriorityASAP    OrderPriority = "asap"
)

// ScanResult represents barcode/QR code scan result
type ScanResult struct {
	Code        string            `json:"code"`
	Type        string            `json:"type"`
	Data        map[string]string `json:"data"`
	IsValid     bool              `json:"is_valid"`
	ScannedAt   time.Time         `json:"scanned_at"`
	ScannedBy   string            `json:"scanned_by"`
}

// OfflineData represents data for offline synchronization
type OfflineData struct {
	UserID       string                 `json:"user_id"`
	DeviceID     string                 `json:"device_id"`
	LastSyncAt   time.Time              `json:"last_sync_at"`
	Orders       []CPOEOrder            `json:"orders,omitempty"`
	Scans        []ScanResult           `json:"scans,omitempty"`
	Notes        []ClinicalNote         `json:"notes,omitempty"`
	CustomData   map[string]interface{} `json:"custom_data,omitempty"`
	SyncedAt     time.Time              `json:"synced_at"`
}

// MedicationAdministration represents medication administration record
type MedicationAdministration struct {
	ID            string    `json:"id" db:"id"`
	OrderID       string    `json:"order_id" db:"order_id"`
	PatientID     string    `json:"patient_id" db:"patient_id"`
	NurseID       string    `json:"nurse_id" db:"nurse_id"`
	MedicationID  string    `json:"medication_id" db:"medication_id"`
	Dose          string    `json:"dose" db:"dose"`
	Route         string    `json:"route" db:"route"`
	AdministeredAt time.Time `json:"administered_at" db:"administered_at"`
	Notes         string    `json:"notes" db:"notes"`
	Verified      bool      `json:"verified" db:"verified"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
}

// LabResult represents laboratory test result
type LabResult struct {
	ID          string    `json:"id" db:"id"`
	OrderID     string    `json:"order_id" db:"order_id"`
	PatientID   string    `json:"patient_id" db:"patient_id"`
	TechnicianID string   `json:"technician_id" db:"technician_id"`
	TestName    string    `json:"test_name" db:"test_name"`
	Result      string    `json:"result" db:"result"`
	Units       string    `json:"units" db:"units"`
	ReferenceRange string `json:"reference_range" db:"reference_range"`
	Status      string    `json:"status" db:"status"`
	ResultedAt  time.Time `json:"resulted_at" db:"resulted_at"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// CPOEOrderFilters represents filters for CPOE order queries
type CPOEOrderFilters struct {
	PatientID       string        `json:"patient_id,omitempty"`
	OrderingMD      string        `json:"ordering_md,omitempty"`
	CoSigningMD     string        `json:"co_signing_md,omitempty"`
	OrderType       OrderType     `json:"order_type,omitempty"`
	Status          OrderStatus   `json:"status,omitempty"`
	Priority        OrderPriority `json:"priority,omitempty"`
	RequiresCoSign  *bool         `json:"requires_co_sign,omitempty"`
	CreatedAfter    time.Time     `json:"created_after,omitempty"`
	CreatedBefore   time.Time     `json:"created_before,omitempty"`
	Limit           int           `json:"limit,omitempty"`
	Offset          int           `json:"offset,omitempty"`
}

// CPOEOrderUpdates represents updates to a CPOE order
type CPOEOrderUpdates struct {
	Details       string        `json:"details,omitempty"`
	Status        OrderStatus   `json:"status,omitempty"`
	Priority      OrderPriority `json:"priority,omitempty"`
	CoSigningMD   string        `json:"co_signing_md,omitempty"`
}