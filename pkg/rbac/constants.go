package rbac

// Nine-role definitions as per the Medrex RBAC specification
const (
	RolePatient           = "patient"
	RoleMBBSStudent      = "mbbs_student"
	RoleMDStudent        = "md_student"
	RoleConsultingDoctor = "consulting_doctor"
	RoleNurse            = "nurse"
	RoleLabTechnician    = "lab_technician"
	RoleReceptionist     = "receptionist"
	RoleClinicalStaff    = "clinical_staff"
	RoleAdministrator    = "administrator"
)

// NodeOU mappings for Hyperledger Fabric identity classification
var NodeOUMappings = map[string]string{
	RolePatient:           "Client-Patient",
	RoleMBBSStudent:      "Client-Trainee",
	RoleMDStudent:        "Client-Doctor-PG",
	RoleConsultingDoctor: "Client-Doctor-Faculty",
	RoleNurse:            "Client-Nurse",
	RoleLabTechnician:    "Client-LabStaff",
	RoleReceptionist:     "Client-Admin-FrontDesk",
	RoleClinicalStaff:    "Client-Specialist",
	RoleAdministrator:    "Admin-Compliance",
}

// Role hierarchy levels (higher number = higher privilege)
var RoleLevels = map[string]int{
	RolePatient:           1,
	RoleMBBSStudent:      2,
	RoleMDStudent:        3,
	RoleReceptionist:     3,
	RoleLabTechnician:    4,
	RoleNurse:            4,
	RoleClinicalStaff:    5,
	RoleConsultingDoctor: 6,
	RoleAdministrator:    7,
}

// Resource types in the system
const (
	ResourcePatientEHR      = "patient_ehr"
	ResourceCPOEOrder       = "cpoe_order"
	ResourceLabResult       = "lab_result"
	ResourceMedication      = "medication"
	ResourceAppointment     = "appointment"
	ResourceAuditLog        = "audit_log"
	ResourceSystemConfig    = "system_config"
	ResourceTrainingData    = "training_data"
	ResourceFinancialData   = "financial_data"
	ResourceAdminFunction   = "admin_function"
	ResourceClinicalNote    = "clinical_note"
	ResourceUserManagement  = "user_management"
	ResourceRoleManagement  = "role_management"
	ResourceCertificate     = "certificate"
	ResourceCalendar        = "calendar"
	ResourceWorkflow        = "workflow"
	ResourceBarcodeScanner  = "barcode_scanner"
	ResourceOfflineSync     = "offline_sync"
)

// Action types
const (
	ActionCreate   = "create"
	ActionRead     = "read"
	ActionUpdate   = "update"
	ActionDelete   = "delete"
	ActionApprove  = "approve"
	ActionReject   = "reject"
	ActionSign     = "sign"
	ActionPrescribe = "prescribe"
	ActionAdminister = "administer"
	ActionSchedule = "schedule"
	ActionCancel   = "cancel"
)

// Permission scopes
const (
	ScopeOwn      = "own"      // User's own data only
	ScopeAssigned = "assigned" // Assigned patients/resources
	ScopeWard     = "ward"     // Ward-level access
	ScopeDept     = "department" // Department-level access
	ScopeAll      = "all"      // System-wide access
)

// ABAC operators
const (
	OperatorEquals       = "equals"
	OperatorNotEquals    = "not_equals"
	OperatorContains     = "contains"
	OperatorNotContains  = "not_contains"
	OperatorIn           = "in"
	OperatorNotIn        = "not_in"
	OperatorGreaterThan  = "greater_than"
	OperatorLessThan     = "less_than"
	OperatorMatches      = "matches"
	OperatorNotMatches   = "not_matches"
)

// Attribute types for ABAC
const (
	AttributeRole           = "role"
	AttributeSpecialty      = "specialty"
	AttributeIsTrainee      = "is_trainee"
	AttributeIsSupervisor   = "is_supervisor"
	AttributeWardAssignment = "ward_assignment"
	AttributeLabOrg         = "lab_org"
	AttributeDepartment     = "department"
	AttributeLevel          = "level"
	AttributePatientID      = "patient_id"
	AttributeTime           = "time"
	AttributeLocation       = "location"
	AttributeDeviceType     = "device_type"
	AttributeIPAddress      = "ip_address"
)

// Supervision workflow types
const (
	WorkflowTypeCPOE        = "cpoe"
	WorkflowTypeLabOrder    = "lab_order"
	WorkflowTypeMedication  = "medication"
	WorkflowTypeTraining    = "training"
	WorkflowTypeEmergency   = "emergency"
)

// Supervision action types
const (
	SupervisionActionReview   = "review"
	SupervisionActionApprove  = "approve"
	SupervisionActionCoSign   = "co_sign"
	SupervisionActionReject   = "reject"
	SupervisionActionEscalate = "escalate"
)

// Audit event types
const (
	AuditEventAccessAttempt    = "access_attempt"
	AuditEventPolicyChange     = "policy_change"
	AuditEventRoleAssignment   = "role_assignment"
	AuditEventSupervision      = "supervision"
	AuditEventEmergencyOverride = "emergency_override"
	AuditEventCertificateIssue = "certificate_issue"
	AuditEventCertificateRevoke = "certificate_revoke"
)

// Error codes for RBAC operations
const (
	ErrorCodeInsufficientPrivileges = "RBAC_001"
	ErrorCodeInvalidRole           = "RBAC_002"
	ErrorCodeAttributeValidation   = "RBAC_003"
	ErrorCodeSupervisionRequired   = "RBAC_004"
	ErrorCodeCertificateInvalid    = "RBAC_005"
	ErrorCodePolicyViolation       = "RBAC_006"
	ErrorCodeTimeRestriction       = "RBAC_007"
	ErrorCodeEmergencyOverride     = "RBAC_008"
	ErrorCodeSBEPolicyViolation    = "RBAC_009"
	ErrorCodeWorkflowTimeout       = "RBAC_010"
	ErrorCodeInvalidConfiguration  = "RBAC_011"
	ErrorCodeSystemError           = "RBAC_012"
)

// Default configuration values
const (
	DefaultPolicyCacheTTL      = 300  // 5 minutes
	DefaultSupervisionTimeout  = 3600 // 1 hour
	DefaultCertificateValidity = 8760 // 1 year in hours
	DefaultAuditRetention      = 2555 // 7 years in days
	MaxPolicyVersions          = 10
	MaxAuditBatchSize          = 1000
)

// Time formats
const (
	TimeFormatHourMinute = "15:04"
	TimeFormatDate       = "2006-01-02"
	TimeFormatDateTime   = "2006-01-02T15:04:05Z07:00"
)

// Weekdays for time restrictions
var Weekdays = []string{
	"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
}