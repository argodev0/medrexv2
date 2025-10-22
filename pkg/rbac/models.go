package rbac

import (
	"time"
)

// AccessRequest represents a request for resource access
type AccessRequest struct {
	UserID       string            `json:"user_id"`
	ResourceID   string            `json:"resource_id"`
	Action       string            `json:"action"`
	Context      map[string]string `json:"context"`
	Attributes   map[string]string `json:"attributes"`
	Timestamp    time.Time         `json:"timestamp"`
}

// AccessDecision represents the result of an access control decision
type AccessDecision struct {
	Allowed     bool              `json:"allowed"`
	Reason      string            `json:"reason"`
	Conditions  []string          `json:"conditions"`
	TTL         time.Duration     `json:"ttl"`
	Attributes  map[string]string `json:"attributes"`
}

// Role represents a user role in the RBAC system
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	NodeOU      string   `json:"node_ou"`
	Level       int      `json:"level"`
	Parent      string   `json:"parent,omitempty"`
	Children    []string `json:"children,omitempty"`
	Permissions []string `json:"permissions"`
}

// RoleHierarchy represents the complete role hierarchy structure
type RoleHierarchy struct {
	Roles map[string]*RoleNode `json:"roles"`
	Root  string               `json:"root"`
}

// RoleNode represents a node in the role hierarchy tree
type RoleNode struct {
	Role     Role       `json:"role"`
	Parent   *RoleNode  `json:"parent,omitempty"`
	Children []*RoleNode `json:"children,omitempty"`
	Level    int        `json:"level"`
}

// Permission represents a specific permission in the system
type Permission struct {
	Resource        string               `json:"resource"`
	Actions         []string             `json:"actions"`
	Conditions      []string             `json:"conditions,omitempty"`
	Scope           string               `json:"scope"`        // "own", "assigned", "ward", "all"
	TimeRestriction *TimeRestriction     `json:"time_restriction,omitempty"`
}

// TimeRestriction defines time-based access restrictions
type TimeRestriction struct {
	StartTime   string   `json:"start_time"`   // "09:00"
	EndTime     string   `json:"end_time"`     // "17:00"
	DaysOfWeek  []string `json:"days_of_week"` // ["monday", "tuesday", ...]
	Timezone    string   `json:"timezone"`
}

// AccessPolicy represents a complete access control policy
type AccessPolicy struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	Version     string                    `json:"version"`
	Roles       map[string]*RolePermissions `json:"roles"`
	Resources   map[string]*ResourceDef     `json:"resources"`
	Actions     map[string]*ActionDef       `json:"actions"`
	LastUpdated time.Time                   `json:"last_updated"`
}

// RolePermissions defines permissions for a specific role
type RolePermissions struct {
	RoleID      string                    `json:"role_id"`
	Permissions map[string]*Permission    `json:"permissions"`
	Constraints []PermissionConstraint    `json:"constraints"`
}

// PermissionConstraint defines constraints on permissions
type PermissionConstraint struct {
	Type        string      `json:"type"`
	Attribute   string      `json:"attribute"`
	Operator    string      `json:"operator"`
	Value       interface{} `json:"value"`
	Required    bool        `json:"required"`
}

// ResourceDef defines a resource type in the system
type ResourceDef struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Attributes  map[string]string `json:"attributes"`
	Sensitivity string            `json:"sensitivity"` // "public", "internal", "confidential", "restricted"
}

// ActionDef defines an action that can be performed on resources
type ActionDef struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Risk        string   `json:"risk"` // "low", "medium", "high", "critical"
}

// ABACPolicy represents an Attribute-Based Access Control policy
type ABACPolicy struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Rules       []ABACRule            `json:"rules"`
	Conditions  []AttributeCondition  `json:"conditions"`
	Effect      PolicyEffect          `json:"effect"`
	Priority    int                   `json:"priority"`
}

// ABACRule represents a single rule in an ABAC policy
type ABACRule struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	Required  bool        `json:"required"`
}

// AttributeCondition represents a contextual condition for ABAC
type AttributeCondition struct {
	Type        string      `json:"type"`        // "time", "location", "patient_assignment"
	Constraint  string      `json:"constraint"`  // "business_hours", "ward_assignment"
	Value       interface{} `json:"value"`
}

// AttributeConstraint defines constraints on user attributes
type AttributeConstraint struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
	Required  bool        `json:"required"`
}

// PolicyEffect defines the effect of a policy (allow/deny)
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// EnrollmentRequest represents a certificate enrollment request with attributes
type EnrollmentRequest struct {
	UserID         string            `json:"user_id"`
	Role           string            `json:"role"`
	Attributes     map[string]string `json:"attributes"`
	OrgMSP         string            `json:"org_msp"`
	NodeOU         string            `json:"node_ou"`
	ValidityPeriod time.Duration     `json:"validity_period"`
}

// UserAttributes represents attributes extracted from a user certificate
type UserAttributes struct {
	Role           string `json:"role"`
	Specialty      string `json:"specialty,omitempty"`
	IsTrainee      bool   `json:"is_trainee"`
	IsSupervisor   bool   `json:"is_supervisor"`
	WardAssignment string `json:"ward_assignment,omitempty"`
	LabOrg         string `json:"lab_org,omitempty"`
	Department     string `json:"department,omitempty"`
	Level          int    `json:"level"`
}

// SBEPolicy represents a State-Based Endorsement policy
type SBEPolicy struct {
	ID                    string                  `json:"id"`
	Name                  string                  `json:"name"`
	ResourceType          string                  `json:"resource_type"`
	TriggerConditions     []TriggerCondition      `json:"trigger_conditions"`
	RequiredEndorsers     []EndorserRequirement   `json:"required_endorsers"`
	TimeoutDuration       time.Duration           `json:"timeout_duration"`
	EscalationPolicy      string                  `json:"escalation_policy"`
	EmergencyOverride     bool                    `json:"emergency_override"`
}

// TriggerCondition defines when an SBE policy should be triggered
type TriggerCondition struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
}

// EndorserRequirement defines requirements for endorsers in SBE policies
type EndorserRequirement struct {
	Role        string            `json:"role"`
	Attributes  map[string]string `json:"attributes"`
	MinCount    int               `json:"min_count"`
	MaxCount    int               `json:"max_count"`
}

// SupervisionWorkflow represents a trainee supervision workflow
type SupervisionWorkflow struct {
	ID              string                 `json:"id"`
	TraineeID       string                 `json:"trainee_id"`
	SupervisorID    string                 `json:"supervisor_id"`
	ResourceID      string                 `json:"resource_id"`
	WorkflowType    string                 `json:"workflow_type"`
	Status          SupervisionStatus      `json:"status"`
	RequiredActions []SupervisionAction    `json:"required_actions"`
	CompletedActions []CompletedAction     `json:"completed_actions"`
	CreatedAt       time.Time              `json:"created_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// SupervisionStatus represents the status of a supervision workflow
type SupervisionStatus string

const (
	StatusPending    SupervisionStatus = "pending"
	StatusInProgress SupervisionStatus = "in_progress"
	StatusCompleted  SupervisionStatus = "completed"
	StatusExpired    SupervisionStatus = "expired"
	StatusOverridden SupervisionStatus = "overridden"
)

// SupervisionAction represents an action required in a supervision workflow
type SupervisionAction struct {
	Type        string            `json:"type"`        // "review", "approve", "co_sign"
	Description string            `json:"description"`
	Required    bool              `json:"required"`
	Attributes  map[string]string `json:"attributes"`
}

// CompletedAction represents a completed supervision action
type CompletedAction struct {
	Action      SupervisionAction `json:"action"`
	CompletedBy string            `json:"completed_by"`
	CompletedAt time.Time         `json:"completed_at"`
	Signature   string            `json:"signature"`
	Comments    string            `json:"comments,omitempty"`
}

// EmergencyOverrideRequest represents a request for emergency override
type EmergencyOverrideRequest struct {
	UserID      string            `json:"user_id"`
	ResourceID  string            `json:"resource_id"`
	Action      string            `json:"action"`
	Reason      string            `json:"reason"`
	Justification string          `json:"justification"`
	Timestamp   time.Time         `json:"timestamp"`
	Metadata    map[string]string `json:"metadata"`
}

// PermissionMatrix represents the complete permission matrix for the system
type PermissionMatrix struct {
	Roles       map[string]*RolePermissions `json:"roles"`
	Resources   map[string]*ResourceDef     `json:"resources"`
	Actions     map[string]*ActionDef       `json:"actions"`
	LastUpdated time.Time                   `json:"last_updated"`
}

// PolicyFilter represents filters for policy queries
type PolicyFilter struct {
	RoleID     string    `json:"role_id,omitempty"`
	ResourceID string    `json:"resource_id,omitempty"`
	Action     string    `json:"action,omitempty"`
	UpdatedAfter time.Time `json:"updated_after,omitempty"`
	Limit      int       `json:"limit,omitempty"`
	Offset     int       `json:"offset,omitempty"`
}

// PolicyChange represents a change to a policy for audit purposes
type PolicyChange struct {
	PolicyID    string                 `json:"policy_id"`
	ChangeType  string                 `json:"change_type"` // "create", "update", "delete"
	ChangedBy   string                 `json:"changed_by"`
	Timestamp   time.Time              `json:"timestamp"`
	OldPolicy   *AccessPolicy          `json:"old_policy,omitempty"`
	NewPolicy   *AccessPolicy          `json:"new_policy,omitempty"`
	Reason      string                 `json:"reason"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AuditEntry represents an entry in the audit log
type AuditEntry struct {
	ID          string                 `json:"id"`
	EventType   string                 `json:"event_type"`
	UserID      string                 `json:"user_id"`
	ResourceID  string                 `json:"resource_id"`
	Action      string                 `json:"action"`
	Result      string                 `json:"result"`
	Timestamp   time.Time              `json:"timestamp"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// AuditFilter represents filters for audit log queries
type AuditFilter struct {
	UserID      string    `json:"user_id,omitempty"`
	ResourceID  string    `json:"resource_id,omitempty"`
	Action      string    `json:"action,omitempty"`
	Result      string    `json:"result,omitempty"`
	StartTime   time.Time `json:"start_time,omitempty"`
	EndTime     time.Time `json:"end_time,omitempty"`
	Limit       int       `json:"limit,omitempty"`
	Offset      int       `json:"offset,omitempty"`
}

// ComplianceReport represents a comprehensive compliance report
type ComplianceReport struct {
	StartTime            time.Time                        `json:"start_time"`
	EndTime              time.Time                        `json:"end_time"`
	GeneratedAt          time.Time                        `json:"generated_at"`
	AccessStatistics     *AccessStatistics                `json:"access_statistics"`
	PolicyChanges        *PolicyChangeStatistics          `json:"policy_changes"`
	EmergencyOverrides   *EmergencyOverrideStatistics     `json:"emergency_overrides"`
	RoleAccessPatterns   map[string]*RoleAccessPattern    `json:"role_access_patterns"`
}

// AccessStatistics represents access attempt statistics
type AccessStatistics struct {
	TotalAttempts    int `json:"total_attempts"`
	AllowedAttempts  int `json:"allowed_attempts"`
	DeniedAttempts   int `json:"denied_attempts"`
	UniqueUsers      int `json:"unique_users"`
	UniqueResources  int `json:"unique_resources"`
}

// PolicyChangeStatistics represents policy change statistics
type PolicyChangeStatistics struct {
	TotalChanges         int `json:"total_changes"`
	CreatedPolicies      int `json:"created_policies"`
	UpdatedPolicies      int `json:"updated_policies"`
	DeletedPolicies      int `json:"deleted_policies"`
	UniqueAdministrators int `json:"unique_administrators"`
}

// EmergencyOverrideStatistics represents emergency override statistics
type EmergencyOverrideStatistics struct {
	TotalOverrides  int `json:"total_overrides"`
	UniqueUsers     int `json:"unique_users"`
	UniqueResources int `json:"unique_resources"`
}

// RoleAccessPattern represents access patterns for a specific role
type RoleAccessPattern struct {
	TotalAttempts   int `json:"total_attempts"`
	AllowedAttempts int `json:"allowed_attempts"`
	DeniedAttempts  int `json:"denied_attempts"`
}

// Additional constants for access monitoring

// Default configuration values for monitoring
const (
	DefaultAccessMonitorBufferSize = 1000
	DefaultAlertBufferSize         = 500
	DefaultDecisionCacheTTL        = 60 // 1 minute in seconds
)