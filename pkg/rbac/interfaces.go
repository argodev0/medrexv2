package rbac

import (
	"context"
	"crypto/x509"
	"time"
)

// RBACCoreEngine defines the main interface for role-based access control
type RBACCoreEngine interface {
	ValidateAccess(ctx context.Context, req *AccessRequest) (*AccessDecision, error)
	GetUserRoles(userID string) ([]Role, error)
	GetRolePermissions(role Role) ([]Permission, error)
	UpdateRoleHierarchy(hierarchy *RoleHierarchy) error
	CachePolicy(policyID string, policy *AccessPolicy) error
}

// ABACEngine defines the interface for Attribute-Based Access Control
type ABACEngine interface {
	EvaluatePolicy(ctx context.Context, policy *ABACPolicy, attributes map[string]string) (bool, error)
	ExtractCertificateAttributes(cert *x509.Certificate) (map[string]string, error)
	ValidateAttributeConstraints(attributes map[string]string, constraints []AttributeConstraint) error
	GetContextualAttributes(ctx context.Context, userID string) (map[string]string, error)
}

// SBEPolicyManager defines the interface for State-Based Endorsement policy management
type SBEPolicyManager interface {
	CreateSBEPolicy(ctx context.Context, policy *SBEPolicy) error
	ApplySBEPolicy(ctx context.Context, resourceID string, policy *SBEPolicy) error
	ValidateSupervisorEndorsement(ctx context.Context, resourceID, supervisorID string) error
	GetRequiredEndorsers(ctx context.Context, resourceID string) ([]string, error)
	HandleEmergencyOverride(ctx context.Context, req *EmergencyOverrideRequest) error
}

// CertificateManager defines the interface for X.509 certificate management with attributes
type CertificateManager interface {
	EnrollUserWithAttributes(ctx context.Context, req *EnrollmentRequest) (*x509.Certificate, error)
	ExtractUserAttributes(cert *x509.Certificate) (*UserAttributes, error)
	ValidateCertificateAttributes(cert *x509.Certificate, requiredAttrs []string) error
	RenewCertificateWithUpdatedAttributes(ctx context.Context, userID string, newAttrs map[string]string) error
	RevokeCertificate(ctx context.Context, userID string, reason string) error
}

// PolicyManager defines the interface for RBAC policy management
type PolicyManager interface {
	CreatePolicy(ctx context.Context, policy *AccessPolicy) error
	UpdatePolicy(ctx context.Context, policyID string, policy *AccessPolicy) error
	DeletePolicy(ctx context.Context, policyID string) error
	GetPolicy(ctx context.Context, policyID string) (*AccessPolicy, error)
	ListPolicies(ctx context.Context, filter *PolicyFilter) ([]*AccessPolicy, error)
	ValidatePolicy(ctx context.Context, policy *AccessPolicy) error
}

// AuditLogger defines the interface for RBAC audit logging
type AuditLogger interface {
	LogAccessAttempt(ctx context.Context, req *AccessRequest, decision *AccessDecision) error
	LogPolicyChange(ctx context.Context, change *PolicyChange) error
	LogEmergencyOverride(ctx context.Context, override *EmergencyOverrideRequest) error
	GetAuditTrail(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error)
	GetPolicyAuditTrail(ctx context.Context, policyID string, limit int) ([]*PolicyChange, error)
	GenerateComplianceReport(ctx context.Context, startTime, endTime time.Time) (*ComplianceReport, error)
}

// SupervisionWorkflowEngine defines the interface for trainee supervision workflows
type SupervisionWorkflowEngine interface {
	CreateSupervisionWorkflow(ctx context.Context, workflow *SupervisionWorkflow) error
	UpdateWorkflowStatus(ctx context.Context, workflowID string, status SupervisionStatus) error
	AssignSupervisor(ctx context.Context, workflowID, supervisorID string) error
	CompleteSupervisionAction(ctx context.Context, workflowID string, action *CompletedAction) error
	GetPendingSupervision(ctx context.Context, supervisorID string) ([]*SupervisionWorkflow, error)
}