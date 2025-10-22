package rbac

import (
	"fmt"
)

// RBACErrorType represents the type of RBAC error
type RBACErrorType string

const (
	ErrorTypeInsufficientPrivileges RBACErrorType = "insufficient_privileges"
	ErrorTypeInvalidRole           RBACErrorType = "invalid_role"
	ErrorTypeAttributeValidation   RBACErrorType = "attribute_validation"
	ErrorTypeSupervisionRequired   RBACErrorType = "supervision_required"
	ErrorTypeCertificateInvalid    RBACErrorType = "certificate_invalid"
	ErrorTypePolicyViolation       RBACErrorType = "policy_violation"
	ErrorTypeTimeRestriction       RBACErrorType = "time_restriction"
	ErrorTypeEmergencyOverride     RBACErrorType = "emergency_override"
	ErrorTypeSBEPolicyViolation    RBACErrorType = "sbe_policy_violation"
	ErrorTypeWorkflowTimeout       RBACErrorType = "workflow_timeout"
	ErrorTypeInvalidConfiguration  RBACErrorType = "invalid_configuration"
	ErrorTypeSystemError           RBACErrorType = "system_error"
)



// RBACError represents an RBAC-specific error with detailed context
type RBACError struct {
	Type              RBACErrorType `json:"type"`
	Code              string        `json:"code"`
	Message           string        `json:"message"`
	UserID            string        `json:"user_id"`
	ResourceID        string        `json:"resource_id"`
	Action            string        `json:"action"`
	RequiredRole      string        `json:"required_role,omitempty"`
	MissingAttributes []string      `json:"missing_attributes,omitempty"`
	Suggestions       []string      `json:"suggestions,omitempty"`
	Cause             error         `json:"cause,omitempty"`
}

// Error implements the error interface
func (e *RBACError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%s] %s: %s (caused by: %v)", e.Code, e.Type, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Code, e.Type, e.Message)
}

// Unwrap returns the underlying cause of the error
func (e *RBACError) Unwrap() error {
	return e.Cause
}

// NewRBACError creates a new RBAC error
func NewRBACError(errorType RBACErrorType, code, message string) *RBACError {
	return &RBACError{
		Type:    errorType,
		Code:    code,
		Message: message,
	}
}

// NewRBACErrorWithCause creates a new RBAC error with an underlying cause
func NewRBACErrorWithCause(errorType RBACErrorType, code, message string, cause error) *RBACError {
	return &RBACError{
		Type:    errorType,
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// WithContext adds context information to an RBAC error
func (e *RBACError) WithContext(userID, resourceID, action string) *RBACError {
	e.UserID = userID
	e.ResourceID = resourceID
	e.Action = action
	return e
}

// WithRequiredRole adds required role information to an RBAC error
func (e *RBACError) WithRequiredRole(role string) *RBACError {
	e.RequiredRole = role
	return e
}

// WithMissingAttributes adds missing attributes information to an RBAC error
func (e *RBACError) WithMissingAttributes(attributes []string) *RBACError {
	e.MissingAttributes = attributes
	return e
}

// WithSuggestions adds suggestions for resolving the error
func (e *RBACError) WithSuggestions(suggestions []string) *RBACError {
	e.Suggestions = suggestions
	return e
}

// Predefined RBAC errors
var (
	ErrInsufficientPrivileges = NewRBACError(
		ErrorTypeInsufficientPrivileges,
		ErrorCodeInsufficientPrivileges,
		"User does not have sufficient privileges to perform this action",
	)

	ErrInvalidRole = NewRBACError(
		ErrorTypeInvalidRole,
		ErrorCodeInvalidRole,
		"Invalid or unrecognized user role",
	)

	ErrAttributeValidation = NewRBACError(
		ErrorTypeAttributeValidation,
		ErrorCodeAttributeValidation,
		"User attributes do not meet the required criteria",
	)

	ErrSupervisionRequired = NewRBACError(
		ErrorTypeSupervisionRequired,
		ErrorCodeSupervisionRequired,
		"This action requires supervisor approval",
	)

	ErrCertificateInvalid = NewRBACError(
		ErrorTypeCertificateInvalid,
		ErrorCodeCertificateInvalid,
		"User certificate is invalid or expired",
	)

	ErrPolicyViolation = NewRBACError(
		ErrorTypePolicyViolation,
		ErrorCodePolicyViolation,
		"Action violates access control policy",
	)

	ErrTimeRestriction = NewRBACError(
		ErrorTypeTimeRestriction,
		ErrorCodeTimeRestriction,
		"Action is not permitted at this time",
	)

	ErrEmergencyOverride = NewRBACError(
		ErrorTypeEmergencyOverride,
		ErrorCodeEmergencyOverride,
		"Emergency override is required for this action",
	)

	ErrSBEPolicyViolation = NewRBACError(
		ErrorTypeSBEPolicyViolation,
		ErrorCodeSBEPolicyViolation,
		"Action violates State-Based Endorsement policy",
	)

	ErrWorkflowTimeout = NewRBACError(
		ErrorTypeWorkflowTimeout,
		ErrorCodeWorkflowTimeout,
		"Supervision workflow has timed out",
	)
)

// IsRBACError checks if an error is an RBAC error
func IsRBACError(err error) bool {
	_, ok := err.(*RBACError)
	return ok
}

// GetRBACError extracts an RBAC error from a generic error
func GetRBACError(err error) (*RBACError, bool) {
	rbacErr, ok := err.(*RBACError)
	return rbacErr, ok
}

// ValidationError represents a validation error with field-specific details
type ValidationError struct {
	Field   string `json:"field"`
	Value   string `json:"value"`
	Message string `json:"message"`
}

// Error implements the error interface for ValidationError
func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s' with value '%s': %s", e.Field, e.Value, e.Message)
}

// ValidationErrors represents a collection of validation errors
type ValidationErrors []ValidationError

// Error implements the error interface for ValidationErrors
func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return "no validation errors"
	}
	if len(e) == 1 {
		return e[0].Error()
	}
	return fmt.Sprintf("multiple validation errors: %d errors found", len(e))
}

// Add adds a validation error to the collection
func (e *ValidationErrors) Add(field, value, message string) {
	*e = append(*e, ValidationError{
		Field:   field,
		Value:   value,
		Message: message,
	})
}

// HasErrors returns true if there are validation errors
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// ConfigurationError represents a configuration-related error
type ConfigurationError struct {
	Component string `json:"component"`
	Setting   string `json:"setting"`
	Value     string `json:"value"`
	Message   string `json:"message"`
}

// Error implements the error interface for ConfigurationError
func (e *ConfigurationError) Error() string {
	return fmt.Sprintf("configuration error in %s.%s='%s': %s", e.Component, e.Setting, e.Value, e.Message)
}

// NewConfigurationError creates a new configuration error
func NewConfigurationError(component, setting, value, message string) *ConfigurationError {
	return &ConfigurationError{
		Component: component,
		Setting:   setting,
		Value:     value,
		Message:   message,
	}
}