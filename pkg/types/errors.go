package types

import "fmt"

// ErrorType represents different categories of errors
type ErrorType string

const (
	ErrorTypeValidation    ErrorType = "validation"
	ErrorTypeAuthorization ErrorType = "authorization"
	ErrorTypeAuthentication ErrorType = "authentication"
	ErrorTypeNotFound      ErrorType = "not_found"
	ErrorTypeConflict      ErrorType = "conflict"
	ErrorTypeInternal      ErrorType = "internal"
	ErrorTypeExternal      ErrorType = "external"
	ErrorTypeCompliance    ErrorType = "compliance"
	ErrorTypeRateLimit     ErrorType = "rate_limit"
	ErrorTypeTimeout       ErrorType = "timeout"
)

// MedrexError represents a structured error in the Medrex system
type MedrexError struct {
	Type    ErrorType              `json:"type"`
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
	Cause   error                  `json:"-"`
}

// Error implements the error interface
func (e *MedrexError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying cause error
func (e *MedrexError) Unwrap() error {
	return e.Cause
}

// NewValidationError creates a new validation error
func NewValidationError(code, message string, details map[string]interface{}) *MedrexError {
	return &MedrexError{
		Type:    ErrorTypeValidation,
		Code:    code,
		Message: message,
		Details: details,
	}
}

// NewAuthorizationError creates a new authorization error
func NewAuthorizationError(code, message string) *MedrexError {
	return &MedrexError{
		Type:    ErrorTypeAuthorization,
		Code:    code,
		Message: message,
	}
}

// NewAuthenticationError creates a new authentication error
func NewAuthenticationError(code, message string) *MedrexError {
	return &MedrexError{
		Type:    ErrorTypeAuthentication,
		Code:    code,
		Message: message,
	}
}

// NewNotFoundError creates a new not found error
func NewNotFoundError(code, message string) *MedrexError {
	return &MedrexError{
		Type:    ErrorTypeNotFound,
		Code:    code,
		Message: message,
	}
}

// NewInternalError creates a new internal error
func NewInternalError(code, message string, cause error) *MedrexError {
	return &MedrexError{
		Type:    ErrorTypeInternal,
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

// NewComplianceError creates a new compliance error
func NewComplianceError(code, message string, details map[string]interface{}) *MedrexError {
	return &MedrexError{
		Type:    ErrorTypeCompliance,
		Code:    code,
		Message: message,
		Details: details,
	}
}

// Common error codes
const (
	ErrCodeInvalidInput        = "INVALID_INPUT"
	ErrCodeUnauthorized        = "UNAUTHORIZED"
	ErrCodeForbidden          = "FORBIDDEN"
	ErrCodeNotFound           = "NOT_FOUND"
	ErrCodeConflict           = "CONFLICT"
	ErrCodeInternalError      = "INTERNAL_ERROR"
	ErrCodeExternalError      = "EXTERNAL_ERROR"
	ErrCodeValidationFailed   = "VALIDATION_FAILED"
	ErrCodeAuthenticationFailed = "AUTHENTICATION_FAILED"
	ErrCodeRateLimitExceeded  = "RATE_LIMIT_EXCEEDED"
	ErrCodeTimeout            = "TIMEOUT"
	ErrCodeComplianceViolation = "COMPLIANCE_VIOLATION"
)