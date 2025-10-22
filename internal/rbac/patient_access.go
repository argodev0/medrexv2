package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// PatientAccessController implements patient-specific access controls
type PatientAccessController struct {
	logger       *logrus.Logger
	coreEngine   rbac.RBACCoreEngine
	auditLogger  rbac.AuditLogger
}

// NewPatientAccessController creates a new patient access controller
func NewPatientAccessController(logger *logrus.Logger, coreEngine rbac.RBACCoreEngine, auditLogger rbac.AuditLogger) *PatientAccessController {
	return &PatientAccessController{
		logger:      logger,
		coreEngine:  coreEngine,
		auditLogger: auditLogger,
	}
}

// ValidatePatientAccess validates access for patient role with own-data restrictions
func (p *PatientAccessController) ValidatePatientAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Extract patient ID from user ID (format: patient_<patientID>)
	patientID := p.extractPatientID(req.UserID)
	if patientID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid patient user ID format",
		}, nil
	}

	// Validate own-data access restriction
	if !p.isOwnDataAccess(patientID, req.ResourceID) {
		p.logger.WithFields(logrus.Fields{
			"patient_id":  patientID,
			"resource_id": req.ResourceID,
			"action":      req.Action,
		}).Warn("Patient attempted to access non-own data")

		// Log security violation
		if p.auditLogger != nil {
			p.auditLogger.LogAccessAttempt(ctx, req, &rbac.AccessDecision{
				Allowed: false,
				Reason:  "Own-data access violation",
			})
		}

		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Patients can only access their own data",
		}, nil
	}

	// Validate allowed actions for patient role
	if !p.isAllowedPatientAction(req.Action, req.ResourceID) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Action '%s' not allowed for patient role", req.Action),
		}, nil
	}

	// Check resource-specific restrictions
	decision, err := p.validateResourceSpecificAccess(ctx, patientID, req)
	if err != nil {
		return nil, err
	}
	if !decision.Allowed {
		return decision, nil
	}

	// All patient-specific validations passed
	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Patient access granted for own data",
		Attributes: map[string]string{
			"patient_id":    patientID,
			"access_scope":  "own_data",
			"resource_type": p.getResourceType(req.ResourceID),
		},
		TTL: 5 * time.Minute, // Short TTL for patient access
	}, nil
}

// ValidateSecureCommunication validates patient's secure communication capabilities
func (p *PatientAccessController) ValidateSecureCommunication(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	patientID := p.extractPatientID(req.UserID)
	if patientID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid patient user ID format",
		}, nil
	}

	// Validate communication type
	commType := req.Attributes["communication_type"]
	if !p.isAllowedCommunicationType(commType) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Communication type '%s' not allowed for patients", commType),
		}, nil
	}

	// Validate recipient (patients can only communicate with their care team)
	recipientID := req.Attributes["recipient_id"]
	if !p.isAuthorizedRecipient(ctx, patientID, recipientID) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Patient can only communicate with authorized care team members",
		}, nil
	}

	// Check message content restrictions
	if req.Action == rbac.ActionCreate {
		if err := p.validateMessageContent(req.Attributes["message_content"]); err != nil {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Message content validation failed: %s", err.Error()),
			}, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Secure communication access granted",
		Attributes: map[string]string{
			"patient_id":         patientID,
			"communication_type": commType,
			"recipient_id":       recipientID,
		},
		TTL: 10 * time.Minute,
	}, nil
}

// GetPatientAccessibleResources returns resources accessible to a specific patient
func (p *PatientAccessController) GetPatientAccessibleResources(ctx context.Context, patientID string) ([]string, error) {
	resources := []string{
		fmt.Sprintf("patient_ehr_%s", patientID),
		fmt.Sprintf("appointment_%s", patientID),
		fmt.Sprintf("lab_results_%s", patientID),
		fmt.Sprintf("medication_list_%s", patientID),
		fmt.Sprintf("billing_info_%s", patientID),
		fmt.Sprintf("communication_%s", patientID),
	}

	return resources, nil
}

// ValidatePatientDataScope ensures patient can only access data within their scope
func (p *PatientAccessController) ValidatePatientDataScope(ctx context.Context, patientID, resourceID string, dataScope map[string]interface{}) (*rbac.AccessDecision, error) {
	// Check if the data belongs to the patient
	if dataPatientID, exists := dataScope["patient_id"]; exists {
		if dataPatientID != patientID {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  "Data does not belong to the requesting patient",
			}, nil
		}
	}

	// Check data sensitivity level
	if sensitivity, exists := dataScope["sensitivity"]; exists {
		if !p.isPatientAllowedSensitivity(sensitivity.(string)) {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  "Patient not authorized for this data sensitivity level",
			}, nil
		}
	}

	// Check temporal restrictions (e.g., future appointments)
	if dataTime, exists := dataScope["data_timestamp"]; exists {
		if !p.isPatientAllowedTimeAccess(dataTime.(time.Time)) {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  "Patient not authorized to access future-dated information",
			}, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Patient data scope validation passed",
	}, nil
}

// Helper methods

func (p *PatientAccessController) extractPatientID(userID string) string {
	// Expected format: patient_<patientID>
	if strings.HasPrefix(userID, "patient_") {
		return strings.TrimPrefix(userID, "patient_")
	}
	return ""
}

func (p *PatientAccessController) isOwnDataAccess(patientID, resourceID string) bool {
	// Check if resource belongs to the patient
	// Resource format examples:
	// - patient_ehr_123 (patient ID 123's EHR)
	// - appointment_123_456 (appointment 456 for patient 123)
	// - lab_results_123_789 (lab results 789 for patient 123)
	
	return strings.Contains(resourceID, patientID)
}

func (p *PatientAccessController) isAllowedPatientAction(action, resourceID string) bool {
	allowedActions := map[string][]string{
		"patient":      {rbac.ActionRead},
		"appointment":  {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionCancel},
		"lab":          {rbac.ActionRead},
		"medication":   {rbac.ActionRead},
		"billing":      {rbac.ActionRead},
		"communication": {rbac.ActionCreate, rbac.ActionRead},
		"portal":       {rbac.ActionRead, rbac.ActionUpdate},
	}

	resourceType := p.getResourceType(resourceID)
	if actions, exists := allowedActions[resourceType]; exists {
		for _, allowedAction := range actions {
			if action == allowedAction {
				return true
			}
		}
	}

	return false
}

func (p *PatientAccessController) getResourceType(resourceID string) string {
	// Extract resource type from resource ID
	parts := strings.Split(resourceID, "_")
	if len(parts) >= 1 {
		return parts[0]
	}
	return resourceID
}

func (p *PatientAccessController) validateResourceSpecificAccess(ctx context.Context, patientID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	resourceType := p.getResourceType(req.ResourceID)

	switch resourceType {
	case "patient":
		return p.validateEHRAccess(ctx, patientID, req)
	case "appointment":
		return p.validateAppointmentAccess(ctx, patientID, req)
	case "lab":
		return p.validateLabResultsAccess(ctx, patientID, req)
	case "billing":
		return p.validateBillingAccess(ctx, patientID, req)
	case "communication":
		return p.validateCommunicationAccess(ctx, patientID, req)
	default:
		return &rbac.AccessDecision{
			Allowed: true,
			Reason:  "No specific restrictions for resource type",
		}, nil
	}
}

func (p *PatientAccessController) validateEHRAccess(ctx context.Context, patientID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Patients can only read their own EHR
	if req.Action != rbac.ActionRead {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Patients can only read their EHR data",
		}, nil
	}

	// Check if requesting sensitive sections
	if section := req.Attributes["ehr_section"]; section != "" {
		if !p.isPatientAllowedEHRSection(section) {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Patient not authorized to access EHR section: %s", section),
			}, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Patient EHR access granted",
	}, nil
}

func (p *PatientAccessController) validateAppointmentAccess(ctx context.Context, patientID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Patients can manage their own appointments
	allowedActions := []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionCancel}
	
	actionAllowed := false
	for _, action := range allowedActions {
		if req.Action == action {
			actionAllowed = true
			break
		}
	}

	if !actionAllowed {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Action '%s' not allowed for patient appointments", req.Action),
		}, nil
	}

	// Additional validation for appointment creation/modification
	if req.Action == rbac.ActionCreate || req.Action == rbac.ActionUpdate {
		if err := p.validateAppointmentData(req.Attributes); err != nil {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Appointment data validation failed: %s", err.Error()),
			}, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Patient appointment access granted",
	}, nil
}

func (p *PatientAccessController) validateLabResultsAccess(ctx context.Context, patientID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Patients can only read their lab results
	if req.Action != rbac.ActionRead {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Patients can only read their lab results",
		}, nil
	}

	// Check if results are released to patient
	if status := req.Attributes["result_status"]; status == "pending_review" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Lab results not yet released to patient",
		}, nil
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Patient lab results access granted",
	}, nil
}

func (p *PatientAccessController) validateBillingAccess(ctx context.Context, patientID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Patients can only read their billing information
	if req.Action != rbac.ActionRead {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Patients can only read their billing information",
		}, nil
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Patient billing access granted",
	}, nil
}

func (p *PatientAccessController) validateCommunicationAccess(ctx context.Context, patientID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Patients can create and read their communications
	if req.Action != rbac.ActionCreate && req.Action != rbac.ActionRead {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Patients can only create and read communications",
		}, nil
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Patient communication access granted",
	}, nil
}

func (p *PatientAccessController) isAllowedCommunicationType(commType string) bool {
	allowedTypes := []string{
		"secure_message",
		"appointment_request",
		"prescription_refill",
		"general_inquiry",
	}

	for _, allowed := range allowedTypes {
		if commType == allowed {
			return true
		}
	}
	return false
}

func (p *PatientAccessController) isAuthorizedRecipient(ctx context.Context, patientID, recipientID string) bool {
	// In a real implementation, this would check the patient's care team
	// For now, we'll check if recipient is a healthcare provider
	return strings.HasPrefix(recipientID, "consulting_doctor_") ||
		strings.HasPrefix(recipientID, "nurse_") ||
		strings.HasPrefix(recipientID, "clinical_staff_") ||
		strings.HasPrefix(recipientID, "receptionist_")
}

func (p *PatientAccessController) validateMessageContent(content string) error {
	// Basic content validation
	if len(content) > 5000 {
		return fmt.Errorf("message content exceeds maximum length")
	}

	// Check for prohibited content (simplified)
	prohibitedWords := []string{"emergency", "urgent", "critical"}
	contentLower := strings.ToLower(content)
	for _, word := range prohibitedWords {
		if strings.Contains(contentLower, word) {
			return fmt.Errorf("emergency communications should use appropriate channels")
		}
	}

	return nil
}

func (p *PatientAccessController) isPatientAllowedSensitivity(sensitivity string) bool {
	// Patients can access most of their data except highly sensitive clinical notes
	allowedSensitivities := []string{"public", "internal", "confidential"}
	
	for _, allowed := range allowedSensitivities {
		if sensitivity == allowed {
			return true
		}
	}
	return false
}

func (p *PatientAccessController) isPatientAllowedTimeAccess(dataTime time.Time) bool {
	// Patients cannot access future-dated information (e.g., planned procedures)
	return dataTime.Before(time.Now()) || dataTime.Equal(time.Now())
}

func (p *PatientAccessController) isPatientAllowedEHRSection(section string) bool {
	// Define which EHR sections patients can access
	allowedSections := []string{
		"demographics",
		"allergies",
		"medications",
		"lab_results",
		"imaging_results",
		"visit_history",
		"immunizations",
		"vital_signs",
	}

	// Restricted sections (clinical notes, provider communications, etc.)
	restrictedSections := []string{
		"clinical_notes",
		"provider_communications",
		"treatment_plans",
		"differential_diagnosis",
	}

	for _, restricted := range restrictedSections {
		if section == restricted {
			return false
		}
	}

	for _, allowed := range allowedSections {
		if section == allowed {
			return true
		}
	}

	// Default to not allowed for unknown sections
	return false
}

func (p *PatientAccessController) validateAppointmentData(attributes map[string]string) error {
	// Validate appointment type
	appointmentType := attributes["appointment_type"]
	if appointmentType == "" {
		return fmt.Errorf("appointment type is required")
	}

	// Validate appointment time (must be in the future)
	if appointmentTimeStr := attributes["appointment_time"]; appointmentTimeStr != "" {
		appointmentTime, err := time.Parse(time.RFC3339, appointmentTimeStr)
		if err != nil {
			return fmt.Errorf("invalid appointment time format")
		}
		if appointmentTime.Before(time.Now()) {
			return fmt.Errorf("appointment time must be in the future")
		}
	}

	// Validate provider (if specified)
	if providerID := attributes["provider_id"]; providerID != "" {
		if !p.isValidProvider(providerID) {
			return fmt.Errorf("invalid provider specified")
		}
	}

	return nil
}

func (p *PatientAccessController) isValidProvider(providerID string) bool {
	// In a real implementation, this would validate against a provider directory
	return strings.HasPrefix(providerID, "consulting_doctor_") ||
		strings.HasPrefix(providerID, "clinical_staff_")
}