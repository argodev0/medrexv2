package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// ClinicalStaffAccessController implements role-specific access controls for clinical staff
type ClinicalStaffAccessController struct {
	logger      *logrus.Logger
	coreEngine  rbac.RBACCoreEngine
	auditLogger rbac.AuditLogger
}

// NewClinicalStaffAccessController creates a new clinical staff access controller
func NewClinicalStaffAccessController(logger *logrus.Logger, coreEngine rbac.RBACCoreEngine, auditLogger rbac.AuditLogger) *ClinicalStaffAccessController {
	return &ClinicalStaffAccessController{
		logger:      logger,
		coreEngine:  coreEngine,
		auditLogger: auditLogger,
	}
}

// ValidateNursingStaffAccess validates access for nursing staff with ward-based restrictions
func (c *ClinicalStaffAccessController) ValidateNursingStaffAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	nurseID := c.extractStaffID(req.UserID, "nurse")
	if nurseID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid nursing staff user ID format",
		}, nil
	}

	// Get nurse's ward assignment
	wardAssignment := req.Attributes["ward_assignment"]
	if wardAssignment == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Ward assignment required for nursing staff access",
		}, nil
	}

	// Validate ward-based access
	if !c.isWardBasedAccess(req.ResourceID, wardAssignment) {
		c.logger.WithFields(logrus.Fields{
			"nurse_id":        nurseID,
			"ward_assignment": wardAssignment,
			"resource_id":     req.ResourceID,
		}).Warn("Nurse attempted to access patient outside assigned ward")

		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Nursing staff can only access patients in their assigned ward",
		}, nil
	}

	// Validate nursing-specific actions
	if !c.isAllowedNursingAction(req.Action, req.ResourceID) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Action '%s' not allowed for nursing staff", req.Action),
		}, nil
	}

	// Check shift-based time restrictions
	if !c.isWithinShiftHours(req.Attributes["shift_type"], req.Timestamp) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Access restricted outside assigned shift hours",
		}, nil
	}

	// Validate medication administration permissions
	if strings.Contains(req.ResourceID, "medication") && req.Action == rbac.ActionAdminister {
		decision, err := c.validateMedicationAdministration(ctx, nurseID, req)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Nursing staff access granted for ward-assigned patient",
		Attributes: map[string]string{
			"nurse_id":        nurseID,
			"ward_assignment": wardAssignment,
			"access_scope":    "ward_based",
		},
		TTL: 2 * time.Hour, // Shift-based TTL
	}, nil
}

// ValidateLabTechnicianAccess validates access for lab technicians with result management focus
func (c *ClinicalStaffAccessController) ValidateLabTechnicianAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	techID := c.extractStaffID(req.UserID, "lab_technician")
	if techID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid lab technician user ID format",
		}, nil
	}

	// Get lab organization assignment
	labOrg := req.Attributes["lab_org"]
	if labOrg == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Lab organization assignment required for lab technician access",
		}, nil
	}

	// Validate lab-specific access
	if !c.isLabRelevantAccess(req.ResourceID, req.Action, labOrg) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Lab technicians can only access lab-relevant resources",
		}, nil
	}

	// Validate allowed actions for lab technicians
	if !c.isAllowedLabTechAction(req.Action, req.ResourceID) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Action '%s' not allowed for lab technicians", req.Action),
		}, nil
	}

	// Check lab result management permissions
	if strings.Contains(req.ResourceID, "lab_result") {
		decision, err := c.validateLabResultManagement(ctx, techID, req)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}

	// Validate specimen handling permissions
	if strings.Contains(req.ResourceID, "specimen") {
		decision, err := c.validateSpecimenHandling(ctx, techID, req)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Lab technician access granted for lab-relevant resources",
		Attributes: map[string]string{
			"tech_id":    techID,
			"lab_org":    labOrg,
			"access_scope": "lab_relevant",
		},
		TTL: 4 * time.Hour,
	}, nil
}

// ValidateClinicalSpecialistAccess validates access for clinical specialists with specialty-based permissions
func (c *ClinicalStaffAccessController) ValidateClinicalSpecialistAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	specialistID := c.extractStaffID(req.UserID, "clinical_staff")
	if specialistID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid clinical specialist user ID format",
		}, nil
	}

	// Get specialty and department
	specialty := req.Attributes["specialty"]
	department := req.Attributes["department"]
	if specialty == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Specialty assignment required for clinical specialist access",
		}, nil
	}

	// Validate specialty-based access
	if !c.isSpecialtyRelevantAccess(req.ResourceID, specialty, department) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Clinical specialists can only access specialty-relevant resources",
		}, nil
	}

	// Validate allowed actions for clinical specialists
	if !c.isAllowedSpecialistAction(req.Action, req.ResourceID, specialty) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Action '%s' not allowed for %s specialists", req.Action, specialty),
		}, nil
	}

	// Check specialized service permissions
	if strings.Contains(req.ResourceID, "specialized_service") {
		decision, err := c.validateSpecializedService(ctx, specialistID, req)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}

	// Validate diagnostic order permissions
	if strings.Contains(req.ResourceID, "diagnostic_order") {
		decision, err := c.validateDiagnosticOrder(ctx, specialistID, req)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  fmt.Sprintf("Clinical specialist access granted for %s-relevant resources", specialty),
		Attributes: map[string]string{
			"specialist_id": specialistID,
			"specialty":     specialty,
			"department":    department,
			"access_scope":  "specialty_based",
		},
		TTL: 6 * time.Hour,
	}, nil
}

// ValidateReceptionistAccess validates access for receptionist/front desk staff
func (c *ClinicalStaffAccessController) ValidateReceptionistAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	receptionistID := c.extractStaffID(req.UserID, "receptionist")
	if receptionistID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid receptionist user ID format",
		}, nil
	}

	// Validate allowed actions for receptionists
	if !c.isAllowedReceptionistAction(req.Action, req.ResourceID) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Action '%s' not allowed for receptionist staff", req.Action),
		}, nil
	}

	// Check patient registration permissions
	if strings.Contains(req.ResourceID, "patient_registration") {
		decision, err := c.validatePatientRegistration(ctx, receptionistID, req)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}

	// Check appointment management permissions
	if strings.Contains(req.ResourceID, "appointment") {
		decision, err := c.validateAppointmentManagement(ctx, receptionistID, req)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}

	// Check billing access permissions
	if strings.Contains(req.ResourceID, "billing") {
		decision, err := c.validateBillingAccess(ctx, receptionistID, req)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return decision, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Receptionist access granted for administrative functions",
		Attributes: map[string]string{
			"receptionist_id": receptionistID,
			"access_scope":    "administrative",
		},
		TTL: 8 * time.Hour, // Full shift TTL
	}, nil
}

// Helper methods

func (c *ClinicalStaffAccessController) extractStaffID(userID, rolePrefix string) string {
	// Expected format: <role>_<staffID>
	prefix := rolePrefix + "_"
	if strings.HasPrefix(userID, prefix) {
		return strings.TrimPrefix(userID, prefix)
	}
	return ""
}

func (c *ClinicalStaffAccessController) isWardBasedAccess(resourceID, wardAssignment string) bool {
	// Check if resource is within the assigned ward
	// Resource format: patient_ehr_<patientID>_ward_<wardID>
	return strings.Contains(resourceID, fmt.Sprintf("ward_%s", wardAssignment)) ||
		   strings.Contains(resourceID, wardAssignment)
}

func (c *ClinicalStaffAccessController) isAllowedNursingAction(action, resourceID string) bool {
	allowedActions := map[string][]string{
		"medication": {rbac.ActionAdminister, rbac.ActionRead, rbac.ActionUpdate},
		"patient":    {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"vital":      {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"nursing":    {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"care":       {rbac.ActionRead, rbac.ActionUpdate},
	}

	resourceType := c.getResourceType(resourceID)
	if actions, exists := allowedActions[resourceType]; exists {
		for _, allowedAction := range actions {
			if action == allowedAction {
				return true
			}
		}
	}

	return false
}

func (c *ClinicalStaffAccessController) isAllowedLabTechAction(action, resourceID string) bool {
	allowedActions := map[string][]string{
		"lab":       {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"specimen":  {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, "process"},
		"patient":   {rbac.ActionRead}, // Limited to lab-relevant sections
		"equipment": {rbac.ActionRead, rbac.ActionUpdate, "calibrate"},
	}

	resourceType := c.getResourceType(resourceID)
	if actions, exists := allowedActions[resourceType]; exists {
		for _, allowedAction := range actions {
			if action == allowedAction {
				return true
			}
		}
	}

	return false
}

func (c *ClinicalStaffAccessController) isAllowedSpecialistAction(action, resourceID, specialty string) bool {
	// Base allowed actions for all specialists
	baseActions := map[string][]string{
		"patient":     {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"diagnostic":  {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"specialized": {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"lab":         {rbac.ActionRead},
		"imaging":     {rbac.ActionRead},
	}

	// Specialty-specific additional actions
	specialtyActions := map[string]map[string][]string{
		"radiology": {
			"imaging": {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, "interpret", "report"},
		},
		"pathology": {
			"biopsy":     {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, "interpret"},
			"pathology":  {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		},
		"cardiology": {
			"ecg":     {rbac.ActionRead, rbac.ActionUpdate, "interpret"},
			"cardiac": {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		},
	}

	resourceType := c.getResourceType(resourceID)

	// Check base actions
	if actions, exists := baseActions[resourceType]; exists {
		for _, allowedAction := range actions {
			if action == allowedAction {
				return true
			}
		}
	}

	// Check specialty-specific actions
	if specialtyMap, exists := specialtyActions[specialty]; exists {
		if actions, exists := specialtyMap[resourceType]; exists {
			for _, allowedAction := range actions {
				if action == allowedAction {
					return true
				}
			}
		}
	}

	return false
}

func (c *ClinicalStaffAccessController) isAllowedReceptionistAction(action, resourceID string) bool {
	allowedActions := map[string][]string{
		"patient":      {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"appointment":  {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionSchedule, rbac.ActionCancel},
		"billing":      {rbac.ActionRead, rbac.ActionUpdate},
		"insurance":    {rbac.ActionRead, rbac.ActionUpdate, "verify"},
		"demographics": {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
		"contact":      {rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
	}

	resourceType := c.getResourceType(resourceID)
	if actions, exists := allowedActions[resourceType]; exists {
		for _, allowedAction := range actions {
			if action == allowedAction {
				return true
			}
		}
	}

	return false
}

func (c *ClinicalStaffAccessController) isWithinShiftHours(shiftType string, timestamp time.Time) bool {
	// Define shift hours
	shiftHours := map[string]struct {
		start, end int
	}{
		"day":   {start: 7, end: 19},   // 7 AM to 7 PM
		"night": {start: 19, end: 7},   // 7 PM to 7 AM (next day)
		"swing": {start: 15, end: 23},  // 3 PM to 11 PM
	}

	if shift, exists := shiftHours[shiftType]; exists {
		hour := timestamp.Hour()
		if shift.start < shift.end {
			return hour >= shift.start && hour < shift.end
		} else {
			// Night shift spans midnight
			return hour >= shift.start || hour < shift.end
		}
	}

	// If no shift type specified, allow access during business hours
	return timestamp.Hour() >= 6 && timestamp.Hour() < 22
}

func (c *ClinicalStaffAccessController) isLabRelevantAccess(resourceID, action, labOrg string) bool {
	// Check if resource is lab-relevant
	labRelevantResources := []string{
		"lab", "specimen", "equipment", "quality",
	}

	resourceType := c.getResourceType(resourceID)
	for _, relevant := range labRelevantResources {
		if strings.Contains(resourceType, relevant) {
			return true
		}
	}

	// Check if accessing lab-relevant patient data
	if resourceType == "patient" && action == rbac.ActionRead {
		// Only allow access to lab-relevant sections
		return true // This would be further restricted by data filtering
	}

	return false
}

func (c *ClinicalStaffAccessController) isSpecialtyRelevantAccess(resourceID, specialty, department string) bool {
	// Check if resource is relevant to the specialist's area
	resourceType := c.getResourceType(resourceID)

	// General clinical resources
	generalResources := []string{
		"patient", "diagnostic", "specialized", "lab", "imaging",
	}

	for _, general := range generalResources {
		if strings.Contains(resourceType, general) {
			return true
		}
	}

	// Specialty-specific resources
	specialtyResources := map[string][]string{
		"radiology": {"imaging", "radiology"},
		"pathology": {"biopsy", "pathology", "cytology"},
		"cardiology": {"ecg", "cardiac", "stress"},
		"neurology": {"eeg", "neurological", "brain"},
	}

	if resources, exists := specialtyResources[specialty]; exists {
		for _, resource := range resources {
			if strings.Contains(resourceType, resource) {
				return true
			}
		}
	}

	return false
}

func (c *ClinicalStaffAccessController) getResourceType(resourceID string) string {
	parts := strings.Split(resourceID, "_")
	if len(parts) >= 1 {
		return parts[0]
	}
	return resourceID
}

// Validation methods for specific actions

func (c *ClinicalStaffAccessController) validateMedicationAdministration(ctx context.Context, nurseID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Check if medication order exists and is valid
	orderID := req.Attributes["order_id"]
	if orderID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Medication order ID required for administration",
		}, nil
	}

	// Check if nurse is authorized to administer this medication
	medicationType := req.Attributes["medication_type"]
	if !c.isNurseAuthorizedForMedication(nurseID, medicationType) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Nurse not authorized to administer this medication type",
		}, nil
	}

	// Check if administration is within time window
	if !c.isWithinAdministrationWindow(req.Attributes["scheduled_time"]) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Medication administration outside allowed time window",
		}, nil
	}

	return &rbac.AccessDecision{Allowed: true}, nil
}

func (c *ClinicalStaffAccessController) validateLabResultManagement(ctx context.Context, techID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Check if lab technician is qualified for this test type
	testType := req.Attributes["test_type"]
	if !c.isLabTechQualifiedForTest(techID, testType) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Lab technician not qualified for this test type",
		}, nil
	}

	// Check if result requires supervisor review
	if req.Action == rbac.ActionCreate && req.Attributes["critical_value"] == "true" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Critical lab results require supervisor review before release",
		}, nil
	}

	return &rbac.AccessDecision{Allowed: true}, nil
}

func (c *ClinicalStaffAccessController) validateSpecimenHandling(ctx context.Context, techID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Check specimen handling authorization
	specimenType := req.Attributes["specimen_type"]
	if !c.isAuthorizedForSpecimenType(techID, specimenType) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Lab technician not authorized for this specimen type",
		}, nil
	}

	return &rbac.AccessDecision{Allowed: true}, nil
}

func (c *ClinicalStaffAccessController) validateSpecializedService(ctx context.Context, specialistID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Check if specialist is qualified for this service
	serviceType := req.Attributes["service_type"]
	specialty := req.Attributes["specialty"]
	
	if !c.isSpecialistQualifiedForService(specialistID, serviceType, specialty) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Specialist not qualified for this service type",
		}, nil
	}

	return &rbac.AccessDecision{Allowed: true}, nil
}

func (c *ClinicalStaffAccessController) validateDiagnosticOrder(ctx context.Context, specialistID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Check if specialist can order this diagnostic test
	orderType := req.Attributes["order_type"]
	specialty := req.Attributes["specialty"]
	
	if !c.canSpecialistOrderDiagnostic(specialty, orderType) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Specialist not authorized to order this diagnostic test",
		}, nil
	}

	return &rbac.AccessDecision{Allowed: true}, nil
}

func (c *ClinicalStaffAccessController) validatePatientRegistration(ctx context.Context, receptionistID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Check if receptionist can register patients
	if req.Action == rbac.ActionCreate {
		// Validate required registration fields
		requiredFields := []string{"patient_name", "date_of_birth", "contact_info"}
		for _, field := range requiredFields {
			if req.Attributes[field] == "" {
				return &rbac.AccessDecision{
					Allowed: false,
					Reason:  fmt.Sprintf("Required field missing: %s", field),
				}, nil
			}
		}
	}

	return &rbac.AccessDecision{Allowed: true}, nil
}

func (c *ClinicalStaffAccessController) validateAppointmentManagement(ctx context.Context, receptionistID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Check appointment management permissions
	if req.Action == rbac.ActionSchedule {
		// Validate appointment scheduling rules
		if !c.isValidAppointmentTime(req.Attributes["appointment_time"]) {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  "Invalid appointment time",
			}, nil
		}
	}

	return &rbac.AccessDecision{Allowed: true}, nil
}

func (c *ClinicalStaffAccessController) validateBillingAccess(ctx context.Context, receptionistID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Receptionists can only access billing for administrative purposes
	if req.Action != rbac.ActionRead && req.Action != rbac.ActionUpdate {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Receptionists can only read and update billing information",
		}, nil
	}

	return &rbac.AccessDecision{Allowed: true}, nil
}

// Helper validation methods

func (c *ClinicalStaffAccessController) isNurseAuthorizedForMedication(nurseID, medicationType string) bool {
	// Check nurse's medication administration certifications
	// This would query the nurse's qualifications database
	restrictedMedications := []string{"chemotherapy", "controlled_substance_schedule_ii"}
	
	for _, restricted := range restrictedMedications {
		if medicationType == restricted {
			// Would check for special certification
			return false // For now, assume not authorized
		}
	}
	
	return true
}

func (c *ClinicalStaffAccessController) isWithinAdministrationWindow(scheduledTime string) bool {
	if scheduledTime == "" {
		return true // No time restriction
	}
	
	scheduled, err := time.Parse(time.RFC3339, scheduledTime)
	if err != nil {
		return false
	}
	
	now := time.Now()
	// Allow administration within 1 hour before or after scheduled time
	return now.After(scheduled.Add(-1*time.Hour)) && now.Before(scheduled.Add(1*time.Hour))
}

func (c *ClinicalStaffAccessController) isLabTechQualifiedForTest(techID, testType string) bool {
	// Check lab technician's qualifications for specific test types
	// This would query the technician's certification database
	return true // For now, assume qualified
}

func (c *ClinicalStaffAccessController) isAuthorizedForSpecimenType(techID, specimenType string) bool {
	// Check authorization for handling specific specimen types
	restrictedSpecimens := []string{"infectious_disease", "hazardous_material"}
	
	for _, restricted := range restrictedSpecimens {
		if specimenType == restricted {
			// Would check for special authorization
			return false // For now, assume not authorized
		}
	}
	
	return true
}

func (c *ClinicalStaffAccessController) isSpecialistQualifiedForService(specialistID, serviceType, specialty string) bool {
	// Check if specialist's qualifications match the service requirements
	// This would query the specialist's credentials and certifications
	return true // For now, assume qualified
}

func (c *ClinicalStaffAccessController) canSpecialistOrderDiagnostic(specialty, orderType string) bool {
	// Define which specialists can order which diagnostic tests
	allowedOrders := map[string][]string{
		"radiology": {"ct_scan", "mri", "x_ray", "ultrasound"},
		"cardiology": {"ecg", "echocardiogram", "stress_test", "cardiac_catheterization", "ct_scan"}, // Cardiologists can order CT scans
		"pathology": {"biopsy", "cytology", "histopathology"},
		"neurology": {"eeg", "emg", "nerve_conduction_study"},
	}
	
	if orders, exists := allowedOrders[specialty]; exists {
		for _, allowed := range orders {
			if orderType == allowed {
				return true
			}
		}
	}
	
	return false
}

func (c *ClinicalStaffAccessController) isValidAppointmentTime(appointmentTime string) bool {
	if appointmentTime == "" {
		return false
	}
	
	apptTime, err := time.Parse(time.RFC3339, appointmentTime)
	if err != nil {
		return false
	}
	
	// Appointment must be in the future and within business hours
	now := time.Now()
	if apptTime.Before(now) {
		return false
	}
	
	// Check if within business hours (8 AM to 6 PM)
	hour := apptTime.Hour()
	return hour >= 8 && hour < 18
}