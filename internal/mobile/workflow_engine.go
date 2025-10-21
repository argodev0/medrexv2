package mobile

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/medrex/dlt-emr/pkg/interfaces"
)

// WorkflowEngine implements specialized mobile workflows
type WorkflowEngine struct {
	mobileService interfaces.MobileWorkflowService
	auditService  interfaces.AuditService
	workflows     map[string]*WorkflowTemplate
}

// WorkflowTemplate defines a workflow template
type WorkflowTemplate struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Steps       []WorkflowStep         `json:"steps"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// WorkflowStep defines a single step in a workflow
type WorkflowStep struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        string                 `json:"type"`
	Required    bool                   `json:"required"`
	Validation  map[string]interface{} `json:"validation"`
	NextSteps   []string               `json:"next_steps"`
	Actions     []WorkflowAction       `json:"actions"`
}

// WorkflowAction defines an action within a workflow step
type WorkflowAction struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

// WorkflowInstance represents an active workflow instance
type WorkflowInstance struct {
	ID          string                 `json:"id"`
	WorkflowID  string                 `json:"workflow_id"`
	UserID      string                 `json:"user_id"`
	Status      string                 `json:"status"`
	CurrentStep string                 `json:"current_step"`
	Data        map[string]interface{} `json:"data"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// NewWorkflowEngine creates a new workflow engine
func NewWorkflowEngine(mobileService interfaces.MobileWorkflowService, auditService interfaces.AuditService) *WorkflowEngine {
	engine := &WorkflowEngine{
		mobileService: mobileService,
		auditService:  auditService,
		workflows:     make(map[string]*WorkflowTemplate),
	}

	// Register built-in workflows
	engine.registerBuiltInWorkflows()

	return engine
}

// Workflow Execution

// StartWorkflow starts a new workflow instance
func (e *WorkflowEngine) StartWorkflow(workflowType, userID string, params map[string]interface{}) (string, error) {
	template, exists := e.workflows[workflowType]
	if !exists {
		return "", fmt.Errorf("workflow template not found: %s", workflowType)
	}

	// Create workflow instance
	instance := &WorkflowInstance{
		ID:          uuid.New().String(),
		WorkflowID:  workflowType,
		UserID:      userID,
		Status:      "active",
		CurrentStep: template.Steps[0].ID,
		Data:        params,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Log workflow start
	auditData := map[string]interface{}{
		"workflow_id":   instance.ID,
		"workflow_type": workflowType,
		"parameters":    params,
	}
	if err := e.auditService.LogEvent(userID, "workflow_started", instance.ID, true, auditData); err != nil {
		fmt.Printf("Failed to log workflow start: %v\n", err)
	}

	return instance.ID, nil
}

// ContinueWorkflow continues a workflow with the next action
func (e *WorkflowEngine) ContinueWorkflow(workflowID string, action string, data map[string]interface{}) error {
	// In a real implementation, this would retrieve the workflow instance from storage
	// For now, we'll simulate workflow continuation
	
	// Log workflow continuation
	auditData := map[string]interface{}{
		"workflow_id": workflowID,
		"action":      action,
		"data":        data,
	}
	if err := e.auditService.LogEvent("system", "workflow_continued", workflowID, true, auditData); err != nil {
		fmt.Printf("Failed to log workflow continuation: %v\n", err)
	}

	return nil
}

// CompleteWorkflow completes a workflow instance
func (e *WorkflowEngine) CompleteWorkflow(workflowID string) error {
	// Log workflow completion
	auditData := map[string]interface{}{
		"workflow_id": workflowID,
	}
	if err := e.auditService.LogEvent("system", "workflow_completed", workflowID, true, auditData); err != nil {
		fmt.Printf("Failed to log workflow completion: %v\n", err)
	}

	return nil
}

// CancelWorkflow cancels a workflow instance
func (e *WorkflowEngine) CancelWorkflow(workflowID string, reason string) error {
	// Log workflow cancellation
	auditData := map[string]interface{}{
		"workflow_id": workflowID,
		"reason":      reason,
	}
	if err := e.auditService.LogEvent("system", "workflow_cancelled", workflowID, true, auditData); err != nil {
		fmt.Printf("Failed to log workflow cancellation: %v\n", err)
	}

	return nil
}

// Workflow State Management

// GetWorkflowState retrieves the current state of a workflow
func (e *WorkflowEngine) GetWorkflowState(workflowID string) (map[string]interface{}, error) {
	// In a real implementation, this would retrieve from storage
	state := map[string]interface{}{
		"workflow_id":   workflowID,
		"status":        "active",
		"current_step":  "step_1",
		"progress":      50,
		"data":          map[string]interface{}{},
	}

	return state, nil
}

// GetActiveWorkflows retrieves active workflows for a user
func (e *WorkflowEngine) GetActiveWorkflows(userID string) ([]map[string]interface{}, error) {
	// In a real implementation, this would query active workflows from storage
	workflows := []map[string]interface{}{
		{
			"workflow_id":   "wf-001",
			"workflow_type": "medication_administration",
			"status":        "active",
			"current_step":  "scan_medication",
			"created_at":    time.Now().Add(-10 * time.Minute),
		},
	}

	return workflows, nil
}

// Workflow Template Management

// RegisterWorkflowTemplate registers a new workflow template
func (e *WorkflowEngine) RegisterWorkflowTemplate(name string, template map[string]interface{}) error {
	templateBytes, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	var workflowTemplate WorkflowTemplate
	if err := json.Unmarshal(templateBytes, &workflowTemplate); err != nil {
		return fmt.Errorf("failed to unmarshal template: %w", err)
	}

	e.workflows[name] = &workflowTemplate
	return nil
}

// GetWorkflowTemplate retrieves a workflow template
func (e *WorkflowEngine) GetWorkflowTemplate(name string) (map[string]interface{}, error) {
	template, exists := e.workflows[name]
	if !exists {
		return nil, fmt.Errorf("workflow template not found: %s", name)
	}

	templateBytes, err := json.Marshal(template)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal template: %w", err)
	}

	var templateMap map[string]interface{}
	if err := json.Unmarshal(templateBytes, &templateMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template: %w", err)
	}

	return templateMap, nil
}

// Built-in Workflow Registration

// registerBuiltInWorkflows registers all built-in workflow templates
func (e *WorkflowEngine) registerBuiltInWorkflows() {
	// Register medication administration workflow
	e.registerMedicationAdministrationWorkflow()
	
	// Register lab result entry workflow
	e.registerLabResultEntryWorkflow()
	
	// Register patient communication workflow
	e.registerPatientCommunicationWorkflow()
	
	// Register nurse medication workflow
	e.registerNurseMedicationWorkflow()
	
	// Register technician lab workflow
	e.registerTechnicianLabWorkflow()
}

// registerMedicationAdministrationWorkflow registers the medication administration workflow
func (e *WorkflowEngine) registerMedicationAdministrationWorkflow() {
	template := &WorkflowTemplate{
		Name:        "medication_administration",
		Description: "Workflow for nurses to administer medications safely",
		Steps: []WorkflowStep{
			{
				ID:       "verify_patient",
				Name:     "Verify Patient Identity",
				Type:     "barcode_scan",
				Required: true,
				Validation: map[string]interface{}{
					"barcode_type": "patient",
				},
				NextSteps: []string{"scan_medication"},
				Actions: []WorkflowAction{
					{
						Type: "scan_patient_wristband",
						Parameters: map[string]interface{}{
							"required_fields": []string{"patient_id", "name"},
						},
					},
				},
			},
			{
				ID:       "scan_medication",
				Name:     "Scan Medication Barcode",
				Type:     "barcode_scan",
				Required: true,
				Validation: map[string]interface{}{
					"barcode_type": "medication",
				},
				NextSteps: []string{"verify_medication"},
				Actions: []WorkflowAction{
					{
						Type: "scan_medication_barcode",
						Parameters: map[string]interface{}{
							"verify_against_order": true,
						},
					},
				},
			},
			{
				ID:       "verify_medication",
				Name:     "Verify Medication Details",
				Type:     "verification",
				Required: true,
				Validation: map[string]interface{}{
					"check_allergies":    true,
					"check_interactions": true,
				},
				NextSteps: []string{"record_administration"},
				Actions: []WorkflowAction{
					{
						Type: "verify_medication_safety",
						Parameters: map[string]interface{}{
							"include_allergies":    true,
							"include_interactions": true,
						},
					},
				},
			},
			{
				ID:       "record_administration",
				Name:     "Record Medication Administration",
				Type:     "data_entry",
				Required: true,
				Validation: map[string]interface{}{
					"required_fields": []string{"dose", "route", "time"},
				},
				NextSteps: []string{},
				Actions: []WorkflowAction{
					{
						Type: "record_medication_admin",
						Parameters: map[string]interface{}{
							"auto_timestamp": true,
						},
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"role_required": "nurse",
			"estimated_time": "5-10 minutes",
		},
	}

	e.workflows["medication_administration"] = template
}

// registerLabResultEntryWorkflow registers the lab result entry workflow
func (e *WorkflowEngine) registerLabResultEntryWorkflow() {
	template := &WorkflowTemplate{
		Name:        "lab_result_entry",
		Description: "Workflow for lab technicians to enter test results",
		Steps: []WorkflowStep{
			{
				ID:       "scan_specimen",
				Name:     "Scan Specimen Barcode",
				Type:     "barcode_scan",
				Required: true,
				Validation: map[string]interface{}{
					"barcode_type": "specimen",
				},
				NextSteps: []string{"verify_test_order"},
				Actions: []WorkflowAction{
					{
						Type: "scan_specimen_barcode",
						Parameters: map[string]interface{}{
							"required_fields": []string{"specimen_id", "patient_id", "test_type"},
						},
					},
				},
			},
			{
				ID:       "verify_test_order",
				Name:     "Verify Test Order",
				Type:     "verification",
				Required: true,
				Validation: map[string]interface{}{
					"order_exists": true,
					"order_status": "approved",
				},
				NextSteps: []string{"enter_results"},
				Actions: []WorkflowAction{
					{
						Type: "verify_lab_order",
						Parameters: map[string]interface{}{
							"check_order_status": true,
						},
					},
				},
			},
			{
				ID:       "enter_results",
				Name:     "Enter Test Results",
				Type:     "data_entry",
				Required: true,
				Validation: map[string]interface{}{
					"required_fields": []string{"result", "units", "reference_range"},
				},
				NextSteps: []string{"review_results"},
				Actions: []WorkflowAction{
					{
						Type: "enter_lab_result",
						Parameters: map[string]interface{}{
							"validate_ranges": true,
						},
					},
				},
			},
			{
				ID:       "review_results",
				Name:     "Review and Finalize Results",
				Type:     "review",
				Required: true,
				Validation: map[string]interface{}{
					"technician_review": true,
				},
				NextSteps: []string{},
				Actions: []WorkflowAction{
					{
						Type: "finalize_lab_result",
						Parameters: map[string]interface{}{
							"auto_timestamp": true,
							"require_signature": true,
						},
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"role_required": "lab_technician",
			"estimated_time": "10-15 minutes",
		},
	}

	e.workflows["lab_result_entry"] = template
}

// registerPatientCommunicationWorkflow registers the patient communication workflow
func (e *WorkflowEngine) registerPatientCommunicationWorkflow() {
	template := &WorkflowTemplate{
		Name:        "patient_communication",
		Description: "Workflow for secure patient communication",
		Steps: []WorkflowStep{
			{
				ID:       "verify_patient_identity",
				Name:     "Verify Patient Identity",
				Type:     "verification",
				Required: true,
				Validation: map[string]interface{}{
					"identity_check": true,
				},
				NextSteps: []string{"select_communication_type"},
				Actions: []WorkflowAction{
					{
						Type: "verify_patient_identity",
						Parameters: map[string]interface{}{
							"methods": []string{"wristband", "verbal_confirmation"},
						},
					},
				},
			},
			{
				ID:       "select_communication_type",
				Name:     "Select Communication Type",
				Type:     "selection",
				Required: true,
				Validation: map[string]interface{}{
					"valid_types": []string{"education", "discharge_instructions", "test_results", "general"},
				},
				NextSteps: []string{"compose_message"},
				Actions: []WorkflowAction{
					{
						Type: "select_communication_type",
						Parameters: map[string]interface{}{
							"available_types": []string{"education", "discharge_instructions", "test_results", "general"},
						},
					},
				},
			},
			{
				ID:       "compose_message",
				Name:     "Compose Message",
				Type:     "data_entry",
				Required: true,
				Validation: map[string]interface{}{
					"max_length": 1000,
					"required_fields": []string{"message"},
				},
				NextSteps: []string{"send_message"},
				Actions: []WorkflowAction{
					{
						Type: "compose_patient_message",
						Parameters: map[string]interface{}{
							"template_available": true,
							"spell_check": true,
						},
					},
				},
			},
			{
				ID:       "send_message",
				Name:     "Send Message",
				Type:     "action",
				Required: true,
				Validation: map[string]interface{}{
					"delivery_method": []string{"portal", "sms", "email"},
				},
				NextSteps: []string{},
				Actions: []WorkflowAction{
					{
						Type: "send_patient_message",
						Parameters: map[string]interface{}{
							"delivery_confirmation": true,
							"audit_trail": true,
						},
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"role_required": "clinical_staff",
			"estimated_time": "3-5 minutes",
		},
	}

	e.workflows["patient_communication"] = template
}

// registerNurseMedicationWorkflow registers the nurse-specific medication workflow
func (e *WorkflowEngine) registerNurseMedicationWorkflow() {
	template := &WorkflowTemplate{
		Name:        "nurse_medication_workflow",
		Description: "Comprehensive medication workflow for nurses",
		Steps: []WorkflowStep{
			{
				ID:       "review_medication_orders",
				Name:     "Review Medication Orders",
				Type:     "review",
				Required: true,
				Validation: map[string]interface{}{
					"orders_exist": true,
				},
				NextSteps: []string{"prepare_medications"},
				Actions: []WorkflowAction{
					{
						Type: "get_medication_schedule",
						Parameters: map[string]interface{}{
							"include_due_now": true,
							"include_overdue": true,
						},
					},
				},
			},
			{
				ID:       "prepare_medications",
				Name:     "Prepare Medications",
				Type:     "preparation",
				Required: true,
				Validation: map[string]interface{}{
					"five_rights_check": true,
				},
				NextSteps: []string{"administer_medications"},
				Actions: []WorkflowAction{
					{
						Type: "prepare_medication_doses",
						Parameters: map[string]interface{}{
							"verify_five_rights": true,
						},
					},
				},
			},
			{
				ID:       "administer_medications",
				Name:     "Administer Medications",
				Type:     "administration",
				Required: true,
				Validation: map[string]interface{}{
					"patient_consent": true,
				},
				NextSteps: []string{"document_administration"},
				Actions: []WorkflowAction{
					{
						Type: "administer_medication",
						Parameters: map[string]interface{}{
							"real_time_documentation": true,
						},
					},
				},
			},
			{
				ID:       "document_administration",
				Name:     "Document Administration",
				Type:     "documentation",
				Required: true,
				Validation: map[string]interface{}{
					"complete_documentation": true,
				},
				NextSteps: []string{},
				Actions: []WorkflowAction{
					{
						Type: "complete_medication_documentation",
						Parameters: map[string]interface{}{
							"include_patient_response": true,
						},
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"role_required": "nurse",
			"estimated_time": "15-30 minutes",
		},
	}

	e.workflows["nurse_medication_workflow"] = template
}

// registerTechnicianLabWorkflow registers the technician-specific lab workflow
func (e *WorkflowEngine) registerTechnicianLabWorkflow() {
	template := &WorkflowTemplate{
		Name:        "technician_lab_workflow",
		Description: "Comprehensive lab workflow for technicians",
		Steps: []WorkflowStep{
			{
				ID:       "receive_specimens",
				Name:     "Receive and Log Specimens",
				Type:     "receiving",
				Required: true,
				Validation: map[string]interface{}{
					"specimen_integrity": true,
				},
				NextSteps: []string{"process_specimens"},
				Actions: []WorkflowAction{
					{
						Type: "log_specimen_receipt",
						Parameters: map[string]interface{}{
							"check_integrity": true,
							"verify_labels": true,
						},
					},
				},
			},
			{
				ID:       "process_specimens",
				Name:     "Process Specimens",
				Type:     "processing",
				Required: true,
				Validation: map[string]interface{}{
					"processing_protocol": true,
				},
				NextSteps: []string{"run_tests"},
				Actions: []WorkflowAction{
					{
						Type: "process_lab_specimens",
						Parameters: map[string]interface{}{
							"follow_protocol": true,
							"quality_control": true,
						},
					},
				},
			},
			{
				ID:       "run_tests",
				Name:     "Run Laboratory Tests",
				Type:     "testing",
				Required: true,
				Validation: map[string]interface{}{
					"calibration_check": true,
				},
				NextSteps: []string{"enter_results"},
				Actions: []WorkflowAction{
					{
						Type: "run_lab_tests",
						Parameters: map[string]interface{}{
							"automated_analysis": true,
							"quality_controls": true,
						},
					},
				},
			},
			{
				ID:       "enter_results",
				Name:     "Enter and Verify Results",
				Type:     "data_entry",
				Required: true,
				Validation: map[string]interface{}{
					"double_check": true,
				},
				NextSteps: []string{},
				Actions: []WorkflowAction{
					{
						Type: "enter_verified_results",
						Parameters: map[string]interface{}{
							"peer_review": true,
							"critical_value_alert": true,
						},
					},
				},
			},
		},
		Metadata: map[string]interface{}{
			"role_required": "lab_technician",
			"estimated_time": "30-60 minutes",
		},
	}

	e.workflows["technician_lab_workflow"] = template
}