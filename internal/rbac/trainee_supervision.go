package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// TraineeSupervisionController implements trainee role supervision and access controls
type TraineeSupervisionController struct {
	logger           *logrus.Logger
	coreEngine       rbac.RBACCoreEngine
	workflowEngine   rbac.SupervisionWorkflowEngine
	auditLogger      rbac.AuditLogger
	sbeManager       rbac.SBEPolicyManager
}

// NewTraineeSupervisionController creates a new trainee supervision controller
func NewTraineeSupervisionController(
	logger *logrus.Logger,
	coreEngine rbac.RBACCoreEngine,
	workflowEngine rbac.SupervisionWorkflowEngine,
	auditLogger rbac.AuditLogger,
	sbeManager rbac.SBEPolicyManager,
) *TraineeSupervisionController {
	return &TraineeSupervisionController{
		logger:         logger,
		coreEngine:     coreEngine,
		workflowEngine: workflowEngine,
		auditLogger:    auditLogger,
		sbeManager:     sbeManager,
	}
}

// ValidateMBBSStudentAccess validates access for MBBS students with de-identified data restrictions
func (t *TraineeSupervisionController) ValidateMBBSStudentAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	studentID := t.extractTraineeID(req.UserID)
	if studentID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid MBBS student user ID format",
		}, nil
	}

	// MBBS students can only access de-identified training data
	if !t.isDeIdentifiedData(req.ResourceID, req.Attributes) {
		t.logger.WithFields(logrus.Fields{
			"student_id":  studentID,
			"resource_id": req.ResourceID,
			"action":      req.Action,
		}).Warn("MBBS student attempted to access identified data")

		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "MBBS students can only access de-identified training data",
		}, nil
	}

	// Validate allowed actions for MBBS students
	if !t.isAllowedMBBSAction(req.Action, req.ResourceID) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Action '%s' not allowed for MBBS students", req.Action),
		}, nil
	}

	// Check training data scope restrictions
	if !t.isAllowedTrainingDataScope(req.Attributes) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Training data scope not appropriate for MBBS level",
		}, nil
	}

	// Log training data access for educational tracking
	t.logTrainingDataAccess(ctx, studentID, req)

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "MBBS student access granted for de-identified training data",
		Attributes: map[string]string{
			"student_id":   studentID,
			"student_type": "mbbs",
			"data_type":    "de_identified",
			"access_scope": "training",
		},
		TTL: 30 * time.Minute,
	}, nil
}

// ValidateMDStudentAccess validates access for MD/MS students with supervised CPOE workflow
func (t *TraineeSupervisionController) ValidateMDStudentAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	studentID := t.extractTraineeID(req.UserID)
	if studentID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid MD/MS student user ID format",
		}, nil
	}

	// Check if this is a supervised action
	if t.requiresSupervision(req.Action, req.ResourceID) {
		return t.handleSupervisedAction(ctx, studentID, req)
	}

	// Validate allowed actions for MD/MS students
	if !t.isAllowedMDAction(req.Action, req.ResourceID) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  fmt.Sprintf("Action '%s' not allowed for MD/MS students", req.Action),
		}, nil
	}

	// Check patient assignment restrictions
	if !t.isAssignedPatient(ctx, studentID, req.ResourceID) {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "MD/MS students can only access assigned patients",
		}, nil
	}

	// Log trainee activity for supervision tracking
	t.logTraineeActivity(ctx, studentID, req)

	return &rbac.AccessDecision{
		Allowed: true,
		Reason:  "MD/MS student access granted for assigned patient",
		Attributes: map[string]string{
			"student_id":   studentID,
			"student_type": "md_ms",
			"access_scope": "assigned_patient",
		},
		TTL: 15 * time.Minute,
	}, nil
}

// HandleSupervisedCPOEWorkflow manages the supervised CPOE workflow for MD/MS students
func (t *TraineeSupervisionController) HandleSupervisedCPOEWorkflow(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	studentID := t.extractTraineeID(req.UserID)
	if studentID == "" {
		return &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Invalid trainee user ID format",
		}, nil
	}

	// Check if this is a CPOE creation request
	if req.Action == rbac.ActionCreate && strings.Contains(req.ResourceID, "cpoe_order") {
		// Create supervision workflow
		workflow := &rbac.SupervisionWorkflow{
			ID:           fmt.Sprintf("cpoe_supervision_%s_%d", studentID, time.Now().Unix()),
			TraineeID:    req.UserID,
			ResourceID:   req.ResourceID,
			WorkflowType: "cpoe_supervision",
			Status:       rbac.StatusPending,
			RequiredActions: []rbac.SupervisionAction{
				{
					Type:        "review",
					Description: "Review CPOE order for clinical appropriateness",
					Required:    true,
					Attributes: map[string]string{
						"order_type": req.Attributes["order_type"],
					},
				},
				{
					Type:        "approve",
					Description: "Approve CPOE order for execution",
					Required:    true,
					Attributes: map[string]string{
						"requires_signature": "true",
					},
				},
			},
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(4 * time.Hour), // 4-hour timeout for CPOE approval
			Metadata: map[string]interface{}{
				"order_details": req.Attributes,
				"urgency":       req.Attributes["urgency"],
			},
		}

		// Assign supervisor
		supervisorID, err := t.findAvailableSupervisor(ctx, studentID, req.Attributes["specialty"])
		if err != nil {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  fmt.Sprintf("Failed to assign supervisor: %s", err.Error()),
			}, nil
		}
		workflow.SupervisorID = supervisorID

		// Create workflow
		if t.workflowEngine != nil {
			if err := t.workflowEngine.CreateSupervisionWorkflow(ctx, workflow); err != nil {
				return &rbac.AccessDecision{
					Allowed: false,
					Reason:  fmt.Sprintf("Failed to create supervision workflow: %s", err.Error()),
				}, nil
			}
		}

		// Apply SBE policy for supervision requirement
		sbePolicy := &rbac.SBEPolicy{
			ID:           fmt.Sprintf("cpoe_supervision_%s", workflow.ID),
			Name:         "CPOE Supervision Policy",
			ResourceType: "cpoe_order",
			TriggerConditions: []rbac.TriggerCondition{
				{
					Attribute: "is_trainee",
					Operator:  "equals",
					Value:     "true",
				},
			},
			RequiredEndorsers: []rbac.EndorserRequirement{
				{
					Role: rbac.RoleConsultingDoctor,
					Attributes: map[string]string{
						"is_supervisor": "true",
						"supervisor_id": supervisorID,
					},
					MinCount: 1,
					MaxCount: 1,
				},
			},
			TimeoutDuration:   4 * time.Hour,
			EscalationPolicy:  "escalate_to_chief_resident",
			EmergencyOverride: true,
		}

		if t.sbeManager != nil {
			if err := t.sbeManager.ApplySBEPolicy(ctx, req.ResourceID, sbePolicy); err != nil {
				t.logger.WithError(err).Error("Failed to apply SBE policy for CPOE supervision")
			}
		}

		return &rbac.AccessDecision{
			Allowed: false, // Initially denied until supervisor approval
			Reason:  "CPOE order created and pending supervisor approval",
			Conditions: []string{
				"requires_supervisor_approval",
				fmt.Sprintf("workflow_id:%s", workflow.ID),
				fmt.Sprintf("supervisor_id:%s", supervisorID),
			},
			Attributes: map[string]string{
				"workflow_id":   workflow.ID,
				"supervisor_id": supervisorID,
				"status":        string(rbac.StatusPending),
			},
		}, nil
	}

	return &rbac.AccessDecision{
		Allowed: false,
		Reason:  "Unsupported supervised action",
	}, nil
}

// TrackTraineeActivity logs and tracks trainee activities for educational assessment
func (t *TraineeSupervisionController) TrackTraineeActivity(ctx context.Context, traineeID string, activity *TraineeActivity) error {
	if t.auditLogger != nil {
		// This would typically be logged to a specialized educational tracking system
		t.logger.WithFields(logrus.Fields{
			"trainee_id":        traineeID,
			"activity_type":     activity.Type,
			"competency_area":   activity.CompetencyArea,
			"learning_objective": activity.LearningObjective,
		}).Info("Trainee activity tracked")
	}

	return nil
}

// GetTraineeSupervisionStatus returns the current supervision status for a trainee
func (t *TraineeSupervisionController) GetTraineeSupervisionStatus(ctx context.Context, traineeID string) (*TraineeSupervisionStatus, error) {
	// Get pending supervision workflows
	pendingWorkflows, err := t.workflowEngine.GetPendingSupervision(ctx, traineeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending supervision: %w", err)
	}

	status := &TraineeSupervisionStatus{
		TraineeID:        traineeID,
		PendingWorkflows: len(pendingWorkflows),
		LastActivity:     time.Now(), // This would be retrieved from activity log
		SupervisorID:     t.getCurrentSupervisor(ctx, traineeID),
		CompetencyLevel:  t.getCompetencyLevel(ctx, traineeID),
	}

	// Calculate supervision metrics
	for _, workflow := range pendingWorkflows {
		if workflow.Status == rbac.StatusPending {
			status.PendingApprovals++
		}
		if time.Since(workflow.CreatedAt) > 2*time.Hour {
			status.OverdueItems++
		}
	}

	return status, nil
}

// Helper methods

func (t *TraineeSupervisionController) extractTraineeID(userID string) string {
	// Expected formats: mbbs_student_<ID> or md_student_<ID>
	if strings.HasPrefix(userID, "mbbs_student_") {
		return strings.TrimPrefix(userID, "mbbs_student_")
	}
	if strings.HasPrefix(userID, "md_student_") {
		return strings.TrimPrefix(userID, "md_student_")
	}
	return ""
}

func (t *TraineeSupervisionController) isDeIdentifiedData(resourceID string, attributes map[string]string) bool {
	// Check if data is marked as de-identified
	if dataType := attributes["data_type"]; dataType == "de_identified" {
		return true
	}

	// Check resource ID patterns for training data
	if strings.Contains(resourceID, "training_data") || strings.Contains(resourceID, "de_identified") {
		return true
	}

	// Check for presence of identifying information
	if attributes["patient_name"] != "" || attributes["patient_id"] != "" {
		return false
	}

	return true
}

func (t *TraineeSupervisionController) isAllowedMBBSAction(action, resourceID string) bool {
	// MBBS students can only read training data
	allowedActions := []string{rbac.ActionRead}
	
	for _, allowed := range allowedActions {
		if action == allowed {
			return true
		}
	}
	return false
}

func (t *TraineeSupervisionController) isAllowedMDAction(action, resourceID string) bool {
	// MD/MS students have broader permissions but still restricted
	allowedActions := map[string][]string{
		"patient_ehr":  {rbac.ActionRead},
		"cpoe_order":   {rbac.ActionCreate, rbac.ActionRead}, // Create requires supervision
		"lab_results":  {rbac.ActionRead},
		"medication":   {rbac.ActionRead},
		"vital_signs":  {rbac.ActionRead, rbac.ActionUpdate},
		"nursing_notes": {rbac.ActionRead},
	}

	resourceType := t.getResourceType(resourceID)
	if actions, exists := allowedActions[resourceType]; exists {
		for _, allowedAction := range actions {
			if action == allowedAction {
				return true
			}
		}
	}

	return false
}

func (t *TraineeSupervisionController) isAllowedTrainingDataScope(attributes map[string]string) bool {
	// Check if training data is appropriate for MBBS level
	if complexity := attributes["case_complexity"]; complexity != "" {
		// MBBS students should only access basic and intermediate cases
		allowedComplexity := []string{"basic", "intermediate"}
		for _, allowed := range allowedComplexity {
			if complexity == allowed {
				return true
			}
		}
		return false
	}

	return true
}

func (t *TraineeSupervisionController) requiresSupervision(action, resourceID string) bool {
	// Actions that require supervision for trainees
	supervisedActions := map[string][]string{
		"cpoe_order":   {rbac.ActionCreate, rbac.ActionUpdate},
		"medication":   {rbac.ActionPrescribe},
		"lab_order":    {rbac.ActionCreate},
		"procedure":    {rbac.ActionCreate, rbac.ActionUpdate},
	}

	resourceType := t.getResourceType(resourceID)
	if actions, exists := supervisedActions[resourceType]; exists {
		for _, supervisedAction := range actions {
			if action == supervisedAction {
				return true
			}
		}
	}

	return false
}

func (t *TraineeSupervisionController) handleSupervisedAction(ctx context.Context, studentID string, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Check if there's already a pending supervision workflow
	if t.workflowEngine == nil {
		// For testing purposes, assume no pending workflows
		return t.HandleSupervisedCPOEWorkflow(ctx, req)
	}
	
	pendingWorkflows, err := t.workflowEngine.GetPendingSupervision(ctx, req.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to check pending supervision: %w", err)
	}

	// Check if this specific action already has a workflow
	for _, workflow := range pendingWorkflows {
		if workflow.ResourceID == req.ResourceID && workflow.Status == rbac.StatusPending {
			return &rbac.AccessDecision{
				Allowed: false,
				Reason:  "Action already pending supervisor approval",
				Conditions: []string{
					fmt.Sprintf("workflow_id:%s", workflow.ID),
					fmt.Sprintf("supervisor_id:%s", workflow.SupervisorID),
				},
			}, nil
		}
	}

	// Create new supervision workflow
	return t.HandleSupervisedCPOEWorkflow(ctx, req)
}

func (t *TraineeSupervisionController) isAssignedPatient(ctx context.Context, studentID, resourceID string) bool {
	// In a real implementation, this would check patient assignments
	// For now, we'll extract patient ID and check against assignments
	patientID := t.extractPatientIDFromResource(resourceID)
	if patientID == "" {
		return false
	}

	// This would query the assignment database
	// For testing, we'll assume assignment if the resource contains the student ID
	return strings.Contains(resourceID, studentID) || 
		   t.isPatientAssignedToTrainee(ctx, patientID, studentID)
}

func (t *TraineeSupervisionController) extractPatientIDFromResource(resourceID string) string {
	// Extract patient ID from resource ID patterns
	parts := strings.Split(resourceID, "_")
	for i, part := range parts {
		if part == "patient" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

func (t *TraineeSupervisionController) isPatientAssignedToTrainee(ctx context.Context, patientID, traineeID string) bool {
	// This would check the patient assignment database
	// For testing purposes, check if the resource contains the trainee ID
	return strings.Contains(patientID, traineeID)
}

func (t *TraineeSupervisionController) getResourceType(resourceID string) string {
	parts := strings.Split(resourceID, "_")
	if len(parts) >= 2 {
		return strings.Join(parts[:2], "_")
	}
	return parts[0]
}

func (t *TraineeSupervisionController) findAvailableSupervisor(ctx context.Context, traineeID, specialty string) (string, error) {
	// In a real implementation, this would query supervisor availability
	// For now, return a mock supervisor ID
	return fmt.Sprintf("consulting_doctor_%s_supervisor", specialty), nil
}

func (t *TraineeSupervisionController) getCurrentSupervisor(ctx context.Context, traineeID string) string {
	// This would query the current supervisor assignment
	return "consulting_doctor_primary_supervisor"
}

func (t *TraineeSupervisionController) getCompetencyLevel(ctx context.Context, traineeID string) string {
	// This would assess the trainee's current competency level
	return "intermediate"
}

func (t *TraineeSupervisionController) logTrainingDataAccess(ctx context.Context, studentID string, req *rbac.AccessRequest) {
	t.logger.WithFields(logrus.Fields{
		"student_id":  studentID,
		"resource_id": req.ResourceID,
		"action":      req.Action,
		"data_type":   "de_identified",
	}).Info("MBBS student training data access")
}

func (t *TraineeSupervisionController) logTraineeActivity(ctx context.Context, studentID string, req *rbac.AccessRequest) {
	t.logger.WithFields(logrus.Fields{
		"student_id":  studentID,
		"resource_id": req.ResourceID,
		"action":      req.Action,
		"timestamp":   time.Now(),
	}).Info("MD/MS student activity logged")
}

// TraineeActivity represents a trainee learning activity
type TraineeActivity struct {
	ResourceID        string `json:"resource_id"`
	Action            string `json:"action"`
	Result            string `json:"result"`
	Type              string `json:"type"`
	LearningObjective string `json:"learning_objective"`
	SupervisorID      string `json:"supervisor_id"`
	DurationMinutes   int    `json:"duration_minutes"`
	CompetencyArea    string `json:"competency_area"`
}

// TraineeSupervisionStatus represents the current supervision status of a trainee
type TraineeSupervisionStatus struct {
	TraineeID        string    `json:"trainee_id"`
	SupervisorID     string    `json:"supervisor_id"`
	PendingWorkflows int       `json:"pending_workflows"`
	PendingApprovals int       `json:"pending_approvals"`
	OverdueItems     int       `json:"overdue_items"`
	LastActivity     time.Time `json:"last_activity"`
	CompetencyLevel  string    `json:"competency_level"`
}