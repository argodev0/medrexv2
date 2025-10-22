package rbac

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// WorkflowStorage defines the interface for supervision workflow storage
type WorkflowStorage interface {
	StoreWorkflow(ctx context.Context, workflow *rbac.SupervisionWorkflow) error
	GetWorkflow(ctx context.Context, workflowID string) (*rbac.SupervisionWorkflow, error)
	UpdateWorkflow(ctx context.Context, workflow *rbac.SupervisionWorkflow) error
	DeleteWorkflow(ctx context.Context, workflowID string) error
	ListWorkflowsByStatus(ctx context.Context, status rbac.SupervisionStatus) ([]*rbac.SupervisionWorkflow, error)
	ListWorkflowsBySupervisor(ctx context.Context, supervisorID string) ([]*rbac.SupervisionWorkflow, error)
	ListWorkflowsByTrainee(ctx context.Context, traineeID string) ([]*rbac.SupervisionWorkflow, error)
	ListExpiredWorkflows(ctx context.Context) ([]*rbac.SupervisionWorkflow, error)
}

// InMemoryWorkflowStorage provides in-memory storage for supervision workflows
type InMemoryWorkflowStorage struct {
	mu        sync.RWMutex
	workflows map[string]*rbac.SupervisionWorkflow
}

// NewInMemoryWorkflowStorage creates a new in-memory workflow storage
func NewInMemoryWorkflowStorage() *InMemoryWorkflowStorage {
	return &InMemoryWorkflowStorage{
		workflows: make(map[string]*rbac.SupervisionWorkflow),
	}
}

// StoreWorkflow stores a supervision workflow
func (s *InMemoryWorkflowStorage) StoreWorkflow(ctx context.Context, workflow *rbac.SupervisionWorkflow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.workflows[workflow.ID] = workflow
	return nil
}

// GetWorkflow retrieves a supervision workflow by ID
func (s *InMemoryWorkflowStorage) GetWorkflow(ctx context.Context, workflowID string) (*rbac.SupervisionWorkflow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	workflow, exists := s.workflows[workflowID]
	if !exists {
		return nil, fmt.Errorf("workflow %s not found", workflowID)
	}

	return workflow, nil
}

// UpdateWorkflow updates a supervision workflow
func (s *InMemoryWorkflowStorage) UpdateWorkflow(ctx context.Context, workflow *rbac.SupervisionWorkflow) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.workflows[workflow.ID]; !exists {
		return fmt.Errorf("workflow %s not found", workflow.ID)
	}

	s.workflows[workflow.ID] = workflow
	return nil
}

// DeleteWorkflow deletes a supervision workflow
func (s *InMemoryWorkflowStorage) DeleteWorkflow(ctx context.Context, workflowID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.workflows, workflowID)
	return nil
}

// ListWorkflowsByStatus lists workflows by status
func (s *InMemoryWorkflowStorage) ListWorkflowsByStatus(ctx context.Context, status rbac.SupervisionStatus) ([]*rbac.SupervisionWorkflow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var workflows []*rbac.SupervisionWorkflow
	for _, workflow := range s.workflows {
		if workflow.Status == status {
			workflows = append(workflows, workflow)
		}
	}

	return workflows, nil
}

// ListWorkflowsBySupervisor lists workflows by supervisor ID
func (s *InMemoryWorkflowStorage) ListWorkflowsBySupervisor(ctx context.Context, supervisorID string) ([]*rbac.SupervisionWorkflow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var workflows []*rbac.SupervisionWorkflow
	for _, workflow := range s.workflows {
		if workflow.SupervisorID == supervisorID {
			workflows = append(workflows, workflow)
		}
	}

	return workflows, nil
}

// ListWorkflowsByTrainee lists workflows by trainee ID
func (s *InMemoryWorkflowStorage) ListWorkflowsByTrainee(ctx context.Context, traineeID string) ([]*rbac.SupervisionWorkflow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var workflows []*rbac.SupervisionWorkflow
	for _, workflow := range s.workflows {
		if workflow.TraineeID == traineeID {
			workflows = append(workflows, workflow)
		}
	}

	return workflows, nil
}

// ListExpiredWorkflows lists workflows that have expired
func (s *InMemoryWorkflowStorage) ListExpiredWorkflows(ctx context.Context) ([]*rbac.SupervisionWorkflow, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	var workflows []*rbac.SupervisionWorkflow
	for _, workflow := range s.workflows {
		if workflow.ExpiresAt.Before(now) && workflow.Status != rbac.StatusCompleted && workflow.Status != rbac.StatusExpired {
			workflows = append(workflows, workflow)
		}
	}

	return workflows, nil
}

// SupervisionWorkflowEngine implements trainee supervision workflow automation
type SupervisionWorkflowEngine struct {
	config           *Config
	logger           *logrus.Logger
	storage          WorkflowStorage
	sbeManager       *SBEPolicyManager
	mu               sync.RWMutex
	escalationTicker *time.Ticker
	stopChan         chan struct{}
}

// NewSupervisionWorkflowEngine creates a new supervision workflow engine
func NewSupervisionWorkflowEngine(config *Config, logger *logrus.Logger, sbeManager *SBEPolicyManager) (*SupervisionWorkflowEngine, error) {
	storage := NewInMemoryWorkflowStorage()
	
	engine := &SupervisionWorkflowEngine{
		config:     config,
		logger:     logger,
		storage:    storage,
		sbeManager: sbeManager,
		stopChan:   make(chan struct{}),
	}

	// Start background escalation processor
	engine.startEscalationProcessor()

	return engine, nil
}

// NewSupervisionWorkflowEngineWithStorage creates a new supervision workflow engine with custom storage
func NewSupervisionWorkflowEngineWithStorage(config *Config, logger *logrus.Logger, storage WorkflowStorage, sbeManager *SBEPolicyManager) (*SupervisionWorkflowEngine, error) {
	engine := &SupervisionWorkflowEngine{
		config:     config,
		logger:     logger,
		storage:    storage,
		sbeManager: sbeManager,
		stopChan:   make(chan struct{}),
	}

	// Start background escalation processor
	engine.startEscalationProcessor()

	return engine, nil
}

// CreateSupervisionWorkflow creates a new supervision workflow
func (e *SupervisionWorkflowEngine) CreateSupervisionWorkflow(ctx context.Context, workflow *rbac.SupervisionWorkflow) error {
	if err := e.validateSupervisionWorkflow(workflow); err != nil {
		return fmt.Errorf("invalid supervision workflow: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Set initial status and timestamps
	workflow.Status = rbac.StatusPending
	workflow.CreatedAt = time.Now()
	
	// Set expiration time based on workflow type
	workflow.ExpiresAt = e.calculateExpirationTime(workflow)

	// Store the workflow
	if err := e.storage.StoreWorkflow(ctx, workflow); err != nil {
		return fmt.Errorf("failed to store workflow: %w", err)
	}

	e.logger.WithFields(logrus.Fields{
		"workflow_id":   workflow.ID,
		"trainee_id":    workflow.TraineeID,
		"supervisor_id": workflow.SupervisorID,
		"resource_id":   workflow.ResourceID,
		"workflow_type": workflow.WorkflowType,
		"expires_at":    workflow.ExpiresAt,
	}).Info("Created supervision workflow")

	return nil
}

// UpdateWorkflowStatus updates the status of a supervision workflow
func (e *SupervisionWorkflowEngine) UpdateWorkflowStatus(ctx context.Context, workflowID string, status rbac.SupervisionStatus) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	workflow, err := e.storage.GetWorkflow(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}

	oldStatus := workflow.Status
	workflow.Status = status

	if err := e.storage.UpdateWorkflow(ctx, workflow); err != nil {
		return fmt.Errorf("failed to update workflow: %w", err)
	}

	e.logger.WithFields(logrus.Fields{
		"workflow_id": workflowID,
		"old_status":  oldStatus,
		"new_status":  status,
	}).Info("Updated workflow status")

	return nil
}

// AssignSupervisor assigns a supervisor to a workflow
func (e *SupervisionWorkflowEngine) AssignSupervisor(ctx context.Context, workflowID, supervisorID string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	workflow, err := e.storage.GetWorkflow(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}

	// Validate supervisor eligibility
	if err := e.validateSupervisorEligibility(ctx, supervisorID, workflow); err != nil {
		return fmt.Errorf("supervisor validation failed: %w", err)
	}

	workflow.SupervisorID = supervisorID
	workflow.Status = rbac.StatusInProgress

	if err := e.storage.UpdateWorkflow(ctx, workflow); err != nil {
		return fmt.Errorf("failed to update workflow: %w", err)
	}

	e.logger.WithFields(logrus.Fields{
		"workflow_id":   workflowID,
		"supervisor_id": supervisorID,
		"trainee_id":    workflow.TraineeID,
	}).Info("Assigned supervisor to workflow")

	return nil
}

// CompleteSupervisionAction completes a supervision action
func (e *SupervisionWorkflowEngine) CompleteSupervisionAction(ctx context.Context, workflowID string, action *rbac.CompletedAction) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	workflow, err := e.storage.GetWorkflow(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}

	// Validate the action
	if err := e.validateSupervisionAction(action, workflow); err != nil {
		return fmt.Errorf("invalid supervision action: %w", err)
	}

	// Add the completed action
	action.CompletedAt = time.Now()
	workflow.CompletedActions = append(workflow.CompletedActions, *action)

	// Check if all required actions are completed
	if e.areAllRequiredActionsCompleted(workflow) {
		workflow.Status = rbac.StatusCompleted
	}

	if err := e.storage.UpdateWorkflow(ctx, workflow); err != nil {
		return fmt.Errorf("failed to update workflow: %w", err)
	}

	e.logger.WithFields(logrus.Fields{
		"workflow_id":    workflowID,
		"action_type":    action.Action.Type,
		"completed_by":   action.CompletedBy,
		"workflow_status": workflow.Status,
	}).Info("Completed supervision action")

	return nil
}

// GetPendingSupervision returns pending supervision workflows for a supervisor
func (e *SupervisionWorkflowEngine) GetPendingSupervision(ctx context.Context, supervisorID string) ([]*rbac.SupervisionWorkflow, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	workflows, err := e.storage.ListWorkflowsBySupervisor(ctx, supervisorID)
	if err != nil {
		return nil, fmt.Errorf("failed to list workflows: %w", err)
	}

	var pending []*rbac.SupervisionWorkflow
	for _, workflow := range workflows {
		if workflow.Status == rbac.StatusPending || workflow.Status == rbac.StatusInProgress {
			pending = append(pending, workflow)
		}
	}

	return pending, nil
}

// HandleEmergencyOverride handles emergency override for supervision workflows
func (e *SupervisionWorkflowEngine) HandleEmergencyOverride(ctx context.Context, workflowID string, req *rbac.EmergencyOverrideRequest) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	workflow, err := e.storage.GetWorkflow(ctx, workflowID)
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}

	// Validate emergency override request
	if err := e.validateEmergencyOverride(req, workflow); err != nil {
		return fmt.Errorf("invalid emergency override: %w", err)
	}

	// Update workflow status
	workflow.Status = rbac.StatusOverridden
	
	// Add override metadata
	if workflow.Metadata == nil {
		workflow.Metadata = make(map[string]interface{})
	}
	workflow.Metadata["emergency_override"] = map[string]interface{}{
		"user_id":       req.UserID,
		"reason":        req.Reason,
		"justification": req.Justification,
		"timestamp":     req.Timestamp,
	}

	if err := e.storage.UpdateWorkflow(ctx, workflow); err != nil {
		return fmt.Errorf("failed to update workflow: %w", err)
	}

	// Delegate to SBE manager for additional override handling
	if err := e.sbeManager.HandleEmergencyOverride(ctx, req); err != nil {
		e.logger.WithError(err).Warn("SBE manager emergency override handling failed")
	}

	e.logger.WithFields(logrus.Fields{
		"workflow_id":    workflowID,
		"user_id":        req.UserID,
		"reason":         req.Reason,
		"justification":  req.Justification,
	}).Warn("Emergency override applied to supervision workflow")

	return nil
}

// Stop stops the supervision workflow engine
func (e *SupervisionWorkflowEngine) Stop() {
	close(e.stopChan)
	if e.escalationTicker != nil {
		e.escalationTicker.Stop()
	}
}

// Helper methods

func (e *SupervisionWorkflowEngine) validateSupervisionWorkflow(workflow *rbac.SupervisionWorkflow) error {
	var validationErrors rbac.ValidationErrors

	if workflow.ID == "" {
		validationErrors.Add("id", workflow.ID, "Workflow ID is required")
	}

	if workflow.TraineeID == "" {
		validationErrors.Add("trainee_id", workflow.TraineeID, "Trainee ID is required")
	}

	if workflow.ResourceID == "" {
		validationErrors.Add("resource_id", workflow.ResourceID, "Resource ID is required")
	}

	if workflow.WorkflowType == "" {
		validationErrors.Add("workflow_type", workflow.WorkflowType, "Workflow type is required")
	}

	if len(workflow.RequiredActions) == 0 {
		validationErrors.Add("required_actions", "empty", "At least one required action is needed")
	}

	if validationErrors.HasErrors() {
		return &validationErrors
	}

	return nil
}

func (e *SupervisionWorkflowEngine) calculateExpirationTime(workflow *rbac.SupervisionWorkflow) time.Time {
	// Default expiration times based on workflow type
	var duration time.Duration
	
	switch workflow.WorkflowType {
	case "cpoe_order":
		duration = 4 * time.Hour // CPOE orders expire in 4 hours
	case "clinical_note":
		duration = 24 * time.Hour // Clinical notes expire in 24 hours
	case "medication_administration":
		duration = 2 * time.Hour // Medication admin expires in 2 hours
	default:
		duration = 8 * time.Hour // Default 8 hours
	}

	return time.Now().Add(duration)
}

func (e *SupervisionWorkflowEngine) validateSupervisorEligibility(ctx context.Context, supervisorID string, workflow *rbac.SupervisionWorkflow) error {
	// In a real implementation, this would:
	// 1. Check supervisor's role and attributes
	// 2. Validate supervisor has appropriate specialty/department
	// 3. Check supervisor's current workload
	// 4. Verify supervisor is not the same as trainee
	
	if supervisorID == workflow.TraineeID {
		return fmt.Errorf("supervisor cannot be the same as trainee")
	}

	return nil
}

func (e *SupervisionWorkflowEngine) validateSupervisionAction(action *rbac.CompletedAction, workflow *rbac.SupervisionWorkflow) error {
	// Check if the action is in the required actions list
	found := false
	for _, requiredAction := range workflow.RequiredActions {
		if requiredAction.Type == action.Action.Type {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("action type %s is not required for this workflow", action.Action.Type)
	}

	// Check if the action was completed by an authorized user
	if action.CompletedBy != workflow.SupervisorID {
		return fmt.Errorf("action must be completed by assigned supervisor")
	}

	return nil
}

func (e *SupervisionWorkflowEngine) areAllRequiredActionsCompleted(workflow *rbac.SupervisionWorkflow) bool {
	completedTypes := make(map[string]bool)
	for _, completed := range workflow.CompletedActions {
		completedTypes[completed.Action.Type] = true
	}

	for _, required := range workflow.RequiredActions {
		if required.Required && !completedTypes[required.Type] {
			return false
		}
	}

	return true
}

func (e *SupervisionWorkflowEngine) validateEmergencyOverride(req *rbac.EmergencyOverrideRequest, workflow *rbac.SupervisionWorkflow) error {
	if req.UserID == "" {
		return fmt.Errorf("user ID is required for emergency override")
	}

	if req.Reason == "" {
		return fmt.Errorf("reason is required for emergency override")
	}

	if req.Justification == "" {
		return fmt.Errorf("justification is required for emergency override")
	}

	// Check if workflow allows emergency override
	if workflow.Status == rbac.StatusCompleted {
		return fmt.Errorf("cannot override completed workflow")
	}

	return nil
}

func (e *SupervisionWorkflowEngine) startEscalationProcessor() {
	// Process escalations every 5 minutes
	e.escalationTicker = time.NewTicker(5 * time.Minute)
	
	go func() {
		for {
			select {
			case <-e.escalationTicker.C:
				e.processEscalations()
			case <-e.stopChan:
				return
			}
		}
	}()
}

func (e *SupervisionWorkflowEngine) processEscalations() {
	ctx := context.Background()
	
	// Get expired workflows
	expiredWorkflows, err := e.storage.ListExpiredWorkflows(ctx)
	if err != nil {
		e.logger.WithError(err).Error("Failed to list expired workflows")
		return
	}

	for _, workflow := range expiredWorkflows {
		e.handleWorkflowEscalation(ctx, workflow)
	}
}

func (e *SupervisionWorkflowEngine) handleWorkflowEscalation(ctx context.Context, workflow *rbac.SupervisionWorkflow) {
	// Update workflow status to expired
	workflow.Status = rbac.StatusExpired
	
	if err := e.storage.UpdateWorkflow(ctx, workflow); err != nil {
		e.logger.WithError(err).WithField("workflow_id", workflow.ID).Error("Failed to update expired workflow")
		return
	}

	e.logger.WithFields(logrus.Fields{
		"workflow_id":   workflow.ID,
		"trainee_id":    workflow.TraineeID,
		"supervisor_id": workflow.SupervisorID,
		"expired_at":    workflow.ExpiresAt,
	}).Warn("Supervision workflow expired - escalation required")

	// In a real implementation, this would:
	// 1. Notify department heads or senior supervisors
	// 2. Create escalation tickets
	// 3. Send alerts to compliance officers
	// 4. Update audit logs with escalation events
}