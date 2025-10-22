package rbac

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// RBACCoreEngine implements the core RBAC functionality
type RBACCoreEngine struct {
	config             *Config
	logger             *logrus.Logger
	roleHierarchy      *rbac.RoleHierarchy
	permissionMatrix   *rbac.PermissionMatrix
	policyCache        map[string]*rbac.AccessPolicy
	decisionCache      map[string]*CachedDecision
	rolePermCache      map[string][]rbac.Permission
	cacheMutex         sync.RWMutex
	lastUpdate         time.Time
	cacheStats         *CacheStatistics
	accessMonitor      *AccessMonitor
	performanceMonitor *PerformanceMonitor
}

// CachedDecision represents a cached access decision with TTL
type CachedDecision struct {
	Decision  *rbac.AccessDecision `json:"decision"`
	ExpiresAt time.Time            `json:"expires_at"`
	HitCount  int64                `json:"hit_count"`
}

// CacheStatistics tracks cache performance metrics
type CacheStatistics struct {
	PolicyCacheHits     int64 `json:"policy_cache_hits"`
	PolicyCacheMisses   int64 `json:"policy_cache_misses"`
	DecisionCacheHits   int64 `json:"decision_cache_hits"`
	DecisionCacheMisses int64 `json:"decision_cache_misses"`
	RolePermCacheHits   int64 `json:"role_perm_cache_hits"`
	RolePermCacheMisses int64 `json:"role_perm_cache_misses"`
	CacheEvictions      int64 `json:"cache_evictions"`
	LastReset           time.Time `json:"last_reset"`
}

// NewRBACCoreEngine creates a new RBAC core engine
func NewRBACCoreEngine(config *Config, logger *logrus.Logger) (*RBACCoreEngine, error) {
	engine := &RBACCoreEngine{
		config:        config,
		logger:        logger,
		policyCache:   make(map[string]*rbac.AccessPolicy),
		decisionCache: make(map[string]*CachedDecision),
		rolePermCache: make(map[string][]rbac.Permission),
		cacheStats: &CacheStatistics{
			LastReset: time.Now(),
		},
	}

	// Initialize role hierarchy
	if err := engine.initializeRoleHierarchy(); err != nil {
		return nil, fmt.Errorf("failed to initialize role hierarchy: %w", err)
	}

	// Initialize permission matrix
	if err := engine.initializePermissionMatrix(); err != nil {
		return nil, fmt.Errorf("failed to initialize permission matrix: %w", err)
	}

	// Initialize access monitor
	accessMonitor, err := NewAccessMonitor(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize access monitor: %w", err)
	}
	engine.accessMonitor = accessMonitor

	// Initialize performance monitor
	performanceMonitor, err := NewPerformanceMonitor(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize performance monitor: %w", err)
	}
	engine.performanceMonitor = performanceMonitor

	// Cache cleanup will be handled by TTL expiration

	return engine, nil
}

// ValidateAccess validates access based on RBAC rules with hierarchy inheritance
func (e *RBACCoreEngine) ValidateAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	start := time.Now()
	cacheHit := false
	
	// Check decision cache first
	cacheKey := e.generateDecisionCacheKey(req)
	if cachedDecision := e.getCachedDecision(cacheKey); cachedDecision != nil {
		cacheHit = true
		responseTime := time.Since(start)
		
		// Record cache performance
		if e.performanceMonitor != nil {
			e.performanceMonitor.RecordCachePerformance("decision", true, responseTime)
			if logErr := e.performanceMonitor.RecordDecisionLatency(ctx, req, cachedDecision, responseTime, cacheHit); logErr != nil {
				e.logger.WithError(logErr).Warn("Failed to record decision latency")
			}
		}
		
		// Log access attempt for monitoring
		if e.accessMonitor != nil {
			if logErr := e.accessMonitor.LogAccessAttempt(ctx, req, cachedDecision, responseTime); logErr != nil {
				e.logger.WithError(logErr).Warn("Failed to log access attempt")
			}
		}
		
		return cachedDecision, nil
	}
	
	// Record cache miss
	if e.performanceMonitor != nil {
		e.performanceMonitor.RecordCachePerformance("decision", false, time.Since(start))
	}
	
	// Get user roles
	userRoles, err := e.GetUserRoles(req.UserID)
	if err != nil {
		decision := &rbac.AccessDecision{
			Allowed: false,
			Reason:  "Failed to retrieve user roles",
		}
		
		responseTime := time.Since(start)
		
		// Record performance metrics
		if e.performanceMonitor != nil {
			if logErr := e.performanceMonitor.RecordDecisionLatency(ctx, req, decision, responseTime, cacheHit); logErr != nil {
				e.logger.WithError(logErr).Warn("Failed to record decision latency")
			}
		}
		
		// Log access attempt for monitoring
		if e.accessMonitor != nil {
			if logErr := e.accessMonitor.LogAccessAttempt(ctx, req, decision, responseTime); logErr != nil {
				e.logger.WithError(logErr).Warn("Failed to log access attempt")
			}
		}
		
		return nil, rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeInvalidRole,
			rbac.ErrorCodeInvalidRole,
			"Failed to retrieve user roles",
			err,
		).WithContext(req.UserID, req.ResourceID, req.Action)
	}

	if len(userRoles) == 0 {
		decision := &rbac.AccessDecision{
			Allowed: false,
			Reason:  "No roles assigned to user",
		}
		
		responseTime := time.Since(start)
		
		// Record performance metrics
		if e.performanceMonitor != nil {
			if logErr := e.performanceMonitor.RecordDecisionLatency(ctx, req, decision, responseTime, cacheHit); logErr != nil {
				e.logger.WithError(logErr).Warn("Failed to record decision latency")
			}
		}
		
		// Log access attempt for monitoring
		if e.accessMonitor != nil {
			if logErr := e.accessMonitor.LogAccessAttempt(ctx, req, decision, responseTime); logErr != nil {
				e.logger.WithError(logErr).Warn("Failed to log access attempt")
			}
		}
		
		return decision, nil
	}

	// Check each role for permission, including inherited permissions
	for _, role := range userRoles {
		decision, err := e.checkRolePermissionWithInheritance(ctx, role, req)
		if err != nil {
			e.logger.WithError(err).Warn("Error checking role permission")
			continue
		}

		if decision.Allowed {
			responseTime := time.Since(start)
			
			// Cache the positive decision
			e.cacheDecision(cacheKey, decision)
			
			// Record performance metrics
			if e.performanceMonitor != nil {
				if logErr := e.performanceMonitor.RecordDecisionLatency(ctx, req, decision, responseTime, cacheHit); logErr != nil {
					e.logger.WithError(logErr).Warn("Failed to record decision latency")
				}
			}
			
			// Log successful access attempt for monitoring
			if e.accessMonitor != nil {
				if logErr := e.accessMonitor.LogAccessAttempt(ctx, req, decision, responseTime); logErr != nil {
					e.logger.WithError(logErr).Warn("Failed to log access attempt")
				}
			}
			return decision, nil
		}
	}

	// No role granted access
	decision := &rbac.AccessDecision{
		Allowed: false,
		Reason:  "Insufficient privileges for requested action",
	}
	
	responseTime := time.Since(start)
	
	// Cache the negative decision (with shorter TTL)
	e.cacheDecision(cacheKey, decision)
	
	// Record performance metrics
	if e.performanceMonitor != nil {
		if logErr := e.performanceMonitor.RecordDecisionLatency(ctx, req, decision, responseTime, cacheHit); logErr != nil {
			e.logger.WithError(logErr).Warn("Failed to record decision latency")
		}
	}
	
	// Log denied access attempt for monitoring
	if e.accessMonitor != nil {
		if logErr := e.accessMonitor.LogAccessAttempt(ctx, req, decision, responseTime); logErr != nil {
			e.logger.WithError(logErr).Warn("Failed to log access attempt")
		}
	}
	
	return decision, nil
}

// GetUserRoles retrieves roles for a user
func (e *RBACCoreEngine) GetUserRoles(userID string) ([]rbac.Role, error) {
	// In a real implementation, this would query a user store or certificate
	// For now, we'll extract role from userID pattern (for testing)
	// Format: role_userid (e.g., "consulting_doctor_123")
	
	// This is a placeholder implementation - in reality, roles would be
	// extracted from X.509 certificates or user database
	roleID := e.extractRoleFromUserID(userID)
	
	if roleNode, exists := e.roleHierarchy.Roles[roleID]; exists {
		return []rbac.Role{roleNode.Role}, nil
	}

	return nil, rbac.NewRBACError(
		rbac.ErrorTypeInvalidRole,
		rbac.ErrorCodeInvalidRole,
		fmt.Sprintf("Role not found for user: %s", userID),
	)
}

// GetRolePermissions retrieves permissions for a role
func (e *RBACCoreEngine) GetRolePermissions(role rbac.Role) ([]rbac.Permission, error) {
	if e.permissionMatrix == nil || e.permissionMatrix.Roles == nil {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeSystemError,
			"RBAC_PERM_001",
			"Permission matrix not initialized",
		)
	}

	rolePerms, exists := e.permissionMatrix.Roles[role.ID]
	if !exists {
		return []rbac.Permission{}, nil
	}

	permissions := make([]rbac.Permission, 0, len(rolePerms.Permissions))
	for _, perm := range rolePerms.Permissions {
		permissions = append(permissions, *perm)
	}

	return permissions, nil
}

// UpdateRoleHierarchy updates the role hierarchy
func (e *RBACCoreEngine) UpdateRoleHierarchy(hierarchy *rbac.RoleHierarchy) error {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	e.roleHierarchy = hierarchy
	e.lastUpdate = time.Now()
	
	// Clear policy cache when hierarchy changes
	e.policyCache = make(map[string]*rbac.AccessPolicy)

	e.logger.Info("Role hierarchy updated successfully")
	return nil
}

// CachePolicy caches an access policy
func (e *RBACCoreEngine) CachePolicy(policyID string, policy *rbac.AccessPolicy) error {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	e.policyCache[policyID] = policy
	return nil
}

// GetRoleHierarchy returns the complete role hierarchy
func (e *RBACCoreEngine) GetRoleHierarchy() *rbac.RoleHierarchy {
	return e.roleHierarchy
}

// GetRoleByID retrieves a role by its ID
func (e *RBACCoreEngine) GetRoleByID(roleID string) (*rbac.Role, error) {
	if e.roleHierarchy == nil || e.roleHierarchy.Roles == nil {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeSystemError,
			"RBAC_HIER_001",
			"Role hierarchy not initialized",
		)
	}

	roleNode, exists := e.roleHierarchy.Roles[roleID]
	if !exists {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeInvalidRole,
			rbac.ErrorCodeInvalidRole,
			fmt.Sprintf("Role not found: %s", roleID),
		)
	}

	return &roleNode.Role, nil
}

// GetRolesByLevel retrieves all roles at a specific hierarchy level
func (e *RBACCoreEngine) GetRolesByLevel(level int) ([]rbac.Role, error) {
	if e.roleHierarchy == nil || e.roleHierarchy.Roles == nil {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeSystemError,
			"RBAC_HIER_002",
			"Role hierarchy not initialized",
		)
	}

	var roles []rbac.Role
	for _, roleNode := range e.roleHierarchy.Roles {
		if roleNode.Level == level {
			roles = append(roles, roleNode.Role)
		}
	}

	return roles, nil
}

// GetParentRoles retrieves all parent roles for a given role (up the hierarchy)
func (e *RBACCoreEngine) GetParentRoles(roleID string) ([]rbac.Role, error) {
	roleNode, exists := e.roleHierarchy.Roles[roleID]
	if !exists {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeInvalidRole,
			rbac.ErrorCodeInvalidRole,
			fmt.Sprintf("Role not found: %s", roleID),
		)
	}

	var parents []rbac.Role
	current := roleNode.Parent
	for current != nil {
		parents = append(parents, current.Role)
		current = current.Parent
	}

	return parents, nil
}

// GetChildRoles retrieves all child roles for a given role (down the hierarchy)
func (e *RBACCoreEngine) GetChildRoles(roleID string) ([]rbac.Role, error) {
	roleNode, exists := e.roleHierarchy.Roles[roleID]
	if !exists {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeInvalidRole,
			rbac.ErrorCodeInvalidRole,
			fmt.Sprintf("Role not found: %s", roleID),
		)
	}

	var children []rbac.Role
	e.collectChildRoles(roleNode, &children)
	return children, nil
}

// collectChildRoles recursively collects all child roles
func (e *RBACCoreEngine) collectChildRoles(node *rbac.RoleNode, children *[]rbac.Role) {
	for _, child := range node.Children {
		*children = append(*children, child.Role)
		e.collectChildRoles(child, children)
	}
}

// IsRoleInHierarchy checks if a role has permission through hierarchy inheritance
func (e *RBACCoreEngine) IsRoleInHierarchy(userRoleID, requiredRoleID string) (bool, error) {
	userRole, exists := e.roleHierarchy.Roles[userRoleID]
	if !exists {
		return false, rbac.NewRBACError(
			rbac.ErrorTypeInvalidRole,
			rbac.ErrorCodeInvalidRole,
			fmt.Sprintf("User role not found: %s", userRoleID),
		)
	}

	requiredRole, exists := e.roleHierarchy.Roles[requiredRoleID]
	if !exists {
		return false, rbac.NewRBACError(
			rbac.ErrorTypeInvalidRole,
			rbac.ErrorCodeInvalidRole,
			fmt.Sprintf("Required role not found: %s", requiredRoleID),
		)
	}

	// Check if user role level is equal or higher than required role level
	return userRole.Level >= requiredRole.Level, nil
}

// GetEffectivePermissions returns all permissions for a role including inherited permissions
func (e *RBACCoreEngine) GetEffectivePermissions(roleID string) ([]rbac.Permission, error) {
	roleNode, exists := e.roleHierarchy.Roles[roleID]
	if !exists {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeInvalidRole,
			rbac.ErrorCodeInvalidRole,
			fmt.Sprintf("Role not found: %s", roleID),
		)
	}

	permissionMap := make(map[string]*rbac.Permission)
	
	// Start from the current role and traverse up the hierarchy
	current := roleNode
	for current != nil {
		rolePerms, exists := e.permissionMatrix.Roles[current.Role.ID]
		if exists {
			// Add permissions from this role level
			for permID, perm := range rolePerms.Permissions {
				// Only add if not already present (child role permissions take precedence)
				if _, exists := permissionMap[permID]; !exists {
					permissionMap[permID] = perm
				}
			}
		}
		current = current.Parent
	}

	// Convert map to slice
	permissions := make([]rbac.Permission, 0, len(permissionMap))
	for _, perm := range permissionMap {
		permissions = append(permissions, *perm)
	}

	return permissions, nil
}

// ValidateRoleHierarchy validates the integrity of the role hierarchy
func (e *RBACCoreEngine) ValidateRoleHierarchy() error {
	if e.roleHierarchy == nil || e.roleHierarchy.Roles == nil {
		return rbac.NewRBACError(
			rbac.ErrorTypeSystemError,
			"RBAC_HIER_003",
			"Role hierarchy not initialized",
		)
	}

	// Check for cycles in the hierarchy
	visited := make(map[string]bool)
	recursionStack := make(map[string]bool)

	for roleID := range e.roleHierarchy.Roles {
		if !visited[roleID] {
			if e.hasCycle(roleID, visited, recursionStack) {
				return rbac.NewRBACError(
					rbac.ErrorTypeSystemError,
					"RBAC_HIER_004",
					fmt.Sprintf("Cycle detected in role hierarchy starting from role: %s", roleID),
				)
			}
		}
	}

	// Validate NodeOU mappings
	for roleID, roleNode := range e.roleHierarchy.Roles {
		expectedNodeOU, exists := rbac.NodeOUMappings[roleID]
		if !exists {
			return rbac.NewRBACError(
				rbac.ErrorTypeSystemError,
				"RBAC_HIER_005",
				fmt.Sprintf("NodeOU mapping not found for role: %s", roleID),
			)
		}
		
		if roleNode.Role.NodeOU != expectedNodeOU {
			return rbac.NewRBACError(
				rbac.ErrorTypeSystemError,
				"RBAC_HIER_006",
				fmt.Sprintf("NodeOU mismatch for role %s: expected %s, got %s", 
					roleID, expectedNodeOU, roleNode.Role.NodeOU),
			)
		}
	}

	// Validate role levels
	for roleID, roleNode := range e.roleHierarchy.Roles {
		expectedLevel, exists := rbac.RoleLevels[roleID]
		if !exists {
			return rbac.NewRBACError(
				rbac.ErrorTypeSystemError,
				"RBAC_HIER_007",
				fmt.Sprintf("Role level not defined for role: %s", roleID),
			)
		}
		
		if roleNode.Level != expectedLevel {
			return rbac.NewRBACError(
				rbac.ErrorTypeSystemError,
				"RBAC_HIER_008",
				fmt.Sprintf("Role level mismatch for role %s: expected %d, got %d", 
					roleID, expectedLevel, roleNode.Level),
			)
		}
	}

	return nil
}

// hasCycle detects cycles in the role hierarchy using DFS
func (e *RBACCoreEngine) hasCycle(roleID string, visited, recursionStack map[string]bool) bool {
	visited[roleID] = true
	recursionStack[roleID] = true

	roleNode := e.roleHierarchy.Roles[roleID]
	if roleNode.Parent != nil {
		parentID := roleNode.Parent.Role.ID
		if !visited[parentID] {
			if e.hasCycle(parentID, visited, recursionStack) {
				return true
			}
		} else if recursionStack[parentID] {
			return true
		}
	}

	recursionStack[roleID] = false
	return false
}

// GetRoleToNodeOUMapping returns the complete role to NodeOU mapping
func (e *RBACCoreEngine) GetRoleToNodeOUMapping() map[string]string {
	return rbac.NodeOUMappings
}

// GetNodeOUToRoleMapping returns the reverse mapping from NodeOU to role
func (e *RBACCoreEngine) GetNodeOUToRoleMapping() map[string]string {
	nodeOUToRole := make(map[string]string)
	for roleID, nodeOU := range rbac.NodeOUMappings {
		nodeOUToRole[nodeOU] = roleID
	}
	return nodeOUToRole
}

// Helper methods

func (e *RBACCoreEngine) initializeRoleHierarchy() error {
	// Initialize the nine-role hierarchy as defined in the specification
	roles := make(map[string]*rbac.RoleNode)

	// Create role nodes
	for roleID, level := range rbac.RoleLevels {
		nodeOU := rbac.NodeOUMappings[roleID]
		role := rbac.Role{
			ID:     roleID,
			Name:   roleID,
			NodeOU: nodeOU,
			Level:  level,
		}

		roles[roleID] = &rbac.RoleNode{
			Role:  role,
			Level: level,
		}
	}

	// Set up hierarchy relationships
	e.setupRoleRelationships(roles)

	e.roleHierarchy = &rbac.RoleHierarchy{
		Roles: roles,
		Root:  rbac.RoleAdministrator,
	}

	return nil
}

func (e *RBACCoreEngine) setupRoleRelationships(roles map[string]*rbac.RoleNode) {
	// Define parent-child relationships based on the nine-role hierarchy
	// Higher level roles inherit permissions from lower level roles
	relationships := map[string]string{
		rbac.RoleMBBSStudent:      rbac.RoleMDStudent,
		rbac.RoleMDStudent:        rbac.RoleConsultingDoctor,
		rbac.RoleNurse:            rbac.RoleConsultingDoctor,
		rbac.RoleLabTechnician:    rbac.RoleClinicalStaff,
		rbac.RoleReceptionist:     rbac.RoleClinicalStaff,
		rbac.RoleClinicalStaff:    rbac.RoleConsultingDoctor,
		rbac.RoleConsultingDoctor: rbac.RoleAdministrator,
		// Patient role has no parent (isolated for security)
	}

	for childID, parentID := range relationships {
		if child, exists := roles[childID]; exists {
			if parent, exists := roles[parentID]; exists {
				child.Parent = parent
				parent.Children = append(parent.Children, child)
				child.Role.Parent = parentID
				parent.Role.Children = append(parent.Role.Children, childID)
			}
		}
	}
}

func (e *RBACCoreEngine) initializePermissionMatrix() error {
	// Initialize basic permission matrix
	// This would typically be loaded from configuration or database
	e.permissionMatrix = &rbac.PermissionMatrix{
		Roles:       make(map[string]*rbac.RolePermissions),
		Resources:   make(map[string]*rbac.ResourceDef),
		Actions:     make(map[string]*rbac.ActionDef),
		LastUpdated: time.Now(),
	}

	// Define basic permissions for each role
	e.defineRolePermissions()
	e.defineResources()
	e.defineActions()

	return nil
}

func (e *RBACCoreEngine) defineRolePermissions() {
	// Patient permissions - Level 1
	e.permissionMatrix.Roles[rbac.RolePatient] = &rbac.RolePermissions{
		RoleID: rbac.RolePatient,
		Permissions: map[string]*rbac.Permission{
			"own_ehr_read": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionRead},
				Scope:    rbac.ScopeOwn,
			},
			"appointment_manage": {
				Resource: rbac.ResourceAppointment,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionCancel},
				Scope:    rbac.ScopeOwn,
			},
		},
	}

	// MBBS Student permissions - Level 2
	e.permissionMatrix.Roles[rbac.RoleMBBSStudent] = &rbac.RolePermissions{
		RoleID: rbac.RoleMBBSStudent,
		Permissions: map[string]*rbac.Permission{
			"training_data_read": {
				Resource: rbac.ResourceTrainingData,
				Actions:  []string{rbac.ActionRead},
				Scope:    rbac.ScopeAll,
			},
			"basic_ehr_read": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionRead},
				Scope:    rbac.ScopeAssigned,
				Conditions: []string{"de_identified_only"},
			},
		},
	}

	// MD/MS Student permissions - Level 3
	e.permissionMatrix.Roles[rbac.RoleMDStudent] = &rbac.RolePermissions{
		RoleID: rbac.RoleMDStudent,
		Permissions: map[string]*rbac.Permission{
			"cpoe_create_supervised": {
				Resource:   rbac.ResourceCPOEOrder,
				Actions:    []string{rbac.ActionCreate},
				Scope:      rbac.ScopeAssigned,
				Conditions: []string{"requires_supervisor_approval"},
			},
			"patient_ehr_read": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionRead},
				Scope:    rbac.ScopeAssigned,
			},
			"lab_order_supervised": {
				Resource:   rbac.ResourceLabResult,
				Actions:    []string{rbac.ActionCreate},
				Scope:      rbac.ScopeAssigned,
				Conditions: []string{"requires_supervisor_approval"},
			},
		},
	}

	// Receptionist permissions - Level 3
	e.permissionMatrix.Roles[rbac.RoleReceptionist] = &rbac.RolePermissions{
		RoleID: rbac.RoleReceptionist,
		Permissions: map[string]*rbac.Permission{
			"patient_registration": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionCreate},
				Scope:    rbac.ScopeAll,
				Conditions: []string{"demographics_only"},
			},
			"appointment_management": {
				Resource: rbac.ResourceAppointment,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionSchedule, rbac.ActionCancel},
				Scope:    rbac.ScopeAll,
			},
			"financial_basic": {
				Resource: rbac.ResourceFinancialData,
				Actions:  []string{rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeAll,
				Conditions: []string{"billing_only"},
			},
		},
	}

	// Lab Technician permissions - Level 4
	e.permissionMatrix.Roles[rbac.RoleLabTechnician] = &rbac.RolePermissions{
		RoleID: rbac.RoleLabTechnician,
		Permissions: map[string]*rbac.Permission{
			"lab_result_management": {
				Resource: rbac.ResourceLabResult,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeAll,
			},
			"lab_order_read": {
				Resource: rbac.ResourceCPOEOrder,
				Actions:  []string{rbac.ActionRead},
				Scope:    rbac.ScopeAll,
				Conditions: []string{"lab_orders_only"},
			},
			"patient_ehr_limited": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionRead},
				Scope:    rbac.ScopeAll,
				Conditions: []string{"lab_relevant_only"},
			},
		},
	}

	// Nurse permissions - Level 4
	e.permissionMatrix.Roles[rbac.RoleNurse] = &rbac.RolePermissions{
		RoleID: rbac.RoleNurse,
		Permissions: map[string]*rbac.Permission{
			"medication_administration": {
				Resource: rbac.ResourceMedication,
				Actions:  []string{rbac.ActionAdminister, rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeWard,
			},
			"patient_care_notes": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeWard,
				Conditions: []string{"nursing_notes_only"},
			},
			"vital_signs": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeWard,
				Conditions: []string{"vitals_only"},
			},
		},
	}

	// Clinical Staff permissions - Level 5
	e.permissionMatrix.Roles[rbac.RoleClinicalStaff] = &rbac.RolePermissions{
		RoleID: rbac.RoleClinicalStaff,
		Permissions: map[string]*rbac.Permission{
			"specialized_services": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeDept,
				Conditions: []string{"specialty_relevant"},
			},
			"diagnostic_orders": {
				Resource: rbac.ResourceCPOEOrder,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeDept,
				Conditions: []string{"diagnostic_only"},
			},
			"lab_result_review": {
				Resource: rbac.ResourceLabResult,
				Actions:  []string{rbac.ActionRead},
				Scope:    rbac.ScopeDept,
			},
		},
	}

	// Consulting Doctor permissions - Level 6
	e.permissionMatrix.Roles[rbac.RoleConsultingDoctor] = &rbac.RolePermissions{
		RoleID: rbac.RoleConsultingDoctor,
		Permissions: map[string]*rbac.Permission{
			"full_clinical_access": {
				Resource: rbac.ResourcePatientEHR,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeAssigned,
			},
			"cpoe_full": {
				Resource: rbac.ResourceCPOEOrder,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionApprove, rbac.ActionSign},
				Scope:    rbac.ScopeAssigned,
			},
			"supervision_authority": {
				Resource: rbac.ResourceTrainingData,
				Actions:  []string{rbac.ActionApprove, rbac.ActionSign},
				Scope:    rbac.ScopeAll,
				Conditions: []string{"supervisor_role"},
			},
			"medication_prescribe": {
				Resource: rbac.ResourceMedication,
				Actions:  []string{rbac.ActionPrescribe, rbac.ActionRead, rbac.ActionUpdate},
				Scope:    rbac.ScopeAssigned,
			},
		},
	}

	// Administrator permissions - Level 7
	e.permissionMatrix.Roles[rbac.RoleAdministrator] = &rbac.RolePermissions{
		RoleID: rbac.RoleAdministrator,
		Permissions: map[string]*rbac.Permission{
			"system_administration": {
				Resource: rbac.ResourceSystemConfig,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionDelete},
				Scope:    rbac.ScopeAll,
			},
			"audit_access": {
				Resource: rbac.ResourceAuditLog,
				Actions:  []string{rbac.ActionRead},
				Scope:    rbac.ScopeAll,
			},
			"user_management": {
				Resource: rbac.ResourceAdminFunction,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionDelete},
				Scope:    rbac.ScopeAll,
			},
			"policy_management": {
				Resource: rbac.ResourceSystemConfig,
				Actions:  []string{rbac.ActionCreate, rbac.ActionRead, rbac.ActionUpdate, rbac.ActionDelete},
				Scope:    rbac.ScopeAll,
				Conditions: []string{"rbac_policies"},
			},
		},
	}
}

func (e *RBACCoreEngine) defineResources() {
	resources := map[string]*rbac.ResourceDef{
		rbac.ResourcePatientEHR: {
			ID:          rbac.ResourcePatientEHR,
			Name:        "Patient Electronic Health Record",
			Type:        "clinical_data",
			Sensitivity: "confidential",
		},
		rbac.ResourceCPOEOrder: {
			ID:          rbac.ResourceCPOEOrder,
			Name:        "Computerized Provider Order Entry",
			Type:        "clinical_order",
			Sensitivity: "restricted",
		},
		rbac.ResourceTrainingData: {
			ID:          rbac.ResourceTrainingData,
			Name:        "De-identified Training Data",
			Type:        "educational",
			Sensitivity: "internal",
		},
	}

	for id, resource := range resources {
		e.permissionMatrix.Resources[id] = resource
	}
}

func (e *RBACCoreEngine) defineActions() {
	actions := map[string]*rbac.ActionDef{
		rbac.ActionCreate: {
			ID:          rbac.ActionCreate,
			Name:        "Create",
			Description: "Create new resource",
			Risk:        "medium",
		},
		rbac.ActionRead: {
			ID:          rbac.ActionRead,
			Name:        "Read",
			Description: "Read resource data",
			Risk:        "low",
		},
		rbac.ActionUpdate: {
			ID:          rbac.ActionUpdate,
			Name:        "Update",
			Description: "Update existing resource",
			Risk:        "medium",
		},
		rbac.ActionApprove: {
			ID:          rbac.ActionApprove,
			Name:        "Approve",
			Description: "Approve resource or action",
			Risk:        "high",
		},
	}

	for id, action := range actions {
		e.permissionMatrix.Actions[id] = action
	}
}

// checkRolePermissionWithInheritance checks permissions including inherited permissions from parent roles
func (e *RBACCoreEngine) checkRolePermissionWithInheritance(ctx context.Context, role rbac.Role, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	// Get all effective permissions for this role (including inherited)
	effectivePermissions, err := e.GetEffectivePermissions(role.ID)
	if err != nil {
		return nil, err
	}

	// Check each effective permission
	for _, perm := range effectivePermissions {
		if e.permissionMatches(&perm, req) {
			// Check time restrictions if any
			if perm.TimeRestriction != nil {
				if !e.checkTimeRestriction(perm.TimeRestriction, req.Timestamp) {
					return &rbac.AccessDecision{
						Allowed: false,
						Reason:  "Access denied due to time restrictions",
					}, nil
				}
			}

			// Check attribute-based constraints
			if len(perm.Conditions) > 0 {
				if !e.checkPermissionConditions(perm.Conditions, req) {
					return &rbac.AccessDecision{
						Allowed: false,
						Reason:  "Access denied due to permission conditions not met",
						Conditions: perm.Conditions,
					}, nil
				}
			}

			return &rbac.AccessDecision{
				Allowed:    true,
				Reason:     fmt.Sprintf("Access granted via role: %s (scope: %s)", role.ID, perm.Scope),
				Conditions: perm.Conditions,
				TTL:        time.Duration(rbac.DefaultPolicyCacheTTL) * time.Second,
				Attributes: map[string]string{
					"granted_role": role.ID,
					"permission_scope": perm.Scope,
					"resource": perm.Resource,
				},
			}, nil
		}
	}

	return &rbac.AccessDecision{
		Allowed: false,
		Reason:  fmt.Sprintf("No matching permissions for role: %s", role.ID),
	}, nil
}

// checkRolePermission checks permissions for a specific role (legacy method for backward compatibility)
func (e *RBACCoreEngine) checkRolePermission(ctx context.Context, role rbac.Role, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	return e.checkRolePermissionWithInheritance(ctx, role, req)
}

// checkPermissionConditions validates permission conditions against the request
func (e *RBACCoreEngine) checkPermissionConditions(conditions []string, req *rbac.AccessRequest) bool {
	for _, condition := range conditions {
		switch condition {
		case "requires_supervisor_approval":
			// Check if this is a supervised action
			if req.Attributes["is_trainee"] == "true" && req.Attributes["supervisor_approved"] != "true" {
				return false
			}
		case "de_identified_only":
			// Check if data is de-identified for training purposes
			if req.Attributes["data_type"] != "de_identified" {
				return false
			}
		case "demographics_only":
			// Restrict to demographic data only
			if req.Action != rbac.ActionCreate && req.Action != rbac.ActionRead {
				return false
			}
		case "nursing_notes_only":
			// Restrict to nursing-specific data
			if req.Attributes["data_category"] != "nursing" {
				return false
			}
		case "vitals_only":
			// Restrict to vital signs data
			if req.Attributes["data_category"] != "vitals" {
				return false
			}
		case "lab_orders_only":
			// Restrict to laboratory orders
			if req.Attributes["order_type"] != "lab" {
				return false
			}
		case "lab_relevant_only":
			// Restrict to lab-relevant patient data
			if req.Attributes["data_relevance"] != "lab" {
				return false
			}
		case "specialty_relevant":
			// Check if data is relevant to user's specialty
			userSpecialty := req.Attributes["user_specialty"]
			dataSpecialty := req.Attributes["data_specialty"]
			if userSpecialty != "" && dataSpecialty != "" && userSpecialty != dataSpecialty {
				return false
			}
		case "diagnostic_only":
			// Restrict to diagnostic orders
			if req.Attributes["order_category"] != "diagnostic" {
				return false
			}
		case "supervisor_role":
			// Check if user has supervisor privileges
			if req.Attributes["is_supervisor"] != "true" {
				return false
			}
		case "billing_only":
			// Restrict to billing-related financial data
			if req.Attributes["financial_category"] != "billing" {
				return false
			}
		case "rbac_policies":
			// Restrict to RBAC policy management
			if req.Attributes["config_type"] != "rbac" {
				return false
			}
		}
	}
	return true
}

func (e *RBACCoreEngine) permissionMatches(perm *rbac.Permission, req *rbac.AccessRequest) bool {
	// Check resource match (simplified - would need more sophisticated matching)
	if perm.Resource != req.ResourceID && perm.Resource != "*" {
		return false
	}

	// Check action match
	for _, action := range perm.Actions {
		if action == req.Action || action == "*" {
			return true
		}
	}

	return false
}

func (e *RBACCoreEngine) checkTimeRestriction(restriction *rbac.TimeRestriction, timestamp time.Time) bool {
	// Simplified time restriction check
	// In a real implementation, this would handle timezone conversion and more complex logic
	
	if len(restriction.DaysOfWeek) > 0 {
		weekday := timestamp.Weekday().String()
		allowed := false
		for _, day := range restriction.DaysOfWeek {
			if day == weekday {
				allowed = true
				break
			}
		}
		if !allowed {
			return false
		}
	}

	// Check time range (simplified)
	if restriction.StartTime != "" && restriction.EndTime != "" {
		currentTime := timestamp.Format(rbac.TimeFormatHourMinute)
		if currentTime < restriction.StartTime || currentTime > restriction.EndTime {
			return false
		}
	}

	return true
}

func (e *RBACCoreEngine) extractRoleFromUserID(userID string) string {
	// This is a placeholder implementation for testing
	// In reality, roles would be extracted from X.509 certificates
	
	// Check if userID contains role prefix
	for roleID := range rbac.RoleLevels {
		if len(userID) > len(roleID) && userID[:len(roleID)] == roleID {
			return roleID
		}
	}

	// Default to patient role if no role found
	return rbac.RolePatient
}

// StartAccessMonitoring starts the access monitoring service
func (e *RBACCoreEngine) StartAccessMonitoring(ctx context.Context) error {
	if e.accessMonitor == nil {
		return fmt.Errorf("access monitor not initialized")
	}
	
	return e.accessMonitor.Start(ctx)
}

// StopAccessMonitoring stops the access monitoring service
func (e *RBACCoreEngine) StopAccessMonitoring() error {
	if e.accessMonitor == nil {
		return nil
	}
	
	return e.accessMonitor.Stop()
}

// GetAccessMonitoringMetrics returns access monitoring metrics
func (e *RBACCoreEngine) GetAccessMonitoringMetrics() *AccessMonitoringMetrics {
	if e.accessMonitor == nil {
		return nil
	}
	
	return e.accessMonitor.GetMetrics()
}

// GetAccessAttempts retrieves access attempts based on filter criteria
func (e *RBACCoreEngine) GetAccessAttempts(ctx context.Context, filter *AccessAttemptFilter) ([]*AccessAttemptEvent, error) {
	if e.accessMonitor == nil {
		return nil, fmt.Errorf("access monitor not initialized")
	}
	
	return e.accessMonitor.GetAccessAttempts(ctx, filter)
}

// GetSecurityAlerts retrieves security alerts based on filter criteria
func (e *RBACCoreEngine) GetSecurityAlerts(ctx context.Context, filter *SecurityAlertFilter) ([]*SecurityAlert, error) {
	if e.accessMonitor == nil {
		return nil, fmt.Errorf("access monitor not initialized")
	}
	
	return e.accessMonitor.GetSecurityAlerts(ctx, filter)
}

// AcknowledgeAlert acknowledges a security alert
func (e *RBACCoreEngine) AcknowledgeAlert(ctx context.Context, alertID, acknowledgedBy string) error {
	if e.accessMonitor == nil {
		return fmt.Errorf("access monitor not initialized")
	}
	
	return e.accessMonitor.AcknowledgeAlert(ctx, alertID, acknowledgedBy)
}

// ResolveAlert resolves a security alert
func (e *RBACCoreEngine) ResolveAlert(ctx context.Context, alertID, resolvedBy string) error {
	if e.accessMonitor == nil {
		return fmt.Errorf("access monitor not initialized")
	}
	
	return e.accessMonitor.ResolveAlert(ctx, alertID, resolvedBy)
}

// GetSuspiciousActivityProfile returns suspicious activity profiles
func (e *RBACCoreEngine) GetSuspiciousActivityProfile(userID string) *UserActivityProfile {
	if e.accessMonitor == nil || e.accessMonitor.suspiciousDetector == nil {
		return nil
	}
	
	return e.accessMonitor.suspiciousDetector.GetUserProfile(userID)
}

// BlacklistIP adds an IP address to the blacklist
func (e *RBACCoreEngine) BlacklistIP(ipAddress, reason string) {
	if e.accessMonitor != nil && e.accessMonitor.suspiciousDetector != nil {
		e.accessMonitor.suspiciousDetector.BlacklistIP(ipAddress, reason)
	}
}

// RemoveIPFromBlacklist removes an IP address from the blacklist
func (e *RBACCoreEngine) RemoveIPFromBlacklist(ipAddress string) {
	if e.accessMonitor != nil && e.accessMonitor.suspiciousDetector != nil {
		e.accessMonitor.suspiciousDetector.RemoveIPFromBlacklist(ipAddress)
	}
}

// IsIPBlacklisted checks if an IP address is blacklisted
func (e *RBACCoreEngine) IsIPBlacklisted(ipAddress string) bool {
	if e.accessMonitor != nil && e.accessMonitor.suspiciousDetector != nil {
		return e.accessMonitor.suspiciousDetector.IsIPBlacklisted(ipAddress)
	}
	return false
}

// Performance monitoring methods

// StartPerformanceMonitoring starts the performance monitoring service
func (e *RBACCoreEngine) StartPerformanceMonitoring(ctx context.Context) error {
	if e.performanceMonitor == nil {
		return fmt.Errorf("performance monitor not initialized")
	}
	return e.performanceMonitor.Start(ctx)
}

// StopPerformanceMonitoring stops the performance monitoring service
func (e *RBACCoreEngine) StopPerformanceMonitoring() error {
	if e.performanceMonitor == nil {
		return nil
	}
	return e.performanceMonitor.Stop()
}

// GetDecisionMetrics returns current decision performance metrics
func (e *RBACCoreEngine) GetDecisionMetrics() *DecisionMetrics {
	if e.performanceMonitor == nil {
		return nil
	}
	return e.performanceMonitor.GetDecisionMetrics()
}

// GetCacheMetrics returns current cache performance metrics
func (e *RBACCoreEngine) GetCacheMetrics() *CachePerformanceMetrics {
	if e.performanceMonitor == nil {
		return nil
	}
	return e.performanceMonitor.GetCacheMetrics()
}

// GetOptimizationRecommendations returns current optimization recommendations
func (e *RBACCoreEngine) GetOptimizationRecommendations() []*OptimizationRecommendation {
	if e.performanceMonitor == nil {
		return nil
	}
	return e.performanceMonitor.GetOptimizationRecommendations()
}

// UpdateCacheSize updates cache size metrics for performance monitoring
func (e *RBACCoreEngine) UpdateCacheSize(cacheType string, currentSize, maxSize int) {
	if e.performanceMonitor != nil {
		e.performanceMonitor.UpdateCacheSize(cacheType, currentSize, maxSize)
	}
}

// RecordCacheEviction records cache eviction events for performance monitoring
func (e *RBACCoreEngine) RecordCacheEviction(cacheType string) {
	if e.performanceMonitor != nil {
		e.performanceMonitor.RecordCacheEviction(cacheType)
	}
}

// Cache helper methods

// generateDecisionCacheKey generates a cache key for access decisions
func (e *RBACCoreEngine) generateDecisionCacheKey(req *rbac.AccessRequest) string {
	// Create a deterministic cache key based on request parameters
	return fmt.Sprintf("decision:%s:%s:%s:%v", req.UserID, req.ResourceID, req.Action, req.Attributes)
}

// getCachedDecision retrieves a cached decision if available and not expired
func (e *RBACCoreEngine) getCachedDecision(cacheKey string) *rbac.AccessDecision {
	e.cacheMutex.RLock()
	defer e.cacheMutex.RUnlock()

	if cached, exists := e.decisionCache[cacheKey]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			// Update cache statistics
			e.cacheStats.DecisionCacheHits++
			cached.HitCount++
			
			// Record cache hit for performance monitoring
			if e.performanceMonitor != nil {
				e.performanceMonitor.RecordCachePerformance("decision", true, 0)
			}
			
			return cached.Decision
		} else {
			// Cache entry expired, remove it
			delete(e.decisionCache, cacheKey)
			e.cacheStats.CacheEvictions++
			
			// Record cache eviction
			if e.performanceMonitor != nil {
				e.performanceMonitor.RecordCacheEviction("decision")
			}
		}
	}

	// Cache miss
	e.cacheStats.DecisionCacheMisses++
	return nil
}

// cacheDecision stores a decision in the cache with appropriate TTL
func (e *RBACCoreEngine) cacheDecision(cacheKey string, decision *rbac.AccessDecision) {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	// Determine TTL based on decision type
	var ttl time.Duration
	if decision.Allowed {
		ttl = 5 * time.Minute // Cache positive decisions longer
	} else {
		ttl = 1 * time.Minute // Cache negative decisions for shorter time
	}

	// Override with decision-specific TTL if provided
	if decision.TTL > 0 {
		ttl = decision.TTL
	}

	cached := &CachedDecision{
		Decision:  decision,
		ExpiresAt: time.Now().Add(ttl),
		HitCount:  0,
	}

	e.decisionCache[cacheKey] = cached

	// Update cache size metrics
	if e.performanceMonitor != nil {
		e.performanceMonitor.UpdateCacheSize("decision", len(e.decisionCache), e.config.DecisionCacheSize)
	}

	// Clean up expired entries if cache is getting full
	if len(e.decisionCache) > e.config.DecisionCacheSize {
		e.cleanupExpiredDecisions()
	}
}

// cleanupExpiredDecisions removes expired decisions from cache
func (e *RBACCoreEngine) cleanupExpiredDecisions() {
	now := time.Now()
	for key, cached := range e.decisionCache {
		if now.After(cached.ExpiresAt) {
			delete(e.decisionCache, key)
			e.cacheStats.CacheEvictions++
			
			// Record cache eviction
			if e.performanceMonitor != nil {
				e.performanceMonitor.RecordCacheEviction("decision")
			}
		}
	}
}

// getCachedRolePermissions retrieves cached role permissions
func (e *RBACCoreEngine) getCachedRolePermissions(roleID string) []rbac.Permission {
	e.cacheMutex.RLock()
	defer e.cacheMutex.RUnlock()

	if permissions, exists := e.rolePermCache[roleID]; exists {
		e.cacheStats.RolePermCacheHits++
		
		// Record cache hit for performance monitoring
		if e.performanceMonitor != nil {
			e.performanceMonitor.RecordCachePerformance("role_permission", true, 0)
		}
		
		return permissions
	}

	e.cacheStats.RolePermCacheMisses++
	
	// Record cache miss for performance monitoring
	if e.performanceMonitor != nil {
		e.performanceMonitor.RecordCachePerformance("role_permission", false, 0)
	}
	
	return nil
}

// cacheRolePermissions stores role permissions in cache
func (e *RBACCoreEngine) cacheRolePermissions(roleID string, permissions []rbac.Permission) {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	e.rolePermCache[roleID] = permissions

	// Update cache size metrics
	if e.performanceMonitor != nil {
		e.performanceMonitor.UpdateCacheSize("role_permission", len(e.rolePermCache), e.config.RolePermCacheSize)
	}
}

// GetCacheStatistics returns current cache statistics
func (e *RBACCoreEngine) GetCacheStatistics() *CacheStatistics {
	e.cacheMutex.RLock()
	defer e.cacheMutex.RUnlock()

	// Create a copy to avoid race conditions
	stats := &CacheStatistics{
		PolicyCacheHits:     e.cacheStats.PolicyCacheHits,
		PolicyCacheMisses:   e.cacheStats.PolicyCacheMisses,
		DecisionCacheHits:   e.cacheStats.DecisionCacheHits,
		DecisionCacheMisses: e.cacheStats.DecisionCacheMisses,
		RolePermCacheHits:   e.cacheStats.RolePermCacheHits,
		RolePermCacheMisses: e.cacheStats.RolePermCacheMisses,
		CacheEvictions:      e.cacheStats.CacheEvictions,
		LastReset:           e.cacheStats.LastReset,
	}

	return stats
}

// ResetCacheStatistics resets cache statistics
func (e *RBACCoreEngine) ResetCacheStatistics() {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()

	e.cacheStats = &CacheStatistics{
		LastReset: time.Now(),
	}
}