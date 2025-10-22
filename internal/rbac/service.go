package rbac

import (
	"context"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// Service implements the main RBAC service that coordinates all RBAC components
type Service struct {
	coreEngine     *RBACCoreEngine
	abacEngine     *ABACEngine
	sbeManager     *SBEPolicyManager
	certManager    *CertificateManager
	policyManager  *PolicyManager
	auditLogger    *AuditLogger
	workflowEngine *SupervisionWorkflowEngine
	
	config *Config
	logger *logrus.Logger
	
	// Cache for frequently accessed data
	roleCache    map[string]*rbac.Role
	policyCache  map[string]*rbac.AccessPolicy
	cacheMutex   sync.RWMutex
	cacheExpiry  map[string]time.Time
}

// Config holds configuration for the RBAC service
type Config struct {
	CacheTTL                     time.Duration                     `yaml:"cache_ttl"`
	SupervisionTimeout           time.Duration                     `yaml:"supervision_timeout"`
	CertificateValidity          time.Duration                     `yaml:"certificate_validity"`
	AuditRetentionDays           int                               `yaml:"audit_retention_days"`
	MaxPolicyVersions            int                               `yaml:"max_policy_versions"`
	EnableEmergencyOverride      bool                              `yaml:"enable_emergency_override"`
	FabricNetworkConfig          string                            `yaml:"fabric_network_config"`
	DatabaseURL                  string                            `yaml:"database_url"`
	AccessMonitorBufferSize      int                               `yaml:"access_monitor_buffer_size"`
	AlertBufferSize              int                               `yaml:"alert_buffer_size"`
	PerformanceBufferSize        int                               `yaml:"performance_buffer_size"`
	DecisionCacheSize            int                               `yaml:"decision_cache_size"`
	RolePermCacheSize            int                               `yaml:"role_perm_cache_size"`
	SuspiciousActivityThresholds SuspiciousActivityThresholds      `yaml:"suspicious_activity_thresholds"`
	AlertChannels                AlertChannelsConfig               `yaml:"alert_channels"`
}

// AlertChannelsConfig holds configuration for alert channels
type AlertChannelsConfig struct {
	Webhooks []WebhookChannelConfig `yaml:"webhooks"`
	Email    EmailChannelConfig     `yaml:"email"`
	Slack    SlackChannelConfig     `yaml:"slack"`
	Log      LogChannelConfig       `yaml:"log"`
}

// WebhookChannelConfig holds configuration for webhook alert channels
type WebhookChannelConfig struct {
	Name       string            `yaml:"name"`
	URL        string            `yaml:"url"`
	Method     string            `yaml:"method"`
	Headers    map[string]string `yaml:"headers"`
	Timeout    time.Duration     `yaml:"timeout"`
	Enabled    bool              `yaml:"enabled"`
	RetryCount int               `yaml:"retry_count"`
	RetryDelay time.Duration     `yaml:"retry_delay"`
}

// EmailChannelConfig holds configuration for email alert channels
type EmailChannelConfig struct {
	Name        string   `yaml:"name"`
	SMTPServer  string   `yaml:"smtp_server"`
	SMTPPort    int      `yaml:"smtp_port"`
	Username    string   `yaml:"username"`
	Password    string   `yaml:"password"`
	FromAddress string   `yaml:"from_address"`
	ToAddresses []string `yaml:"to_addresses"`
	Enabled     bool     `yaml:"enabled"`
}

// SlackChannelConfig holds configuration for Slack alert channels
type SlackChannelConfig struct {
	Name       string `yaml:"name"`
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
	Username   string `yaml:"username"`
	IconEmoji  string `yaml:"icon_emoji"`
	Enabled    bool   `yaml:"enabled"`
}

// LogChannelConfig holds configuration for log alert channels
type LogChannelConfig struct {
	Name    string `yaml:"name"`
	Level   string `yaml:"level"`
	Enabled bool   `yaml:"enabled"`
}

// NewService creates a new RBAC service instance
func NewService(config *Config, logger *logrus.Logger) *Service {
	return &Service{
		config:      config,
		logger:      logger,
		roleCache:   make(map[string]*rbac.Role),
		policyCache: make(map[string]*rbac.AccessPolicy),
		cacheExpiry: make(map[string]time.Time),
	}
}

// Initialize sets up all RBAC components and their dependencies
func (s *Service) Initialize(ctx context.Context) error {
	s.logger.Info("Initializing RBAC service components")

	// Initialize core engine
	coreEngine, err := NewRBACCoreEngine(s.config, s.logger)
	if err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_001",
			"Failed to initialize RBAC core engine",
			err,
		)
	}
	s.coreEngine = coreEngine

	// Initialize ABAC engine
	abacEngine, err := NewABACEngine(s.config, s.logger, s.certManager)
	if err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_002",
			"Failed to initialize ABAC engine",
			err,
		)
	}
	s.abacEngine = abacEngine

	// Initialize SBE policy manager
	sbeManager, err := NewSBEPolicyManager(s.config, s.logger)
	if err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_003",
			"Failed to initialize SBE policy manager",
			err,
		)
	}
	s.sbeManager = sbeManager

	// Initialize certificate manager
	certConfig := &CertManagerConfig{
		OrgMSP:     "HospitalMSP", // Default MSP, should be configurable
		CAURL:      s.config.FabricNetworkConfig,
		TLSEnabled: true,
	}
	
	// Create a mock CA client for now - in production, use real Fabric CA client
	mockCAClient := &MockCAClient{}
	
	certManager, err := NewCertificateManager(certConfig, s.logger, mockCAClient)
	if err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_004",
			"Failed to initialize certificate manager",
			err,
		)
	}
	s.certManager = certManager

	// Initialize policy manager
	policyManager, err := NewPolicyManager(s.config, s.logger)
	if err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_005",
			"Failed to initialize policy manager",
			err,
		)
	}
	s.policyManager = policyManager

	// Initialize audit logger
	auditLogger, err := NewAuditLogger(s.config, s.logger)
	if err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_006",
			"Failed to initialize audit logger",
			err,
		)
	}
	s.auditLogger = auditLogger

	// Initialize supervision workflow engine
	workflowEngine, err := NewSupervisionWorkflowEngine(s.config, s.logger, sbeManager)
	if err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_007",
			"Failed to initialize supervision workflow engine",
			err,
		)
	}
	s.workflowEngine = workflowEngine

	// Start access monitoring
	if err := s.coreEngine.StartAccessMonitoring(ctx); err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_008",
			"Failed to start access monitoring",
			err,
		)
	}

	// Start performance monitoring
	if err := s.coreEngine.StartPerformanceMonitoring(ctx); err != nil {
		return rbac.NewRBACErrorWithCause(
			rbac.ErrorTypeSystemError,
			"RBAC_INIT_009",
			"Failed to start performance monitoring",
			err,
		)
	}

	s.logger.Info("RBAC service initialization completed successfully")
	return nil
}

// ValidateAccess validates access to a resource using the complete RBAC system
func (s *Service) ValidateAccess(ctx context.Context, req *rbac.AccessRequest) (*rbac.AccessDecision, error) {
	startTime := time.Now()
	
	// Log the access attempt
	defer func() {
		duration := time.Since(startTime)
		s.logger.WithFields(logrus.Fields{
			"user_id":     req.UserID,
			"resource_id": req.ResourceID,
			"action":      req.Action,
			"duration_ms": duration.Milliseconds(),
		}).Debug("Access validation completed")
	}()

	// Step 1: Basic RBAC validation
	decision, err := s.coreEngine.ValidateAccess(ctx, req)
	if err != nil {
		s.auditLogger.LogAccessAttempt(ctx, req, &rbac.AccessDecision{
			Allowed: false,
			Reason:  "RBAC validation failed: " + err.Error(),
		})
		return nil, err
	}

	// Step 2: If basic RBAC allows, check ABAC policies
	if decision.Allowed && len(req.Attributes) > 0 {
		// Get applicable ABAC policies
		abacPolicies, err := s.getApplicableABACPolicies(ctx, req)
		if err != nil {
			s.logger.WithError(err).Warn("Failed to retrieve ABAC policies")
		} else {
			for _, policy := range abacPolicies {
				allowed, err := s.abacEngine.EvaluatePolicy(ctx, policy, req.Attributes)
				if err != nil {
					s.logger.WithError(err).Warn("ABAC policy evaluation failed")
					continue
				}
				if !allowed {
					decision.Allowed = false
					decision.Reason = "ABAC policy violation: " + policy.Name
					break
				}
			}
		}
	}

	// Step 3: Check SBE policies if applicable
	if decision.Allowed {
		sbeRequired, err := s.checkSBERequirement(ctx, req)
		if err != nil {
			s.logger.WithError(err).Warn("SBE requirement check failed")
		} else if sbeRequired {
			decision.Allowed = false
			decision.Reason = "State-Based Endorsement required"
			decision.Conditions = append(decision.Conditions, "requires_supervisor_approval")
		}
	}

	// Log the final decision
	s.auditLogger.LogAccessAttempt(ctx, req, decision)

	return decision, nil
}

// GetUserRoles retrieves roles for a user with caching
func (s *Service) GetUserRoles(userID string) ([]rbac.Role, error) {
	s.cacheMutex.RLock()
	if role, exists := s.roleCache[userID]; exists {
		if expiry, hasExpiry := s.cacheExpiry[userID]; hasExpiry && time.Now().Before(expiry) {
			s.cacheMutex.RUnlock()
			return []rbac.Role{*role}, nil
		}
	}
	s.cacheMutex.RUnlock()

	// Cache miss or expired, fetch from core engine
	roles, err := s.coreEngine.GetUserRoles(userID)
	if err != nil {
		return nil, err
	}

	// Update cache
	if len(roles) > 0 {
		s.cacheMutex.Lock()
		s.roleCache[userID] = &roles[0]
		s.cacheExpiry[userID] = time.Now().Add(s.config.CacheTTL)
		s.cacheMutex.Unlock()
	}

	return roles, nil
}

// EnrollUserWithAttributes enrolls a user with role attributes
func (s *Service) EnrollUserWithAttributes(ctx context.Context, req *rbac.EnrollmentRequest) (*x509.Certificate, error) {
	// Validate enrollment request
	if err := s.validateEnrollmentRequest(req); err != nil {
		return nil, err
	}

	// Enroll user with certificate manager
	cert, err := s.certManager.EnrollUserWithAttributes(ctx, req)
	if err != nil {
		return nil, err
	}

	// Log certificate issuance
	s.auditLogger.LogAccessAttempt(ctx, &rbac.AccessRequest{
		UserID:    req.UserID,
		Action:    "certificate_issue",
		Timestamp: time.Now(),
	}, &rbac.AccessDecision{
		Allowed: true,
		Reason:  "Certificate issued successfully",
	})

	return cert, nil
}

// CreateSupervisionWorkflow creates a new supervision workflow
func (s *Service) CreateSupervisionWorkflow(ctx context.Context, workflow *rbac.SupervisionWorkflow) error {
	return s.workflowEngine.CreateSupervisionWorkflow(ctx, workflow)
}

// HandleEmergencyOverride handles emergency override requests
func (s *Service) HandleEmergencyOverride(ctx context.Context, req *rbac.EmergencyOverrideRequest) error {
	if !s.config.EnableEmergencyOverride {
		return rbac.NewRBACError(
			rbac.ErrorTypeEmergencyOverride,
			rbac.ErrorCodeEmergencyOverride,
			"Emergency override is disabled",
		)
	}

	// Log emergency override attempt
	s.auditLogger.LogEmergencyOverride(ctx, req)

	return s.sbeManager.HandleEmergencyOverride(ctx, req)
}



// Helper methods

func (s *Service) getApplicableABACPolicies(ctx context.Context, req *rbac.AccessRequest) ([]*rbac.ABACPolicy, error) {
	// This would typically query a policy store for applicable ABAC policies
	// For now, return empty slice - will be implemented in later tasks
	return []*rbac.ABACPolicy{}, nil
}

func (s *Service) checkSBERequirement(ctx context.Context, req *rbac.AccessRequest) (bool, error) {
	// Check if the request requires State-Based Endorsement
	// This would typically check SBE policies against the request
	// For now, return false - will be implemented in later tasks
	return false, nil
}

func (s *Service) validateEnrollmentRequest(req *rbac.EnrollmentRequest) error {
	var validationErrors rbac.ValidationErrors

	if req.UserID == "" {
		validationErrors.Add("user_id", req.UserID, "User ID is required")
	}

	if req.Role == "" {
		validationErrors.Add("role", req.Role, "Role is required")
	} else if _, exists := rbac.NodeOUMappings[req.Role]; !exists {
		validationErrors.Add("role", req.Role, "Invalid role specified")
	}

	if req.OrgMSP == "" {
		validationErrors.Add("org_msp", req.OrgMSP, "Organization MSP is required")
	}

	if req.ValidityPeriod <= 0 {
		validationErrors.Add("validity_period", req.ValidityPeriod.String(), "Validity period must be positive")
	}

	if validationErrors.HasErrors() {
		return &validationErrors
	}

	return nil
}

// MockCAClient is a simple mock implementation for development/testing
type MockCAClient struct{}

func (m *MockCAClient) EnrollWithAttributes(enrollmentID, enrollmentSecret string, attrs []FabricAttribute) (*EnrollmentResponse, error) {
	return &EnrollmentResponse{
		Certificate: "mock-certificate",
		PrivateKey:  "mock-private-key",
		CACerts:     "mock-ca-certs",
	}, nil
}

func (m *MockCAClient) RegisterUser(regRequest *RegistrationRequest) (*RegistrationResponse, error) {
	return &RegistrationResponse{
		Secret: "mock-secret",
	}, nil
}

func (m *MockCAClient) RevokeUser(revRequest *RevocationRequest) (*RevocationResponse, error) {
	return &RevocationResponse{
		RevokedCerts: []RevokedCertificate{},
		CRL:          "mock-crl",
	}, nil
}

func (m *MockCAClient) GetCACertificateChain() ([]*x509.Certificate, error) {
	return []*x509.Certificate{}, nil
}

func (m *MockCAClient) ReenrollWithAttributes(cert, key string, attrs []FabricAttribute) (*EnrollmentResponse, error) {
	return &EnrollmentResponse{
		Certificate: "mock-renewed-certificate",
		PrivateKey:  "mock-renewed-private-key",
		CACerts:     "mock-ca-certs",
	}, nil
}

func (m *MockCAClient) ValidateConnection() error {
	return nil
}

// Shutdown gracefully shuts down the RBAC service and all its components
func (s *Service) Shutdown(ctx context.Context) error {
	s.logger.Info("Shutting down RBAC service")

	// Stop access monitoring
	if s.coreEngine != nil {
		if err := s.coreEngine.StopAccessMonitoring(); err != nil {
			s.logger.WithError(err).Warn("Error stopping access monitoring")
		}

		// Stop performance monitoring
		if err := s.coreEngine.StopPerformanceMonitoring(); err != nil {
			s.logger.WithError(err).Warn("Error stopping performance monitoring")
		}
	}

	// TODO: Add shutdown logic for other components as needed
	// - Close database connections
	// - Stop background processes
	// - Clean up resources

	s.logger.Info("RBAC service shutdown completed")
	return nil
}

// GetAccessMonitoringMetrics returns access monitoring metrics
func (s *Service) GetAccessMonitoringMetrics() *AccessMonitoringMetrics {
	if s.coreEngine == nil {
		return nil
	}
	return s.coreEngine.GetAccessMonitoringMetrics()
}

// GetDecisionMetrics returns current decision performance metrics
func (s *Service) GetDecisionMetrics() *DecisionMetrics {
	if s.coreEngine == nil {
		return nil
	}
	return s.coreEngine.GetDecisionMetrics()
}

// GetCacheMetrics returns current cache performance metrics
func (s *Service) GetCacheMetrics() *CachePerformanceMetrics {
	if s.coreEngine == nil {
		return nil
	}
	return s.coreEngine.GetCacheMetrics()
}

// GetOptimizationRecommendations returns current optimization recommendations
func (s *Service) GetOptimizationRecommendations() []*OptimizationRecommendation {
	if s.coreEngine == nil {
		return nil
	}
	return s.coreEngine.GetOptimizationRecommendations()
}

// GetCacheStatistics returns current cache statistics
func (s *Service) GetCacheStatistics() *CacheStatistics {
	if s.coreEngine == nil {
		return nil
	}
	return s.coreEngine.GetCacheStatistics()
}

// ResetCacheStatistics resets cache statistics
func (s *Service) ResetCacheStatistics() {
	if s.coreEngine != nil {
		s.coreEngine.ResetCacheStatistics()
	}
}

// GetAccessAttempts retrieves access attempts based on filter criteria
func (s *Service) GetAccessAttempts(ctx context.Context, filter *AccessAttemptFilter) ([]*AccessAttemptEvent, error) {
	if s.coreEngine == nil {
		return nil, fmt.Errorf("RBAC core engine not initialized")
	}
	return s.coreEngine.GetAccessAttempts(ctx, filter)
}

// GetSecurityAlerts retrieves security alerts based on filter criteria
func (s *Service) GetSecurityAlerts(ctx context.Context, filter *SecurityAlertFilter) ([]*SecurityAlert, error) {
	if s.coreEngine == nil {
		return nil, fmt.Errorf("RBAC core engine not initialized")
	}
	return s.coreEngine.GetSecurityAlerts(ctx, filter)
}

// AcknowledgeAlert acknowledges a security alert
func (s *Service) AcknowledgeAlert(ctx context.Context, alertID, acknowledgedBy string) error {
	if s.coreEngine == nil {
		return fmt.Errorf("RBAC core engine not initialized")
	}
	return s.coreEngine.AcknowledgeAlert(ctx, alertID, acknowledgedBy)
}

// ResolveAlert resolves a security alert
func (s *Service) ResolveAlert(ctx context.Context, alertID, resolvedBy string) error {
	if s.coreEngine == nil {
		return fmt.Errorf("RBAC core engine not initialized")
	}
	return s.coreEngine.ResolveAlert(ctx, alertID, resolvedBy)
}

// BlacklistIP adds an IP address to the blacklist
func (s *Service) BlacklistIP(ipAddress, reason string) {
	if s.coreEngine != nil {
		s.coreEngine.BlacklistIP(ipAddress, reason)
	}
}

// RemoveIPFromBlacklist removes an IP address from the blacklist
func (s *Service) RemoveIPFromBlacklist(ipAddress string) {
	if s.coreEngine != nil {
		s.coreEngine.RemoveIPFromBlacklist(ipAddress)
	}
}

// IsIPBlacklisted checks if an IP address is blacklisted
func (s *Service) IsIPBlacklisted(ipAddress string) bool {
	if s.coreEngine != nil {
		return s.coreEngine.IsIPBlacklisted(ipAddress)
	}
	return false
}