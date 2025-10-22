package rbac

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// AccessMonitor implements real-time access monitoring and alerting
type AccessMonitor struct {
	db                    *sql.DB
	logger                *logrus.Logger
	config                *Config
	alertManager          *AlertManager
	suspiciousDetector    *SuspiciousActivityDetector
	accessAttemptBuffer   chan *AccessAttemptEvent
	alertBuffer           chan *SecurityAlert
	stopChan              chan struct{}
	wg                    sync.WaitGroup
	metrics               *AccessMonitoringMetrics
	mutex                 sync.RWMutex
}

// AccessAttemptEvent represents an access attempt event for monitoring
type AccessAttemptEvent struct {
	ID            string                 `json:"id"`
	UserID        string                 `json:"user_id"`
	ResourceID    string                 `json:"resource_id"`
	Action        string                 `json:"action"`
	Result        string                 `json:"result"`
	Reason        string                 `json:"reason"`
	IPAddress     string                 `json:"ip_address"`
	UserAgent     string                 `json:"user_agent"`
	Timestamp     time.Time              `json:"timestamp"`
	ResponseTime  time.Duration          `json:"response_time"`
	UserRole      string                 `json:"user_role"`
	ResourceType  string                 `json:"resource_type"`
	Context       map[string]string      `json:"context"`
	Attributes    map[string]string      `json:"attributes"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// SecurityAlert represents a security alert for policy violations
type SecurityAlert struct {
	ID              string                 `json:"id"`
	AlertType       string                 `json:"alert_type"`
	Severity        string                 `json:"severity"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	UserID          string                 `json:"user_id"`
	ResourceID      string                 `json:"resource_id"`
	IPAddress       string                 `json:"ip_address"`
	Timestamp       time.Time              `json:"timestamp"`
	RelatedEvents   []string               `json:"related_events"`
	Metadata        map[string]interface{} `json:"metadata"`
	Status          string                 `json:"status"` // "new", "acknowledged", "resolved"
	AcknowledgedBy  string                 `json:"acknowledged_by,omitempty"`
	AcknowledgedAt  *time.Time             `json:"acknowledged_at,omitempty"`
	ResolvedBy      string                 `json:"resolved_by,omitempty"`
	ResolvedAt      *time.Time             `json:"resolved_at,omitempty"`
}

// AccessMonitoringMetrics tracks monitoring performance metrics
type AccessMonitoringMetrics struct {
	TotalAccessAttempts     int64     `json:"total_access_attempts"`
	AllowedAttempts         int64     `json:"allowed_attempts"`
	DeniedAttempts          int64     `json:"denied_attempts"`
	SuspiciousActivities    int64     `json:"suspicious_activities"`
	AlertsGenerated         int64     `json:"alerts_generated"`
	AlertsAcknowledged      int64     `json:"alerts_acknowledged"`
	AlertsResolved          int64     `json:"alerts_resolved"`
	AverageResponseTime     time.Duration `json:"average_response_time"`
	LastActivityTimestamp   time.Time `json:"last_activity_timestamp"`
	MonitoringStartTime     time.Time `json:"monitoring_start_time"`
	BufferUtilization       float64   `json:"buffer_utilization"`
}

// AlertSeverity defines alert severity levels
type AlertSeverity string

const (
	SeverityLow      AlertSeverity = "low"
	SeverityMedium   AlertSeverity = "medium"
	SeverityHigh     AlertSeverity = "high"
	SeverityCritical AlertSeverity = "critical"
)

// AlertType defines types of security alerts
type AlertType string

const (
	AlertTypeMultipleFailures     AlertType = "multiple_failures"
	AlertTypeUnusualAccess        AlertType = "unusual_access"
	AlertTypePrivilegeEscalation  AlertType = "privilege_escalation"
	AlertTypeAfterHoursAccess     AlertType = "after_hours_access"
	AlertTypeSuspiciousPattern    AlertType = "suspicious_pattern"
	AlertTypeRateLimitExceeded    AlertType = "rate_limit_exceeded"
	AlertTypeUnauthorizedResource AlertType = "unauthorized_resource"
	AlertTypePolicyViolation      AlertType = "policy_violation"
	AlertTypeAnomalousActivity    AlertType = "anomalous_activity"
)

// NewAccessMonitor creates a new access monitor instance
func NewAccessMonitor(config *Config, logger *logrus.Logger) (*AccessMonitor, error) {
	db, err := sql.Open("postgres", config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	monitor := &AccessMonitor{
		db:                  db,
		logger:              logger,
		config:              config,
		accessAttemptBuffer: make(chan *AccessAttemptEvent, config.AccessMonitorBufferSize),
		alertBuffer:         make(chan *SecurityAlert, config.AlertBufferSize),
		stopChan:            make(chan struct{}),
		metrics: &AccessMonitoringMetrics{
			MonitoringStartTime: time.Now(),
		},
	}

	// Initialize alert manager
	monitor.alertManager = NewAlertManager(config, logger)

	// Initialize suspicious activity detector
	monitor.suspiciousDetector = NewSuspiciousActivityDetector(config, logger)

	// Initialize database tables
	if err := monitor.initializeTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize monitoring tables: %w", err)
	}

	return monitor, nil
}

// Start starts the access monitoring service
func (am *AccessMonitor) Start(ctx context.Context) error {
	am.logger.Info("Starting access monitoring service")

	// Start access attempt processor
	am.wg.Add(1)
	go am.processAccessAttempts(ctx)

	// Start alert processor
	am.wg.Add(1)
	go am.processAlerts(ctx)

	// Start metrics updater
	am.wg.Add(1)
	go am.updateMetrics(ctx)

	// Start suspicious activity detector
	if err := am.suspiciousDetector.Start(ctx); err != nil {
		return fmt.Errorf("failed to start suspicious activity detector: %w", err)
	}

	// Start alert manager
	if err := am.alertManager.Start(ctx); err != nil {
		return fmt.Errorf("failed to start alert manager: %w", err)
	}

	am.logger.Info("Access monitoring service started successfully")
	return nil
}

// Stop stops the access monitoring service
func (am *AccessMonitor) Stop() error {
	am.logger.Info("Stopping access monitoring service")

	close(am.stopChan)
	am.wg.Wait()

	// Stop alert manager
	if err := am.alertManager.Stop(); err != nil {
		am.logger.WithError(err).Warn("Error stopping alert manager")
	}

	// Stop suspicious activity detector
	if err := am.suspiciousDetector.Stop(); err != nil {
		am.logger.WithError(err).Warn("Error stopping suspicious activity detector")
	}

	// Close database connection
	if err := am.db.Close(); err != nil {
		am.logger.WithError(err).Warn("Error closing database connection")
	}

	am.logger.Info("Access monitoring service stopped")
	return nil
}

// LogAccessAttempt logs an access attempt for real-time monitoring
func (am *AccessMonitor) LogAccessAttempt(ctx context.Context, req *rbac.AccessRequest, decision *rbac.AccessDecision, responseTime time.Duration) error {
	event := &AccessAttemptEvent{
		ID:           uuid.New().String(),
		UserID:       req.UserID,
		ResourceID:   req.ResourceID,
		Action:       req.Action,
		Result:       am.getResultString(decision.Allowed),
		Reason:       decision.Reason,
		Timestamp:    time.Now(),
		ResponseTime: responseTime,
		Context:      req.Context,
		Attributes:   req.Attributes,
		Metadata:     make(map[string]interface{}),
	}

	// Extract additional context information
	if ipAddr, ok := ctx.Value("ip_address").(string); ok {
		event.IPAddress = ipAddr
	}
	if userAgent, ok := ctx.Value("user_agent").(string); ok {
		event.UserAgent = userAgent
	}
	if userRole, ok := req.Attributes["role"]; ok {
		event.UserRole = userRole
	}
	if resourceType, ok := req.Attributes["resource_type"]; ok {
		event.ResourceType = resourceType
	}

	// Add decision metadata
	if len(decision.Conditions) > 0 {
		event.Metadata["decision_conditions"] = decision.Conditions
	}
	if len(decision.Attributes) > 0 {
		event.Metadata["decision_attributes"] = decision.Attributes
	}
	event.Metadata["decision_ttl"] = decision.TTL.String()

	// Send to processing buffer (non-blocking)
	select {
	case am.accessAttemptBuffer <- event:
		// Successfully queued
	default:
		// Buffer full, log warning and process synchronously
		am.logger.Warn("Access attempt buffer full, processing synchronously")
		return am.processAccessAttemptSync(event)
	}

	return nil
}

// GetAccessAttempts retrieves access attempts based on filter criteria
func (am *AccessMonitor) GetAccessAttempts(ctx context.Context, filter *AccessAttemptFilter) ([]*AccessAttemptEvent, error) {
	query := `
		SELECT id, user_id, resource_id, action, result, reason, ip_address, 
		       user_agent, timestamp, response_time_ms, user_role, resource_type, 
		       context, attributes, metadata
		FROM rbac_access_attempts 
		WHERE 1=1`
	
	args := []interface{}{}
	argIndex := 1

	// Build dynamic WHERE clause
	if filter.UserID != "" {
		query += fmt.Sprintf(" AND user_id = $%d", argIndex)
		args = append(args, filter.UserID)
		argIndex++
	}

	if filter.ResourceID != "" {
		query += fmt.Sprintf(" AND resource_id = $%d", argIndex)
		args = append(args, filter.ResourceID)
		argIndex++
	}

	if filter.Action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIndex)
		args = append(args, filter.Action)
		argIndex++
	}

	if filter.Result != "" {
		query += fmt.Sprintf(" AND result = $%d", argIndex)
		args = append(args, filter.Result)
		argIndex++
	}

	if filter.UserRole != "" {
		query += fmt.Sprintf(" AND user_role = $%d", argIndex)
		args = append(args, filter.UserRole)
		argIndex++
	}

	if !filter.StartTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, filter.StartTime)
		argIndex++
	}

	if !filter.EndTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, filter.EndTime)
		argIndex++
	}

	if filter.IPAddress != "" {
		query += fmt.Sprintf(" AND ip_address = $%d", argIndex)
		args = append(args, filter.IPAddress)
		argIndex++
	}

	// Add ordering and pagination
	query += " ORDER BY timestamp DESC"
	
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
	}

	rows, err := am.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query access attempts: %w", err)
	}
	defer rows.Close()

	var events []*AccessAttemptEvent
	for rows.Next() {
		event := &AccessAttemptEvent{}
		var responseTimeMs int64
		var contextJSON, attributesJSON, metadataJSON []byte
		var ipAddress, userAgent, userRole, resourceType sql.NullString

		err := rows.Scan(
			&event.ID,
			&event.UserID,
			&event.ResourceID,
			&event.Action,
			&event.Result,
			&event.Reason,
			&ipAddress,
			&userAgent,
			&event.Timestamp,
			&responseTimeMs,
			&userRole,
			&resourceType,
			&contextJSON,
			&attributesJSON,
			&metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan access attempt: %w", err)
		}

		// Convert response time from milliseconds
		event.ResponseTime = time.Duration(responseTimeMs) * time.Millisecond

		// Handle nullable fields
		if ipAddress.Valid {
			event.IPAddress = ipAddress.String
		}
		if userAgent.Valid {
			event.UserAgent = userAgent.String
		}
		if userRole.Valid {
			event.UserRole = userRole.String
		}
		if resourceType.Valid {
			event.ResourceType = resourceType.String
		}

		// Unmarshal JSON fields
		if len(contextJSON) > 0 {
			if err := json.Unmarshal(contextJSON, &event.Context); err != nil {
				am.logger.WithError(err).Warn("Failed to unmarshal context JSON")
				event.Context = make(map[string]string)
			}
		}

		if len(attributesJSON) > 0 {
			if err := json.Unmarshal(attributesJSON, &event.Attributes); err != nil {
				am.logger.WithError(err).Warn("Failed to unmarshal attributes JSON")
				event.Attributes = make(map[string]string)
			}
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
				am.logger.WithError(err).Warn("Failed to unmarshal metadata JSON")
				event.Metadata = make(map[string]interface{})
			}
		}

		events = append(events, event)
	}

	return events, nil
}

// GetSecurityAlerts retrieves security alerts based on filter criteria
func (am *AccessMonitor) GetSecurityAlerts(ctx context.Context, filter *SecurityAlertFilter) ([]*SecurityAlert, error) {
	query := `
		SELECT id, alert_type, severity, title, description, user_id, resource_id, 
		       ip_address, timestamp, related_events, metadata, status, 
		       acknowledged_by, acknowledged_at, resolved_by, resolved_at
		FROM rbac_security_alerts 
		WHERE 1=1`
	
	args := []interface{}{}
	argIndex := 1

	// Build dynamic WHERE clause
	if filter.AlertType != "" {
		query += fmt.Sprintf(" AND alert_type = $%d", argIndex)
		args = append(args, filter.AlertType)
		argIndex++
	}

	if filter.Severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIndex)
		args = append(args, filter.Severity)
		argIndex++
	}

	if filter.Status != "" {
		query += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, filter.Status)
		argIndex++
	}

	if filter.UserID != "" {
		query += fmt.Sprintf(" AND user_id = $%d", argIndex)
		args = append(args, filter.UserID)
		argIndex++
	}

	if !filter.StartTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, filter.StartTime)
		argIndex++
	}

	if !filter.EndTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, filter.EndTime)
		argIndex++
	}

	// Add ordering and pagination
	query += " ORDER BY timestamp DESC"
	
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}

	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
	}

	rows, err := am.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query security alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*SecurityAlert
	for rows.Next() {
		alert := &SecurityAlert{}
		var relatedEventsJSON, metadataJSON []byte
		var acknowledgedBy, resolvedBy sql.NullString
		var acknowledgedAt, resolvedAt sql.NullTime

		err := rows.Scan(
			&alert.ID,
			&alert.AlertType,
			&alert.Severity,
			&alert.Title,
			&alert.Description,
			&alert.UserID,
			&alert.ResourceID,
			&alert.IPAddress,
			&alert.Timestamp,
			&relatedEventsJSON,
			&metadataJSON,
			&alert.Status,
			&acknowledgedBy,
			&acknowledgedAt,
			&resolvedBy,
			&resolvedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan security alert: %w", err)
		}

		// Handle nullable fields
		if acknowledgedBy.Valid {
			alert.AcknowledgedBy = acknowledgedBy.String
		}
		if acknowledgedAt.Valid {
			alert.AcknowledgedAt = &acknowledgedAt.Time
		}
		if resolvedBy.Valid {
			alert.ResolvedBy = resolvedBy.String
		}
		if resolvedAt.Valid {
			alert.ResolvedAt = &resolvedAt.Time
		}

		// Unmarshal JSON fields
		if len(relatedEventsJSON) > 0 {
			if err := json.Unmarshal(relatedEventsJSON, &alert.RelatedEvents); err != nil {
				am.logger.WithError(err).Warn("Failed to unmarshal related events JSON")
				alert.RelatedEvents = []string{}
			}
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &alert.Metadata); err != nil {
				am.logger.WithError(err).Warn("Failed to unmarshal metadata JSON")
				alert.Metadata = make(map[string]interface{})
			}
		}

		alerts = append(alerts, alert)
	}

	return alerts, nil
}

// AcknowledgeAlert acknowledges a security alert
func (am *AccessMonitor) AcknowledgeAlert(ctx context.Context, alertID, acknowledgedBy string) error {
	query := `
		UPDATE rbac_security_alerts 
		SET status = 'acknowledged', acknowledged_by = $1, acknowledged_at = $2
		WHERE id = $3 AND status = 'new'
	`

	result, err := am.db.ExecContext(ctx, query, acknowledgedBy, time.Now(), alertID)
	if err != nil {
		return fmt.Errorf("failed to acknowledge alert: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("alert not found or already acknowledged: %s", alertID)
	}

	am.mutex.Lock()
	am.metrics.AlertsAcknowledged++
	am.mutex.Unlock()

	am.logger.Info("Security alert acknowledged",
		"alert_id", alertID,
		"acknowledged_by", acknowledgedBy,
	)

	return nil
}

// ResolveAlert resolves a security alert
func (am *AccessMonitor) ResolveAlert(ctx context.Context, alertID, resolvedBy string) error {
	query := `
		UPDATE rbac_security_alerts 
		SET status = 'resolved', resolved_by = $1, resolved_at = $2
		WHERE id = $3 AND status IN ('new', 'acknowledged')
	`

	result, err := am.db.ExecContext(ctx, query, resolvedBy, time.Now(), alertID)
	if err != nil {
		return fmt.Errorf("failed to resolve alert: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("alert not found or already resolved: %s", alertID)
	}

	am.mutex.Lock()
	am.metrics.AlertsResolved++
	am.mutex.Unlock()

	am.logger.Info("Security alert resolved",
		"alert_id", alertID,
		"resolved_by", resolvedBy,
	)

	return nil
}

// GetMetrics returns current monitoring metrics
func (am *AccessMonitor) GetMetrics() *AccessMonitoringMetrics {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	// Calculate buffer utilization
	bufferUtilization := float64(len(am.accessAttemptBuffer)) / float64(cap(am.accessAttemptBuffer)) * 100

	metrics := *am.metrics
	metrics.BufferUtilization = bufferUtilization

	return &metrics
}

// Helper methods

func (am *AccessMonitor) initializeTables() error {
	// Create access attempts table
	accessAttemptsSQL := `
		CREATE TABLE IF NOT EXISTS rbac_access_attempts (
			id VARCHAR(36) PRIMARY KEY,
			user_id VARCHAR(100) NOT NULL,
			resource_id VARCHAR(100),
			action VARCHAR(50) NOT NULL,
			result VARCHAR(20) NOT NULL,
			reason TEXT,
			ip_address INET,
			user_agent TEXT,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			response_time_ms BIGINT,
			user_role VARCHAR(50),
			resource_type VARCHAR(50),
			context JSONB,
			attributes JSONB,
			metadata JSONB,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		
		CREATE INDEX IF NOT EXISTS idx_access_attempts_user_id ON rbac_access_attempts(user_id);
		CREATE INDEX IF NOT EXISTS idx_access_attempts_timestamp ON rbac_access_attempts(timestamp);
		CREATE INDEX IF NOT EXISTS idx_access_attempts_result ON rbac_access_attempts(result);
		CREATE INDEX IF NOT EXISTS idx_access_attempts_ip_address ON rbac_access_attempts(ip_address);
		CREATE INDEX IF NOT EXISTS idx_access_attempts_user_role ON rbac_access_attempts(user_role);
	`

	// Create security alerts table
	securityAlertsSQL := `
		CREATE TABLE IF NOT EXISTS rbac_security_alerts (
			id VARCHAR(36) PRIMARY KEY,
			alert_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			title VARCHAR(200) NOT NULL,
			description TEXT,
			user_id VARCHAR(100),
			resource_id VARCHAR(100),
			ip_address INET,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			related_events JSONB,
			metadata JSONB,
			status VARCHAR(20) DEFAULT 'new',
			acknowledged_by VARCHAR(100),
			acknowledged_at TIMESTAMP WITH TIME ZONE,
			resolved_by VARCHAR(100),
			resolved_at TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		
		CREATE INDEX IF NOT EXISTS idx_security_alerts_alert_type ON rbac_security_alerts(alert_type);
		CREATE INDEX IF NOT EXISTS idx_security_alerts_severity ON rbac_security_alerts(severity);
		CREATE INDEX IF NOT EXISTS idx_security_alerts_status ON rbac_security_alerts(status);
		CREATE INDEX IF NOT EXISTS idx_security_alerts_timestamp ON rbac_security_alerts(timestamp);
		CREATE INDEX IF NOT EXISTS idx_security_alerts_user_id ON rbac_security_alerts(user_id);
	`

	if _, err := am.db.Exec(accessAttemptsSQL); err != nil {
		return fmt.Errorf("failed to create access attempts table: %w", err)
	}

	if _, err := am.db.Exec(securityAlertsSQL); err != nil {
		return fmt.Errorf("failed to create security alerts table: %w", err)
	}

	return nil
}

func (am *AccessMonitor) processAccessAttempts(ctx context.Context) {
	defer am.wg.Done()

	for {
		select {
		case event := <-am.accessAttemptBuffer:
			if err := am.processAccessAttemptSync(event); err != nil {
				am.logger.WithError(err).Error("Failed to process access attempt")
			}
		case <-ctx.Done():
			am.logger.Info("Access attempt processor stopping")
			return
		case <-am.stopChan:
			am.logger.Info("Access attempt processor stopping")
			return
		}
	}
}

func (am *AccessMonitor) processAccessAttemptSync(event *AccessAttemptEvent) error {
	// Store access attempt in database
	if err := am.insertAccessAttempt(event); err != nil {
		return fmt.Errorf("failed to insert access attempt: %w", err)
	}

	// Update metrics
	am.mutex.Lock()
	am.metrics.TotalAccessAttempts++
	if event.Result == "allowed" {
		am.metrics.AllowedAttempts++
	} else {
		am.metrics.DeniedAttempts++
	}
	am.metrics.LastActivityTimestamp = event.Timestamp

	// Update average response time
	if am.metrics.TotalAccessAttempts == 1 {
		am.metrics.AverageResponseTime = event.ResponseTime
	} else {
		// Calculate running average
		totalTime := am.metrics.AverageResponseTime * time.Duration(am.metrics.TotalAccessAttempts-1)
		am.metrics.AverageResponseTime = (totalTime + event.ResponseTime) / time.Duration(am.metrics.TotalAccessAttempts)
	}
	am.mutex.Unlock()

	// Check for suspicious activity
	if suspicious, alertType := am.suspiciousDetector.AnalyzeAccessAttempt(event); suspicious {
		alert := am.createSecurityAlert(alertType, event)
		
		// Send alert to processing buffer
		select {
		case am.alertBuffer <- alert:
			// Successfully queued
		default:
			// Buffer full, process synchronously
			am.logger.Warn("Alert buffer full, processing alert synchronously")
			if err := am.processSecurityAlertSync(alert); err != nil {
				am.logger.WithError(err).Error("Failed to process security alert")
			}
		}
	}

	return nil
}

func (am *AccessMonitor) processAlerts(ctx context.Context) {
	defer am.wg.Done()

	for {
		select {
		case alert := <-am.alertBuffer:
			if err := am.processSecurityAlertSync(alert); err != nil {
				am.logger.WithError(err).Error("Failed to process security alert")
			}
		case <-ctx.Done():
			am.logger.Info("Alert processor stopping")
			return
		case <-am.stopChan:
			am.logger.Info("Alert processor stopping")
			return
		}
	}
}

func (am *AccessMonitor) processSecurityAlertSync(alert *SecurityAlert) error {
	// Store alert in database
	if err := am.insertSecurityAlert(alert); err != nil {
		return fmt.Errorf("failed to insert security alert: %w", err)
	}

	// Update metrics
	am.mutex.Lock()
	am.metrics.AlertsGenerated++
	am.mutex.Unlock()

	// Send real-time notification
	if err := am.alertManager.SendAlert(alert); err != nil {
		am.logger.WithError(err).Warn("Failed to send real-time alert notification")
	}

	am.logger.Warn("Security alert generated",
		"alert_id", alert.ID,
		"alert_type", alert.AlertType,
		"severity", alert.Severity,
		"user_id", alert.UserID,
		"resource_id", alert.ResourceID,
	)

	return nil
}

func (am *AccessMonitor) updateMetrics(ctx context.Context) {
	defer am.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Update buffer utilization and other real-time metrics
			am.mutex.Lock()
			am.metrics.BufferUtilization = float64(len(am.accessAttemptBuffer)) / float64(cap(am.accessAttemptBuffer)) * 100
			am.mutex.Unlock()
		case <-ctx.Done():
			am.logger.Info("Metrics updater stopping")
			return
		case <-am.stopChan:
			am.logger.Info("Metrics updater stopping")
			return
		}
	}
}

func (am *AccessMonitor) insertAccessAttempt(event *AccessAttemptEvent) error {
	contextJSON, err := json.Marshal(event.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	attributesJSON, err := json.Marshal(event.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO rbac_access_attempts 
		(id, user_id, resource_id, action, result, reason, ip_address, user_agent, 
		 timestamp, response_time_ms, user_role, resource_type, context, attributes, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = am.db.Exec(query,
		event.ID,
		event.UserID,
		event.ResourceID,
		event.Action,
		event.Result,
		event.Reason,
		am.nullString(event.IPAddress),
		am.nullString(event.UserAgent),
		event.Timestamp,
		event.ResponseTime.Milliseconds(),
		am.nullString(event.UserRole),
		am.nullString(event.ResourceType),
		contextJSON,
		attributesJSON,
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to insert access attempt: %w", err)
	}

	return nil
}

func (am *AccessMonitor) insertSecurityAlert(alert *SecurityAlert) error {
	relatedEventsJSON, err := json.Marshal(alert.RelatedEvents)
	if err != nil {
		return fmt.Errorf("failed to marshal related events: %w", err)
	}

	metadataJSON, err := json.Marshal(alert.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO rbac_security_alerts 
		(id, alert_type, severity, title, description, user_id, resource_id, 
		 ip_address, timestamp, related_events, metadata, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = am.db.Exec(query,
		alert.ID,
		alert.AlertType,
		alert.Severity,
		alert.Title,
		alert.Description,
		am.nullString(alert.UserID),
		am.nullString(alert.ResourceID),
		am.nullString(alert.IPAddress),
		alert.Timestamp,
		relatedEventsJSON,
		metadataJSON,
		alert.Status,
	)

	if err != nil {
		return fmt.Errorf("failed to insert security alert: %w", err)
	}

	return nil
}

func (am *AccessMonitor) createSecurityAlert(alertType AlertType, event *AccessAttemptEvent) *SecurityAlert {
	alert := &SecurityAlert{
		ID:            uuid.New().String(),
		AlertType:     string(alertType),
		UserID:        event.UserID,
		ResourceID:    event.ResourceID,
		IPAddress:     event.IPAddress,
		Timestamp:     time.Now(),
		RelatedEvents: []string{event.ID},
		Metadata:      make(map[string]interface{}),
		Status:        "new",
	}

	// Set alert details based on type
	switch alertType {
	case AlertTypeMultipleFailures:
		alert.Severity = string(SeverityHigh)
		alert.Title = "Multiple Access Failures Detected"
		alert.Description = fmt.Sprintf("User %s has multiple failed access attempts", event.UserID)
	case AlertTypeUnusualAccess:
		alert.Severity = string(SeverityMedium)
		alert.Title = "Unusual Access Pattern Detected"
		alert.Description = fmt.Sprintf("Unusual access pattern detected for user %s", event.UserID)
	case AlertTypePrivilegeEscalation:
		alert.Severity = string(SeverityCritical)
		alert.Title = "Potential Privilege Escalation"
		alert.Description = fmt.Sprintf("Potential privilege escalation attempt by user %s", event.UserID)
	case AlertTypeAfterHoursAccess:
		alert.Severity = string(SeverityMedium)
		alert.Title = "After Hours Access Attempt"
		alert.Description = fmt.Sprintf("After hours access attempt by user %s", event.UserID)
	case AlertTypeSuspiciousPattern:
		alert.Severity = string(SeverityHigh)
		alert.Title = "Suspicious Activity Pattern"
		alert.Description = fmt.Sprintf("Suspicious activity pattern detected for user %s", event.UserID)
	case AlertTypeRateLimitExceeded:
		alert.Severity = string(SeverityMedium)
		alert.Title = "Rate Limit Exceeded"
		alert.Description = fmt.Sprintf("Rate limit exceeded by user %s", event.UserID)
	case AlertTypeUnauthorizedResource:
		alert.Severity = string(SeverityHigh)
		alert.Title = "Unauthorized Resource Access"
		alert.Description = fmt.Sprintf("Unauthorized resource access attempt by user %s", event.UserID)
	case AlertTypePolicyViolation:
		alert.Severity = string(SeverityHigh)
		alert.Title = "Policy Violation Detected"
		alert.Description = fmt.Sprintf("Policy violation detected for user %s", event.UserID)
	case AlertTypeAnomalousActivity:
		alert.Severity = string(SeverityMedium)
		alert.Title = "Anomalous Activity Detected"
		alert.Description = fmt.Sprintf("Anomalous activity detected for user %s", event.UserID)
	default:
		alert.Severity = string(SeverityLow)
		alert.Title = "Security Event"
		alert.Description = fmt.Sprintf("Security event detected for user %s", event.UserID)
	}

	// Add event metadata to alert
	alert.Metadata["original_event"] = map[string]interface{}{
		"action":        event.Action,
		"result":        event.Result,
		"reason":        event.Reason,
		"user_role":     event.UserRole,
		"resource_type": event.ResourceType,
		"response_time": event.ResponseTime.String(),
	}

	return alert
}

func (am *AccessMonitor) getResultString(allowed bool) string {
	if allowed {
		return "allowed"
	}
	return "denied"
}

func (am *AccessMonitor) nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// Filter types for queries

// AccessAttemptFilter represents filters for access attempt queries
type AccessAttemptFilter struct {
	UserID      string    `json:"user_id,omitempty"`
	ResourceID  string    `json:"resource_id,omitempty"`
	Action      string    `json:"action,omitempty"`
	Result      string    `json:"result,omitempty"`
	UserRole    string    `json:"user_role,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	StartTime   time.Time `json:"start_time,omitempty"`
	EndTime     time.Time `json:"end_time,omitempty"`
	Limit       int       `json:"limit,omitempty"`
	Offset      int       `json:"offset,omitempty"`
}

// SecurityAlertFilter represents filters for security alert queries
type SecurityAlertFilter struct {
	AlertType string    `json:"alert_type,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	Status    string    `json:"status,omitempty"`
	UserID    string    `json:"user_id,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	Offset    int       `json:"offset,omitempty"`
}