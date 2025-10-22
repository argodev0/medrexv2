package rbac

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// AuditLogger implements comprehensive RBAC audit logging
type AuditLogger struct {
	db     *sql.DB
	logger *logrus.Logger
	config *Config
}

// NewAuditLogger creates a new audit logger instance
func NewAuditLogger(config *Config, logger *logrus.Logger) (*AuditLogger, error) {
	db, err := sql.Open("postgres", config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	auditLogger := &AuditLogger{
		db:     db,
		logger: logger,
		config: config,
	}

	// Initialize audit tables
	if err := auditLogger.initializeTables(); err != nil {
		return nil, fmt.Errorf("failed to initialize audit tables: %w", err)
	}

	return auditLogger, nil
}

// LogAccessAttempt logs an access attempt with the decision
func (a *AuditLogger) LogAccessAttempt(ctx context.Context, req *rbac.AccessRequest, decision *rbac.AccessDecision) error {
	entry := &rbac.AuditEntry{
		ID:         uuid.New().String(),
		EventType:  rbac.AuditEventAccessAttempt,
		UserID:     req.UserID,
		ResourceID: req.ResourceID,
		Action:     req.Action,
		Result:     a.getResultString(decision.Allowed),
		Timestamp:  time.Now(),
		Metadata: map[string]interface{}{
			"decision_reason":   decision.Reason,
			"decision_conditions": decision.Conditions,
			"request_context":   req.Context,
			"request_attributes": req.Attributes,
			"decision_ttl":      decision.TTL.String(),
		},
	}

	// Extract IP address and user agent from context if available
	if ipAddr, ok := ctx.Value("ip_address").(string); ok {
		entry.IPAddress = ipAddr
	}
	if userAgent, ok := ctx.Value("user_agent").(string); ok {
		entry.UserAgent = userAgent
	}

	return a.insertAuditEntry(entry)
}

// LogPolicyChange logs a policy change event
func (a *AuditLogger) LogPolicyChange(ctx context.Context, change *rbac.PolicyChange) error {
	entry := &rbac.AuditEntry{
		ID:        uuid.New().String(),
		EventType: rbac.AuditEventPolicyChange,
		UserID:    change.ChangedBy,
		Action:    change.ChangeType,
		Result:    "success",
		Timestamp: change.Timestamp,
		Metadata: map[string]interface{}{
			"policy_id":     change.PolicyID,
			"change_reason": change.Reason,
			"change_metadata": change.Metadata,
		},
	}

	// Include policy details based on change type
	if change.OldPolicy != nil {
		entry.Metadata["old_policy_version"] = change.OldPolicy.Version
		entry.Metadata["old_policy_name"] = change.OldPolicy.Name
	}
	if change.NewPolicy != nil {
		entry.Metadata["new_policy_version"] = change.NewPolicy.Version
		entry.Metadata["new_policy_name"] = change.NewPolicy.Name
		entry.ResourceID = change.NewPolicy.ID
	}

	// Store detailed policy changes in separate table
	if err := a.insertPolicyChange(change); err != nil {
		a.logger.WithError(err).Warn("Failed to insert detailed policy change")
	}

	return a.insertAuditEntry(entry)
}

// LogEmergencyOverride logs an emergency override event
func (a *AuditLogger) LogEmergencyOverride(ctx context.Context, override *rbac.EmergencyOverrideRequest) error {
	entry := &rbac.AuditEntry{
		ID:         uuid.New().String(),
		EventType:  rbac.AuditEventEmergencyOverride,
		UserID:     override.UserID,
		ResourceID: override.ResourceID,
		Action:     override.Action,
		Result:     "override_requested",
		Timestamp:  override.Timestamp,
		Metadata: map[string]interface{}{
			"override_reason":      override.Reason,
			"override_justification": override.Justification,
			"override_metadata":    override.Metadata,
		},
	}

	// Extract IP address from context if available
	if ipAddr, ok := ctx.Value("ip_address").(string); ok {
		entry.IPAddress = ipAddr
	}

	return a.insertAuditEntry(entry)
}

// GetAuditTrail retrieves audit entries based on filter criteria
func (a *AuditLogger) GetAuditTrail(ctx context.Context, filter *rbac.AuditFilter) ([]*rbac.AuditEntry, error) {
	query := `
		SELECT id, event_type, user_id, resource_id, action, result, timestamp, 
		       ip_address, user_agent, metadata
		FROM rbac_audit_log 
		WHERE 1=1`
	
	args := []interface{}{}
	argIndex := 1

	// Build dynamic WHERE clause based on filter
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

	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit trail: %w", err)
	}
	defer rows.Close()

	var entries []*rbac.AuditEntry
	for rows.Next() {
		entry := &rbac.AuditEntry{}
		var metadataJSON []byte
		var ipAddress, userAgent sql.NullString

		err := rows.Scan(
			&entry.ID,
			&entry.EventType,
			&entry.UserID,
			&entry.ResourceID,
			&entry.Action,
			&entry.Result,
			&entry.Timestamp,
			&ipAddress,
			&userAgent,
			&metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit entry: %w", err)
		}

		if ipAddress.Valid {
			entry.IPAddress = ipAddress.String
		}
		if userAgent.Valid {
			entry.UserAgent = userAgent.String
		}

		if len(metadataJSON) > 0 {
			if err := json.Unmarshal(metadataJSON, &entry.Metadata); err != nil {
				a.logger.WithError(err).Warn("Failed to unmarshal audit entry metadata")
				entry.Metadata = make(map[string]interface{})
			}
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

// GetPolicyAuditTrail retrieves policy-specific audit trail
func (a *AuditLogger) GetPolicyAuditTrail(ctx context.Context, policyID string, limit int) ([]*rbac.PolicyChange, error) {
	query := `
		SELECT policy_id, change_type, changed_by, timestamp, reason, 
		       old_policy, new_policy, metadata
		FROM rbac_policy_changes 
		WHERE policy_id = $1 
		ORDER BY timestamp DESC`
	
	args := []interface{}{policyID}
	if limit > 0 {
		query += " LIMIT $2"
		args = append(args, limit)
	}

	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query policy audit trail: %w", err)
	}
	defer rows.Close()

	var changes []*rbac.PolicyChange
	for rows.Next() {
		change := &rbac.PolicyChange{}
		var oldPolicyJSON, newPolicyJSON, metadataJSON sql.NullString

		err := rows.Scan(
			&change.PolicyID,
			&change.ChangeType,
			&change.ChangedBy,
			&change.Timestamp,
			&change.Reason,
			&oldPolicyJSON,
			&newPolicyJSON,
			&metadataJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan policy change: %w", err)
		}

		// Unmarshal policy JSON if present
		if oldPolicyJSON.Valid && oldPolicyJSON.String != "" {
			change.OldPolicy = &rbac.AccessPolicy{}
			if err := json.Unmarshal([]byte(oldPolicyJSON.String), change.OldPolicy); err != nil {
				a.logger.WithError(err).Warn("Failed to unmarshal old policy JSON")
			}
		}

		if newPolicyJSON.Valid && newPolicyJSON.String != "" {
			change.NewPolicy = &rbac.AccessPolicy{}
			if err := json.Unmarshal([]byte(newPolicyJSON.String), change.NewPolicy); err != nil {
				a.logger.WithError(err).Warn("Failed to unmarshal new policy JSON")
			}
		}

		if metadataJSON.Valid && metadataJSON.String != "" {
			if err := json.Unmarshal([]byte(metadataJSON.String), &change.Metadata); err != nil {
				a.logger.WithError(err).Warn("Failed to unmarshal policy change metadata")
				change.Metadata = make(map[string]interface{})
			}
		}

		changes = append(changes, change)
	}

	return changes, nil
}

// GenerateComplianceReport generates a compliance report for a given time period
func (a *AuditLogger) GenerateComplianceReport(ctx context.Context, startTime, endTime time.Time) (*rbac.ComplianceReport, error) {
	report := &rbac.ComplianceReport{
		StartTime:   startTime,
		EndTime:     endTime,
		GeneratedAt: time.Now(),
	}

	// Get access attempt statistics
	accessStats, err := a.getAccessStatistics(ctx, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get access statistics: %w", err)
	}
	report.AccessStatistics = accessStats

	// Get policy change statistics
	policyStats, err := a.getPolicyChangeStatistics(ctx, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get policy change statistics: %w", err)
	}
	report.PolicyChanges = policyStats

	// Get emergency override statistics
	overrideStats, err := a.getEmergencyOverrideStatistics(ctx, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get emergency override statistics: %w", err)
	}
	report.EmergencyOverrides = overrideStats

	// Get role-based access patterns
	rolePatterns, err := a.getRoleAccessPatterns(ctx, startTime, endTime)
	if err != nil {
		return nil, fmt.Errorf("failed to get role access patterns: %w", err)
	}
	report.RoleAccessPatterns = rolePatterns

	return report, nil
}

// Helper methods

func (a *AuditLogger) initializeTables() error {
	// Create audit log table
	auditTableSQL := `
		CREATE TABLE IF NOT EXISTS rbac_audit_log (
			id VARCHAR(36) PRIMARY KEY,
			event_type VARCHAR(50) NOT NULL,
			user_id VARCHAR(100) NOT NULL,
			resource_id VARCHAR(100),
			action VARCHAR(50) NOT NULL,
			result VARCHAR(20) NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			ip_address INET,
			user_agent TEXT,
			metadata JSONB,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		
		CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON rbac_audit_log(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON rbac_audit_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON rbac_audit_log(event_type);
		CREATE INDEX IF NOT EXISTS idx_audit_log_result ON rbac_audit_log(result);
	`

	// Create policy changes table
	policyTableSQL := `
		CREATE TABLE IF NOT EXISTS rbac_policy_changes (
			id SERIAL PRIMARY KEY,
			policy_id VARCHAR(100) NOT NULL,
			change_type VARCHAR(20) NOT NULL,
			changed_by VARCHAR(100) NOT NULL,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			reason TEXT,
			old_policy JSONB,
			new_policy JSONB,
			metadata JSONB,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);
		
		CREATE INDEX IF NOT EXISTS idx_policy_changes_policy_id ON rbac_policy_changes(policy_id);
		CREATE INDEX IF NOT EXISTS idx_policy_changes_timestamp ON rbac_policy_changes(timestamp);
		CREATE INDEX IF NOT EXISTS idx_policy_changes_changed_by ON rbac_policy_changes(changed_by);
	`

	if _, err := a.db.Exec(auditTableSQL); err != nil {
		return fmt.Errorf("failed to create audit log table: %w", err)
	}

	if _, err := a.db.Exec(policyTableSQL); err != nil {
		return fmt.Errorf("failed to create policy changes table: %w", err)
	}

	return nil
}

func (a *AuditLogger) insertAuditEntry(entry *rbac.AuditEntry) error {
	metadataJSON, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO rbac_audit_log 
		(id, event_type, user_id, resource_id, action, result, timestamp, ip_address, user_agent, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err = a.db.Exec(query,
		entry.ID,
		entry.EventType,
		entry.UserID,
		entry.ResourceID,
		entry.Action,
		entry.Result,
		entry.Timestamp,
		a.nullString(entry.IPAddress),
		a.nullString(entry.UserAgent),
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}

	return nil
}

func (a *AuditLogger) insertPolicyChange(change *rbac.PolicyChange) error {
	var oldPolicyJSON, newPolicyJSON []byte
	var err error

	if change.OldPolicy != nil {
		oldPolicyJSON, err = json.Marshal(change.OldPolicy)
		if err != nil {
			return fmt.Errorf("failed to marshal old policy: %w", err)
		}
	}

	if change.NewPolicy != nil {
		newPolicyJSON, err = json.Marshal(change.NewPolicy)
		if err != nil {
			return fmt.Errorf("failed to marshal new policy: %w", err)
		}
	}

	metadataJSON, err := json.Marshal(change.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO rbac_policy_changes 
		(policy_id, change_type, changed_by, timestamp, reason, old_policy, new_policy, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err = a.db.Exec(query,
		change.PolicyID,
		change.ChangeType,
		change.ChangedBy,
		change.Timestamp,
		change.Reason,
		a.nullBytes(oldPolicyJSON),
		a.nullBytes(newPolicyJSON),
		metadataJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to insert policy change: %w", err)
	}

	return nil
}

func (a *AuditLogger) getResultString(allowed bool) string {
	if allowed {
		return "allowed"
	}
	return "denied"
}

func (a *AuditLogger) nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

func (a *AuditLogger) nullBytes(b []byte) sql.NullString {
	return sql.NullString{String: string(b), Valid: len(b) > 0}
}

func (a *AuditLogger) getAccessStatistics(ctx context.Context, startTime, endTime time.Time) (*rbac.AccessStatistics, error) {
	query := `
		SELECT 
			COUNT(*) as total_attempts,
			COUNT(CASE WHEN result = 'allowed' THEN 1 END) as allowed_attempts,
			COUNT(CASE WHEN result = 'denied' THEN 1 END) as denied_attempts,
			COUNT(DISTINCT user_id) as unique_users,
			COUNT(DISTINCT resource_id) as unique_resources
		FROM rbac_audit_log 
		WHERE event_type = $1 AND timestamp BETWEEN $2 AND $3
	`

	stats := &rbac.AccessStatistics{}
	err := a.db.QueryRowContext(ctx, query, rbac.AuditEventAccessAttempt, startTime, endTime).Scan(
		&stats.TotalAttempts,
		&stats.AllowedAttempts,
		&stats.DeniedAttempts,
		&stats.UniqueUsers,
		&stats.UniqueResources,
	)

	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (a *AuditLogger) getPolicyChangeStatistics(ctx context.Context, startTime, endTime time.Time) (*rbac.PolicyChangeStatistics, error) {
	query := `
		SELECT 
			COUNT(*) as total_changes,
			COUNT(CASE WHEN change_type = 'create' THEN 1 END) as created_policies,
			COUNT(CASE WHEN change_type = 'update' THEN 1 END) as updated_policies,
			COUNT(CASE WHEN change_type = 'delete' THEN 1 END) as deleted_policies,
			COUNT(DISTINCT changed_by) as unique_administrators
		FROM rbac_policy_changes 
		WHERE timestamp BETWEEN $1 AND $2
	`

	stats := &rbac.PolicyChangeStatistics{}
	err := a.db.QueryRowContext(ctx, query, startTime, endTime).Scan(
		&stats.TotalChanges,
		&stats.CreatedPolicies,
		&stats.UpdatedPolicies,
		&stats.DeletedPolicies,
		&stats.UniqueAdministrators,
	)

	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (a *AuditLogger) getEmergencyOverrideStatistics(ctx context.Context, startTime, endTime time.Time) (*rbac.EmergencyOverrideStatistics, error) {
	query := `
		SELECT 
			COUNT(*) as total_overrides,
			COUNT(DISTINCT user_id) as unique_users,
			COUNT(DISTINCT resource_id) as unique_resources
		FROM rbac_audit_log 
		WHERE event_type = $1 AND timestamp BETWEEN $2 AND $3
	`

	stats := &rbac.EmergencyOverrideStatistics{}
	err := a.db.QueryRowContext(ctx, query, rbac.AuditEventEmergencyOverride, startTime, endTime).Scan(
		&stats.TotalOverrides,
		&stats.UniqueUsers,
		&stats.UniqueResources,
	)

	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (a *AuditLogger) getRoleAccessPatterns(ctx context.Context, startTime, endTime time.Time) (map[string]*rbac.RoleAccessPattern, error) {
	query := `
		SELECT 
			metadata->>'role' as role,
			COUNT(*) as total_attempts,
			COUNT(CASE WHEN result = 'allowed' THEN 1 END) as allowed_attempts,
			COUNT(CASE WHEN result = 'denied' THEN 1 END) as denied_attempts
		FROM rbac_audit_log 
		WHERE event_type = $1 AND timestamp BETWEEN $2 AND $3 
		  AND metadata->>'role' IS NOT NULL
		GROUP BY metadata->>'role'
	`

	rows, err := a.db.QueryContext(ctx, query, rbac.AuditEventAccessAttempt, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	patterns := make(map[string]*rbac.RoleAccessPattern)
	for rows.Next() {
		var role string
		pattern := &rbac.RoleAccessPattern{}

		err := rows.Scan(
			&role,
			&pattern.TotalAttempts,
			&pattern.AllowedAttempts,
			&pattern.DeniedAttempts,
		)
		if err != nil {
			return nil, err
		}

		patterns[role] = pattern
	}

	return patterns, nil
}

