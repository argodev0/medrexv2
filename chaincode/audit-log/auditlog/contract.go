package auditlog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SmartContract provides functions for managing audit logs
type SmartContract struct {
	contractapi.Contract
}

// AuditLogEntry represents an immutable audit log entry
type AuditLogEntry struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	UserRole   string                 `json:"user_role"`
	Action     string                 `json:"action"`
	ResourceID string                 `json:"resource_id"`
	ResourceType string               `json:"resource_type"`
	Timestamp  time.Time              `json:"timestamp"`
	Success    bool                   `json:"success"`
	Details    map[string]interface{} `json:"details"`
	Signature  string                 `json:"signature"`
	TxID       string                 `json:"tx_id"`
	BlockNumber uint64                `json:"block_number"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
}

// AuditEventType represents different types of audit events
type AuditEventType string

const (
	EventUserLogin          AuditEventType = "user_login"
	EventUserLogout         AuditEventType = "user_logout"
	EventPHIAccess          AuditEventType = "phi_access"
	EventPHICreate          AuditEventType = "phi_create"
	EventPHIUpdate          AuditEventType = "phi_update"
	EventPHIDelete          AuditEventType = "phi_delete"
	EventCPOECreate         AuditEventType = "cpoe_create"
	EventCPOEApprove        AuditEventType = "cpoe_approve"
	EventAppointmentCreate  AuditEventType = "appointment_create"
	EventAppointmentUpdate  AuditEventType = "appointment_update"
	EventAppointmentCancel  AuditEventType = "appointment_cancel"
	EventSystemAccess       AuditEventType = "system_access"
	EventDataExport         AuditEventType = "data_export"
	EventConfigChange       AuditEventType = "config_change"
	EventSecurityViolation  AuditEventType = "security_violation"
)

// QueryFilter represents filters for audit log queries
type QueryFilter struct {
	UserID       string    `json:"user_id,omitempty"`
	Action       string    `json:"action,omitempty"`
	ResourceType string    `json:"resource_type,omitempty"`
	ResourceID   string    `json:"resource_id,omitempty"`
	StartTime    time.Time `json:"start_time,omitempty"`
	EndTime      time.Time `json:"end_time,omitempty"`
	Success      *bool     `json:"success,omitempty"`
}

// InitLedger initializes the audit log ledger
func (s *SmartContract) InitLedger(ctx contractapi.TransactionContextInterface) error {
	// Create initial audit entry for system initialization
	callerID, err := s.getCallerIdentity(ctx)
	if err != nil {
		callerID = "system"
	}

	initEntry := AuditLogEntry{
		ID:           s.generateAuditID("system_init", time.Now()),
		UserID:       callerID,
		UserRole:     "administrator",
		Action:       "system_init",
		ResourceID:   "audit_log_chaincode",
		ResourceType: "system",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"event": "Audit log chaincode initialized",
			"version": "1.0.0",
		},
		TxID: ctx.GetStub().GetTxID(),
	}

	// Generate signature for the entry
	signature, err := s.generateEntrySignature(initEntry)
	if err != nil {
		return fmt.Errorf("failed to generate signature: %v", err)
	}
	initEntry.Signature = signature

	// Store the initial entry
	entryJSON, err := json.Marshal(initEntry)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(initEntry.ID, entryJSON)
}

// LogUserLogin logs a user login event
func (s *SmartContract) LogUserLogin(ctx contractapi.TransactionContextInterface, userID, userRole, ipAddress, userAgent string, success bool) error {
	details := map[string]interface{}{
		"event_type": string(EventUserLogin),
		"ip_address": ipAddress,
		"user_agent": userAgent,
	}

	if !success {
		details["failure_reason"] = "Authentication failed"
	}

	return s.createAuditEntry(ctx, userID, userRole, string(EventUserLogin), "user_session", userID, success, details, ipAddress, userAgent)
}

// LogUserLogout logs a user logout event
func (s *SmartContract) LogUserLogout(ctx contractapi.TransactionContextInterface, userID, userRole, ipAddress string, success bool) error {
	details := map[string]interface{}{
		"event_type": string(EventUserLogout),
		"ip_address": ipAddress,
	}

	return s.createAuditEntry(ctx, userID, userRole, string(EventUserLogout), "user_session", userID, success, details, ipAddress, "")
}

// LogPHIAccess logs PHI access events
func (s *SmartContract) LogPHIAccess(ctx contractapi.TransactionContextInterface, userID, userRole, resourceID, action, ipAddress string, success bool, additionalDetails map[string]interface{}) error {
	details := map[string]interface{}{
		"event_type": string(EventPHIAccess),
		"access_type": action,
		"ip_address": ipAddress,
	}

	// Merge additional details
	for k, v := range additionalDetails {
		details[k] = v
	}

	return s.createAuditEntry(ctx, userID, userRole, string(EventPHIAccess), "phi", resourceID, success, details, ipAddress, "")
}

// LogCPOEEntry logs CPOE (Computerized Provider Order Entry) events
func (s *SmartContract) LogCPOEEntry(ctx contractapi.TransactionContextInterface, userID, userRole, orderID, orderType, patientID string, requiresCoSign bool, success bool) error {
	details := map[string]interface{}{
		"event_type": string(EventCPOECreate),
		"order_type": orderType,
		"patient_id": patientID,
		"requires_cosign": requiresCoSign,
	}

	return s.createAuditEntry(ctx, userID, userRole, string(EventCPOECreate), "cpoe_order", orderID, success, details, "", "")
}

// LogDataModification logs data modification events
func (s *SmartContract) LogDataModification(ctx contractapi.TransactionContextInterface, userID, userRole, resourceID, resourceType, action string, success bool, changes map[string]interface{}) error {
	details := map[string]interface{}{
		"event_type": "data_modification",
		"modification_type": action,
		"changes": changes,
	}

	return s.createAuditEntry(ctx, userID, userRole, action, resourceType, resourceID, success, details, "", "")
}

// LogSecurityViolation logs security violation events
func (s *SmartContract) LogSecurityViolation(ctx contractapi.TransactionContextInterface, userID, userRole, violationType, description, ipAddress string) error {
	details := map[string]interface{}{
		"event_type": string(EventSecurityViolation),
		"violation_type": violationType,
		"description": description,
		"ip_address": ipAddress,
		"severity": "high",
	}

	return s.createAuditEntry(ctx, userID, userRole, string(EventSecurityViolation), "security", "violation_"+s.generateTimestamp(), false, details, ipAddress, "")
}

// GetAuditEntry retrieves a specific audit entry by ID
func (s *SmartContract) GetAuditEntry(ctx contractapi.TransactionContextInterface, entryID string) (*AuditLogEntry, error) {
	entryJSON, err := ctx.GetStub().GetState(entryID)
	if err != nil {
		return nil, fmt.Errorf("failed to read audit entry from world state: %v", err)
	}
	if entryJSON == nil {
		return nil, fmt.Errorf("audit entry %s does not exist", entryID)
	}

	var entry AuditLogEntry
	err = json.Unmarshal(entryJSON, &entry)
	if err != nil {
		return nil, err
	}

	return &entry, nil
}

// QueryAuditLogs queries audit logs based on filters
func (s *SmartContract) QueryAuditLogs(ctx contractapi.TransactionContextInterface, filterJSON string) ([]*AuditLogEntry, error) {
	var filter QueryFilter
	if filterJSON != "" {
		err := json.Unmarshal([]byte(filterJSON), &filter)
		if err != nil {
			return nil, fmt.Errorf("invalid filter JSON: %v", err)
		}
	}

	// Build CouchDB query
	query := s.buildCouchDBQuery(filter)
	
	resultsIterator, err := ctx.GetStub().GetQueryResult(query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %v", err)
	}
	defer resultsIterator.Close()

	var entries []*AuditLogEntry
	for resultsIterator.HasNext() {
		queryResponse, err := resultsIterator.Next()
		if err != nil {
			return nil, err
		}

		var entry AuditLogEntry
		err = json.Unmarshal(queryResponse.Value, &entry)
		if err != nil {
			return nil, err
		}

		entries = append(entries, &entry)
	}

	return entries, nil
}

// GetAuditTrailByUser retrieves audit trail for a specific user
func (s *SmartContract) GetAuditTrailByUser(ctx contractapi.TransactionContextInterface, userID string, startTime, endTime int64) ([]*AuditLogEntry, error) {
	filter := QueryFilter{
		UserID: userID,
	}

	if startTime > 0 {
		filter.StartTime = time.Unix(startTime, 0)
	}
	if endTime > 0 {
		filter.EndTime = time.Unix(endTime, 0)
	}

	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return nil, err
	}

	return s.QueryAuditLogs(ctx, string(filterJSON))
}

// GetAuditTrailByResource retrieves audit trail for a specific resource
func (s *SmartContract) GetAuditTrailByResource(ctx contractapi.TransactionContextInterface, resourceType, resourceID string, startTime, endTime int64) ([]*AuditLogEntry, error) {
	filter := QueryFilter{
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}

	if startTime > 0 {
		filter.StartTime = time.Unix(startTime, 0)
	}
	if endTime > 0 {
		filter.EndTime = time.Unix(endTime, 0)
	}

	filterJSON, err := json.Marshal(filter)
	if err != nil {
		return nil, err
	}

	return s.QueryAuditLogs(ctx, string(filterJSON))
}

// VerifyAuditIntegrity verifies the integrity of an audit entry
func (s *SmartContract) VerifyAuditIntegrity(ctx contractapi.TransactionContextInterface, entryID string) (bool, error) {
	entry, err := s.GetAuditEntry(ctx, entryID)
	if err != nil {
		return false, err
	}

	// Regenerate signature and compare
	expectedSignature, err := s.generateEntrySignature(*entry)
	if err != nil {
		return false, fmt.Errorf("failed to generate signature for verification: %v", err)
	}

	return entry.Signature == expectedSignature, nil
}

// Helper functions

// createAuditEntry creates a new audit log entry
func (s *SmartContract) createAuditEntry(ctx contractapi.TransactionContextInterface, userID, userRole, action, resourceType, resourceID string, success bool, details map[string]interface{}, ipAddress, userAgent string) error {
	timestamp := time.Now()
	entryID := s.generateAuditID(action+"_"+userID, timestamp)

	entry := AuditLogEntry{
		ID:           entryID,
		UserID:       userID,
		UserRole:     userRole,
		Action:       action,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Timestamp:    timestamp,
		Success:      success,
		Details:      details,
		TxID:         ctx.GetStub().GetTxID(),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	}

	// Generate cryptographic signature
	signature, err := s.generateEntrySignature(entry)
	if err != nil {
		return fmt.Errorf("failed to generate signature: %v", err)
	}
	entry.Signature = signature

	// Store the entry
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	return ctx.GetStub().PutState(entryID, entryJSON)
}

// generateAuditID generates a unique audit entry ID
func (s *SmartContract) generateAuditID(prefix string, timestamp time.Time) string {
	// Create deterministic ID based on prefix and timestamp
	input := fmt.Sprintf("%s_%d_%d", prefix, timestamp.Unix(), timestamp.Nanosecond())
	hash := sha256.Sum256([]byte(input))
	return "audit_" + hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter ID
}

// generateEntrySignature generates a cryptographic signature for an audit entry
func (s *SmartContract) generateEntrySignature(entry AuditLogEntry) (string, error) {
	// Create signature input (exclude signature field itself)
	signatureInput := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%d|%t|%s",
		entry.ID,
		entry.UserID,
		entry.UserRole,
		entry.Action,
		entry.ResourceID,
		entry.ResourceType,
		entry.Timestamp.Unix(),
		entry.Success,
		entry.TxID,
	)

	// Add details to signature input
	if entry.Details != nil {
		detailsJSON, err := json.Marshal(entry.Details)
		if err == nil {
			signatureInput += "|" + string(detailsJSON)
		}
	}

	// Generate SHA-256 hash as signature
	hash := sha256.Sum256([]byte(signatureInput))
	return hex.EncodeToString(hash[:]), nil
}

// getCallerIdentity gets the identity of the transaction caller
func (s *SmartContract) getCallerIdentity(ctx contractapi.TransactionContextInterface) (string, error) {
	clientIdentity := ctx.GetClientIdentity()
	id, err := clientIdentity.GetID()
	if err != nil {
		return "", fmt.Errorf("failed to get client ID: %v", err)
	}
	return id, nil
}

// generateTimestamp generates a timestamp string
func (s *SmartContract) generateTimestamp() string {
	return strconv.FormatInt(time.Now().UnixNano(), 10)
}

// buildCouchDBQuery builds a CouchDB query based on filters
func (s *SmartContract) buildCouchDBQuery(filter QueryFilter) string {
	query := map[string]interface{}{
		"selector": map[string]interface{}{},
		"sort": []map[string]string{
			{"timestamp": "desc"},
		},
	}

	selector := query["selector"].(map[string]interface{})

	if filter.UserID != "" {
		selector["user_id"] = filter.UserID
	}

	if filter.Action != "" {
		selector["action"] = filter.Action
	}

	if filter.ResourceType != "" {
		selector["resource_type"] = filter.ResourceType
	}

	if filter.ResourceID != "" {
		selector["resource_id"] = filter.ResourceID
	}

	if filter.Success != nil {
		selector["success"] = *filter.Success
	}

	// Add time range filter
	if !filter.StartTime.IsZero() || !filter.EndTime.IsZero() {
		timeFilter := map[string]interface{}{}
		
		if !filter.StartTime.IsZero() {
			timeFilter["$gte"] = filter.StartTime.Format(time.RFC3339)
		}
		
		if !filter.EndTime.IsZero() {
			timeFilter["$lte"] = filter.EndTime.Format(time.RFC3339)
		}
		
		selector["timestamp"] = timeFilter
	}

	queryJSON, _ := json.Marshal(query)
	return string(queryJSON)
}