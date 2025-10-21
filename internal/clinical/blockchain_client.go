package clinical

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// BlockchainClient implements blockchain operations for clinical notes
type BlockchainClient struct {
	config     *config.FabricConfig
	logger     *logger.Logger
	channelID  string
	accessPolicyCC string
	auditLogCC     string
}

// NewBlockchainClient creates a new blockchain client for clinical operations
func NewBlockchainClient(cfg *config.FabricConfig, log *logger.Logger) *BlockchainClient {
	return &BlockchainClient{
		config:         cfg,
		logger:         log,
		channelID:      cfg.ChannelName,
		accessPolicyCC: cfg.Chaincodes["access_policy"],
		auditLogCC:     cfg.Chaincodes["audit_log"],
	}
}

// CheckAccess validates user access via AccessPolicy chaincode
func (c *BlockchainClient) CheckAccess(userID, resourceID, action string) (bool, error) {
	c.logger.Info("Checking access via chaincode", "userID", userID, "resourceID", resourceID, "action", action)

	// Prepare chaincode invocation arguments
	args := []string{
		"CheckAccess",
		userID,
		resourceID,
		action,
	}

	// Query chaincode
	response, err := c.queryChaincode(c.accessPolicyCC, args)
	if err != nil {
		return false, fmt.Errorf("access check failed: %w", err)
	}

	// Parse response
	var result struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason,omitempty"`
	}

	if err := json.Unmarshal(response, &result); err != nil {
		return false, fmt.Errorf("failed to parse access check response: %w", err)
	}

	if !result.Allowed {
		c.logger.Warn("Access denied by chaincode", "userID", userID, "reason", result.Reason)
	}

	return result.Allowed, nil
}

// GetAccessToken retrieves PRE access token from chaincode
func (c *BlockchainClient) GetAccessToken(userID, resourceID string) (*types.AccessToken, error) {
	c.logger.Info("Getting access token from chaincode", "userID", userID, "resourceID", resourceID)

	args := []string{
		"GetAccessToken",
		userID,
		resourceID,
	}

	response, err := c.queryChaincode(c.accessPolicyCC, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get access token: %w", err)
	}

	if len(response) == 0 {
		return nil, nil // No token available
	}

	var token types.AccessToken
	if err := json.Unmarshal(response, &token); err != nil {
		return nil, fmt.Errorf("failed to parse access token: %w", err)
	}

	return &token, nil
}

// LogActivity logs an audit entry to the AuditLog chaincode
func (c *BlockchainClient) LogActivity(entry *types.AuditLogEntry) error {
	c.logger.Info("Logging activity to chaincode", "userID", entry.UserID, "action", entry.Action, "resourceID", entry.ResourceID)

	// Generate entry ID if not provided
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Marshal entry to JSON
	entryJSON, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal audit entry: %w", err)
	}

	args := []string{
		"LogActivity",
		string(entryJSON),
	}

	// Invoke chaincode
	_, err = c.invokeChaincode(c.auditLogCC, args)
	if err != nil {
		return fmt.Errorf("failed to log activity: %w", err)
	}

	c.logger.Info("Activity logged successfully", "entryID", entry.ID, "userID", entry.UserID)
	return nil
}

// GetAuditTrail retrieves audit trail for a resource
func (c *BlockchainClient) GetAuditTrail(resourceID string) ([]*types.AuditLogEntry, error) {
	c.logger.Info("Getting audit trail from chaincode", "resourceID", resourceID)

	args := []string{
		"GetAuditTrail",
		resourceID,
	}

	response, err := c.queryChaincode(c.auditLogCC, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit trail: %w", err)
	}

	var entries []*types.AuditLogEntry
	if err := json.Unmarshal(response, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse audit trail: %w", err)
	}

	return entries, nil
}

// StorePHIHash stores PHI hash on blockchain
func (c *BlockchainClient) StorePHIHash(hash *types.PHIHash) error {
	c.logger.Info("Storing PHI hash on chaincode", "hashID", hash.ID, "patientID", hash.PatientID)

	// Generate hash ID if not provided
	if hash.ID == "" {
		hash.ID = uuid.New().String()
	}

	// Set timestamp if not provided
	if hash.CreatedAt.IsZero() {
		hash.CreatedAt = time.Now()
	}

	// Marshal hash to JSON
	hashJSON, err := json.Marshal(hash)
	if err != nil {
		return fmt.Errorf("failed to marshal PHI hash: %w", err)
	}

	args := []string{
		"StorePHIHash",
		string(hashJSON),
	}

	// Invoke chaincode
	_, err = c.invokeChaincode(c.accessPolicyCC, args)
	if err != nil {
		return fmt.Errorf("failed to store PHI hash: %w", err)
	}

	c.logger.Info("PHI hash stored successfully", "hashID", hash.ID)
	return nil
}

// GetPHIHash retrieves PHI hash from blockchain
func (c *BlockchainClient) GetPHIHash(resourceID string) (*types.PHIHash, error) {
	c.logger.Info("Getting PHI hash from chaincode", "resourceID", resourceID)

	args := []string{
		"GetPHIHash",
		resourceID,
	}

	response, err := c.queryChaincode(c.accessPolicyCC, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get PHI hash: %w", err)
	}

	if len(response) == 0 {
		return nil, nil // No hash found
	}

	var hash types.PHIHash
	if err := json.Unmarshal(response, &hash); err != nil {
		return nil, fmt.Errorf("failed to parse PHI hash: %w", err)
	}

	return &hash, nil
}

// SubmitTransaction submits a transaction to chaincode
func (c *BlockchainClient) SubmitTransaction(chaincode, function string, args []string) (*types.ChaincodeTxResult, error) {
	c.logger.Info("Submitting transaction to chaincode", "chaincode", chaincode, "function", function)

	// Prepare full args with function name
	fullArgs := append([]string{function}, args...)

	// Invoke chaincode
	response, err := c.invokeChaincode(chaincode, fullArgs)
	if err != nil {
		return nil, fmt.Errorf("transaction submission failed: %w", err)
	}

	// Create transaction result
	result := &types.ChaincodeTxResult{
		TxID:      uuid.New().String(), // In real implementation, this would be the actual transaction ID
		Success:   true,
		Message:   "Transaction submitted successfully",
		Timestamp: time.Now(),
	}

	// Try to parse response data
	if len(response) > 0 {
		var data map[string]interface{}
		if err := json.Unmarshal(response, &data); err == nil {
			result.Data = data
		}
	}

	return result, nil
}

// QueryChaincode queries chaincode for read-only operations
func (c *BlockchainClient) QueryChaincode(chaincode, function string, args []string) ([]byte, error) {
	c.logger.Info("Querying chaincode", "chaincode", chaincode, "function", function)

	// Prepare full args with function name
	fullArgs := append([]string{function}, args...)

	return c.queryChaincode(chaincode, fullArgs)
}

// invokeChaincode invokes a chaincode function (for state-changing operations)
func (c *BlockchainClient) invokeChaincode(chaincode string, args []string) ([]byte, error) {
	// In a real implementation, this would use the Hyperledger Fabric SDK
	// to invoke the chaincode. For now, we'll simulate the response.
	
	c.logger.Info("Invoking chaincode", "chaincode", chaincode, "function", args[0], "args_count", len(args)-1)

	// Simulate chaincode response based on function
	switch args[0] {
	case "CheckAccess":
		// Simulate access validation - allow most operations for development
		response := map[string]interface{}{
			"allowed": true,
			"reason":  "Access granted by policy",
		}
		return json.Marshal(response)

	case "LogActivity":
		// Simulate audit log entry creation
		response := map[string]interface{}{
			"success":   true,
			"message":   "Activity logged successfully",
			"timestamp": time.Now().Format(time.RFC3339),
		}
		return json.Marshal(response)

	case "StorePHIHash":
		// Simulate PHI hash storage
		response := map[string]interface{}{
			"success":   true,
			"message":   "PHI hash stored successfully",
			"timestamp": time.Now().Format(time.RFC3339),
		}
		return json.Marshal(response)

	default:
		return nil, fmt.Errorf("unknown chaincode function: %s", args[0])
	}
}

// queryChaincode queries a chaincode function (for read-only operations)
func (c *BlockchainClient) queryChaincode(chaincode string, args []string) ([]byte, error) {
	// In a real implementation, this would use the Hyperledger Fabric SDK
	// to query the chaincode. For now, we'll simulate the response.
	
	c.logger.Info("Querying chaincode", "chaincode", chaincode, "function", args[0], "args_count", len(args)-1)

	switch args[0] {
	case "GetAccessToken":
		// Simulate access token retrieval
		if len(args) >= 3 {
			userID := args[1]
			resourceID := args[2]
			
			token := types.AccessToken{
				ID:         uuid.New().String(),
				UserID:     userID,
				ResourceID: resourceID,
				TokenType:  "PRE",
				Token:      "mock_pre_token_" + userID + "_" + resourceID,
				ExpiresAt:  time.Now().Add(24 * time.Hour),
				IssuedAt:   time.Now(),
			}
			return json.Marshal(token)
		}
		return []byte("{}"), nil

	case "GetAuditTrail":
		// Simulate audit trail retrieval
		if len(args) >= 2 {
			resourceID := args[1]
			
			entries := []*types.AuditLogEntry{
				{
					ID:           uuid.New().String(),
					UserID:       "mock_user",
					Action:       "create_clinical_note",
					ResourceID:   resourceID,
					ResourceType: "clinical_note",
					Timestamp:    time.Now().Add(-1 * time.Hour),
					Success:      true,
					Details: map[string]interface{}{
						"note_type": "progress_note",
					},
				},
			}
			return json.Marshal(entries)
		}
		return []byte("[]"), nil

	case "GetPHIHash":
		// Simulate PHI hash retrieval
		if len(args) >= 2 {
			resourceID := args[1]
			
			hash := types.PHIHash{
				ID:        resourceID,
				PatientID: "mock_patient_id",
				Hash:      "mock_hash_" + resourceID,
				Algorithm: "SHA-256",
				CreatedBy: "mock_user",
				CreatedAt: time.Now().Add(-1 * time.Hour),
			}
			return json.Marshal(hash)
		}
		return []byte("{}"), nil

	default:
		return nil, fmt.Errorf("unknown chaincode query function: %s", args[0])
	}
}

// ValidateUserRole validates user role via AccessPolicy chaincode
func (c *BlockchainClient) ValidateUserRole(userID string, requiredRole string) (bool, error) {
	c.logger.Info("Validating user role via chaincode", "userID", userID, "requiredRole", requiredRole)

	args := []string{
		"ValidateUserRole",
		userID,
		requiredRole,
	}

	response, err := c.queryChaincode(c.accessPolicyCC, args)
	if err != nil {
		return false, fmt.Errorf("role validation failed: %w", err)
	}

	var result struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason,omitempty"`
	}

	if err := json.Unmarshal(response, &result); err != nil {
		return false, fmt.Errorf("failed to parse role validation response: %w", err)
	}

	return result.Valid, nil
}

// CreateAccessPolicy creates a new access policy on blockchain
func (c *BlockchainClient) CreateAccessPolicy(policy *types.AccessPolicy) error {
	c.logger.Info("Creating access policy on chaincode", "policyID", policy.ID)

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal access policy: %w", err)
	}

	args := []string{
		"CreateAccessPolicy",
		string(policyJSON),
	}

	_, err = c.invokeChaincode(c.accessPolicyCC, args)
	if err != nil {
		return fmt.Errorf("failed to create access policy: %w", err)
	}

	c.logger.Info("Access policy created successfully", "policyID", policy.ID)
	return nil
}

// GetAccessPolicy retrieves an access policy from blockchain
func (c *BlockchainClient) GetAccessPolicy(resourceType, userRole string) (*types.AccessPolicy, error) {
	c.logger.Info("Getting access policy from chaincode", "resourceType", resourceType, "userRole", userRole)

	args := []string{
		"GetAccessPolicy",
		resourceType,
		userRole,
	}

	response, err := c.queryChaincode(c.accessPolicyCC, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get access policy: %w", err)
	}

	if len(response) == 0 {
		return nil, nil // No policy found
	}

	var policy types.AccessPolicy
	if err := json.Unmarshal(response, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse access policy: %w", err)
	}

	return &policy, nil
}

// LogUserActivity logs comprehensive user activity for audit
func (c *BlockchainClient) LogUserActivity(userID, action, resourceType, resourceID string, success bool, details map[string]interface{}, ipAddress, userAgent string) error {
	entry := &types.AuditLogEntry{
		ID:           uuid.New().String(),
		UserID:       userID,
		Action:       action,
		ResourceID:   resourceID,
		ResourceType: resourceType,
		Timestamp:    time.Now(),
		Success:      success,
		Details:      details,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
	}

	return c.LogActivity(entry)
}

// GetUserAuditTrail retrieves audit trail for a specific user
func (c *BlockchainClient) GetUserAuditTrail(userID string, limit int) ([]*types.AuditLogEntry, error) {
	c.logger.Info("Getting user audit trail from chaincode", "userID", userID)

	args := []string{
		"GetUserAuditTrail",
		userID,
		fmt.Sprintf("%d", limit),
	}

	response, err := c.queryChaincode(c.auditLogCC, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get user audit trail: %w", err)
	}

	var entries []*types.AuditLogEntry
	if err := json.Unmarshal(response, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse user audit trail: %w", err)
	}

	return entries, nil
}

// ValidateDataIntegrity validates data integrity using blockchain hash
func (c *BlockchainClient) ValidateDataIntegrity(resourceID, currentHash string) (bool, error) {
	c.logger.Info("Validating data integrity via chaincode", "resourceID", resourceID)

	// Get stored hash from blockchain
	storedHash, err := c.GetPHIHash(resourceID)
	if err != nil {
		return false, fmt.Errorf("failed to get stored hash: %w", err)
	}

	if storedHash == nil {
		return false, fmt.Errorf("no hash found for resource: %s", resourceID)
	}

	// Compare hashes
	isValid := storedHash.Hash == currentHash
	
	// Log integrity check
	c.LogActivity(&types.AuditLogEntry{
		ID:           uuid.New().String(),
		UserID:       "system",
		Action:       "validate_data_integrity",
		ResourceID:   resourceID,
		ResourceType: "phi_hash",
		Timestamp:    time.Now(),
		Success:      isValid,
		Details: map[string]interface{}{
			"stored_hash":  storedHash.Hash,
			"current_hash": currentHash,
			"valid":        isValid,
		},
	})

	return isValid, nil
}

// CreateReEncryptionToken creates a PRE token for secure data sharing
func (c *BlockchainClient) CreateReEncryptionToken(fromUserID, toUserID, resourceID string, expiresIn time.Duration) (*types.AccessToken, error) {
	c.logger.Info("Creating re-encryption token via chaincode", "fromUserID", fromUserID, "toUserID", toUserID, "resourceID", resourceID)

	token := &types.AccessToken{
		ID:         uuid.New().String(),
		UserID:     toUserID,
		ResourceID: resourceID,
		TokenType:  "PRE",
		Token:      fmt.Sprintf("pre_token_%s_%s_%s", fromUserID, toUserID, resourceID),
		ExpiresAt:  time.Now().Add(expiresIn),
		Metadata: map[string]string{
			"from_user_id": fromUserID,
			"to_user_id":   toUserID,
		},
		IssuedAt: time.Now(),
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal access token: %w", err)
	}

	args := []string{
		"CreateAccessToken",
		string(tokenJSON),
	}

	_, err = c.invokeChaincode(c.accessPolicyCC, args)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	// Log token creation
	c.LogActivity(&types.AuditLogEntry{
		ID:           uuid.New().String(),
		UserID:       fromUserID,
		Action:       "create_re_encryption_token",
		ResourceID:   resourceID,
		ResourceType: "access_token",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"token_id":     token.ID,
			"to_user_id":   toUserID,
			"expires_at":   token.ExpiresAt,
		},
	})

	c.logger.Info("Re-encryption token created successfully", "tokenID", token.ID)
	return token, nil
}

// RevokeAccessToken revokes an access token
func (c *BlockchainClient) RevokeAccessToken(tokenID, userID string) error {
	c.logger.Info("Revoking access token via chaincode", "tokenID", tokenID, "userID", userID)

	args := []string{
		"RevokeAccessToken",
		tokenID,
		userID,
	}

	_, err := c.invokeChaincode(c.accessPolicyCC, args)
	if err != nil {
		return fmt.Errorf("failed to revoke access token: %w", err)
	}

	// Log token revocation
	c.LogActivity(&types.AuditLogEntry{
		ID:           uuid.New().String(),
		UserID:       userID,
		Action:       "revoke_access_token",
		ResourceID:   tokenID,
		ResourceType: "access_token",
		Timestamp:    time.Now(),
		Success:      true,
		Details: map[string]interface{}{
			"token_id": tokenID,
		},
	})

	c.logger.Info("Access token revoked successfully", "tokenID", tokenID)
	return nil
}

// GetComplianceReport generates compliance report from audit logs
func (c *BlockchainClient) GetComplianceReport(startDate, endDate time.Time, resourceType string) (map[string]interface{}, error) {
	c.logger.Info("Generating compliance report from chaincode", "startDate", startDate, "endDate", endDate, "resourceType", resourceType)

	args := []string{
		"GetComplianceReport",
		startDate.Format(time.RFC3339),
		endDate.Format(time.RFC3339),
		resourceType,
	}

	response, err := c.queryChaincode(c.auditLogCC, args)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance report: %w", err)
	}

	var report map[string]interface{}
	if err := json.Unmarshal(response, &report); err != nil {
		return nil, fmt.Errorf("failed to parse compliance report: %w", err)
	}

	return report, nil
}

// Enhanced mock responses for new functions
func (c *BlockchainClient) enhancedQueryChaincode(chaincode string, args []string) ([]byte, error) {
	switch args[0] {
	case "ValidateUserRole":
		if len(args) >= 3 {
			result := struct {
				Valid  bool   `json:"valid"`
				Reason string `json:"reason,omitempty"`
			}{
				Valid: true, // Mock validation - always allow for development
			}
			return json.Marshal(result)
		}
		return []byte("{}"), nil

	case "GetAccessPolicy":
		if len(args) >= 3 {
			resourceType := args[1]
			userRole := args[2]
			
			policy := types.AccessPolicy{
				ID:           fmt.Sprintf("policy_%s_%s", resourceType, userRole),
				ResourceType: resourceType,
				UserRole:     userRole,
				Actions:      []string{"create", "read", "update", "delete"},
				Conditions:   map[string]string{},
				CreatedBy:    "system",
				CreatedAt:    time.Now(),
			}
			return json.Marshal(policy)
		}
		return []byte("{}"), nil

	case "GetUserAuditTrail":
		if len(args) >= 2 {
			userID := args[1]
			
			entries := []*types.AuditLogEntry{
				{
					ID:           uuid.New().String(),
					UserID:       userID,
					Action:       "login",
					ResourceID:   userID,
					ResourceType: "user",
					Timestamp:    time.Now().Add(-2 * time.Hour),
					Success:      true,
					Details: map[string]interface{}{
						"login_method": "certificate",
					},
				},
				{
					ID:           uuid.New().String(),
					UserID:       userID,
					Action:       "read_clinical_note",
					ResourceID:   "note_123",
					ResourceType: "clinical_note",
					Timestamp:    time.Now().Add(-1 * time.Hour),
					Success:      true,
					Details: map[string]interface{}{
						"patient_id": "patient_456",
					},
				},
			}
			return json.Marshal(entries)
		}
		return []byte("[]"), nil

	case "GetComplianceReport":
		if len(args) >= 4 {
			report := map[string]interface{}{
				"period": map[string]string{
					"start": args[1],
					"end":   args[2],
				},
				"resource_type": args[3],
				"summary": map[string]interface{}{
					"total_activities":     150,
					"successful_activities": 148,
					"failed_activities":    2,
					"unique_users":         25,
				},
				"activities_by_action": map[string]int{
					"create_clinical_note": 45,
					"read_clinical_note":   80,
					"update_clinical_note": 20,
					"delete_clinical_note": 3,
					"login":                25,
				},
				"compliance_status": "COMPLIANT",
			}
			return json.Marshal(report)
		}
		return []byte("{}"), nil

	default:
		// Fall back to original query function
		return c.queryChaincode(chaincode, args)
	}
}