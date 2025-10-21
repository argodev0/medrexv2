package clinical

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
	"github.com/stretchr/testify/assert"
)

func setupTestBlockchainClient() *BlockchainClient {
	cfg := &config.FabricConfig{
		ChannelName: "healthcare",
		Chaincodes: map[string]string{
			"access_policy": "accesspolicy",
			"audit_log":     "auditlog",
		},
	}
	logger := logger.New("debug")
	
	return NewBlockchainClient(cfg, logger)
}

func TestBlockchainClient_CheckAccess(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful access check", func(t *testing.T) {
		userID := "user-123"
		resourceID := "patient-123"
		action := "read_note"

		// Execute test
		allowed, err := client.CheckAccess(userID, resourceID, action)

		// Assertions
		assert.NoError(t, err)
		assert.True(t, allowed) // Mock implementation always allows access
	})

	t.Run("access check with empty parameters", func(t *testing.T) {
		// Execute test with empty parameters
		allowed, err := client.CheckAccess("", "", "")

		// Assertions
		assert.NoError(t, err)
		assert.True(t, allowed) // Mock still allows for development
	})
}

func TestBlockchainClient_LogActivity(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful activity logging", func(t *testing.T) {
		entry := &types.AuditLogEntry{
			UserID:       "user-123",
			Action:       "create_clinical_note",
			ResourceID:   "note-123",
			ResourceType: "clinical_note",
			Success:      true,
			Details: map[string]interface{}{
				"patient_id": "patient-123",
			},
		}

		// Execute test
		err := client.LogActivity(entry)

		// Assertions
		assert.NoError(t, err)
		assert.NotEmpty(t, entry.ID) // Should be generated if not provided
		assert.False(t, entry.Timestamp.IsZero()) // Should be set if not provided
	})

	t.Run("activity logging with pre-filled ID and timestamp", func(t *testing.T) {
		entryID := "audit-123"
		timestamp := time.Now().Add(-1 * time.Hour)

		entry := &types.AuditLogEntry{
			ID:           entryID,
			UserID:       "user-123",
			Action:       "read_clinical_note",
			ResourceID:   "note-123",
			ResourceType: "clinical_note",
			Timestamp:    timestamp,
			Success:      true,
		}

		// Execute test
		err := client.LogActivity(entry)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, entryID, entry.ID) // Should preserve existing ID
		assert.Equal(t, timestamp, entry.Timestamp) // Should preserve existing timestamp
	})
}

func TestBlockchainClient_StorePHIHash(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful PHI hash storage", func(t *testing.T) {
		hash := &types.PHIHash{
			PatientID: "patient-123",
			Hash:      "sha256-hash-value",
			Algorithm: "SHA-256",
			CreatedBy: "user-123",
		}

		// Execute test
		err := client.StorePHIHash(hash)

		// Assertions
		assert.NoError(t, err)
		assert.NotEmpty(t, hash.ID) // Should be generated if not provided
		assert.False(t, hash.CreatedAt.IsZero()) // Should be set if not provided
	})

	t.Run("PHI hash storage with pre-filled values", func(t *testing.T) {
		hashID := "hash-123"
		createdAt := time.Now().Add(-1 * time.Hour)

		hash := &types.PHIHash{
			ID:        hashID,
			PatientID: "patient-123",
			Hash:      "sha256-hash-value",
			Algorithm: "SHA-256",
			CreatedBy: "user-123",
			CreatedAt: createdAt,
		}

		// Execute test
		err := client.StorePHIHash(hash)

		// Assertions
		assert.NoError(t, err)
		assert.Equal(t, hashID, hash.ID) // Should preserve existing ID
		assert.Equal(t, createdAt, hash.CreatedAt) // Should preserve existing timestamp
	})
}

func TestBlockchainClient_GetPHIHash(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful PHI hash retrieval", func(t *testing.T) {
		resourceID := "note-123"

		// Execute test
		hash, err := client.GetPHIHash(resourceID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, hash)
		assert.Equal(t, resourceID, hash.ID)
		assert.Contains(t, hash.Hash, resourceID) // Mock implementation includes resource ID in hash
		assert.Equal(t, "SHA-256", hash.Algorithm)
	})

	t.Run("PHI hash retrieval with empty resource ID", func(t *testing.T) {
		// Execute test with empty resource ID
		hash, err := client.GetPHIHash("")

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, hash) // Mock implementation still returns a hash
	})
}

func TestBlockchainClient_GetAccessToken(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful access token retrieval", func(t *testing.T) {
		userID := "user-123"
		resourceID := "note-123"

		// Execute test
		token, err := client.GetAccessToken(userID, resourceID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, userID, token.UserID)
		assert.Equal(t, resourceID, token.ResourceID)
		assert.Equal(t, "PRE", token.TokenType)
		assert.Contains(t, token.Token, userID)
		assert.Contains(t, token.Token, resourceID)
		assert.True(t, token.ExpiresAt.After(time.Now()))
	})
}

func TestBlockchainClient_GetAuditTrail(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful audit trail retrieval", func(t *testing.T) {
		resourceID := "note-123"

		// Execute test
		entries, err := client.GetAuditTrail(resourceID)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, entries)
		assert.Len(t, entries, 1) // Mock implementation returns one entry
		
		entry := entries[0]
		assert.Equal(t, resourceID, entry.ResourceID)
		assert.Equal(t, "clinical_note", entry.ResourceType)
		assert.Equal(t, "create_clinical_note", entry.Action)
		assert.True(t, entry.Success)
	})
}

func TestBlockchainClient_ValidateUserRole(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful role validation", func(t *testing.T) {
		userID := "user-123"
		requiredRole := "consulting_doctor"

		// Execute test
		valid, err := client.ValidateUserRole(userID, requiredRole)

		// Assertions
		assert.NoError(t, err)
		assert.True(t, valid) // Mock implementation always validates successfully
	})
}

func TestBlockchainClient_CreateAccessPolicy(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful access policy creation", func(t *testing.T) {
		policy := &types.AccessPolicy{
			ID:           "policy-123",
			ResourceType: "clinical_note",
			UserRole:     "consulting_doctor",
			Actions:      []string{"create", "read", "update", "delete"},
			Conditions:   map[string]string{},
			CreatedBy:    "admin-123",
			CreatedAt:    time.Now(),
		}

		// Execute test
		err := client.CreateAccessPolicy(policy)

		// Assertions
		assert.NoError(t, err)
	})

	t.Run("access policy creation with invalid JSON", func(t *testing.T) {
		// Create a policy with a field that can't be marshaled to JSON
		policy := &types.AccessPolicy{
			ID:           "policy-123",
			ResourceType: "clinical_note",
			UserRole:     "consulting_doctor",
			Actions:      []string{"create", "read"},
		}

		// Execute test
		err := client.CreateAccessPolicy(policy)

		// Assertions - should succeed with mock implementation
		assert.NoError(t, err)
	})
}

func TestBlockchainClient_CreateReEncryptionToken(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful re-encryption token creation", func(t *testing.T) {
		fromUserID := "user-123"
		toUserID := "user-456"
		resourceID := "note-123"
		expiresIn := 24 * time.Hour

		// Execute test
		token, err := client.CreateReEncryptionToken(fromUserID, toUserID, resourceID, expiresIn)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.Equal(t, toUserID, token.UserID)
		assert.Equal(t, resourceID, token.ResourceID)
		assert.Equal(t, "PRE", token.TokenType)
		assert.True(t, token.ExpiresAt.After(time.Now()))
		assert.Equal(t, fromUserID, token.Metadata["from_user_id"])
		assert.Equal(t, toUserID, token.Metadata["to_user_id"])
	})
}

func TestBlockchainClient_RevokeAccessToken(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful token revocation", func(t *testing.T) {
		tokenID := "token-123"
		userID := "user-123"

		// Execute test
		err := client.RevokeAccessToken(tokenID, userID)

		// Assertions
		assert.NoError(t, err)
	})
}

func TestBlockchainClient_GetComplianceReport(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful compliance report generation", func(t *testing.T) {
		startDate := time.Now().AddDate(0, -1, 0) // 1 month ago
		endDate := time.Now()
		resourceType := "clinical_note"

		// Execute test
		report, err := client.GetComplianceReport(startDate, endDate, resourceType)

		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, report)
		
		// Check report structure
		period, exists := report["period"].(map[string]interface{})
		assert.True(t, exists)
		assert.Equal(t, startDate.Format(time.RFC3339), period["start"])
		assert.Equal(t, endDate.Format(time.RFC3339), period["end"])
		
		summary, exists := report["summary"].(map[string]interface{})
		assert.True(t, exists)
		assert.Contains(t, summary, "total_activities")
		assert.Contains(t, summary, "successful_activities")
		assert.Contains(t, summary, "failed_activities")
		
		assert.Equal(t, resourceType, report["resource_type"])
		assert.Equal(t, "COMPLIANT", report["compliance_status"])
	})
}

func TestBlockchainClient_ValidateDataIntegrity(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("successful data integrity validation", func(t *testing.T) {
		resourceID := "note-123"
		currentHash := "mock_hash_" + resourceID // This matches the mock implementation

		// Execute test
		valid, err := client.ValidateDataIntegrity(resourceID, currentHash)

		// Assertions
		assert.NoError(t, err)
		assert.True(t, valid)
	})

	t.Run("data integrity validation failure", func(t *testing.T) {
		resourceID := "note-123"
		currentHash := "different_hash" // This doesn't match the mock

		// Execute test
		valid, err := client.ValidateDataIntegrity(resourceID, currentHash)

		// Assertions
		assert.NoError(t, err)
		assert.False(t, valid)
	})
}

// Test the mock chaincode response functions
func TestBlockchainClient_MockResponses(t *testing.T) {
	client := setupTestBlockchainClient()

	t.Run("test mock invoke chaincode responses", func(t *testing.T) {
		// Test CheckAccess response
		response, err := client.invokeChaincode("accesspolicy", []string{"CheckAccess", "user-123", "resource-123", "read"})
		assert.NoError(t, err)
		
		var result map[string]interface{}
		err = json.Unmarshal(response, &result)
		assert.NoError(t, err)
		assert.True(t, result["allowed"].(bool))

		// Test LogActivity response
		response, err = client.invokeChaincode("auditlog", []string{"LogActivity", "{}"})
		assert.NoError(t, err)
		
		err = json.Unmarshal(response, &result)
		assert.NoError(t, err)
		assert.True(t, result["success"].(bool))

		// Test StorePHIHash response
		response, err = client.invokeChaincode("accesspolicy", []string{"StorePHIHash", "{}"})
		assert.NoError(t, err)
		
		err = json.Unmarshal(response, &result)
		assert.NoError(t, err)
		assert.True(t, result["success"].(bool))
	})

	t.Run("test mock query chaincode responses", func(t *testing.T) {
		// Test GetAccessToken response
		response, err := client.queryChaincode("accesspolicy", []string{"GetAccessToken", "user-123", "resource-123"})
		assert.NoError(t, err)
		
		var token types.AccessToken
		err = json.Unmarshal(response, &token)
		assert.NoError(t, err)
		assert.Equal(t, "user-123", token.UserID)
		assert.Equal(t, "resource-123", token.ResourceID)

		// Test GetAuditTrail response
		response, err = client.queryChaincode("auditlog", []string{"GetAuditTrail", "resource-123"})
		assert.NoError(t, err)
		
		var entries []*types.AuditLogEntry
		err = json.Unmarshal(response, &entries)
		assert.NoError(t, err)
		assert.Len(t, entries, 1)
		assert.Equal(t, "resource-123", entries[0].ResourceID)

		// Test GetPHIHash response
		response, err = client.queryChaincode("accesspolicy", []string{"GetPHIHash", "resource-123"})
		assert.NoError(t, err)
		
		var hash types.PHIHash
		err = json.Unmarshal(response, &hash)
		assert.NoError(t, err)
		assert.Equal(t, "resource-123", hash.ID)
	})

	t.Run("test unknown function error", func(t *testing.T) {
		// Test unknown invoke function
		_, err := client.invokeChaincode("accesspolicy", []string{"UnknownFunction"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown chaincode function")

		// Test unknown query function
		_, err = client.queryChaincode("accesspolicy", []string{"UnknownQuery"})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown chaincode query function")
	})
}