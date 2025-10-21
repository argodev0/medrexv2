package iam

import (
	"encoding/json"
	"fmt"

	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// AccessPolicyChaincodeClient implements AccessPolicyChaincode interface
type AccessPolicyChaincodeClient struct {
	config     *config.FabricConfig
	logger     logger.Logger
	channelID  string
	chaincodeID string
}

// NewAccessPolicyChaincodeClient creates a new chaincode client
func NewAccessPolicyChaincodeClient(cfg *config.FabricConfig, log logger.Logger) *AccessPolicyChaincodeClient {
	return &AccessPolicyChaincodeClient{
		config:      cfg,
		logger:      log,
		channelID:   cfg.ChannelName,
		chaincodeID: cfg.Chaincodes["access_policy"],
	}
}

// ValidateAccess validates user access via AccessPolicy chaincode
func (c *AccessPolicyChaincodeClient) ValidateAccess(userID, resource, action string, userRole types.UserRole) (bool, error) {
	c.logger.Info("Validating access via chaincode", "user_id", userID, "resource", resource, "action", action, "role", userRole)

	// Prepare chaincode invocation arguments
	args := []string{
		"ValidateAccess",
		userID,
		resource,
		action,
		string(userRole),
	}

	// Invoke chaincode
	response, err := c.invokeChaincode(args)
	if err != nil {
		return false, fmt.Errorf("chaincode invocation failed: %w", err)
	}

	// Parse response
	var result struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reason,omitempty"`
	}

	if err := json.Unmarshal(response, &result); err != nil {
		return false, fmt.Errorf("failed to parse chaincode response: %w", err)
	}

	if !result.Allowed {
		c.logger.Warn("Access denied by chaincode", "reason", result.Reason)
	}

	return result.Allowed, nil
}

// GetAccessPolicy retrieves an access policy from chaincode
func (c *AccessPolicyChaincodeClient) GetAccessPolicy(resource string, userRole types.UserRole) (*AccessPolicy, error) {
	c.logger.Info("Getting access policy from chaincode", "resource", resource, "role", userRole)

	args := []string{
		"GetAccessPolicy",
		resource,
		string(userRole),
	}

	response, err := c.queryChaincode(args)
	if err != nil {
		return nil, fmt.Errorf("chaincode query failed: %w", err)
	}

	if len(response) == 0 {
		return nil, nil // No policy found
	}

	var policy AccessPolicy
	if err := json.Unmarshal(response, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse access policy: %w", err)
	}

	return &policy, nil
}

// CreateAccessPolicy creates a new access policy in chaincode
func (c *AccessPolicyChaincodeClient) CreateAccessPolicy(policy *AccessPolicy) error {
	c.logger.Info("Creating access policy in chaincode", "policy_id", policy.ID)

	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}

	args := []string{
		"CreateAccessPolicy",
		string(policyJSON),
	}

	_, err = c.invokeChaincode(args)
	if err != nil {
		return fmt.Errorf("failed to create access policy: %w", err)
	}

	c.logger.Info("Access policy created successfully", "policy_id", policy.ID)
	return nil
}

// UpdateAccessPolicy updates an existing access policy in chaincode
func (c *AccessPolicyChaincodeClient) UpdateAccessPolicy(policyID string, updates map[string]interface{}) error {
	c.logger.Info("Updating access policy in chaincode", "policy_id", policyID)

	updatesJSON, err := json.Marshal(updates)
	if err != nil {
		return fmt.Errorf("failed to marshal updates: %w", err)
	}

	args := []string{
		"UpdateAccessPolicy",
		policyID,
		string(updatesJSON),
	}

	_, err = c.invokeChaincode(args)
	if err != nil {
		return fmt.Errorf("failed to update access policy: %w", err)
	}

	c.logger.Info("Access policy updated successfully", "policy_id", policyID)
	return nil
}

// invokeChaincode invokes a chaincode function (for state-changing operations)
func (c *AccessPolicyChaincodeClient) invokeChaincode(args []string) ([]byte, error) {
	// In a real implementation, this would use the Hyperledger Fabric SDK
	// to invoke the chaincode. For now, we'll simulate the response.
	
	c.logger.Info("Invoking chaincode", "function", args[0], "args_count", len(args)-1)

	// Simulate chaincode response based on function
	switch args[0] {
	case "ValidateAccess":
		// Simulate access validation
		response := map[string]interface{}{
			"allowed": true,
			"reason":  "Access granted by policy",
		}
		return json.Marshal(response)

	case "CreateAccessPolicy":
		// Simulate policy creation
		response := map[string]interface{}{
			"success": true,
			"message": "Access policy created successfully",
		}
		return json.Marshal(response)

	case "UpdateAccessPolicy":
		// Simulate policy update
		response := map[string]interface{}{
			"success": true,
			"message": "Access policy updated successfully",
		}
		return json.Marshal(response)

	default:
		return nil, fmt.Errorf("unknown chaincode function: %s", args[0])
	}
}

// queryChaincode queries a chaincode function (for read-only operations)
func (c *AccessPolicyChaincodeClient) queryChaincode(args []string) ([]byte, error) {
	// In a real implementation, this would use the Hyperledger Fabric SDK
	// to query the chaincode. For now, we'll simulate the response.
	
	c.logger.Info("Querying chaincode", "function", args[0], "args_count", len(args)-1)

	switch args[0] {
	case "GetAccessPolicy":
		// Simulate policy retrieval
		if len(args) >= 3 {
			resource := args[1]
			userRole := args[2]
			
			// Return a mock policy
			policy := AccessPolicy{
				ID:           fmt.Sprintf("policy_%s_%s", resource, userRole),
				ResourceType: resource,
				UserRole:     types.UserRole(userRole),
				Actions:      []string{"read", "create", "update"},
				Conditions:   map[string]string{},
				CreatedBy:    "system",
				CreatedAt:    "2023-12-01T00:00:00Z",
			}
			return json.Marshal(policy)
		}
		return []byte("{}"), nil

	default:
		return nil, fmt.Errorf("unknown chaincode query function: %s", args[0])
	}
}

// GetAllPolicies retrieves all access policies (for administrative purposes)
func (c *AccessPolicyChaincodeClient) GetAllPolicies() ([]*AccessPolicy, error) {
	c.logger.Info("Getting all access policies from chaincode")

	args := []string{"GetAllPolicies"}
	response, err := c.queryChaincode(args)
	if err != nil {
		return nil, fmt.Errorf("failed to get all policies: %w", err)
	}

	var policies []*AccessPolicy
	if err := json.Unmarshal(response, &policies); err != nil {
		return nil, fmt.Errorf("failed to parse policies: %w", err)
	}

	return policies, nil
}

// DeleteAccessPolicy deletes an access policy from chaincode
func (c *AccessPolicyChaincodeClient) DeleteAccessPolicy(policyID string) error {
	c.logger.Info("Deleting access policy from chaincode", "policy_id", policyID)

	args := []string{
		"DeleteAccessPolicy",
		policyID,
	}

	_, err := c.invokeChaincode(args)
	if err != nil {
		return fmt.Errorf("failed to delete access policy: %w", err)
	}

	c.logger.Info("Access policy deleted successfully", "policy_id", policyID)
	return nil
}

// ValidateUserCertificate validates a user's X.509 certificate via chaincode
func (c *AccessPolicyChaincodeClient) ValidateUserCertificate(userID, certificate string) (bool, map[string]string, error) {
	c.logger.Info("Validating user certificate via chaincode", "user_id", userID)

	args := []string{
		"ValidateUserCertificate",
		userID,
		certificate,
	}

	response, err := c.queryChaincode(args)
	if err != nil {
		return false, nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	var result struct {
		Valid      bool              `json:"valid"`
		Attributes map[string]string `json:"attributes"`
		Reason     string            `json:"reason,omitempty"`
	}

	if err := json.Unmarshal(response, &result); err != nil {
		return false, nil, fmt.Errorf("failed to parse certificate validation response: %w", err)
	}

	if !result.Valid {
		c.logger.Warn("Certificate validation failed", "reason", result.Reason)
	}

	return result.Valid, result.Attributes, nil
}

// GetUserPermissions retrieves user permissions from chaincode
func (c *AccessPolicyChaincodeClient) GetUserPermissions(userID string, userRole types.UserRole) ([]string, error) {
	c.logger.Info("Getting user permissions from chaincode", "user_id", userID, "role", userRole)

	args := []string{
		"GetUserPermissions",
		userID,
		string(userRole),
	}

	response, err := c.queryChaincode(args)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}

	var result struct {
		Permissions []string `json:"permissions"`
	}

	if err := json.Unmarshal(response, &result); err != nil {
		return nil, fmt.Errorf("failed to parse permissions response: %w", err)
	}

	return result.Permissions, nil
}