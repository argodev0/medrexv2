package types

import "time"

// AccessPolicy represents blockchain-stored access control policy
type AccessPolicy struct {
	ID           string            `json:"id"`
	ResourceType string            `json:"resource_type"`
	UserRole     string            `json:"user_role"`
	Actions      []string          `json:"actions"`
	Conditions   map[string]string `json:"conditions"`
	CreatedBy    string            `json:"created_by"`
	CreatedAt    time.Time         `json:"created_at"`
}

// AuditLogEntry represents blockchain-stored audit log entry
type AuditLogEntry struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	Action     string                 `json:"action"`
	ResourceID string                 `json:"resource_id"`
	ResourceType string               `json:"resource_type"`
	Timestamp  time.Time              `json:"timestamp"`
	Success    bool                   `json:"success"`
	Details    map[string]interface{} `json:"details"`
	Signature  string                 `json:"signature"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
}

// PHIHash represents PHI hash stored on blockchain
type PHIHash struct {
	ID        string    `json:"id"`
	PatientID string    `json:"patient_id"`
	Hash      string    `json:"hash"`      // SHA-256 hash of PHI
	Algorithm string    `json:"algorithm"` // Hash algorithm used
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// AccessToken represents blockchain-issued access token
type AccessToken struct {
	ID         string            `json:"id"`
	UserID     string            `json:"user_id"`
	ResourceID string            `json:"resource_id"`
	TokenType  string            `json:"token_type"`
	Token      string            `json:"token"`      // PRE re-encryption token
	ExpiresAt  time.Time         `json:"expires_at"`
	Metadata   map[string]string `json:"metadata"`
	IssuedAt   time.Time         `json:"issued_at"`
}

// ChaincodeTxResult represents chaincode transaction result
type ChaincodeTxResult struct {
	TxID      string                 `json:"tx_id"`
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// FabricUser represents Hyperledger Fabric user identity
type FabricUser struct {
	Name         string            `json:"name"`
	MSPID        string            `json:"msp_id"`
	Certificate  string            `json:"certificate"`
	PrivateKey   string            `json:"private_key"`
	Attributes   map[string]string `json:"attributes"`
	EnrolledAt   time.Time         `json:"enrolled_at"`
}

// OrganizationMSP represents MSP configuration for an organization
type OrganizationMSP struct {
	MSPID        string   `json:"msp_id"`
	Name         string   `json:"name"`
	RootCerts    []string `json:"root_certs"`
	IntermediateCerts []string `json:"intermediate_certs"`
	Admins       []string `json:"admins"`
	RevocationList []string `json:"revocation_list"`
}