package interfaces

import (
	"time"
	
	"github.com/medrex/dlt-emr/pkg/types"
)

// ClinicalNotesService defines the interface for clinical notes management
type ClinicalNotesService interface {
	// Clinical note operations
	CreateNote(note *types.ClinicalNote, userID string) (*types.ClinicalNote, error)
	GetNote(noteID, userID string) (*types.ClinicalNote, error)
	UpdateNote(noteID string, updates *types.ClinicalNoteUpdates, userID string) error
	DeleteNote(noteID, userID string) error
	
	// Search and retrieval
	SearchNotes(criteria *types.SearchCriteria, userID string) ([]*types.ClinicalNote, error)
	GetPatientNotes(patientID, userID string) ([]*types.ClinicalNote, error)
	
	// Patient management
	CreatePatient(patient *types.Patient, userID string) (*types.Patient, error)
	GetPatient(patientID, userID string) (*types.Patient, error)
	UpdatePatient(patientID string, updates map[string]interface{}, userID string) error
	SearchPatients(criteria map[string]interface{}, userID string) ([]*types.Patient, error)
	
	// Data integrity
	VerifyDataIntegrity(noteID string) (bool, error)
	GenerateHash(content string) (string, error)
	
	// Service management
	Start(addr string) error
	Stop() error
}

// ClinicalRepository defines the interface for clinical data persistence
type ClinicalRepository interface {
	// Clinical notes
	CreateNote(note *types.ClinicalNote) error
	GetNoteByID(id string) (*types.ClinicalNote, error)
	UpdateNote(id string, updates *types.ClinicalNoteUpdates) error
	DeleteNote(id string) error
	SearchNotes(criteria *types.SearchCriteria) ([]*types.ClinicalNote, error)
	
	// Patients
	CreatePatient(patient *types.Patient) error
	GetPatientByID(id string) (*types.Patient, error)
	GetPatientByMRN(mrn string) (*types.Patient, error)
	UpdatePatient(id string, updates map[string]interface{}) error
	SearchPatients(criteria map[string]interface{}, limit, offset int) ([]*types.Patient, error)
}

// PatientRepository defines the interface for patient data operations
type PatientRepository interface {
	Create(patient *types.Patient) error
	GetByID(id string) (*types.Patient, error)
	Update(id string, updates map[string]interface{}) error
	Delete(id string) error
	Search(criteria map[string]interface{}) ([]*types.Patient, error)
}

// AuditService defines the interface for audit logging
type AuditService interface {
	LogEvent(userID, action, resourceID string, success bool, data map[string]interface{}) error
	GetAuditTrail(resourceID string) ([]*types.AuditLogEntry, error)
	GetUserAuditTrail(userID string, limit int) ([]*types.AuditLogEntry, error)
}

// EncryptionService defines the interface for PHI encryption/decryption
type EncryptionService interface {
	// Encryption operations
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
	
	// Key management
	GenerateKey() (string, error)
	RotateKey(oldKey, newKey string) error
	
	// Proxy Re-Encryption
	GenerateReEncryptionToken(fromKey, toKey string) (string, error)
	ReEncrypt(ciphertext, token string) (string, error)
	
	// Hash operations
	GenerateHash(data string) (string, error)
	VerifyHash(data, hash string) (bool, error)
}

// BlockchainClient defines the interface for blockchain interactions
type BlockchainClient interface {
	// Access policy operations
	CheckAccess(userID, resourceID, action string) (bool, error)
	GetAccessToken(userID, resourceID string) (*types.AccessToken, error)
	ValidateUserRole(userID string, requiredRole string) (bool, error)
	CreateAccessPolicy(policy *types.AccessPolicy) error
	GetAccessPolicy(resourceType, userRole string) (*types.AccessPolicy, error)
	
	// Audit logging
	LogActivity(entry *types.AuditLogEntry) error
	GetAuditTrail(resourceID string) ([]*types.AuditLogEntry, error)
	GetUserAuditTrail(userID string, limit int) ([]*types.AuditLogEntry, error)
	GetComplianceReport(startDate, endDate time.Time, resourceType string) (map[string]interface{}, error)
	
	// PHI hash storage
	StorePHIHash(hash *types.PHIHash) error
	GetPHIHash(resourceID string) (*types.PHIHash, error)
	ValidateDataIntegrity(resourceID, currentHash string) (bool, error)
	
	// Re-encryption tokens
	CreateReEncryptionToken(fromUserID, toUserID, resourceID string, expiresIn time.Duration) (*types.AccessToken, error)
	RevokeAccessToken(tokenID, userID string) error
	
	// Transaction management
	SubmitTransaction(chaincode, function string, args []string) (*types.ChaincodeTxResult, error)
	QueryChaincode(chaincode, function string, args []string) ([]byte, error)
}