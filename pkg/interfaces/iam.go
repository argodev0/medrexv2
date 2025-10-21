package interfaces

import (
	"github.com/medrex/dlt-emr/pkg/types"
)

// IAMService defines the interface for Identity and Access Management
type IAMService interface {
	// User management
	RegisterUser(req *types.UserRegistrationRequest) (*types.User, error)
	GetUser(userID string) (*types.User, error)
	UpdateUser(userID string, updates map[string]interface{}) error
	DeactivateUser(userID string) error
	
	// Authentication
	AuthenticateUser(credentials *types.Credentials) (*types.AuthToken, error)
	RefreshToken(token string) (*types.AuthToken, error)
	RevokeToken(token string) error
	
	// Authorization
	ValidatePermissions(userID, resource, action string) (bool, error)
	GetUserPermissions(userID string) ([]string, error)
	
	// Fabric CA integration
	EnrollWithFabricCA(userID string) (*types.X509Certificate, error)
	RevokeCertificate(userID string) error
	RenewCertificate(userID string) (*types.X509Certificate, error)
	
	// Multi-factor authentication
	EnableMFA(userID string) (string, error) // returns secret
	VerifyMFA(userID, token string) (bool, error)
	DisableMFA(userID string) error
	
	// Service management
	Start(addr string) error
	Stop() error
}

// UserRepository defines the interface for user data persistence
type UserRepository interface {
	Create(user *types.User) error
	GetByID(id string) (*types.User, error)
	GetByUsername(username string) (*types.User, error)
	GetByEmail(email string) (*types.User, error)
	Update(id string, updates map[string]interface{}) error
	Delete(id string) error
	List(filters map[string]interface{}, limit, offset int) ([]*types.User, error)
}

// PasswordManager defines the interface for password operations
type PasswordManager interface {
	HashPassword(password string) (string, error)
	VerifyPassword(hashedPassword, password string) (bool, error)
	GenerateRandomPassword(length int) (string, error)
}

// CertificateManager defines the interface for X.509 certificate operations
type CertificateManager interface {
	EnrollUser(username, password string, attrs map[string]string) (*types.X509Certificate, error)
	RevokeCertificate(serial string, reason int) error
	ValidateCertificate(cert string) (bool, error)
	ExtractAttributes(cert string) (map[string]string, error)
	GetCertificateInfo(cert string) (map[string]interface{}, error)
}

// MFAProvider defines the interface for multi-factor authentication
type MFAProvider interface {
	GenerateSecret(userID string) (string, error)
	GenerateQRCode(userID, secret string) ([]byte, error)
	VerifyToken(secret, token string) (bool, error)
	GetBackupCodes(userID string) ([]string, error)
}