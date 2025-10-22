package types

import "time"

// UserRole represents the different user roles in the system
type UserRole string

const (
	RolePatient           UserRole = "patient"
	RoleMBBSStudent      UserRole = "mbbs_student"
	RoleMDStudent        UserRole = "md_student"
	RoleConsultingDoctor UserRole = "consulting_doctor"
	RoleNurse            UserRole = "nurse"
	RoleLabTechnician    UserRole = "lab_technician"
	RoleReceptionist     UserRole = "receptionist"
	RoleClinicalStaff    UserRole = "clinical_staff"
	RoleAdministrator    UserRole = "administrator"
)

// User represents a system user
type User struct {
	ID           string    `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	Role         UserRole  `json:"role" db:"role"`
	Organization string    `json:"organization" db:"organization"`
	Certificate  string    `json:"certificate" db:"certificate"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// UserClaims represents JWT token claims
type UserClaims struct {
	UserID         string   `json:"user_id"`
	Username       string   `json:"username"`
	Role           UserRole `json:"role"`
	OrgID          string   `json:"org_id"`
	Permissions    []string `json:"permissions"`
	Specialty      string   `json:"specialty,omitempty"`
	Department     string   `json:"department,omitempty"`
	WardAssignment string   `json:"ward_assignment,omitempty"`
	IsTrainee      bool     `json:"is_trainee,omitempty"`
	IsSupervisor   bool     `json:"is_supervisor,omitempty"`
	Level          int      `json:"level,omitempty"`
}

// UserRegistrationRequest represents user registration data
type UserRegistrationRequest struct {
	Username     string   `json:"username" validate:"required,min=3,max=50"`
	Email        string   `json:"email" validate:"required,email"`
	Password     string   `json:"password" validate:"required,min=8"`
	Role         UserRole `json:"role" validate:"required"`
	Organization string   `json:"organization" validate:"required"`
}

// Credentials represents user login credentials
type Credentials struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
	MFAToken string `json:"mfa_token,omitempty"`
}

// AuthToken represents authentication token response
type AuthToken struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	IssuedAt     time.Time `json:"issued_at"`
}

// X509Certificate represents a Fabric CA certificate
type X509Certificate struct {
	Certificate string            `json:"certificate"`
	PrivateKey  string            `json:"private_key"`
	Attributes  map[string]string `json:"attributes"`
	ExpiresAt   time.Time         `json:"expires_at"`
}

// UserUpdates represents updates to user information
type UserUpdates struct {
	Email        string   `json:"email,omitempty"`
	Role         UserRole `json:"role,omitempty"`
	Organization string   `json:"organization,omitempty"`
	IsActive     *bool    `json:"is_active,omitempty"`
}

// UserSearchCriteria represents search criteria for users
type UserSearchCriteria struct {
	Username     string   `json:"username,omitempty"`
	Email        string   `json:"email,omitempty"`
	Role         UserRole `json:"role,omitempty"`
	Organization string   `json:"organization,omitempty"`
	IsActive     *bool    `json:"is_active,omitempty"`
	Limit        int      `json:"limit,omitempty"`
	Offset       int      `json:"offset,omitempty"`
}