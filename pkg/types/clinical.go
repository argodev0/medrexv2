package types

import "time"

// ClinicalNote represents a clinical note with PHI data
type ClinicalNote struct {
	ID              string            `json:"id" db:"id"`
	PatientID       string            `json:"patient_id" db:"patient_id"`
	AuthorID        string            `json:"author_id" db:"author_id"`
	Content         string            `json:"content" db:"content"` // Encrypted
	Hash            string            `json:"hash" db:"hash"`       // SHA-256 hash
	Metadata        map[string]string `json:"metadata" db:"metadata"`
	NoteType        string            `json:"note_type" db:"note_type"`
	BlockchainTxID  string            `json:"blockchain_tx_id" db:"blockchain_tx_id"`
	Version         int               `json:"version" db:"version"`
	IsDeleted       bool              `json:"is_deleted" db:"is_deleted"`
	CreatedAt       time.Time         `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time         `json:"updated_at" db:"updated_at"`
}

// ClinicalNoteUpdates represents updates to a clinical note
type ClinicalNoteUpdates struct {
	Content  string            `json:"content,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	NoteType string            `json:"note_type,omitempty"`
}

// ClinicalNoteFilters represents filters for clinical note queries
type ClinicalNoteFilters struct {
	NoteType      string    `json:"note_type,omitempty"`
	AuthorID      string    `json:"author_id,omitempty"`
	CreatedAfter  time.Time `json:"created_after,omitempty"`
	CreatedBefore time.Time `json:"created_before,omitempty"`
	Limit         int       `json:"limit,omitempty"`
	Offset        int       `json:"offset,omitempty"`
}

// ClinicalNoteSearchCriteria represents search criteria for clinical notes
type ClinicalNoteSearchCriteria struct {
	PatientID     string    `json:"patient_id,omitempty"`
	AuthorID      string    `json:"author_id,omitempty"`
	NoteType      string    `json:"note_type,omitempty"`
	CreatedAfter  time.Time `json:"created_after,omitempty"`
	CreatedBefore time.Time `json:"created_before,omitempty"`
	Keywords      []string  `json:"keywords,omitempty"`
	Limit         int       `json:"limit,omitempty"`
	Offset        int       `json:"offset,omitempty"`
}

// SearchCriteria represents search parameters for clinical notes
type SearchCriteria struct {
	PatientID string    `json:"patient_id,omitempty"`
	AuthorID  string    `json:"author_id,omitempty"`
	NoteType  string    `json:"note_type,omitempty"`
	FromDate  time.Time `json:"from_date,omitempty"`
	ToDate    time.Time `json:"to_date,omitempty"`
	Keywords  []string  `json:"keywords,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	Offset    int       `json:"offset,omitempty"`
}

// Patient represents patient demographic information
type Patient struct {
	ID           string        `json:"id" db:"id"`
	MRN          string        `json:"mrn" db:"mrn"` // Medical Record Number
	Demographics *Demographics `json:"demographics"`
	Insurance    *Insurance    `json:"insurance"`
	CreatedAt    time.Time     `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time     `json:"updated_at" db:"updated_at"`
}

// PatientUpdates represents updates to patient information
type PatientUpdates struct {
	Demographics *Demographics `json:"demographics,omitempty"`
	Insurance    *Insurance    `json:"insurance,omitempty"`
}

// PatientSearchCriteria represents search criteria for patients
type PatientSearchCriteria struct {
	MRN           string    `json:"mrn,omitempty"`
	FirstName     string    `json:"first_name,omitempty"`
	LastName      string    `json:"last_name,omitempty"`
	DateOfBirth   time.Time `json:"date_of_birth,omitempty"`
	CreatedAfter  time.Time `json:"created_after,omitempty"`
	CreatedBefore time.Time `json:"created_before,omitempty"`
	Limit         int       `json:"limit,omitempty"`
	Offset        int       `json:"offset,omitempty"`
}

// Demographics represents patient demographic data
type Demographics struct {
	FirstName   string    `json:"first_name" db:"first_name"`
	LastName    string    `json:"last_name" db:"last_name"`
	DateOfBirth time.Time `json:"date_of_birth" db:"date_of_birth"`
	Gender      string    `json:"gender" db:"gender"`
	Address     Address   `json:"address"`
	Phone       string    `json:"phone" db:"phone"`
	Email       string    `json:"email" db:"email"`
}

// Address represents a physical address
type Address struct {
	Street1    string `json:"street1" db:"street1"`
	Street2    string `json:"street2" db:"street2"`
	City       string `json:"city" db:"city"`
	State      string `json:"state" db:"state"`
	PostalCode string `json:"postal_code" db:"postal_code"`
	Country    string `json:"country" db:"country"`
}

// Insurance represents patient insurance information
type Insurance struct {
	ProviderName string `json:"provider_name" db:"provider_name"`
	PolicyNumber string `json:"policy_number" db:"policy_number"`
	GroupNumber  string `json:"group_number" db:"group_number"`
	IsActive     bool   `json:"is_active" db:"is_active"`
}

// AuditLogFilters represents filters for audit log queries
type AuditLogFilters struct {
	Action        string    `json:"action,omitempty"`
	ResourceType  string    `json:"resource_type,omitempty"`
	Success       *bool     `json:"success,omitempty"`
	CreatedAfter  time.Time `json:"created_after,omitempty"`
	CreatedBefore time.Time `json:"created_before,omitempty"`
	Limit         int       `json:"limit,omitempty"`
	Offset        int       `json:"offset,omitempty"`
}

// AuditLogSearchCriteria represents search criteria for audit logs
type AuditLogSearchCriteria struct {
	UserID        string    `json:"user_id,omitempty"`
	Action        string    `json:"action,omitempty"`
	ResourceType  string    `json:"resource_type,omitempty"`
	ResourceID    string    `json:"resource_id,omitempty"`
	Success       *bool     `json:"success,omitempty"`
	CreatedAfter  time.Time `json:"created_after,omitempty"`
	CreatedBefore time.Time `json:"created_before,omitempty"`
	Limit         int       `json:"limit,omitempty"`
	Offset        int       `json:"offset,omitempty"`
}