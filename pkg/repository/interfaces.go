package repository

import (
	"context"

	"github.com/medrex/dlt-emr/pkg/types"
)

// PatientRepositoryInterface defines the interface for patient data operations
type PatientRepositoryInterface interface {
	Create(ctx context.Context, patient *types.Patient, createdBy string) (*types.Patient, error)
	GetByID(ctx context.Context, patientID string) (*types.Patient, error)
	GetByMRN(ctx context.Context, mrn string) (*types.Patient, error)
	Update(ctx context.Context, patientID string, updates *types.PatientUpdates, updatedBy string) error
	Delete(ctx context.Context, patientID string, deletedBy string) error
	Search(ctx context.Context, criteria *types.PatientSearchCriteria) ([]*types.Patient, error)
	VerifyDataIntegrity(ctx context.Context, patientID string, blockchainHash string) (bool, error)
}

// ClinicalNotesRepositoryInterface defines the interface for clinical notes operations
type ClinicalNotesRepositoryInterface interface {
	Create(ctx context.Context, note *types.ClinicalNote, authorID string) (*types.ClinicalNote, error)
	GetByID(ctx context.Context, noteID string) (*types.ClinicalNote, error)
	GetByPatientID(ctx context.Context, patientID string, filters *types.ClinicalNoteFilters) ([]*types.ClinicalNote, error)
	Update(ctx context.Context, noteID string, updates *types.ClinicalNoteUpdates, updatedBy string) (*types.ClinicalNote, error)
	Delete(ctx context.Context, noteID string, deletedBy string) error
	Search(ctx context.Context, criteria *types.ClinicalNoteSearchCriteria) ([]*types.ClinicalNote, error)
	UpdateBlockchainTxID(ctx context.Context, noteID, txID string) error
}

// AppointmentRepositoryInterface defines the interface for appointment operations
type AppointmentRepositoryInterface interface {
	Create(ctx context.Context, appointment *types.Appointment, createdBy string) (*types.Appointment, error)
	GetByID(ctx context.Context, appointmentID string) (*types.Appointment, error)
	GetByPatientID(ctx context.Context, patientID string, filters *types.AppointmentFilters) ([]*types.Appointment, error)
	GetByProviderID(ctx context.Context, providerID string, filters *types.AppointmentFilters) ([]*types.Appointment, error)
	Update(ctx context.Context, appointmentID string, updates *types.AppointmentUpdates, updatedBy string) error
	Delete(ctx context.Context, appointmentID string, deletedBy string) error
	CheckAvailability(ctx context.Context, providerID string, timeSlot *types.TimeSlot) (bool, error)
}

// CPOERepositoryInterface defines the interface for CPOE order operations
type CPOERepositoryInterface interface {
	Create(ctx context.Context, order *types.CPOEOrder, createdBy string) (*types.CPOEOrder, error)
	GetByID(ctx context.Context, orderID string) (*types.CPOEOrder, error)
	GetByPatientID(ctx context.Context, patientID string, filters *types.CPOEOrderFilters) ([]*types.CPOEOrder, error)
	GetByProviderID(ctx context.Context, providerID string, filters *types.CPOEOrderFilters) ([]*types.CPOEOrder, error)
	Update(ctx context.Context, orderID string, updates *types.CPOEOrderUpdates, updatedBy string) error
	CoSign(ctx context.Context, orderID string, coSigningProviderID string) error
	UpdateStatus(ctx context.Context, orderID string, status string, updatedBy string) error
	UpdateBlockchainTxID(ctx context.Context, orderID, txID string) error
}

// AuditLogRepositoryInterface defines the interface for audit log operations
type AuditLogRepositoryInterface interface {
	Create(ctx context.Context, entry *types.AuditLogEntry) error
	GetByUserID(ctx context.Context, userID string, filters *types.AuditLogFilters) ([]*types.AuditLogEntry, error)
	GetByResourceID(ctx context.Context, resourceID string, filters *types.AuditLogFilters) ([]*types.AuditLogEntry, error)
	Search(ctx context.Context, criteria *types.AuditLogSearchCriteria) ([]*types.AuditLogEntry, error)
	UpdateBlockchainTxID(ctx context.Context, entryID, txID string) error
}

// UserRepositoryInterface defines the interface for user operations
type UserRepositoryInterface interface {
	Create(ctx context.Context, user *types.User, createdBy string) (*types.User, error)
	GetByID(ctx context.Context, userID string) (*types.User, error)
	GetByUsername(ctx context.Context, username string) (*types.User, error)
	GetByFabricCertID(ctx context.Context, certID string) (*types.User, error)
	Update(ctx context.Context, userID string, updates *types.UserUpdates, updatedBy string) error
	UpdateLastLogin(ctx context.Context, userID string) error
	Deactivate(ctx context.Context, userID string, deactivatedBy string) error
	Search(ctx context.Context, criteria *types.UserSearchCriteria) ([]*types.User, error)
}