package types

import "time"

// Appointment represents a scheduled appointment
type Appointment struct {
	ID          string    `json:"id" db:"id"`
	PatientID   string    `json:"patient_id" db:"patient_id"`
	ProviderID  string    `json:"provider_id" db:"provider_id"`
	StartTime   time.Time `json:"start_time" db:"start_time"`
	EndTime     time.Time `json:"end_time" db:"end_time"`
	Type        string    `json:"type" db:"type"`
	Status      string    `json:"status" db:"status"`
	Notes       string    `json:"notes" db:"notes"`
	Location    string    `json:"location" db:"location"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// AppointmentStatus represents appointment status values
type AppointmentStatus string

const (
	StatusScheduled AppointmentStatus = "scheduled"
	StatusConfirmed AppointmentStatus = "confirmed"
	StatusInProgress AppointmentStatus = "in_progress"
	StatusCompleted AppointmentStatus = "completed"
	StatusCancelled AppointmentStatus = "cancelled"
	StatusNoShow    AppointmentStatus = "no_show"
)

// AppointmentType represents appointment type values
type AppointmentType string

const (
	TypeConsultation AppointmentType = "consultation"
	TypeFollowUp     AppointmentType = "follow_up"
	TypeProcedure    AppointmentType = "procedure"
	TypeEmergency    AppointmentType = "emergency"
	TypeTelehealth   AppointmentType = "telehealth"
)

// AppointmentFilters represents filters for appointment queries
type AppointmentFilters struct {
	PatientID  string            `json:"patient_id,omitempty"`
	ProviderID string            `json:"provider_id,omitempty"`
	Status     AppointmentStatus `json:"status,omitempty"`
	Type       AppointmentType   `json:"type,omitempty"`
	FromDate   time.Time         `json:"from_date,omitempty"`
	ToDate     time.Time         `json:"to_date,omitempty"`
	Location   string            `json:"location,omitempty"`
	Limit      int               `json:"limit,omitempty"`
	Offset     int               `json:"offset,omitempty"`
}

// AppointmentUpdates represents updates to an appointment
type AppointmentUpdates struct {
	StartTime *time.Time         `json:"start_time,omitempty"`
	EndTime   *time.Time         `json:"end_time,omitempty"`
	Status    *AppointmentStatus `json:"status,omitempty"`
	Notes     *string            `json:"notes,omitempty"`
	Location  *string            `json:"location,omitempty"`
}

// TimeSlot represents a time slot for availability checking
type TimeSlot struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// Provider represents a healthcare provider
type Provider struct {
	ID           string    `json:"id" db:"id"`
	UserID       string    `json:"user_id" db:"user_id"`
	Specialty    string    `json:"specialty" db:"specialty"`
	LicenseNumber string   `json:"license_number" db:"license_number"`
	Department   string    `json:"department" db:"department"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}