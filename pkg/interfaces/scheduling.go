package interfaces

import (
	"github.com/medrex/dlt-emr/pkg/types"
)

// SchedulingService defines the interface for appointment and resource management
type SchedulingService interface {
	// Appointment management
	CreateAppointment(apt *types.Appointment, userID string) (*types.Appointment, error)
	GetAppointment(aptID, userID string) (*types.Appointment, error)
	UpdateAppointment(aptID string, updates *types.AppointmentUpdates, userID string) error
	CancelAppointment(aptID, userID string) error
	
	// Appointment queries
	GetAppointments(userID string, filters *types.AppointmentFilters) ([]*types.Appointment, error)
	GetPatientAppointments(patientID, userID string) ([]*types.Appointment, error)
	GetProviderAppointments(providerID, userID string) ([]*types.Appointment, error)
	
	// Availability management
	CheckAvailability(providerID string, timeSlot *types.TimeSlot) (bool, error)
	GetAvailableSlots(providerID string, date string) ([]*types.TimeSlot, error)
	BlockTimeSlot(providerID string, timeSlot *types.TimeSlot, reason string) error
	UnblockTimeSlot(providerID string, timeSlot *types.TimeSlot) error
	
	// Provider management
	CreateProvider(provider *types.Provider, userID string) (*types.Provider, error)
	GetProvider(providerID, userID string) (*types.Provider, error)
	UpdateProvider(providerID string, updates map[string]interface{}, userID string) error
	GetProviders(filters map[string]interface{}, userID string) ([]*types.Provider, error)
	
	// Notification management
	SendAppointmentReminder(aptID string) error
	SendAppointmentConfirmation(aptID string) error
	NotifyAppointmentChange(aptID string) error
	
	// Service management
	Start(addr string) error
	Stop() error
}

// SchedulingRepository defines the interface for scheduling data persistence
type SchedulingRepository interface {
	// Appointments
	CreateAppointment(apt *types.Appointment) error
	GetAppointmentByID(id string) (*types.Appointment, error)
	UpdateAppointment(id string, updates *types.AppointmentUpdates) error
	DeleteAppointment(id string) error
	GetAppointments(filters *types.AppointmentFilters) ([]*types.Appointment, error)
	
	// Providers
	CreateProvider(provider *types.Provider) error
	GetProviderByID(id string) (*types.Provider, error)
	GetProviderByUserID(userID string) (*types.Provider, error)
	UpdateProvider(id string, updates map[string]interface{}) error
	GetProviders(filters map[string]interface{}, limit, offset int) ([]*types.Provider, error)
	
	// Availability
	GetConflictingAppointments(providerID string, timeSlot *types.TimeSlot) ([]*types.Appointment, error)
	GetProviderSchedule(providerID string, date string) ([]*types.Appointment, error)
}

// NotificationService defines the interface for appointment notifications
type NotificationService interface {
	// Email notifications
	SendEmail(to, subject, body string) error
	SendEmailTemplate(to, template string, data map[string]interface{}) error
	
	// SMS notifications
	SendSMS(to, message string) error
	SendSMSTemplate(to, template string, data map[string]interface{}) error
	
	// Push notifications
	SendPushNotification(userID, title, message string) error
	
	// Notification preferences
	GetUserPreferences(userID string) (map[string]bool, error)
	UpdateUserPreferences(userID string, preferences map[string]bool) error
}

// CalendarService defines the interface for calendar integration
type CalendarService interface {
	// Calendar operations
	CreateCalendarEvent(providerID string, apt *types.Appointment) error
	UpdateCalendarEvent(providerID, eventID string, apt *types.Appointment) error
	DeleteCalendarEvent(providerID, eventID string) error
	
	// Availability sync
	SyncProviderAvailability(providerID string) error
	GetExternalAvailability(providerID string, date string) ([]*types.TimeSlot, error)
	
	// Calendar providers
	ConnectCalendar(providerID, calendarType, credentials string) error
	DisconnectCalendar(providerID string) error
}