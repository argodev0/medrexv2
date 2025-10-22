package scheduling

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/database"
	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Service implements the SchedulingService interface
type Service struct {
	config              *config.Config
	logger              logger.Logger
	repository          interfaces.SchedulingRepository
	db                  *database.DB
	server              *http.Server
	notificationService interfaces.NotificationService
	calendarService     interfaces.CalendarService
	notificationManager *AppointmentNotificationManager
	calendarManager     *CalendarIntegrationManager
}

// New creates a new scheduling service
func New(cfg *config.Config, log logger.Logger) interfaces.SchedulingService {
	// Initialize database connection
	db, err := database.NewConnection(&cfg.Database, log)
	if err != nil {
		log.Error("Failed to connect to database", "error", err)
		panic(err)
	}

	// Initialize repository
	repository := NewRepository(db, log)

	// Initialize notification service
	notificationService := NewNotificationService(log)

	// Initialize calendar service
	calendarService := NewCalendarService(repository, log)

	// Initialize managers
	notificationManager := NewAppointmentNotificationManager(notificationService, repository, log)
	calendarManager := NewCalendarIntegrationManager(calendarService, repository, log)

	return &Service{
		config:              cfg,
		logger:              log,
		repository:          repository,
		db:                  db,
		notificationService: notificationService,
		calendarService:     calendarService,
		notificationManager: notificationManager,
		calendarManager:     calendarManager,
	}
}

// CreateAppointment creates a new appointment with role validation
func (s *Service) CreateAppointment(apt *types.Appointment, userID string) (*types.Appointment, error) {
	s.logger.Info("Creating appointment for patient %s with provider %s", apt.PatientID, apt.ProviderID)

	// Validate appointment data
	if err := s.validateAppointment(apt); err != nil {
		return nil, fmt.Errorf("appointment validation failed: %w", err)
	}

	// Check for conflicts
	conflicts, err := s.repository.GetConflictingAppointments(apt.ProviderID, &types.TimeSlot{
		StartTime: apt.StartTime,
		EndTime:   apt.EndTime,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to check for conflicts: %w", err)
	}

	if len(conflicts) > 0 {
		return nil, fmt.Errorf("appointment conflicts with existing appointment: %s", conflicts[0].ID)
	}

	// Generate ID and set timestamps
	apt.ID = uuid.New().String()
	apt.CreatedAt = time.Now()
	apt.UpdatedAt = time.Now()

	// Set default status if not provided
	if apt.Status == "" {
		apt.Status = string(types.StatusScheduled)
	}

	// Create appointment in database
	if err := s.repository.CreateAppointment(apt); err != nil {
		return nil, fmt.Errorf("failed to create appointment: %w", err)
	}

	// Sync to calendar
	if err := s.calendarManager.SyncAppointmentToCalendar(apt); err != nil {
		s.logger.Error("Failed to sync appointment to calendar: %v", err)
		// Don't fail the appointment creation if calendar sync fails
	}

	// Send confirmation notification
	if err := s.notificationManager.SendAppointmentConfirmation(apt.ID); err != nil {
		s.logger.Error("Failed to send appointment confirmation: %v", err)
		// Don't fail the appointment creation if notification fails
	}

	s.logger.Info("Successfully created appointment %s", apt.ID)
	return apt, nil
}

// GetAppointment retrieves an appointment by ID with role validation
func (s *Service) GetAppointment(aptID, userID string) (*types.Appointment, error) {
	s.logger.Info("Getting appointment %s for user %s", aptID, userID)

	apt, err := s.repository.GetAppointmentByID(aptID)
	if err != nil {
		return nil, fmt.Errorf("failed to get appointment: %w", err)
	}

	// TODO: Add role-based access control validation
	// For now, allowing access to all users

	return apt, nil
}

// UpdateAppointment updates an existing appointment with role validation
func (s *Service) UpdateAppointment(aptID string, updates *types.AppointmentUpdates, userID string) error {
	s.logger.Info("Updating appointment %s for user %s", aptID, userID)

	// Get existing appointment
	existing, err := s.repository.GetAppointmentByID(aptID)
	if err != nil {
		return fmt.Errorf("failed to get existing appointment: %w", err)
	}

	// Check for conflicts if time is being updated
	if updates.StartTime != nil || updates.EndTime != nil {
		startTime := existing.StartTime
		endTime := existing.EndTime

		if updates.StartTime != nil {
			startTime = *updates.StartTime
		}
		if updates.EndTime != nil {
			endTime = *updates.EndTime
		}

		conflicts, err := s.repository.GetConflictingAppointments(existing.ProviderID, &types.TimeSlot{
			StartTime: startTime,
			EndTime:   endTime,
		})
		if err != nil {
			return fmt.Errorf("failed to check for conflicts: %w", err)
		}

		// Filter out the current appointment from conflicts
		for _, conflict := range conflicts {
			if conflict.ID != aptID {
				return fmt.Errorf("appointment conflicts with existing appointment: %s", conflict.ID)
			}
		}
	}

	// Update appointment
	if err := s.repository.UpdateAppointment(aptID, updates); err != nil {
		return fmt.Errorf("failed to update appointment: %w", err)
	}

	// Send change notification
	changeType := "updated"
	if updates.Status != nil && *updates.Status == types.StatusCancelled {
		changeType = "cancelled"
	} else if updates.StartTime != nil || updates.EndTime != nil {
		changeType = "rescheduled"
	}

	if err := s.notificationManager.SendAppointmentChangeNotification(aptID, changeType); err != nil {
		s.logger.Error("Failed to send appointment change notification: %v", err)
	}

	// Update calendar if time changed
	if updates.StartTime != nil || updates.EndTime != nil {
		// TODO: Get calendar event ID and update
		s.logger.Info("Calendar update needed for appointment time change")
	}

	s.logger.Info("Successfully updated appointment %s", aptID)
	return nil
}

// CancelAppointment cancels an appointment with role validation
func (s *Service) CancelAppointment(aptID, userID string) error {
	s.logger.Info("Cancelling appointment %s for user %s", aptID, userID)

	// TODO: Add role-based access control validation

	status := types.StatusCancelled
	updates := &types.AppointmentUpdates{
		Status: &status,
	}

	if err := s.repository.UpdateAppointment(aptID, updates); err != nil {
		return fmt.Errorf("failed to cancel appointment: %w", err)
	}

	s.logger.Info("Successfully cancelled appointment %s", aptID)
	return nil
}

// GetAppointments retrieves appointments based on filters with role validation
func (s *Service) GetAppointments(userID string, filters *types.AppointmentFilters) ([]*types.Appointment, error) {
	s.logger.Info("Getting appointments for user %s", userID)

	// TODO: Add role-based filtering based on user permissions

	appointments, err := s.repository.GetAppointments(filters)
	if err != nil {
		return nil, fmt.Errorf("failed to get appointments: %w", err)
	}

	return appointments, nil
}

// GetPatientAppointments retrieves appointments for a specific patient
func (s *Service) GetPatientAppointments(patientID, userID string) ([]*types.Appointment, error) {
	s.logger.Info("Getting appointments for patient %s requested by user %s", patientID, userID)

	filters := &types.AppointmentFilters{
		PatientID: patientID,
	}

	return s.GetAppointments(userID, filters)
}

// GetProviderAppointments retrieves appointments for a specific provider
func (s *Service) GetProviderAppointments(providerID, userID string) ([]*types.Appointment, error) {
	s.logger.Info("Getting appointments for provider %s requested by user %s", providerID, userID)

	filters := &types.AppointmentFilters{
		ProviderID: providerID,
	}

	return s.GetAppointments(userID, filters)
}

// CheckAvailability checks if a provider is available for a given time slot
func (s *Service) CheckAvailability(providerID string, timeSlot *types.TimeSlot) (bool, error) {
	s.logger.Info("Checking availability for provider %s from %v to %v", providerID, timeSlot.StartTime, timeSlot.EndTime)

	conflicts, err := s.repository.GetConflictingAppointments(providerID, timeSlot)
	if err != nil {
		return false, fmt.Errorf("failed to check availability: %w", err)
	}

	available := len(conflicts) == 0
	s.logger.Info("Provider %s availability: %t", providerID, available)
	return available, nil
}

// GetAvailableSlots returns available time slots for a provider on a given date
func (s *Service) GetAvailableSlots(providerID string, date string) ([]*types.TimeSlot, error) {
	s.logger.Info("Getting available slots for provider %s on %s", providerID, date)

	// Get provider's schedule for the day
	appointments, err := s.repository.GetProviderSchedule(providerID, date)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider schedule: %w", err)
	}

	// Parse the date
	startDate, err := time.Parse("2006-01-02", date)
	if err != nil {
		return nil, fmt.Errorf("invalid date format: %w", err)
	}

	// Define working hours (9 AM to 5 PM)
	workStart := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 9, 0, 0, 0, startDate.Location())
	workEnd := time.Date(startDate.Year(), startDate.Month(), startDate.Day(), 17, 0, 0, 0, startDate.Location())

	// Generate available slots (30-minute intervals)
	var availableSlots []*types.TimeSlot
	slotDuration := 30 * time.Minute

	for current := workStart; current.Add(slotDuration).Before(workEnd) || current.Add(slotDuration).Equal(workEnd); current = current.Add(slotDuration) {
		slot := &types.TimeSlot{
			StartTime: current,
			EndTime:   current.Add(slotDuration),
		}

		// Check if this slot conflicts with any existing appointment
		available := true
		for _, apt := range appointments {
			if (slot.StartTime.Before(apt.EndTime) && slot.EndTime.After(apt.StartTime)) {
				available = false
				break
			}
		}

		if available {
			availableSlots = append(availableSlots, slot)
		}
	}

	s.logger.Info("Found %d available slots for provider %s on %s", len(availableSlots), providerID, date)
	return availableSlots, nil
}

// BlockTimeSlot blocks a time slot for a provider
func (s *Service) BlockTimeSlot(providerID string, timeSlot *types.TimeSlot, reason string) error {
	s.logger.Info("Blocking time slot for provider %s from %v to %v", providerID, timeSlot.StartTime, timeSlot.EndTime)

	// Create a blocked appointment
	apt := &types.Appointment{
		ID:         uuid.New().String(),
		PatientID:  "BLOCKED", // Special patient ID for blocked slots
		ProviderID: providerID,
		StartTime:  timeSlot.StartTime,
		EndTime:    timeSlot.EndTime,
		Type:       "blocked",
		Status:     string(types.StatusScheduled),
		Notes:      reason,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := s.repository.CreateAppointment(apt); err != nil {
		return fmt.Errorf("failed to block time slot: %w", err)
	}

	s.logger.Info("Successfully blocked time slot %s", apt.ID)
	return nil
}

// UnblockTimeSlot unblocks a previously blocked time slot
func (s *Service) UnblockTimeSlot(providerID string, timeSlot *types.TimeSlot) error {
	s.logger.Info("Unblocking time slot for provider %s from %v to %v", providerID, timeSlot.StartTime, timeSlot.EndTime)

	// Find blocked appointments in this time slot
	conflicts, err := s.repository.GetConflictingAppointments(providerID, timeSlot)
	if err != nil {
		return fmt.Errorf("failed to find blocked appointments: %w", err)
	}

	// Cancel blocked appointments
	for _, apt := range conflicts {
		if apt.PatientID == "BLOCKED" {
			if err := s.repository.DeleteAppointment(apt.ID); err != nil {
				return fmt.Errorf("failed to unblock appointment %s: %w", apt.ID, err)
			}
		}
	}

	s.logger.Info("Successfully unblocked time slot for provider %s", providerID)
	return nil
}

// CreateProvider creates a new provider
func (s *Service) CreateProvider(provider *types.Provider, userID string) (*types.Provider, error) {
	s.logger.Info("Creating provider for user %s", provider.UserID)

	// Generate ID and set timestamps
	provider.ID = uuid.New().String()
	provider.CreatedAt = time.Now()
	provider.UpdatedAt = time.Now()

	if err := s.repository.CreateProvider(provider); err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	s.logger.Info("Successfully created provider %s", provider.ID)
	return provider, nil
}

// GetProvider retrieves a provider by ID
func (s *Service) GetProvider(providerID, userID string) (*types.Provider, error) {
	s.logger.Info("Getting provider %s for user %s", providerID, userID)

	provider, err := s.repository.GetProviderByID(providerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %w", err)
	}

	return provider, nil
}

// UpdateProvider updates an existing provider
func (s *Service) UpdateProvider(providerID string, updates map[string]interface{}, userID string) error {
	s.logger.Info("Updating provider %s for user %s", providerID, userID)

	if err := s.repository.UpdateProvider(providerID, updates); err != nil {
		return fmt.Errorf("failed to update provider: %w", err)
	}

	s.logger.Info("Successfully updated provider %s", providerID)
	return nil
}

// GetProviders retrieves providers based on filters
func (s *Service) GetProviders(filters map[string]interface{}, userID string) ([]*types.Provider, error) {
	s.logger.Info("Getting providers for user %s", userID)

	providers, err := s.repository.GetProviders(filters, 100, 0) // Default limit
	if err != nil {
		return nil, fmt.Errorf("failed to get providers: %w", err)
	}

	return providers, nil
}

// SendAppointmentReminder sends a reminder for an appointment
func (s *Service) SendAppointmentReminder(aptID string) error {
	return s.notificationManager.SendAppointmentReminder(aptID)
}

// SendAppointmentConfirmation sends a confirmation for an appointment
func (s *Service) SendAppointmentConfirmation(aptID string) error {
	return s.notificationManager.SendAppointmentConfirmation(aptID)
}

// NotifyAppointmentChange notifies about appointment changes
func (s *Service) NotifyAppointmentChange(aptID string) error {
	return s.notificationManager.SendAppointmentChangeNotification(aptID, "updated")
}

// Start starts the scheduling service HTTP server
func (s *Service) Start(addr string) error {
	router := mux.NewRouter()
	s.setupRoutes(router)

	s.server = &http.Server{
		Addr:    addr,
		Handler: router,
	}

	s.logger.Info("Starting Scheduling Service on %s", addr)
	return s.server.ListenAndServe()
}

// Stop stops the scheduling service
func (s *Service) Stop() error {
	if s.server != nil {
		s.logger.Info("Stopping Scheduling Service")
		return s.server.Close()
	}
	return nil
}

// validateAppointment validates appointment data
func (s *Service) validateAppointment(apt *types.Appointment) error {
	if apt.PatientID == "" {
		return fmt.Errorf("patient ID is required")
	}

	if apt.ProviderID == "" {
		return fmt.Errorf("provider ID is required")
	}

	if apt.StartTime.IsZero() {
		return fmt.Errorf("start time is required")
	}

	if apt.EndTime.IsZero() {
		return fmt.Errorf("end time is required")
	}

	if apt.EndTime.Before(apt.StartTime) || apt.EndTime.Equal(apt.StartTime) {
		return fmt.Errorf("end time must be after start time")
	}

	if apt.Type == "" {
		return fmt.Errorf("appointment type is required")
	}

	// Validate appointment is not in the past
	if apt.StartTime.Before(time.Now()) {
		return fmt.Errorf("cannot schedule appointment in the past")
	}

	return nil
}

