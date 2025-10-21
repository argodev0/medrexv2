package scheduling

import (
	"testing"
	"time"

	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockCalendarService is a mock implementation of CalendarService
type MockCalendarService struct {
	mock.Mock
}

func (m *MockCalendarService) CreateCalendarEvent(providerID string, apt *types.Appointment) error {
	args := m.Called(providerID, apt)
	return args.Error(0)
}

func (m *MockCalendarService) UpdateCalendarEvent(providerID, eventID string, apt *types.Appointment) error {
	args := m.Called(providerID, eventID, apt)
	return args.Error(0)
}

func (m *MockCalendarService) DeleteCalendarEvent(providerID, eventID string) error {
	args := m.Called(providerID, eventID)
	return args.Error(0)
}

func (m *MockCalendarService) SyncProviderAvailability(providerID string) error {
	args := m.Called(providerID)
	return args.Error(0)
}

func (m *MockCalendarService) GetExternalAvailability(providerID string, date string) ([]*types.TimeSlot, error) {
	args := m.Called(providerID, date)
	return args.Get(0).([]*types.TimeSlot), args.Error(1)
}

func (m *MockCalendarService) ConnectCalendar(providerID, calendarType, credentials string) error {
	args := m.Called(providerID, calendarType, credentials)
	return args.Error(0)
}

func (m *MockCalendarService) DisconnectCalendar(providerID string) error {
	args := m.Called(providerID)
	return args.Error(0)
}

func TestCalendarService_CreateCalendarEvent(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Location:   "Room 101",
	}

	err := service.CreateCalendarEvent("provider-456", apt)
	assert.NoError(t, err)
}

func TestCalendarService_UpdateCalendarEvent(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(48 * time.Hour), // Rescheduled
		EndTime:    time.Now().Add(49 * time.Hour),
		Location:   "Room 102", // Changed location
	}

	err := service.UpdateCalendarEvent("provider-456", "event-123", apt)
	assert.NoError(t, err)
}

func TestCalendarService_DeleteCalendarEvent(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	err := service.DeleteCalendarEvent("provider-456", "event-123")
	assert.NoError(t, err)
}

func TestCalendarService_SyncProviderAvailability(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	err := service.SyncProviderAvailability("provider-456")
	assert.NoError(t, err)
}

func TestCalendarService_GetExternalAvailability(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	date := "2024-01-15"
	slots, err := service.GetExternalAvailability("provider-456", date)

	assert.NoError(t, err)
	assert.NotEmpty(t, slots)

	// Verify we have morning and afternoon slots
	morningSlots := 0
	afternoonSlots := 0

	for _, slot := range slots {
		if slot.StartTime.Hour() < 12 {
			morningSlots++
		} else if slot.StartTime.Hour() >= 13 {
			afternoonSlots++
		}
	}

	assert.Greater(t, morningSlots, 0, "Should have morning slots")
	assert.Greater(t, afternoonSlots, 0, "Should have afternoon slots")

	// Verify slot duration is 30 minutes
	for _, slot := range slots {
		duration := slot.EndTime.Sub(slot.StartTime)
		assert.Equal(t, 30*time.Minute, duration, "Each slot should be 30 minutes")
	}
}

func TestCalendarService_GetExternalAvailability_InvalidDate(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	_, err := service.GetExternalAvailability("provider-456", "invalid-date")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid date format")
}

func TestCalendarService_ConnectCalendar_Google(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	err := service.ConnectCalendar("provider-456", "google", "oauth-credentials")
	assert.NoError(t, err)
}

func TestCalendarService_ConnectCalendar_Outlook(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	err := service.ConnectCalendar("provider-456", "outlook", "oauth-credentials")
	assert.NoError(t, err)
}

func TestCalendarService_ConnectCalendar_Apple(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	err := service.ConnectCalendar("provider-456", "apple", "caldav-credentials")
	assert.NoError(t, err)
}

func TestCalendarService_ConnectCalendar_UnsupportedType(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	err := service.ConnectCalendar("provider-456", "unsupported", "credentials")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported calendar type")
}

func TestCalendarService_DisconnectCalendar(t *testing.T) {
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}
	service := NewCalendarService(mockRepo, log)

	err := service.DisconnectCalendar("provider-456")
	assert.NoError(t, err)
}

func TestCalendarIntegrationManager_SyncAppointmentToCalendar(t *testing.T) {
	log := logger.New("debug")
	mockCalendarService := &MockCalendarService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Location:   "Room 101",
	}

	mockCalendarService.On("CreateCalendarEvent", "provider-456", apt).Return(nil)

	err := manager.SyncAppointmentToCalendar(apt)

	assert.NoError(t, err)
	mockCalendarService.AssertExpectations(t)
}

func TestCalendarIntegrationManager_UpdateAppointmentInCalendar(t *testing.T) {
	log := logger.New("debug")
	mockCalendarService := &MockCalendarService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(48 * time.Hour), // Rescheduled
		EndTime:    time.Now().Add(49 * time.Hour),
		Location:   "Room 102",
	}

	mockCalendarService.On("UpdateCalendarEvent", "provider-456", "event-123", apt).Return(nil)

	err := manager.UpdateAppointmentInCalendar(apt, "event-123")

	assert.NoError(t, err)
	mockCalendarService.AssertExpectations(t)
}

func TestCalendarIntegrationManager_RemoveAppointmentFromCalendar(t *testing.T) {
	log := logger.New("debug")
	mockCalendarService := &MockCalendarService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	mockCalendarService.On("DeleteCalendarEvent", "provider-456", "event-123").Return(nil)

	err := manager.RemoveAppointmentFromCalendar("provider-456", "event-123")

	assert.NoError(t, err)
	mockCalendarService.AssertExpectations(t)
}

func TestCalendarIntegrationManager_DetectConflicts(t *testing.T) {
	log := logger.New("debug")
	mockCalendarService := &MockCalendarService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	date := "2024-01-15"
	providerID := "provider-456"

	// Mock internal appointments
	internalApts := []*types.Appointment{
		{
			ID:         "apt-1",
			ProviderID: providerID,
			StartTime:  time.Date(2024, 1, 15, 9, 0, 0, 0, time.UTC),
			EndTime:    time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		},
	}

	// Mock external availability
	externalSlots := []*types.TimeSlot{
		{
			StartTime: time.Date(2024, 1, 15, 9, 30, 0, 0, time.UTC),
			EndTime:   time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
		},
	}

	mockRepo.On("GetProviderSchedule", providerID, date).Return(internalApts, nil)
	mockCalendarService.On("GetExternalAvailability", providerID, date).Return(externalSlots, nil)

	conflicts, err := manager.DetectConflicts(providerID, date)

	assert.NoError(t, err)
	assert.Equal(t, 0, len(conflicts))
	mockRepo.AssertExpectations(t)
	mockCalendarService.AssertExpectations(t)
}

func TestCalendarIntegrationManager_AutoSyncProviderCalendars(t *testing.T) {
	log := logger.New("debug")
	mockCalendarService := &MockCalendarService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	// This test would normally iterate over providers with calendar integration
	// For now, it just tests the basic flow with no providers
	err := manager.AutoSyncProviderCalendars()

	assert.NoError(t, err)
}

// Test error handling
func TestCalendarIntegrationManager_SyncAppointmentToCalendar_Error(t *testing.T) {
	log := logger.New("debug")
	mockCalendarService := &MockCalendarService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Location:   "Room 101",
	}

	mockCalendarService.On("CreateCalendarEvent", "provider-456", apt).Return(assert.AnError)

	err := manager.SyncAppointmentToCalendar(apt)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create calendar event")
	mockCalendarService.AssertExpectations(t)
}

func TestCalendarIntegrationManager_DetectConflicts_RepositoryError(t *testing.T) {
	log := logger.New("debug")
	mockCalendarService := &MockCalendarService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	date := "2024-01-15"
	providerID := "provider-456"

	mockRepo.On("GetProviderSchedule", providerID, date).Return(([]*types.Appointment)(nil), assert.AnError)

	_, err := manager.DetectConflicts(providerID, date)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get internal appointments")
	mockRepo.AssertExpectations(t)
}

func TestCalendarIntegrationManager_DetectConflicts_CalendarServiceError(t *testing.T) {
	log := logger.New("debug")
	mockCalendarService := &MockCalendarService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	date := "2024-01-15"
	providerID := "provider-456"

	internalApts := []*types.Appointment{}

	mockRepo.On("GetProviderSchedule", providerID, date).Return(internalApts, nil)
	mockCalendarService.On("GetExternalAvailability", providerID, date).Return(([]*types.TimeSlot)(nil), assert.AnError)

	_, err := manager.DetectConflicts(providerID, date)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get external availability")
	mockRepo.AssertExpectations(t)
	mockCalendarService.AssertExpectations(t)
}