package scheduling

import (
	"testing"
	"time"

	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockNotificationService is a mock implementation of NotificationService
type MockNotificationService struct {
	mock.Mock
}

func (m *MockNotificationService) SendEmail(to, subject, body string) error {
	args := m.Called(to, subject, body)
	return args.Error(0)
}

func (m *MockNotificationService) SendEmailTemplate(to, template string, data map[string]interface{}) error {
	args := m.Called(to, template, data)
	return args.Error(0)
}

func (m *MockNotificationService) SendSMS(to, message string) error {
	args := m.Called(to, message)
	return args.Error(0)
}

func (m *MockNotificationService) SendSMSTemplate(to, template string, data map[string]interface{}) error {
	args := m.Called(to, template, data)
	return args.Error(0)
}

func (m *MockNotificationService) SendPushNotification(userID, title, message string) error {
	args := m.Called(userID, title, message)
	return args.Error(0)
}

func (m *MockNotificationService) GetUserPreferences(userID string) (map[string]bool, error) {
	args := m.Called(userID)
	return args.Get(0).(map[string]bool), args.Error(1)
}

func (m *MockNotificationService) UpdateUserPreferences(userID string, preferences map[string]bool) error {
	args := m.Called(userID, preferences)
	return args.Error(0)
}

func TestNotificationService_SendEmail(t *testing.T) {
	log := logger.New("debug")
	service := NewNotificationService(log)

	err := service.SendEmail("test@example.com", "Test Subject", "Test Body")
	assert.NoError(t, err)
}

func TestNotificationService_SendSMS(t *testing.T) {
	log := logger.New("debug")
	service := NewNotificationService(log)

	err := service.SendSMS("+1234567890", "Test SMS message")
	assert.NoError(t, err)
}

func TestNotificationService_SendPushNotification(t *testing.T) {
	log := logger.New("debug")
	service := NewNotificationService(log)

	err := service.SendPushNotification("user-123", "Test Title", "Test Message")
	assert.NoError(t, err)
}

func TestNotificationService_GetUserPreferences(t *testing.T) {
	log := logger.New("debug")
	service := NewNotificationService(log)

	preferences, err := service.GetUserPreferences("user-123")
	assert.NoError(t, err)
	assert.NotNil(t, preferences)
	
	// Check default preferences
	assert.True(t, preferences["email_reminders"])
	assert.False(t, preferences["sms_reminders"])
	assert.True(t, preferences["push_notifications"])
}

func TestNotificationService_UpdateUserPreferences(t *testing.T) {
	log := logger.New("debug")
	service := NewNotificationService(log)

	newPreferences := map[string]bool{
		"email_reminders": false,
		"sms_reminders":   true,
	}

	err := service.UpdateUserPreferences("user-123", newPreferences)
	assert.NoError(t, err)
}

func TestAppointmentNotificationManager_SendAppointmentReminder(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Status:     string(types.StatusScheduled),
		Location:   "Room 101",
	}

	mockRepo.On("GetAppointmentByID", "apt-123").Return(apt, nil)
	mockNotificationService.On("SendEmail", "patient@example.com", "Appointment Reminder", mock.AnythingOfType("string")).Return(nil)
	mockNotificationService.On("SendPushNotification", "patient-123", "Appointment Reminder", mock.AnythingOfType("string")).Return(nil)

	err := manager.SendAppointmentReminder("apt-123")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockNotificationService.AssertExpectations(t)
}

func TestAppointmentNotificationManager_SendAppointmentConfirmation(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Status:     string(types.StatusScheduled),
		Location:   "Room 101",
	}

	mockRepo.On("GetAppointmentByID", "apt-123").Return(apt, nil)
	mockNotificationService.On("SendEmail", "patient@example.com", "Appointment Confirmation", mock.AnythingOfType("string")).Return(nil)
	mockNotificationService.On("SendPushNotification", "patient-123", "Appointment Confirmed", mock.AnythingOfType("string")).Return(nil)

	err := manager.SendAppointmentConfirmation("apt-123")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockNotificationService.AssertExpectations(t)
}

func TestAppointmentNotificationManager_SendAppointmentChangeNotification_Cancelled(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Status:     string(types.StatusCancelled),
		Location:   "Room 101",
	}

	mockRepo.On("GetAppointmentByID", "apt-123").Return(apt, nil)
	mockNotificationService.On("SendEmail", "patient@example.com", "Appointment Cancelled", mock.AnythingOfType("string")).Return(nil)
	mockNotificationService.On("SendPushNotification", "patient-123", "Appointment Cancelled", mock.AnythingOfType("string")).Return(nil)

	err := manager.SendAppointmentChangeNotification("apt-123", "cancelled")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockNotificationService.AssertExpectations(t)
}

func TestAppointmentNotificationManager_SendAppointmentChangeNotification_Rescheduled(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(48 * time.Hour), // Rescheduled to 2 days later
		EndTime:    time.Now().Add(49 * time.Hour),
		Status:     string(types.StatusScheduled),
		Location:   "Room 101",
	}

	mockRepo.On("GetAppointmentByID", "apt-123").Return(apt, nil)
	mockNotificationService.On("SendEmail", "patient@example.com", "Appointment Rescheduled", mock.AnythingOfType("string")).Return(nil)
	mockNotificationService.On("SendPushNotification", "patient-123", "Appointment Rescheduled", mock.AnythingOfType("string")).Return(nil)

	err := manager.SendAppointmentChangeNotification("apt-123", "rescheduled")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockNotificationService.AssertExpectations(t)
}

func TestAppointmentNotificationManager_SendConflictAlert(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	conflictingApts := []*types.Appointment{
		{
			ID:         "apt-1",
			PatientID:  "patient-123",
			ProviderID: "provider-456",
			StartTime:  time.Now().Add(24 * time.Hour),
			EndTime:    time.Now().Add(25 * time.Hour),
		},
		{
			ID:         "apt-2",
			PatientID:  "patient-789",
			ProviderID: "provider-456",
			StartTime:  time.Now().Add(24 * time.Hour),
			EndTime:    time.Now().Add(25 * time.Hour),
		},
	}

	mockNotificationService.On("SendEmail", "provider@example.com", "Scheduling Conflict Alert", mock.AnythingOfType("string")).Return(nil)
	mockNotificationService.On("SendPushNotification", "provider-456", "Scheduling Conflict", mock.AnythingOfType("string")).Return(nil)

	err := manager.SendConflictAlert("provider-456", conflictingApts)

	assert.NoError(t, err)
	mockNotificationService.AssertExpectations(t)
}

func TestAppointmentNotificationManager_SendConflictAlert_NoConflicts(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	err := manager.SendConflictAlert("provider-456", []*types.Appointment{})

	assert.NoError(t, err)
	// No expectations set because no notifications should be sent
}

func TestAppointmentNotificationManager_ScheduleReminders(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	// Mock appointments for tomorrow (24 hours away)
	tomorrow := time.Now().Add(24 * time.Hour)
	appointments := []*types.Appointment{
		{
			ID:         "apt-1",
			PatientID:  "patient-123",
			ProviderID: "provider-456",
			StartTime:  tomorrow,
			EndTime:    tomorrow.Add(time.Hour),
			Status:     string(types.StatusScheduled),
		},
	}

	mockRepo.On("GetAppointments", mock.AnythingOfType("*types.AppointmentFilters")).Return(appointments, nil)
	
	// Expect reminder to be sent for the appointment
	apt := appointments[0]
	mockRepo.On("GetAppointmentByID", apt.ID).Return(apt, nil)
	mockNotificationService.On("SendEmail", "patient@example.com", "Appointment Reminder", mock.AnythingOfType("string")).Return(nil)
	mockNotificationService.On("SendPushNotification", apt.PatientID, "Appointment Reminder", mock.AnythingOfType("string")).Return(nil)

	err := manager.ScheduleReminders()

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockNotificationService.AssertExpectations(t)
}

func TestAppointmentNotificationManager_FormatDuration(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	testCases := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Minute, "30 minutes"},
		{90 * time.Minute, "1 hours"},
		{2 * time.Hour, "2 hours"},
		{25 * time.Hour, "1 days"},
		{48 * time.Hour, "2 days"},
	}

	for _, tc := range testCases {
		result := manager.formatDuration(tc.duration)
		assert.Equal(t, tc.expected, result)
	}
}

// Test error handling
func TestAppointmentNotificationManager_SendAppointmentReminder_RepositoryError(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	mockRepo.On("GetAppointmentByID", "apt-123").Return((*types.Appointment)(nil), assert.AnError)

	err := manager.SendAppointmentReminder("apt-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get appointment")
	mockRepo.AssertExpectations(t)
}

func TestAppointmentNotificationManager_SendAppointmentReminder_NotificationError(t *testing.T) {
	log := logger.New("debug")
	mockNotificationService := &MockNotificationService{}
	mockRepo := &MockSchedulingRepository{}

	manager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)

	apt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		Type:       string(types.TypeConsultation),
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Status:     string(types.StatusScheduled),
		Location:   "Room 101",
	}

	mockRepo.On("GetAppointmentByID", "apt-123").Return(apt, nil)
	mockNotificationService.On("SendEmail", "patient@example.com", "Appointment Reminder", mock.AnythingOfType("string")).Return(assert.AnError)
	mockNotificationService.On("SendPushNotification", "patient-123", "Appointment Reminder", mock.AnythingOfType("string")).Return(nil)

	// Should not return error even if email fails, but should still send push notification
	err := manager.SendAppointmentReminder("apt-123")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
	mockNotificationService.AssertExpectations(t)
}