package scheduling

import (
	"testing"
	"time"

	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSchedulingRepository is a mock implementation of SchedulingRepository
type MockSchedulingRepository struct {
	mock.Mock
}

func (m *MockSchedulingRepository) CreateAppointment(apt *types.Appointment) error {
	args := m.Called(apt)
	return args.Error(0)
}

func (m *MockSchedulingRepository) GetAppointmentByID(id string) (*types.Appointment, error) {
	args := m.Called(id)
	return args.Get(0).(*types.Appointment), args.Error(1)
}

func (m *MockSchedulingRepository) UpdateAppointment(id string, updates *types.AppointmentUpdates) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockSchedulingRepository) DeleteAppointment(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockSchedulingRepository) GetAppointments(filters *types.AppointmentFilters) ([]*types.Appointment, error) {
	args := m.Called(filters)
	return args.Get(0).([]*types.Appointment), args.Error(1)
}

func (m *MockSchedulingRepository) CreateProvider(provider *types.Provider) error {
	args := m.Called(provider)
	return args.Error(0)
}

func (m *MockSchedulingRepository) GetProviderByID(id string) (*types.Provider, error) {
	args := m.Called(id)
	return args.Get(0).(*types.Provider), args.Error(1)
}

func (m *MockSchedulingRepository) GetProviderByUserID(userID string) (*types.Provider, error) {
	args := m.Called(userID)
	return args.Get(0).(*types.Provider), args.Error(1)
}

func (m *MockSchedulingRepository) UpdateProvider(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockSchedulingRepository) GetProviders(filters map[string]interface{}, limit, offset int) ([]*types.Provider, error) {
	args := m.Called(filters, limit, offset)
	return args.Get(0).([]*types.Provider), args.Error(1)
}

func (m *MockSchedulingRepository) GetConflictingAppointments(providerID string, timeSlot *types.TimeSlot) ([]*types.Appointment, error) {
	args := m.Called(providerID, timeSlot)
	return args.Get(0).([]*types.Appointment), args.Error(1)
}

func (m *MockSchedulingRepository) GetProviderSchedule(providerID string, date string) ([]*types.Appointment, error) {
	args := m.Called(providerID, date)
	return args.Get(0).([]*types.Appointment), args.Error(1)
}



// Test setup helper
func setupTestService() (*Service, *MockSchedulingRepository) {
	cfg := &config.Config{}
	log := logger.New("debug")
	mockRepo := &MockSchedulingRepository{}

	// Create mock services
	mockNotificationService := &MockNotificationService{}
	mockCalendarService := &MockCalendarService{}
	
	// Create managers
	notificationManager := NewAppointmentNotificationManager(mockNotificationService, mockRepo, log)
	calendarManager := NewCalendarIntegrationManager(mockCalendarService, mockRepo, log)

	service := &Service{
		config:              cfg,
		logger:              log,
		repository:          mockRepo,
		notificationService: mockNotificationService,
		calendarService:     mockCalendarService,
		notificationManager: notificationManager,
		calendarManager:     calendarManager,
	}

	return service, mockRepo
}

func TestCreateAppointment_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	apt := &types.Appointment{
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Type:       string(types.TypeConsultation),
	}

	// Mock no conflicts
	mockRepo.On("GetConflictingAppointments", apt.ProviderID, mock.AnythingOfType("*types.TimeSlot")).Return([]*types.Appointment{}, nil)
	mockRepo.On("CreateAppointment", mock.AnythingOfType("*types.Appointment")).Return(nil)
	
	// Mock calendar and notification calls
	mockCalendarService := service.calendarService.(*MockCalendarService)
	mockCalendarService.On("CreateCalendarEvent", apt.ProviderID, mock.AnythingOfType("*types.Appointment")).Return(nil)
	
	mockRepo.On("GetAppointmentByID", mock.AnythingOfType("string")).Return(apt, nil)
	
	mockNotificationService := service.notificationService.(*MockNotificationService)
	mockNotificationService.On("SendEmail", "patient@example.com", "Appointment Confirmation", mock.AnythingOfType("string")).Return(nil)
	mockNotificationService.On("SendPushNotification", apt.PatientID, "Appointment Confirmed", mock.AnythingOfType("string")).Return(nil)

	result, err := service.CreateAppointment(apt, "user-123")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.ID)
	assert.Equal(t, string(types.StatusScheduled), result.Status)
	mockRepo.AssertExpectations(t)
}

func TestCreateAppointment_ValidationError(t *testing.T) {
	service, _ := setupTestService()

	// Test missing patient ID
	apt := &types.Appointment{
		ProviderID: "provider-456",
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Type:       string(types.TypeConsultation),
	}

	_, err := service.CreateAppointment(apt, "user-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "patient ID is required")
}

func TestCreateAppointment_PastTime(t *testing.T) {
	service, _ := setupTestService()

	apt := &types.Appointment{
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		StartTime:  time.Now().Add(-1 * time.Hour), // Past time
		EndTime:    time.Now(),
		Type:       string(types.TypeConsultation),
	}

	_, err := service.CreateAppointment(apt, "user-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot schedule appointment in the past")
}

func TestCreateAppointment_Conflict(t *testing.T) {
	service, mockRepo := setupTestService()

	apt := &types.Appointment{
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Type:       string(types.TypeConsultation),
	}

	// Mock existing conflict
	conflictingApt := &types.Appointment{
		ID:         "conflict-123",
		ProviderID: "provider-456",
		StartTime:  apt.StartTime,
		EndTime:    apt.EndTime,
	}

	mockRepo.On("GetConflictingAppointments", apt.ProviderID, mock.AnythingOfType("*types.TimeSlot")).Return([]*types.Appointment{conflictingApt}, nil)

	_, err := service.CreateAppointment(apt, "user-123")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "appointment conflicts")
	mockRepo.AssertExpectations(t)
}

func TestGetAppointment_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	expectedApt := &types.Appointment{
		ID:         "apt-123",
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Type:       string(types.TypeConsultation),
		Status:     string(types.StatusScheduled),
	}

	mockRepo.On("GetAppointmentByID", "apt-123").Return(expectedApt, nil)

	result, err := service.GetAppointment("apt-123", "user-123")

	assert.NoError(t, err)
	assert.Equal(t, expectedApt, result)
	mockRepo.AssertExpectations(t)
}

func TestUpdateAppointment_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	aptID := "apt-123"
	existingApt := &types.Appointment{
		ID:         aptID,
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Type:       string(types.TypeConsultation),
		Status:     string(types.StatusScheduled),
	}

	newStatus := types.StatusConfirmed
	updates := &types.AppointmentUpdates{
		Status: &newStatus,
	}

	mockRepo.On("GetAppointmentByID", aptID).Return(existingApt, nil)
	mockRepo.On("UpdateAppointment", aptID, updates).Return(nil)
	
	// Mock notification calls
	mockRepo.On("GetAppointmentByID", aptID).Return(existingApt, nil)
	mockNotificationService := service.notificationService.(*MockNotificationService)
	mockNotificationService.On("SendEmail", "patient@example.com", "Appointment Updated", mock.AnythingOfType("string")).Return(nil)
	mockNotificationService.On("SendPushNotification", existingApt.PatientID, "Appointment Updated", mock.AnythingOfType("string")).Return(nil)

	err := service.UpdateAppointment(aptID, updates, "user-123")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestUpdateAppointment_TimeConflict(t *testing.T) {
	service, mockRepo := setupTestService()

	aptID := "apt-123"
	existingApt := &types.Appointment{
		ID:         aptID,
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		StartTime:  time.Now().Add(24 * time.Hour),
		EndTime:    time.Now().Add(25 * time.Hour),
		Type:       string(types.TypeConsultation),
		Status:     string(types.StatusScheduled),
	}

	newStartTime := time.Now().Add(26 * time.Hour)
	updates := &types.AppointmentUpdates{
		StartTime: &newStartTime,
	}

	// Mock existing appointment and conflict
	conflictingApt := &types.Appointment{
		ID:         "conflict-123",
		ProviderID: "provider-456",
		StartTime:  newStartTime,
		EndTime:    newStartTime.Add(time.Hour),
	}

	mockRepo.On("GetAppointmentByID", aptID).Return(existingApt, nil)
	mockRepo.On("GetConflictingAppointments", existingApt.ProviderID, mock.AnythingOfType("*types.TimeSlot")).Return([]*types.Appointment{conflictingApt}, nil)

	err := service.UpdateAppointment(aptID, updates, "user-123")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "appointment conflicts")
	mockRepo.AssertExpectations(t)
}

func TestCancelAppointment_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	aptID := "apt-123"
	mockRepo.On("UpdateAppointment", aptID, mock.AnythingOfType("*types.AppointmentUpdates")).Return(nil)

	err := service.CancelAppointment(aptID, "user-123")

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestCheckAvailability_Available(t *testing.T) {
	service, mockRepo := setupTestService()

	providerID := "provider-456"
	timeSlot := &types.TimeSlot{
		StartTime: time.Now().Add(24 * time.Hour),
		EndTime:   time.Now().Add(25 * time.Hour),
	}

	// Mock no conflicts
	mockRepo.On("GetConflictingAppointments", providerID, timeSlot).Return([]*types.Appointment{}, nil)

	available, err := service.CheckAvailability(providerID, timeSlot)

	assert.NoError(t, err)
	assert.True(t, available)
	mockRepo.AssertExpectations(t)
}

func TestCheckAvailability_NotAvailable(t *testing.T) {
	service, mockRepo := setupTestService()

	providerID := "provider-456"
	timeSlot := &types.TimeSlot{
		StartTime: time.Now().Add(24 * time.Hour),
		EndTime:   time.Now().Add(25 * time.Hour),
	}

	// Mock existing conflict
	conflictingApt := &types.Appointment{
		ID:         "conflict-123",
		ProviderID: providerID,
		StartTime:  timeSlot.StartTime,
		EndTime:    timeSlot.EndTime,
	}

	mockRepo.On("GetConflictingAppointments", providerID, timeSlot).Return([]*types.Appointment{conflictingApt}, nil)

	available, err := service.CheckAvailability(providerID, timeSlot)

	assert.NoError(t, err)
	assert.False(t, available)
	mockRepo.AssertExpectations(t)
}

func TestGetAvailableSlots_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	providerID := "provider-456"
	date := time.Now().Format("2006-01-02")

	// Mock existing appointments (lunch time blocked)
	existingApts := []*types.Appointment{
		{
			ID:         "lunch-block",
			ProviderID: providerID,
			StartTime:  time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 12, 0, 0, 0, time.UTC),
			EndTime:    time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 13, 0, 0, 0, time.UTC),
		},
	}

	mockRepo.On("GetProviderSchedule", providerID, date).Return(existingApts, nil)

	slots, err := service.GetAvailableSlots(providerID, date)

	assert.NoError(t, err)
	assert.NotEmpty(t, slots)
	
	// Should have morning and afternoon slots, but not lunch time
	morningSlots := 0
	afternoonSlots := 0
	
	for _, slot := range slots {
		if slot.StartTime.Hour() < 12 {
			morningSlots++
		} else if slot.StartTime.Hour() >= 13 {
			afternoonSlots++
		}
	}
	
	assert.Greater(t, morningSlots, 0)
	assert.Greater(t, afternoonSlots, 0)
	mockRepo.AssertExpectations(t)
}

func TestCreateProvider_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	provider := &types.Provider{
		UserID:        "user-123",
		Specialty:     "Cardiology",
		LicenseNumber: "LIC123456",
		Department:    "Internal Medicine",
		IsActive:      true,
	}

	mockRepo.On("CreateProvider", mock.AnythingOfType("*types.Provider")).Return(nil)

	result, err := service.CreateProvider(provider, "admin-123")

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotEmpty(t, result.ID)
	mockRepo.AssertExpectations(t)
}

func TestGetProvider_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	expectedProvider := &types.Provider{
		ID:            "provider-123",
		UserID:        "user-123",
		Specialty:     "Cardiology",
		LicenseNumber: "LIC123456",
		Department:    "Internal Medicine",
		IsActive:      true,
	}

	mockRepo.On("GetProviderByID", "provider-123").Return(expectedProvider, nil)

	result, err := service.GetProvider("provider-123", "user-123")

	assert.NoError(t, err)
	assert.Equal(t, expectedProvider, result)
	mockRepo.AssertExpectations(t)
}

func TestBlockTimeSlot_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	providerID := "provider-456"
	timeSlot := &types.TimeSlot{
		StartTime: time.Now().Add(24 * time.Hour),
		EndTime:   time.Now().Add(25 * time.Hour),
	}
	reason := "Personal time"

	mockRepo.On("CreateAppointment", mock.AnythingOfType("*types.Appointment")).Return(nil)

	err := service.BlockTimeSlot(providerID, timeSlot, reason)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestUnblockTimeSlot_Success(t *testing.T) {
	service, mockRepo := setupTestService()

	providerID := "provider-456"
	timeSlot := &types.TimeSlot{
		StartTime: time.Now().Add(24 * time.Hour),
		EndTime:   time.Now().Add(25 * time.Hour),
	}

	// Mock blocked appointment
	blockedApt := &types.Appointment{
		ID:         "blocked-123",
		PatientID:  "BLOCKED",
		ProviderID: providerID,
		StartTime:  timeSlot.StartTime,
		EndTime:    timeSlot.EndTime,
	}

	mockRepo.On("GetConflictingAppointments", providerID, timeSlot).Return([]*types.Appointment{blockedApt}, nil)
	mockRepo.On("DeleteAppointment", "blocked-123").Return(nil)

	err := service.UnblockTimeSlot(providerID, timeSlot)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestValidateAppointment_InvalidEndTime(t *testing.T) {
	service, _ := setupTestService()

	apt := &types.Appointment{
		PatientID:  "patient-123",
		ProviderID: "provider-456",
		StartTime:  time.Now().Add(25 * time.Hour),
		EndTime:    time.Now().Add(24 * time.Hour), // End before start
		Type:       string(types.TypeConsultation),
	}

	err := service.validateAppointment(apt)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "end time must be after start time")
}

func TestValidateAppointment_MissingFields(t *testing.T) {
	service, _ := setupTestService()

	testCases := []struct {
		name        string
		appointment *types.Appointment
		expectedErr string
	}{
		{
			name: "missing patient ID",
			appointment: &types.Appointment{
				ProviderID: "provider-456",
				StartTime:  time.Now().Add(24 * time.Hour),
				EndTime:    time.Now().Add(25 * time.Hour),
				Type:       string(types.TypeConsultation),
			},
			expectedErr: "patient ID is required",
		},
		{
			name: "missing provider ID",
			appointment: &types.Appointment{
				PatientID: "patient-123",
				StartTime: time.Now().Add(24 * time.Hour),
				EndTime:   time.Now().Add(25 * time.Hour),
				Type:      string(types.TypeConsultation),
			},
			expectedErr: "provider ID is required",
		},
		{
			name: "missing type",
			appointment: &types.Appointment{
				PatientID:  "patient-123",
				ProviderID: "provider-456",
				StartTime:  time.Now().Add(24 * time.Hour),
				EndTime:    time.Now().Add(25 * time.Hour),
			},
			expectedErr: "appointment type is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := service.validateAppointment(tc.appointment)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tc.expectedErr)
		})
	}
}