package iam

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Mock implementations for testing

type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *types.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(id string) (*types.User, error) {
	args := m.Called(id)
	return args.Get(0).(*types.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(username string) (*types.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*types.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*types.User), args.Error(1)
}

func (m *MockUserRepository) Update(id string, updates map[string]interface{}) error {
	args := m.Called(id, updates)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id string) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) List(filters map[string]interface{}, limit, offset int) ([]*types.User, error) {
	args := m.Called(filters, limit, offset)
	return args.Get(0).([]*types.User), args.Error(1)
}

type MockCertificateManager struct {
	mock.Mock
}

func (m *MockCertificateManager) EnrollUser(username, password string, attrs map[string]string) (*types.X509Certificate, error) {
	args := m.Called(username, password, attrs)
	return args.Get(0).(*types.X509Certificate), args.Error(1)
}

func (m *MockCertificateManager) RevokeCertificate(serial string, reason int) error {
	args := m.Called(serial, reason)
	return args.Error(0)
}

func (m *MockCertificateManager) ValidateCertificate(cert string) (bool, error) {
	args := m.Called(cert)
	return args.Bool(0), args.Error(1)
}

func (m *MockCertificateManager) ExtractAttributes(cert string) (map[string]string, error) {
	args := m.Called(cert)
	return args.Get(0).(map[string]string), args.Error(1)
}

func (m *MockCertificateManager) GetCertificateInfo(cert string) (map[string]interface{}, error) {
	args := m.Called(cert)
	return args.Get(0).(map[string]interface{}), args.Error(1)
}

type MockMFAProvider struct {
	mock.Mock
}

func (m *MockMFAProvider) GenerateSecret(userID string) (string, error) {
	args := m.Called(userID)
	return args.String(0), args.Error(1)
}

func (m *MockMFAProvider) GenerateQRCode(userID, secret string) ([]byte, error) {
	args := m.Called(userID, secret)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockMFAProvider) VerifyToken(secret, token string) (bool, error) {
	args := m.Called(secret, token)
	return args.Bool(0), args.Error(1)
}

func (m *MockMFAProvider) GetBackupCodes(userID string) ([]string, error) {
	args := m.Called(userID)
	return args.Get(0).([]string), args.Error(1)
}

type MockPasswordManager struct {
	mock.Mock
}

func (m *MockPasswordManager) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockPasswordManager) VerifyPassword(hashedPassword, password string) (bool, error) {
	args := m.Called(hashedPassword, password)
	return args.Bool(0), args.Error(1)
}

func (m *MockPasswordManager) GenerateRandomPassword(length int) (string, error) {
	args := m.Called(length)
	return args.String(0), args.Error(1)
}

// Test setup helper
func setupTestService() (*Service, *MockUserRepository, *MockCertificateManager, *MockMFAProvider, *MockPasswordManager) {
	cfg := &config.Config{
		JWT: config.JWTConfig{
			SecretKey:       "test-secret-key",
			AccessTokenTTL:  3600,
			RefreshTokenTTL: 86400,
			Issuer:          "test-issuer",
			Audience:        "test-audience",
		},
		Fabric: config.FabricConfig{
			OrgName: "TestOrg",
		},
	}

	log := logger.New("debug")
	
	mockUserRepo := &MockUserRepository{}
	mockCertManager := &MockCertificateManager{}
	mockMFAProvider := &MockMFAProvider{}
	mockPasswordManager := &MockPasswordManager{}

	// Create service with mocked dependencies
	service := &Service{
		config:          cfg,
		logger:          log,
		userRepo:        mockUserRepo,
		certManager:     mockCertManager,
		mfaProvider:     mockMFAProvider,
		passwordManager: mockPasswordManager,
	}

	return service, mockUserRepo, mockCertManager, mockMFAProvider, mockPasswordManager
}

// Test user registration
func TestService_RegisterUser(t *testing.T) {
	service, mockUserRepo, mockCertManager, _, mockPasswordManager := setupTestService()

	t.Run("successful registration", func(t *testing.T) {
		req := &types.UserRegistrationRequest{
			Username:     "testuser",
			Email:        "test@example.com",
			Password:     "password123",
			Role:         types.RoleConsultingDoctor,
			Organization: "TestOrg",
		}

		// Setup mocks
		mockUserRepo.On("GetByUsername", "testuser").Return(nil, &types.MedrexError{Type: types.ErrorTypeNotFound})
		mockUserRepo.On("GetByEmail", "test@example.com").Return(nil, &types.MedrexError{Type: types.ErrorTypeNotFound})
		mockPasswordManager.On("HashPassword", "password123").Return("hashed-password", nil)
		mockCertManager.On("EnrollUser", "testuser", "password123", mock.AnythingOfType("map[string]string")).Return(&types.X509Certificate{
			Certificate: "mock-cert",
			PrivateKey:  "mock-key",
		}, nil)
		mockUserRepo.On("Create", mock.AnythingOfType("*types.User")).Return(nil)

		// Execute
		user, err := service.RegisterUser(req)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "testuser", user.Username)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, types.RoleConsultingDoctor, user.Role)
		assert.True(t, user.IsActive)

		mockUserRepo.AssertExpectations(t)
		mockCertManager.AssertExpectations(t)
		mockPasswordManager.AssertExpectations(t)
	})

	t.Run("username already exists", func(t *testing.T) {
		req := &types.UserRegistrationRequest{
			Username:     "existinguser",
			Email:        "test@example.com",
			Password:     "password123",
			Role:         types.RoleConsultingDoctor,
			Organization: "TestOrg",
		}

		existingUser := &types.User{
			ID:       "existing-id",
			Username: "existinguser",
		}

		mockUserRepo.On("GetByUsername", "existinguser").Return(existingUser, nil)

		// Execute
		user, err := service.RegisterUser(req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("invalid request validation", func(t *testing.T) {
		req := &types.UserRegistrationRequest{
			Username: "", // Missing username
			Email:    "test@example.com",
			Password: "password123",
			Role:     types.RoleConsultingDoctor,
		}

		// Execute
		user, err := service.RegisterUser(req)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Contains(t, err.Error(), "username is required")
	})
}

// Test user authentication
func TestService_AuthenticateUser(t *testing.T) {
	service, mockUserRepo, _, mockMFAProvider, _ := setupTestService()

	t.Run("successful authentication", func(t *testing.T) {
		credentials := &types.Credentials{
			Username: "testuser",
			Password: "password123",
		}

		user := &types.User{
			ID:           "user-id",
			Username:     "testuser",
			Email:        "test@example.com",
			Role:         types.RoleConsultingDoctor,
			Organization: "TestOrg",
			IsActive:     true,
		}

		mockUserRepo.On("GetByUsername", "testuser").Return(user, nil)
		mockUserRepo.On("Update", "user-id", mock.AnythingOfType("map[string]interface{}")).Return(nil)

		// Execute
		token, err := service.AuthenticateUser(credentials)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, token)
		assert.NotEmpty(t, token.AccessToken)
		assert.NotEmpty(t, token.RefreshToken)
		assert.Equal(t, "Bearer", token.TokenType)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		credentials := &types.Credentials{
			Username: "nonexistent",
			Password: "password123",
		}

		mockUserRepo.On("GetByUsername", "nonexistent").Return(nil, &types.MedrexError{Type: types.ErrorTypeNotFound})

		// Execute
		token, err := service.AuthenticateUser(credentials)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, token)
		
		medrexErr, ok := err.(*types.MedrexError)
		assert.True(t, ok)
		assert.Equal(t, types.ErrorTypeAuthorization, medrexErr.Type)
	})

	t.Run("inactive user", func(t *testing.T) {
		credentials := &types.Credentials{
			Username: "inactiveuser",
			Password: "password123",
		}

		user := &types.User{
			ID:       "user-id",
			Username: "inactiveuser",
			IsActive: false,
		}

		mockUserRepo.On("GetByUsername", "inactiveuser").Return(user, nil)

		// Execute
		token, err := service.AuthenticateUser(credentials)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, token)
		
		medrexErr, ok := err.(*types.MedrexError)
		assert.True(t, ok)
		assert.Equal(t, types.ErrorTypeAuthorization, medrexErr.Type)
		assert.Equal(t, "USER_INACTIVE", medrexErr.Code)
	})

	t.Run("authentication with MFA", func(t *testing.T) {
		credentials := &types.Credentials{
			Username: "testuser",
			Password: "password123",
			MFAToken: "123456",
		}

		user := &types.User{
			ID:           "user-id",
			Username:     "testuser",
			Email:        "test@example.com",
			Role:         types.RoleConsultingDoctor,
			Organization: "TestOrg",
			IsActive:     true,
		}

		mockUserRepo.On("GetByUsername", "testuser").Return(user, nil)
		mockMFAProvider.On("VerifyToken", "user-id", "123456").Return(true, nil)
		mockUserRepo.On("Update", "user-id", mock.AnythingOfType("map[string]interface{}")).Return(nil)

		// Execute
		token, err := service.AuthenticateUser(credentials)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, token)

		mockUserRepo.AssertExpectations(t)
		mockMFAProvider.AssertExpectations(t)
	})
}

// Test MFA operations
func TestService_MFAOperations(t *testing.T) {
	service, _, _, mockMFAProvider, _ := setupTestService()

	t.Run("enable MFA", func(t *testing.T) {
		userID := "user-id"
		expectedSecret := "JBSWY3DPEHPK3PXP"

		mockMFAProvider.On("GenerateSecret", userID).Return(expectedSecret, nil)

		// Execute
		secret, err := service.EnableMFA(userID)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, expectedSecret, secret)

		mockMFAProvider.AssertExpectations(t)
	})

	t.Run("verify MFA token", func(t *testing.T) {
		userID := "user-id"
		token := "123456"

		mockMFAProvider.On("VerifyToken", userID, token).Return(true, nil)

		// Execute
		valid, err := service.VerifyMFA(userID, token)

		// Assert
		assert.NoError(t, err)
		assert.True(t, valid)

		mockMFAProvider.AssertExpectations(t)
	})

	t.Run("verify invalid MFA token", func(t *testing.T) {
		userID := "user-id"
		token := "invalid"

		mockMFAProvider.On("VerifyToken", userID, token).Return(false, nil)

		// Execute
		valid, err := service.VerifyMFA(userID, token)

		// Assert
		assert.NoError(t, err)
		assert.False(t, valid)

		mockMFAProvider.AssertExpectations(t)
	})
}

// Test certificate operations
func TestService_CertificateOperations(t *testing.T) {
	service, mockUserRepo, mockCertManager, _, mockPasswordManager := setupTestService()

	t.Run("enroll with Fabric CA", func(t *testing.T) {
		userID := "user-id"
		user := &types.User{
			ID:           userID,
			Username:     "testuser",
			Role:         types.RoleConsultingDoctor,
			Organization: "TestOrg",
		}

		expectedCert := &types.X509Certificate{
			Certificate: "mock-cert",
			PrivateKey:  "mock-key",
			ExpiresAt:   time.Now().Add(365 * 24 * time.Hour),
		}

		mockUserRepo.On("GetByID", userID).Return(user, nil)
		mockPasswordManager.On("GenerateRandomPassword", 16).Return("temp-password", nil)
		mockCertManager.On("EnrollUser", "testuser", "temp-password", mock.AnythingOfType("map[string]string")).Return(expectedCert, nil)

		// Execute
		cert, err := service.EnrollWithFabricCA(userID)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		assert.Equal(t, expectedCert.Certificate, cert.Certificate)

		mockUserRepo.AssertExpectations(t)
		mockCertManager.AssertExpectations(t)
		mockPasswordManager.AssertExpectations(t)
	})

	t.Run("renew certificate", func(t *testing.T) {
		userID := "user-id"
		user := &types.User{
			ID:          userID,
			Username:    "testuser",
			Certificate: "existing-cert",
		}

		renewedCert := &types.X509Certificate{
			Certificate: "renewed-cert",
			PrivateKey:  "renewed-key",
			ExpiresAt:   time.Now().Add(365 * 24 * time.Hour),
		}

		mockUserRepo.On("GetByID", userID).Return(user, nil)
		mockPasswordManager.On("GenerateRandomPassword", 16).Return("temp-password", nil)
		mockCertManager.On("EnrollUser", "testuser", "temp-password", mock.AnythingOfType("map[string]string")).Return(renewedCert, nil)
		mockUserRepo.On("Update", userID, mock.AnythingOfType("map[string]interface{}")).Return(nil)

		// Execute
		cert, err := service.RenewCertificate(userID)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		assert.Equal(t, renewedCert.Certificate, cert.Certificate)

		mockUserRepo.AssertExpectations(t)
		mockCertManager.AssertExpectations(t)
		mockPasswordManager.AssertExpectations(t)
	})

	t.Run("revoke certificate", func(t *testing.T) {
		userID := "user-id"
		user := &types.User{
			ID:          userID,
			Username:    "testuser",
			Certificate: "existing-cert",
		}

		mockUserRepo.On("GetByID", userID).Return(user, nil)
		mockCertManager.On("RevokeCertificate", "mock-serial-123", 1).Return(nil)
		mockUserRepo.On("Update", userID, mock.AnythingOfType("map[string]interface{}")).Return(nil)

		// Execute
		err := service.RevokeCertificate(userID)

		// Assert
		assert.NoError(t, err)

		mockUserRepo.AssertExpectations(t)
		mockCertManager.AssertExpectations(t)
	})
}

// Test user management operations
func TestService_UserManagement(t *testing.T) {
	service, mockUserRepo, _, _, _ := setupTestService()

	t.Run("get user", func(t *testing.T) {
		userID := "user-id"
		expectedUser := &types.User{
			ID:       userID,
			Username: "testuser",
			Email:    "test@example.com",
		}

		mockUserRepo.On("GetByID", userID).Return(expectedUser, nil)

		// Execute
		user, err := service.GetUser(userID)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, expectedUser, user)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("update user", func(t *testing.T) {
		userID := "user-id"
		updates := map[string]interface{}{
			"email": "newemail@example.com",
		}

		mockUserRepo.On("Update", userID, updates).Return(nil)

		// Execute
		err := service.UpdateUser(userID, updates)

		// Assert
		assert.NoError(t, err)

		mockUserRepo.AssertExpectations(t)
	})

	t.Run("deactivate user", func(t *testing.T) {
		userID := "user-id"

		mockUserRepo.On("Update", userID, mock.AnythingOfType("map[string]interface{}")).Return(nil)

		// Execute
		err := service.DeactivateUser(userID)

		// Assert
		assert.NoError(t, err)

		mockUserRepo.AssertExpectations(t)
	})
}

// Test token operations
func TestService_TokenOperations(t *testing.T) {
	service, mockUserRepo, _, _, _ := setupTestService()

	t.Run("refresh token", func(t *testing.T) {
		// This test would require a valid refresh token
		// For now, we'll test the error case
		invalidToken := "invalid-token"

		// Execute
		token, err := service.RefreshToken(invalidToken)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("revoke token", func(t *testing.T) {
		token := "valid-token"

		// Execute
		err := service.RevokeToken(token)

		// Assert
		assert.NoError(t, err) // Current implementation just logs
	})
}