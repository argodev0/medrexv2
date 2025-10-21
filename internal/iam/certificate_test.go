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

// Mock FabricMSPManager for testing
type MockFabricMSPManager struct {
	mock.Mock
}

func (m *MockFabricMSPManager) RegisterUser(user *types.User, registrarCert, registrarKey string) (string, error) {
	args := m.Called(user, registrarCert, registrarKey)
	return args.String(0), args.Error(1)
}

func (m *MockFabricMSPManager) EnrollUser(username, secret string, user *types.User) (*types.X509Certificate, error) {
	args := m.Called(username, secret, user)
	return args.Get(0).(*types.X509Certificate), args.Error(1)
}

func (m *MockFabricMSPManager) RenewCertificate(currentCert, currentKey string) (*types.X509Certificate, error) {
	args := m.Called(currentCert, currentKey)
	return args.Get(0).(*types.X509Certificate), args.Error(1)
}

func (m *MockFabricMSPManager) RevokeCertificate(username, reason string) error {
	args := m.Called(username, reason)
	return args.Error(0)
}

func (m *MockFabricMSPManager) ValidateMSPIdentity(certPEM string) (bool, error) {
	args := m.Called(certPEM)
	return args.Bool(0), args.Error(1)
}

func (m *MockFabricMSPManager) GetMSPID() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockFabricMSPManager) IsCertificateExpired(certPEM string) (bool, error) {
	args := m.Called(certPEM)
	return args.Bool(0), args.Error(1)
}

// Test setup for certificate manager
func setupCertificateManagerTest() (*CertificateManager, *MockFabricMSPManager) {
	cfg := &config.FabricConfig{
		OrgName: "TestOrg",
	}
	log := logger.New("debug")
	
	mockMSPManager := &MockFabricMSPManager{}
	
	certManager := &CertificateManager{
		config:     cfg,
		logger:     log,
		mspManager: mockMSPManager,
	}
	
	return certManager, mockMSPManager
}

// Test user enrollment
func TestCertificateManager_EnrollUser(t *testing.T) {
	certManager, mockMSPManager := setupCertificateManagerTest()

	t.Run("successful enrollment", func(t *testing.T) {
		username := "testuser"
		password := "password123"
		attrs := map[string]string{
			"role":         "consulting_doctor",
			"organization": "TestOrg",
		}

		expectedCert := &types.X509Certificate{
			Certificate: "mock-certificate",
			PrivateKey:  "mock-private-key",
			Attributes: map[string]string{
				"role":         "consulting_doctor",
				"organization": "TestOrg",
			},
			ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
		}

		mockMSPManager.On("EnrollUser", username, password, mock.AnythingOfType("*types.User")).Return(expectedCert, nil)

		// Execute
		cert, err := certManager.EnrollUser(username, password, attrs)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		assert.Equal(t, expectedCert.Certificate, cert.Certificate)
		assert.Equal(t, expectedCert.PrivateKey, cert.PrivateKey)

		mockMSPManager.AssertExpectations(t)
	})

	t.Run("enrollment failure", func(t *testing.T) {
		username := "testuser"
		password := "password123"
		attrs := map[string]string{
			"role":         "consulting_doctor",
			"organization": "TestOrg",
		}

		mockMSPManager.On("EnrollUser", username, password, mock.AnythingOfType("*types.User")).Return((*types.X509Certificate)(nil), assert.AnError)

		// Execute
		cert, err := certManager.EnrollUser(username, password, attrs)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "MSP enrollment failed")

		mockMSPManager.AssertExpectations(t)
	})
}

// Test certificate validation
func TestCertificateManager_ValidateCertificate(t *testing.T) {
	certManager, mockMSPManager := setupCertificateManagerTest()

	t.Run("valid certificate", func(t *testing.T) {
		certPEM := `-----BEGIN CERTIFICATE-----
MIICXjCCAcegAwIBAgIJAKL0UG+J4XqxMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjMxMjAxMDAwMDAwWhcNMjQxMjAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC7vbqajDw4o6gJy8UtqfeVVvOvtVSku8+Oa9AiLEVz6lYDYuHBvEBmU9E4f5Ng
7b7K9+J5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
QIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAC4f6c7bPrAHBbzCuEB73E+CRcEwwIDA
QAB
-----END CERTIFICATE-----`

		mockMSPManager.On("ValidateMSPIdentity", certPEM).Return(true, nil)

		// Execute
		valid, err := certManager.ValidateCertificate(certPEM)

		// Assert
		assert.NoError(t, err)
		assert.True(t, valid)

		mockMSPManager.AssertExpectations(t)
	})

	t.Run("invalid certificate", func(t *testing.T) {
		certPEM := "invalid-certificate"

		mockMSPManager.On("ValidateMSPIdentity", certPEM).Return(false, nil)

		// Execute
		valid, err := certManager.ValidateCertificate(certPEM)

		// Assert
		assert.NoError(t, err)
		assert.False(t, valid)

		mockMSPManager.AssertExpectations(t)
	})

	t.Run("validation error", func(t *testing.T) {
		certPEM := "malformed-certificate"

		mockMSPManager.On("ValidateMSPIdentity", certPEM).Return(false, assert.AnError)

		// Execute
		valid, err := certManager.ValidateCertificate(certPEM)

		// Assert
		assert.Error(t, err)
		assert.False(t, valid)
		assert.Contains(t, err.Error(), "MSP validation failed")

		mockMSPManager.AssertExpectations(t)
	})
}

// Test certificate revocation
func TestCertificateManager_RevokeCertificate(t *testing.T) {
	certManager, mockMSPManager := setupCertificateManagerTest()

	t.Run("successful revocation", func(t *testing.T) {
		serial := "123456789"
		reason := 1 // key_compromise

		mockMSPManager.On("RevokeCertificate", serial, "key_compromise").Return(nil)

		// Execute
		err := certManager.RevokeCertificate(serial, reason)

		// Assert
		assert.NoError(t, err)

		mockMSPManager.AssertExpectations(t)
	})

	t.Run("revocation failure", func(t *testing.T) {
		serial := "123456789"
		reason := 1

		mockMSPManager.On("RevokeCertificate", serial, "key_compromise").Return(assert.AnError)

		// Execute
		err := certManager.RevokeCertificate(serial, reason)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "MSP revocation failed")

		mockMSPManager.AssertExpectations(t)
	})
}

// Test certificate renewal
func TestCertificateManager_RenewCertificate(t *testing.T) {
	certManager, mockMSPManager := setupCertificateManagerTest()

	t.Run("successful renewal", func(t *testing.T) {
		currentCert := "current-certificate"
		currentKey := "current-private-key"

		renewedCert := &types.X509Certificate{
			Certificate: "renewed-certificate",
			PrivateKey:  "renewed-private-key",
			ExpiresAt:   time.Now().Add(365 * 24 * time.Hour),
		}

		mockMSPManager.On("RenewCertificate", currentCert, currentKey).Return(renewedCert, nil)

		// Execute
		cert, err := certManager.RenewCertificate(currentCert, currentKey)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, cert)
		assert.Equal(t, renewedCert.Certificate, cert.Certificate)
		assert.Equal(t, renewedCert.PrivateKey, cert.PrivateKey)

		mockMSPManager.AssertExpectations(t)
	})

	t.Run("renewal failure", func(t *testing.T) {
		currentCert := "current-certificate"
		currentKey := "current-private-key"

		mockMSPManager.On("RenewCertificate", currentCert, currentKey).Return((*types.X509Certificate)(nil), assert.AnError)

		// Execute
		cert, err := certManager.RenewCertificate(currentCert, currentKey)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, cert)
		assert.Contains(t, err.Error(), "MSP certificate renewal failed")

		mockMSPManager.AssertExpectations(t)
	})
}

// Test revocation reason mapping
func TestCertificateManager_MapRevocationReason(t *testing.T) {
	certManager, _ := setupCertificateManagerTest()

	testCases := []struct {
		reason   int
		expected string
	}{
		{0, "unspecified"},
		{1, "key_compromise"},
		{2, "ca_compromise"},
		{3, "affiliation_changed"},
		{4, "superseded"},
		{5, "cessation_of_operation"},
		{6, "certificate_hold"},
		{8, "remove_from_crl"},
		{9, "privilege_withdrawn"},
		{10, "aa_compromise"},
		{999, "unspecified"}, // Unknown reason
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			result := certManager.mapRevocationReason(tc.reason)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test MSP ID retrieval
func TestCertificateManager_GetMSPID(t *testing.T) {
	certManager, mockMSPManager := setupCertificateManagerTest()

	t.Run("get MSP ID", func(t *testing.T) {
		expectedMSPID := "TestOrgMSP"

		mockMSPManager.On("GetMSPID").Return(expectedMSPID)

		// Execute
		mspID := certManager.GetMSPID()

		// Assert
		assert.Equal(t, expectedMSPID, mspID)

		mockMSPManager.AssertExpectations(t)
	})
}

// Test certificate expiry check
func TestCertificateManager_IsCertificateExpired(t *testing.T) {
	certManager, mockMSPManager := setupCertificateManagerTest()

	t.Run("certificate not expired", func(t *testing.T) {
		certPEM := "valid-certificate"

		mockMSPManager.On("IsCertificateExpired", certPEM).Return(false, nil)

		// Execute
		expired, err := certManager.IsCertificateExpired(certPEM)

		// Assert
		assert.NoError(t, err)
		assert.False(t, expired)

		mockMSPManager.AssertExpectations(t)
	})

	t.Run("certificate expired", func(t *testing.T) {
		certPEM := "expired-certificate"

		mockMSPManager.On("IsCertificateExpired", certPEM).Return(true, nil)

		// Execute
		expired, err := certManager.IsCertificateExpired(certPEM)

		// Assert
		assert.NoError(t, err)
		assert.True(t, expired)

		mockMSPManager.AssertExpectations(t)
	})

	t.Run("error checking expiry", func(t *testing.T) {
		certPEM := "malformed-certificate"

		mockMSPManager.On("IsCertificateExpired", certPEM).Return(false, assert.AnError)

		// Execute
		expired, err := certManager.IsCertificateExpired(certPEM)

		// Assert
		assert.Error(t, err)
		assert.False(t, expired)

		mockMSPManager.AssertExpectations(t)
	})
}

// Test certificate attribute extraction
func TestCertificateManager_ExtractAttributes(t *testing.T) {
	certManager, _ := setupCertificateManagerTest()

	t.Run("extract attributes from valid certificate", func(t *testing.T) {
		// This is a simplified test - in reality, we'd need a properly formatted certificate
		certPEM := `-----BEGIN CERTIFICATE-----
MIICXjCCAcegAwIBAgIJAKL0UG+J4XqxMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjMxMjAxMDAwMDAwWhcNMjQxMjAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC7vbqajDw4o6gJy8UtqfeVVvOvtVSku8+Oa9AiLEVz6lYDYuHBvEBmU9E4f5Ng
7b7K9+J5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
QIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAC4f6c7bPrAHBbzCuEB73E+CRcEwwIDA
QAB
-----END CERTIFICATE-----`

		// Execute
		attrs, err := certManager.ExtractAttributes(certPEM)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, attrs)
		assert.Contains(t, attrs, "common_name")
		assert.Contains(t, attrs, "organization")

		// The mock certificate should have some basic attributes
		assert.NotEmpty(t, attrs["common_name"])
	})

	t.Run("extract attributes from invalid certificate", func(t *testing.T) {
		certPEM := "invalid-certificate-pem"

		// Execute
		attrs, err := certManager.ExtractAttributes(certPEM)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, attrs)
		assert.Contains(t, err.Error(), "failed to parse certificate PEM")
	})
}

// Test certificate info retrieval
func TestCertificateManager_GetCertificateInfo(t *testing.T) {
	certManager, _ := setupCertificateManagerTest()

	t.Run("get info from valid certificate", func(t *testing.T) {
		certPEM := `-----BEGIN CERTIFICATE-----
MIICXjCCAcegAwIBAgIJAKL0UG+J4XqxMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjMxMjAxMDAwMDAwWhcNMjQxMjAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC7vbqajDw4o6gJy8UtqfeVVvOvtVSku8+Oa9AiLEVz6lYDYuHBvEBmU9E4f5Ng
7b7K9+J5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5
QIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAC4f6c7bPrAHBbzCuEB73E+CRcEwwIDA
QAB
-----END CERTIFICATE-----`

		// Execute
		info, err := certManager.GetCertificateInfo(certPEM)

		// Assert
		assert.NoError(t, err)
		assert.NotNil(t, info)
		assert.Contains(t, info, "subject")
		assert.Contains(t, info, "issuer")
		assert.Contains(t, info, "serial")
		assert.Contains(t, info, "not_before")
		assert.Contains(t, info, "not_after")
	})

	t.Run("get info from invalid certificate", func(t *testing.T) {
		certPEM := "invalid-certificate-pem"

		// Execute
		info, err := certManager.GetCertificateInfo(certPEM)

		// Assert
		assert.Error(t, err)
		assert.Nil(t, info)
		assert.Contains(t, err.Error(), "failed to parse certificate PEM")
	})
}