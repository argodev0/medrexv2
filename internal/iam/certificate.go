package iam

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// CertificateManager implements X.509 certificate operations with Fabric CA
type CertificateManager struct {
	config     *config.FabricConfig
	logger     logger.Logger
	mspManager *FabricMSPManager
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(cfg *config.FabricConfig, log logger.Logger) *CertificateManager {
	mspManager := NewFabricMSPManager(cfg, log)
	
	return &CertificateManager{
		config:     cfg,
		logger:     log,
		mspManager: mspManager,
	}
}

// EnrollUser enrolls a user with Fabric CA and returns X.509 certificate
func (cm *CertificateManager) EnrollUser(username, password string, attrs map[string]string) (*types.X509Certificate, error) {
	cm.logger.Info("Enrolling user with Fabric CA", "username", username, "org", cm.config.OrgName)

	// Create a mock user object for MSP enrollment
	user := &types.User{
		Username:     username,
		Role:         types.UserRole(attrs["role"]),
		Organization: attrs["organization"],
	}

	// Use MSP manager for enrollment
	cert, err := cm.mspManager.EnrollUser(username, password, user)
	if err != nil {
		return nil, fmt.Errorf("MSP enrollment failed: %w", err)
	}

	cm.logger.Info("User enrolled successfully with Fabric CA", "username", username)
	return cert, nil
}

// RevokeCertificate revokes a certificate by serial number
func (cm *CertificateManager) RevokeCertificate(serial string, reason int) error {
	cm.logger.Info("Revoking certificate", "serial", serial, "reason", reason)
	
	// Map reason code to string
	reasonStr := cm.mapRevocationReason(reason)
	
	// Use MSP manager for revocation
	err := cm.mspManager.RevokeCertificate(serial, reasonStr)
	if err != nil {
		return fmt.Errorf("MSP revocation failed: %w", err)
	}
	
	cm.logger.Info("Certificate revoked successfully", "serial", serial)
	return nil
}

// ValidateCertificate validates an X.509 certificate
func (cm *CertificateManager) ValidateCertificate(certPEM string) (bool, error) {
	// Use MSP manager for validation
	valid, err := cm.mspManager.ValidateMSPIdentity(certPEM)
	if err != nil {
		return false, fmt.Errorf("MSP validation failed: %w", err)
	}

	if valid {
		cm.logger.Info("Certificate validated successfully")
	} else {
		cm.logger.Warn("Certificate validation failed")
	}

	return valid, nil
}

// ExtractAttributes extracts custom attributes from X.509 certificate
func (cm *CertificateManager) ExtractAttributes(certPEM string) (map[string]string, error) {
	// Parse PEM certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	attrs := make(map[string]string)
	
	// Extract standard attributes
	attrs["common_name"] = cert.Subject.CommonName
	attrs["organization"] = ""
	if len(cert.Subject.Organization) > 0 {
		attrs["organization"] = cert.Subject.Organization[0]
	}
	
	attrs["organizational_unit"] = ""
	if len(cert.Subject.OrganizationalUnit) > 0 {
		attrs["organizational_unit"] = cert.Subject.OrganizationalUnit[0]
	}

	// In Fabric, custom attributes would be stored in certificate extensions
	// For now, we'll extract from subject fields
	for _, name := range cert.Subject.Names {
		if name.Type.String() == "1.2.3.4.5.6.7.8.1" { // Custom OID for role
			if str, ok := name.Value.(string); ok {
				attrs["role"] = str
			}
		}
	}

	cm.logger.Info("Extracted certificate attributes", "attrs", attrs)
	return attrs, nil
}

// GetCertificateInfo returns detailed certificate information
func (cm *CertificateManager) GetCertificateInfo(certPEM string) (map[string]interface{}, error) {
	// Parse PEM certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	info := map[string]interface{}{
		"subject":      cert.Subject.String(),
		"issuer":       cert.Issuer.String(),
		"serial":       cert.SerialNumber.String(),
		"not_before":   cert.NotBefore,
		"not_after":    cert.NotAfter,
		"key_usage":    cert.KeyUsage,
		"ext_key_usage": cert.ExtKeyUsage,
		"is_ca":        cert.IsCA,
	}

	cm.logger.Info("Retrieved certificate information", "subject", cert.Subject.String())
	return info, nil
}

// generateMockCertificate generates a mock certificate for development/testing
func (cm *CertificateManager) generateMockCertificate(username string, attrs map[string]string) (string, string, error) {
	// This is a mock implementation for development
	// In production, this would use the actual Fabric CA SDK
	
	certPEM := fmt.Sprintf(`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`, username)

	privateKeyPEM := `-----BEGIN PRIVATE KEY-----
MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALu9upqMPDijqAnL
xS2p95VW86+1VKS7z45r0CIsRXPqVgNi4cG8QGZTkTh/k2DtvsrX4nlvlvlvlvlv
lvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlv
lvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlv
lvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlvlv
AgMBAAECgYEAr7BXXoqDiVNk2cU2d4LqdgOyR4LE2UBXXoqDiVNk2cU2d4LqdgOy
R4LE2UBXXoqDiVNk2cU2d4LqdgOyR4LE2UBXXoqDiVNk2cU2d4LqdgOyR4LE2UBX
XoqDiVNk2cU2d4LqdgOyR4LE2UBXXoqDiVNk2cU2d4LqdgOyR4LE2UBECQQD2Pnz
-----END PRIVATE KEY-----`

	return certPEM, privateKeyPEM, nil
}

// mapRevocationReason maps integer reason codes to string reasons
func (cm *CertificateManager) mapRevocationReason(reason int) string {
	switch reason {
	case 0:
		return "unspecified"
	case 1:
		return "key_compromise"
	case 2:
		return "ca_compromise"
	case 3:
		return "affiliation_changed"
	case 4:
		return "superseded"
	case 5:
		return "cessation_of_operation"
	case 6:
		return "certificate_hold"
	case 8:
		return "remove_from_crl"
	case 9:
		return "privilege_withdrawn"
	case 10:
		return "aa_compromise"
	default:
		return "unspecified"
	}
}

// RenewCertificate renews an existing certificate
func (cm *CertificateManager) RenewCertificate(currentCert, currentKey string) (*types.X509Certificate, error) {
	cm.logger.Info("Renewing certificate")
	
	// Use MSP manager for certificate renewal
	cert, err := cm.mspManager.RenewCertificate(currentCert, currentKey)
	if err != nil {
		return nil, fmt.Errorf("MSP certificate renewal failed: %w", err)
	}
	
	cm.logger.Info("Certificate renewed successfully")
	return cert, nil
}

// GetMSPID returns the MSP ID for this organization
func (cm *CertificateManager) GetMSPID() string {
	return cm.mspManager.GetMSPID()
}

// IsCertificateExpired checks if a certificate is expired
func (cm *CertificateManager) IsCertificateExpired(certPEM string) (bool, error) {
	return cm.mspManager.IsCertificateExpired(certPEM)
}

// GetCertificateFingerprint generates a fingerprint for the certificate
func (cm *CertificateManager) GetCertificateFingerprint(certPEM string) (string, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", fmt.Errorf("failed to parse certificate PEM")
	}
	
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}
	
	// Use SHA-256 fingerprint
	fingerprint := fmt.Sprintf("%x", cert.Raw)
	return fingerprint, nil
}