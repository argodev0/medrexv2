package iam

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// FabricMSPManager manages Hyperledger Fabric MSP operations
type FabricMSPManager struct {
	config     *config.FabricConfig
	logger     logger.Logger
	caClient   FabricCAClient
	mspID      string
}

// FabricCAClient interface for Fabric CA operations
type FabricCAClient interface {
	Enroll(enrollmentID, enrollmentSecret string, attrs []Attribute) (*EnrollmentResponse, error)
	Register(registrationRequest *RegistrationRequest) (*RegistrationResponse, error)
	Revoke(revocationRequest *RevocationRequest) (*RevocationResponse, error)
	GetCACertificateChain() ([]*x509.Certificate, error)
	Reenroll(cert, key string) (*EnrollmentResponse, error)
}

// Attribute represents a Fabric CA attribute
type Attribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	ECert bool   `json:"ecert"`
}

// EnrollmentResponse represents the response from Fabric CA enrollment
type EnrollmentResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	CACerts     string `json:"ca_certs"`
}

// RegistrationRequest represents a user registration request to Fabric CA
type RegistrationRequest struct {
	Name           string      `json:"name"`
	Type           string      `json:"type"`
	Secret         string      `json:"secret,omitempty"`
	MaxEnrollments int         `json:"max_enrollments"`
	Affiliation    string      `json:"affiliation"`
	Attributes     []Attribute `json:"attrs"`
}

// RegistrationResponse represents the response from Fabric CA registration
type RegistrationResponse struct {
	Secret string `json:"secret"`
}

// RevocationRequest represents a certificate revocation request
type RevocationRequest struct {
	Name   string `json:"name,omitempty"`
	Serial string `json:"serial,omitempty"`
	AKI    string `json:"aki,omitempty"`
	Reason string `json:"reason"`
}

// RevocationResponse represents the response from certificate revocation
type RevocationResponse struct {
	RevokedCerts []RevokedCertificate `json:"revoked_certs"`
	CRL          string               `json:"crl"`
}

// RevokedCertificate represents a revoked certificate
type RevokedCertificate struct {
	Serial string `json:"serial"`
	AKI    string `json:"aki"`
}

// NewFabricMSPManager creates a new Fabric MSP manager
func NewFabricMSPManager(cfg *config.FabricConfig, log logger.Logger) *FabricMSPManager {
	caClient := NewFabricCAClient(cfg, log)
	
	return &FabricMSPManager{
		config:   cfg,
		logger:   log,
		caClient: caClient,
		mspID:    cfg.OrgName + "MSP",
	}
}

// RegisterUser registers a new user with Fabric CA
func (m *FabricMSPManager) RegisterUser(user *types.User, registrarCert, registrarKey string) (string, error) {
	m.logger.Info("Registering user with Fabric CA", "username", user.Username, "role", user.Role)

	// Prepare user attributes based on role
	attributes := m.prepareUserAttributes(user)

	// Create registration request
	regRequest := &RegistrationRequest{
		Name:           user.Username,
		Type:           "client",
		MaxEnrollments: 10, // Allow multiple enrollments
		Affiliation:    m.getAffiliation(user.Organization),
		Attributes:     attributes,
	}

	// Register user with CA
	regResponse, err := m.caClient.Register(regRequest)
	if err != nil {
		return "", fmt.Errorf("failed to register user with CA: %w", err)
	}

	m.logger.Info("User registered successfully with Fabric CA", "username", user.Username, "secret", "***")
	return regResponse.Secret, nil
}

// EnrollUser enrolls a user with Fabric CA and returns certificate
func (m *FabricMSPManager) EnrollUser(username, secret string, user *types.User) (*types.X509Certificate, error) {
	m.logger.Info("Enrolling user with Fabric CA", "username", username)

	// Prepare enrollment attributes
	attributes := m.prepareUserAttributes(user)

	// Enroll user
	enrollResponse, err := m.caClient.Enroll(username, secret, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll user: %w", err)
	}

	// Parse certificate to extract information
	cert, err := m.parseCertificate(enrollResponse.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse enrolled certificate: %w", err)
	}

	x509Cert := &types.X509Certificate{
		Certificate: enrollResponse.Certificate,
		PrivateKey:  enrollResponse.PrivateKey,
		Attributes:  m.extractCertificateAttributes(cert),
		ExpiresAt:   cert.NotAfter,
	}

	m.logger.Info("User enrolled successfully with Fabric CA", "username", username, "expires_at", cert.NotAfter)
	return x509Cert, nil
}

// RenewCertificate renews a user's certificate
func (m *FabricMSPManager) RenewCertificate(currentCert, currentKey string) (*types.X509Certificate, error) {
	m.logger.Info("Renewing certificate with Fabric CA")

	// Re-enroll using existing certificate and key
	enrollResponse, err := m.caClient.Reenroll(currentCert, currentKey)
	if err != nil {
		return nil, fmt.Errorf("failed to re-enroll certificate: %w", err)
	}

	// Parse new certificate
	cert, err := m.parseCertificate(enrollResponse.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse renewed certificate: %w", err)
	}

	x509Cert := &types.X509Certificate{
		Certificate: enrollResponse.Certificate,
		PrivateKey:  enrollResponse.PrivateKey,
		Attributes:  m.extractCertificateAttributes(cert),
		ExpiresAt:   cert.NotAfter,
	}

	m.logger.Info("Certificate renewed successfully", "expires_at", cert.NotAfter)
	return x509Cert, nil
}

// RevokeCertificate revokes a user's certificate
func (m *FabricMSPManager) RevokeCertificate(username, reason string) error {
	m.logger.Info("Revoking certificate", "username", username, "reason", reason)

	revRequest := &RevocationRequest{
		Name:   username,
		Reason: reason,
	}

	_, err := m.caClient.Revoke(revRequest)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate: %w", err)
	}

	m.logger.Info("Certificate revoked successfully", "username", username)
	return nil
}

// ValidateMSPIdentity validates an MSP identity
func (m *FabricMSPManager) ValidateMSPIdentity(certPEM string) (bool, error) {
	m.logger.Info("Validating MSP identity")

	// Parse certificate
	cert, err := m.parseCertificate(certPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		m.logger.Warn("Certificate is expired or not yet valid")
		return false, nil
	}

	// Get CA certificate chain for validation
	caCerts, err := m.caClient.GetCACertificateChain()
	if err != nil {
		return false, fmt.Errorf("failed to get CA certificate chain: %w", err)
	}

	// Validate certificate against CA chain
	roots := x509.NewCertPool()
	for _, caCert := range caCerts {
		roots.AddCert(caCert)
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = cert.Verify(opts)
	if err != nil {
		m.logger.Warn("Certificate verification failed", "error", err)
		return false, nil
	}

	m.logger.Info("MSP identity validated successfully")
	return true, nil
}

// GetMSPID returns the MSP ID for this organization
func (m *FabricMSPManager) GetMSPID() string {
	return m.mspID
}

// prepareUserAttributes prepares Fabric CA attributes based on user information
func (m *FabricMSPManager) prepareUserAttributes(user *types.User) []Attribute {
	attributes := []Attribute{
		{Name: "role", Value: string(user.Role), ECert: true},
		{Name: "organization", Value: user.Organization, ECert: true},
		{Name: "user_id", Value: user.ID, ECert: true},
	}

	// Add role-specific attributes
	switch user.Role {
	case types.RoleConsultingDoctor:
		attributes = append(attributes, Attribute{Name: "can_prescribe", Value: "true", ECert: true})
		attributes = append(attributes, Attribute{Name: "can_co_sign", Value: "true", ECert: true})
	case types.RoleMDStudent:
		attributes = append(attributes, Attribute{Name: "requires_co_sign", Value: "true", ECert: true})
	case types.RoleMBBSStudent:
		attributes = append(attributes, Attribute{Name: "read_only", Value: "true", ECert: true})
	case types.RoleNurse:
		attributes = append(attributes, Attribute{Name: "can_administer_meds", Value: "true", ECert: true})
	case types.RoleAdministrator:
		attributes = append(attributes, Attribute{Name: "admin_access", Value: "true", ECert: true})
	}

	return attributes
}

// getAffiliation returns the Fabric CA affiliation for an organization
func (m *FabricMSPManager) getAffiliation(organization string) string {
	// Map organization to Fabric CA affiliation
	switch organization {
	case "HospitalOrg":
		return "hospital.department1"
	case "PharmacyOrg":
		return "pharmacy.department1"
	default:
		return "org1.department1"
	}
}

// parseCertificate parses a PEM-encoded certificate
func (m *FabricMSPManager) parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

// extractCertificateAttributes extracts attributes from a certificate
func (m *FabricMSPManager) extractCertificateAttributes(cert *x509.Certificate) map[string]string {
	attributes := map[string]string{
		"subject":      cert.Subject.String(),
		"issuer":       cert.Issuer.String(),
		"serial":       cert.SerialNumber.String(),
		"not_before":   cert.NotBefore.Format(time.RFC3339),
		"not_after":    cert.NotAfter.Format(time.RFC3339),
	}

	// Extract organization information
	if len(cert.Subject.Organization) > 0 {
		attributes["organization"] = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		attributes["organizational_unit"] = cert.Subject.OrganizationalUnit[0]
	}

	return attributes
}

// GetCertificateExpiry returns the expiry date of a certificate
func (m *FabricMSPManager) GetCertificateExpiry(certPEM string) (time.Time, error) {
	cert, err := m.parseCertificate(certPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert.NotAfter, nil
}

// IsCertificateExpired checks if a certificate is expired
func (m *FabricMSPManager) IsCertificateExpired(certPEM string) (bool, error) {
	expiry, err := m.GetCertificateExpiry(certPEM)
	if err != nil {
		return false, err
	}

	return time.Now().After(expiry), nil
}