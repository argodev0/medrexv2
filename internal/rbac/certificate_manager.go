package rbac

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// FabricCAClient interface for Fabric CA operations with attribute support
type FabricCAClient interface {
	EnrollWithAttributes(enrollmentID, enrollmentSecret string, attrs []FabricAttribute) (*EnrollmentResponse, error)
	RegisterUser(regRequest *RegistrationRequest) (*RegistrationResponse, error)
	RevokeUser(revRequest *RevocationRequest) (*RevocationResponse, error)
	GetCACertificateChain() ([]*x509.Certificate, error)
	ReenrollWithAttributes(cert, key string, attrs []FabricAttribute) (*EnrollmentResponse, error)
	ValidateConnection() error
}

// FabricAttribute represents a Fabric CA attribute with enrollment certificate embedding
type FabricAttribute struct {
	Name  string `json:"name"`
	Value string `json:"value"`
	ECert bool   `json:"ecert"` // Whether to embed in enrollment certificate
}

// EnrollmentResponse represents the response from Fabric CA enrollment
type EnrollmentResponse struct {
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
	CACerts     string `json:"ca_certs"`
}

// RegistrationRequest represents a user registration request to Fabric CA
type RegistrationRequest struct {
	Name           string            `json:"name"`
	Type           string            `json:"type"`
	Secret         string            `json:"secret,omitempty"`
	MaxEnrollments int               `json:"max_enrollments"`
	Affiliation    string            `json:"affiliation"`
	Attributes     []FabricAttribute `json:"attrs"`
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

// CertificateManager implements X.509 certificate management with RBAC attributes
type CertificateManager struct {
	config    *CertManagerConfig
	logger    *logrus.Logger
	caClient  FabricCAClient
	orgMSP    string
	caURL     string
}

// CertManagerConfig represents the configuration for the certificate manager
type CertManagerConfig struct {
	OrgMSP         string `json:"org_msp"`
	CAURL          string `json:"ca_url"`
	TLSEnabled     bool   `json:"tls_enabled"`
	CACertPath     string `json:"ca_cert_path"`
	ClientCertPath string `json:"client_cert_path"`
	ClientKeyPath  string `json:"client_key_path"`
}

// NewCertificateManager creates a new certificate manager with Fabric CA client
func NewCertificateManager(config *CertManagerConfig, logger *logrus.Logger, caClient FabricCAClient) (*CertificateManager, error) {
	if config == nil {
		return nil, fmt.Errorf("configuration is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}
	if caClient == nil {
		return nil, fmt.Errorf("Fabric CA client is required")
	}

	manager := &CertificateManager{
		config:   config,
		logger:   logger,
		caClient: caClient,
		orgMSP:   config.OrgMSP,
		caURL:    config.CAURL,
	}

	// Validate connection to Fabric CA
	if err := caClient.ValidateConnection(); err != nil {
		return nil, fmt.Errorf("failed to validate CA connection: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"org_msp": config.OrgMSP,
		"ca_url":  config.CAURL,
	}).Info("Certificate manager initialized successfully")

	return manager, nil
}

// EnrollUserWithAttributes enrolls a user and issues a certificate with embedded attributes
func (m *CertificateManager) EnrollUserWithAttributes(ctx context.Context, req *rbac.EnrollmentRequest) (*x509.Certificate, error) {
	m.logger.WithFields(logrus.Fields{
		"user_id": req.UserID,
		"role":    req.Role,
		"org_msp": req.OrgMSP,
		"node_ou": req.NodeOU,
	}).Info("Enrolling user with attributes")

	// Validate enrollment request
	if err := m.validateEnrollmentRequest(req); err != nil {
		return nil, fmt.Errorf("invalid enrollment request: %w", err)
	}

	// First register the user if not already registered
	regRequest := &RegistrationRequest{
		Name:           req.UserID,
		Type:           "client",
		MaxEnrollments: 10, // Allow multiple enrollments for certificate renewal
		Affiliation:    m.getAffiliation(req.Role),
		Attributes:     m.prepareFabricAttributes(req),
	}

	regResponse, err := m.caClient.RegisterUser(regRequest)
	if err != nil {
		// User might already be registered, continue with enrollment
		m.logger.WithFields(logrus.Fields{
			"user_id": req.UserID,
			"error":   err.Error(),
		}).Warn("User registration failed, attempting enrollment with existing registration")
	}

	// Prepare enrollment attributes with embedded certificate attributes
	enrollmentAttrs := m.prepareFabricAttributes(req)

	// Use registration secret or provided secret for enrollment
	enrollmentSecret := regResponse.Secret
	if enrollmentSecret == "" {
		// If no secret from registration, generate one or use provided
		enrollmentSecret = m.generateEnrollmentSecret(req.UserID)
	}

	// Enroll user with Fabric CA
	enrollResponse, err := m.caClient.EnrollWithAttributes(req.UserID, enrollmentSecret, enrollmentAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to enroll user with CA: %w", err)
	}

	// Parse the returned certificate
	cert, err := m.parseCertificate(enrollResponse.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse enrolled certificate: %w", err)
	}

	// Validate that the certificate contains expected attributes
	if err := m.validateCertificateAttributes(cert, req); err != nil {
		return nil, fmt.Errorf("certificate validation failed: %w", err)
	}

	// Store certificate metadata for future reference
	if err := m.storeCertificateMetadata(ctx, req.UserID, cert, enrollResponse); err != nil {
		m.logger.WithFields(logrus.Fields{
			"user_id": req.UserID,
			"error":   err.Error(),
		}).Warn("Failed to store certificate metadata")
	}

	m.logger.WithFields(logrus.Fields{
		"user_id":    req.UserID,
		"subject":    cert.Subject.String(),
		"serial":     cert.SerialNumber.String(),
		"expires_at": cert.NotAfter,
	}).Info("User certificate enrolled successfully")

	return cert, nil
}

// ExtractUserAttributes extracts user attributes from a certificate
func (m *CertificateManager) ExtractUserAttributes(cert *x509.Certificate) (*rbac.UserAttributes, error) {
	if cert == nil {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeCertificateInvalid,
			rbac.ErrorCodeCertificateInvalid,
			"Certificate is nil",
		)
	}

	attributes := &rbac.UserAttributes{}

	// Extract role from NodeOU first
	if len(cert.Subject.OrganizationalUnit) > 0 {
		nodeOU := cert.Subject.OrganizationalUnit[0]
		
		// Map NodeOU back to role
		for role, mappedNodeOU := range rbac.NodeOUMappings {
			if mappedNodeOU == nodeOU {
				attributes.Role = role
				break
			}
		}

		if attributes.Role == "" {
			return nil, rbac.NewRBACError(
				rbac.ErrorTypeCertificateInvalid,
				rbac.ErrorCodeCertificateInvalid,
				fmt.Sprintf("Unknown NodeOU: %s", nodeOU),
			)
		}
	}

	// Extract custom attributes from certificate extensions
	fabricAttrs, err := m.extractFabricAttributes(cert)
	if err != nil {
		m.logger.WithFields(logrus.Fields{
			"subject": cert.Subject.String(),
			"error":   err.Error(),
		}).Warn("Failed to extract Fabric attributes from certificate")
	} else {
		// Override role if explicitly set in Fabric attributes
		if role, exists := fabricAttrs[rbac.AttributeRole]; exists {
			attributes.Role = role
		}

		// Extract other attributes
		if specialty, exists := fabricAttrs[rbac.AttributeSpecialty]; exists {
			attributes.Specialty = specialty
		}
		if wardAssignment, exists := fabricAttrs[rbac.AttributeWardAssignment]; exists {
			attributes.WardAssignment = wardAssignment
		}
		if labOrg, exists := fabricAttrs[rbac.AttributeLabOrg]; exists {
			attributes.LabOrg = labOrg
		}
		if department, exists := fabricAttrs[rbac.AttributeDepartment]; exists {
			attributes.Department = department
		}

		// Parse boolean attributes
		if isTrainee, exists := fabricAttrs[rbac.AttributeIsTrainee]; exists {
			attributes.IsTrainee = strings.ToLower(isTrainee) == "true"
		}
		if isSupervisor, exists := fabricAttrs[rbac.AttributeIsSupervisor]; exists {
			attributes.IsSupervisor = strings.ToLower(isSupervisor) == "true"
		}
	}

	// Set role-specific attributes and defaults
	m.setRoleSpecificAttributes(attributes)

	// Validate extracted attributes
	if err := m.validateExtractedAttributes(attributes); err != nil {
		return nil, fmt.Errorf("attribute validation failed: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"subject":        cert.Subject.String(),
		"role":           attributes.Role,
		"level":          attributes.Level,
		"is_trainee":     attributes.IsTrainee,
		"is_supervisor":  attributes.IsSupervisor,
		"specialty":      attributes.Specialty,
		"ward_assignment": attributes.WardAssignment,
	}).Debug("Extracted user attributes from certificate")

	return attributes, nil
}

// ValidateCertificateAttributes validates that a certificate contains required attributes
func (m *CertificateManager) ValidateCertificateAttributes(cert *x509.Certificate, requiredAttrs []string) error {
	if cert == nil {
		return rbac.NewRBACError(
			rbac.ErrorTypeCertificateInvalid,
			rbac.ErrorCodeCertificateInvalid,
			"Certificate is nil",
		)
	}

	// Extract attributes from certificate
	attributes, err := m.ExtractUserAttributes(cert)
	if err != nil {
		return fmt.Errorf("failed to extract attributes: %w", err)
	}

	// Convert attributes to map for easier validation
	attrMap := m.attributesToMap(attributes)

	// Check each required attribute
	var missingAttrs []string
	for _, requiredAttr := range requiredAttrs {
		if _, exists := attrMap[requiredAttr]; !exists {
			missingAttrs = append(missingAttrs, requiredAttr)
		}
	}

	if len(missingAttrs) > 0 {
		return rbac.NewRBACError(
			rbac.ErrorTypeAttributeValidation,
			rbac.ErrorCodeAttributeValidation,
			"Certificate missing required attributes",
		).WithMissingAttributes(missingAttrs)
	}

	m.logger.WithFields(logrus.Fields{
		"subject":           cert.Subject.String(),
		"required_attrs":    len(requiredAttrs),
		"validation_result": "passed",
	}).Debug("Certificate attribute validation completed")

	return nil
}

// RenewCertificateWithUpdatedAttributes renews a certificate with updated attributes
func (m *CertificateManager) RenewCertificateWithUpdatedAttributes(ctx context.Context, userID string, newAttrs map[string]string) error {
	m.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"new_attrs":  len(newAttrs),
	}).Info("Renewing certificate with updated attributes")

	// Retrieve current certificate and private key
	currentCert, currentKey, err := m.getCurrentCertificate(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to retrieve current certificate: %w", err)
	}

	// Validate new attributes
	if err := m.validateAttributeUpdate(newAttrs); err != nil {
		return fmt.Errorf("invalid attribute update: %w", err)
	}

	// Prepare Fabric attributes for renewal
	fabricAttrs := m.mapAttributesToFabric(newAttrs)

	// Re-enroll with updated attributes
	enrollResponse, err := m.caClient.ReenrollWithAttributes(currentCert, currentKey, fabricAttrs)
	if err != nil {
		return fmt.Errorf("failed to re-enroll certificate: %w", err)
	}

	// Parse the new certificate
	newCert, err := m.parseCertificate(enrollResponse.Certificate)
	if err != nil {
		return fmt.Errorf("failed to parse renewed certificate: %w", err)
	}

	// Validate that the new certificate contains expected attributes
	extractedAttrs, err := m.ExtractUserAttributes(newCert)
	if err != nil {
		return fmt.Errorf("failed to extract attributes from renewed certificate: %w", err)
	}

	// Verify that the new attributes are correctly embedded
	if err := m.verifyAttributeUpdate(extractedAttrs, newAttrs); err != nil {
		return fmt.Errorf("attribute verification failed: %w", err)
	}

	// Update certificate metadata
	if err := m.updateCertificateMetadata(ctx, userID, newCert, enrollResponse); err != nil {
		m.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Warn("Failed to update certificate metadata")
	}

	m.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"serial":     newCert.SerialNumber.String(),
		"expires_at": newCert.NotAfter,
		"attributes": len(newAttrs),
	}).Info("Certificate renewed successfully with updated attributes")

	return nil
}

// RevokeCertificate revokes a user's certificate
func (m *CertificateManager) RevokeCertificate(ctx context.Context, userID string, reason string) error {
	m.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"reason":  reason,
	}).Warn("Revoking user certificate")

	// Validate revocation reason
	if reason == "" {
		reason = "unspecified"
	}

	// Create revocation request
	revRequest := &RevocationRequest{
		Name:   userID,
		Reason: reason,
	}

	// Submit revocation to Fabric CA
	revResponse, err := m.caClient.RevokeUser(revRequest)
	if err != nil {
		return fmt.Errorf("failed to revoke certificate with CA: %w", err)
	}

	// Log revoked certificates
	for _, revokedCert := range revResponse.RevokedCerts {
		m.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"serial":  revokedCert.Serial,
			"aki":     revokedCert.AKI,
		}).Info("Certificate revoked")
	}

	// Update certificate metadata to mark as revoked
	if err := m.markCertificateRevoked(ctx, userID, reason); err != nil {
		m.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Warn("Failed to update certificate metadata for revocation")
	}

	// Notify other services about the revocation
	if err := m.notifyRevocation(ctx, userID, reason); err != nil {
		m.logger.WithFields(logrus.Fields{
			"user_id": userID,
			"error":   err.Error(),
		}).Warn("Failed to notify services about certificate revocation")
	}

	m.logger.WithFields(logrus.Fields{
		"user_id":       userID,
		"reason":        reason,
		"revoked_count": len(revResponse.RevokedCerts),
	}).Warn("Certificate revoked successfully")

	return nil
}

// Helper methods

func (m *CertificateManager) validateEnrollmentRequest(req *rbac.EnrollmentRequest) error {
	var validationErrors rbac.ValidationErrors

	if req.UserID == "" {
		validationErrors.Add("user_id", req.UserID, "User ID is required")
	}

	if req.Role == "" {
		validationErrors.Add("role", req.Role, "Role is required")
	} else if _, exists := rbac.NodeOUMappings[req.Role]; !exists {
		validationErrors.Add("role", req.Role, "Invalid role specified")
	}

	if req.OrgMSP == "" {
		validationErrors.Add("org_msp", req.OrgMSP, "Organization MSP is required")
	}

	if req.NodeOU == "" {
		// Auto-set NodeOU based on role if not provided
		if nodeOU, exists := rbac.NodeOUMappings[req.Role]; exists {
			req.NodeOU = nodeOU
		} else {
			validationErrors.Add("node_ou", req.NodeOU, "NodeOU is required")
		}
	}

	if req.ValidityPeriod <= 0 {
		validationErrors.Add("validity_period", req.ValidityPeriod.String(), "Validity period must be positive")
	}

	// Validate role-specific attributes
	if err := m.validateRoleAttributes(req.Role, req.Attributes); err != nil {
		validationErrors.Add("attributes", fmt.Sprintf("%v", req.Attributes), err.Error())
	}

	if validationErrors.HasErrors() {
		return &validationErrors
	}

	return nil
}

func (m *CertificateManager) validateRoleAttributes(role string, attributes map[string]string) error {
	// Validate role-specific required attributes
	switch role {
	case rbac.RoleNurse:
		if _, exists := attributes[rbac.AttributeWardAssignment]; !exists {
			return fmt.Errorf("ward assignment is required for nurse role")
		}
	case rbac.RoleLabTechnician:
		if _, exists := attributes[rbac.AttributeLabOrg]; !exists {
			return fmt.Errorf("lab organization is required for lab technician role")
		}
	case rbac.RoleClinicalStaff:
		if _, exists := attributes[rbac.AttributeSpecialty]; !exists {
			return fmt.Errorf("specialty is required for clinical staff role")
		}
	case rbac.RoleConsultingDoctor:
		if _, exists := attributes[rbac.AttributeSpecialty]; !exists {
			return fmt.Errorf("specialty is required for consulting doctor role")
		}
	}

	return nil
}

func (m *CertificateManager) setRoleSpecificAttributes(attributes *rbac.UserAttributes) {
	// Set role-specific flags and properties
	switch attributes.Role {
	case rbac.RoleMBBSStudent, rbac.RoleMDStudent:
		attributes.IsTrainee = true
		attributes.IsSupervisor = false
	case rbac.RoleConsultingDoctor:
		attributes.IsTrainee = false
		attributes.IsSupervisor = true
	default:
		attributes.IsTrainee = false
		attributes.IsSupervisor = false
	}

	// Set level based on role
	if level, exists := rbac.RoleLevels[attributes.Role]; exists {
		attributes.Level = level
	}

	// Set default values for optional attributes
	if attributes.Specialty == "" && (attributes.Role == rbac.RoleConsultingDoctor || attributes.Role == rbac.RoleClinicalStaff) {
		attributes.Specialty = "general"
	}

	if attributes.WardAssignment == "" && attributes.Role == rbac.RoleNurse {
		attributes.WardAssignment = "general_ward"
	}

	if attributes.LabOrg == "" && attributes.Role == rbac.RoleLabTechnician {
		attributes.LabOrg = "central_lab"
	}

	if attributes.Department == "" {
		switch attributes.Role {
		case rbac.RoleConsultingDoctor, rbac.RoleMDStudent, rbac.RoleMBBSStudent:
			attributes.Department = "clinical"
		case rbac.RoleNurse:
			attributes.Department = "nursing"
		case rbac.RoleLabTechnician:
			attributes.Department = "laboratory"
		case rbac.RoleReceptionist:
			attributes.Department = "administration"
		case rbac.RoleClinicalStaff:
			attributes.Department = "clinical_support"
		case rbac.RoleAdministrator:
			attributes.Department = "administration"
		default:
			attributes.Department = "general"
		}
	}
}

func (m *CertificateManager) attributesToMap(attributes *rbac.UserAttributes) map[string]string {
	attrMap := make(map[string]string)

	attrMap[rbac.AttributeRole] = attributes.Role
	attrMap[rbac.AttributeLevel] = fmt.Sprintf("%d", attributes.Level)
	attrMap[rbac.AttributeIsTrainee] = fmt.Sprintf("%t", attributes.IsTrainee)
	attrMap[rbac.AttributeIsSupervisor] = fmt.Sprintf("%t", attributes.IsSupervisor)

	if attributes.Specialty != "" {
		attrMap[rbac.AttributeSpecialty] = attributes.Specialty
	}

	if attributes.WardAssignment != "" {
		attrMap[rbac.AttributeWardAssignment] = attributes.WardAssignment
	}

	if attributes.LabOrg != "" {
		attrMap[rbac.AttributeLabOrg] = attributes.LabOrg
	}

	if attributes.Department != "" {
		attrMap[rbac.AttributeDepartment] = attributes.Department
	}

	return attrMap
}

// prepareFabricAttributes prepares Fabric CA attributes from enrollment request
func (m *CertificateManager) prepareFabricAttributes(req *rbac.EnrollmentRequest) []FabricAttribute {
	attributes := []FabricAttribute{
		{Name: rbac.AttributeRole, Value: req.Role, ECert: true},
		{Name: "hf.EnrollmentID", Value: req.UserID, ECert: true},
		{Name: "hf.Type", Value: "client", ECert: true},
	}

	// Add NodeOU attribute
	if req.NodeOU != "" {
		attributes = append(attributes, FabricAttribute{
			Name: "hf.NodeOU", Value: req.NodeOU, ECert: true,
		})
	}

	// Add role-specific attributes
	for key, value := range req.Attributes {
		attributes = append(attributes, FabricAttribute{
			Name: key, Value: value, ECert: true,
		})
	}

	// Add computed attributes based on role
	switch req.Role {
	case rbac.RoleMBBSStudent, rbac.RoleMDStudent:
		attributes = append(attributes, FabricAttribute{
			Name: rbac.AttributeIsTrainee, Value: "true", ECert: true,
		})
		attributes = append(attributes, FabricAttribute{
			Name: rbac.AttributeIsSupervisor, Value: "false", ECert: true,
		})
	case rbac.RoleConsultingDoctor:
		attributes = append(attributes, FabricAttribute{
			Name: rbac.AttributeIsTrainee, Value: "false", ECert: true,
		})
		attributes = append(attributes, FabricAttribute{
			Name: rbac.AttributeIsSupervisor, Value: "true", ECert: true,
		})
	default:
		attributes = append(attributes, FabricAttribute{
			Name: rbac.AttributeIsTrainee, Value: "false", ECert: true,
		})
		attributes = append(attributes, FabricAttribute{
			Name: rbac.AttributeIsSupervisor, Value: "false", ECert: true,
		})
	}

	// Add level attribute
	if level, exists := rbac.RoleLevels[req.Role]; exists {
		attributes = append(attributes, FabricAttribute{
			Name: rbac.AttributeLevel, Value: fmt.Sprintf("%d", level), ECert: true,
		})
	}

	return attributes
}

// getAffiliation returns the Fabric CA affiliation for a role
func (m *CertificateManager) getAffiliation(role string) string {
	switch role {
	case rbac.RoleConsultingDoctor, rbac.RoleMDStudent, rbac.RoleMBBSStudent:
		return "hospital.clinical"
	case rbac.RoleNurse:
		return "hospital.nursing"
	case rbac.RoleLabTechnician:
		return "hospital.laboratory"
	case rbac.RoleClinicalStaff:
		return "hospital.clinical_support"
	case rbac.RoleReceptionist:
		return "hospital.administration"
	case rbac.RoleAdministrator:
		return "hospital.management"
	case rbac.RolePatient:
		return "hospital.patients"
	default:
		return "hospital.general"
	}
}

// generateEnrollmentSecret generates a secure enrollment secret
func (m *CertificateManager) generateEnrollmentSecret(userID string) string {
	// In production, use cryptographically secure random generation
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%d", userID, time.Now().UnixNano())))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes as secret
}

// parseCertificate parses a PEM-encoded certificate
func (m *CertificateManager) parseCertificate(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

// extractFabricAttributes extracts Fabric-specific attributes from certificate extensions
func (m *CertificateManager) extractFabricAttributes(cert *x509.Certificate) (map[string]string, error) {
	attributes := make(map[string]string)

	// Fabric CA embeds attributes in certificate extensions
	// Look for Fabric-specific OIDs and parse the attribute data
	for _, ext := range cert.Extensions {
		if m.isFabricAttributeOID(ext.Id) {
			attrs, err := m.parseFabricExtension(ext.Value)
			if err != nil {
				m.logger.WithFields(logrus.Fields{
					"oid":   ext.Id.String(),
					"error": err.Error(),
				}).Warn("Failed to parse Fabric extension")
				continue
			}
			for key, value := range attrs {
				attributes[key] = value
			}
		}
	}

	// Also extract attributes from subject alternative names if present
	for _, dnsName := range cert.DNSNames {
		if strings.HasPrefix(dnsName, "attr.") {
			// Parse attribute DNS name format: attr.name.value
			parts := strings.SplitN(dnsName, ".", 3)
			if len(parts) == 3 {
				attrName := parts[1]
				attrValue := parts[2]
				attributes[attrName] = attrValue
			}
		}
	}

	return attributes, nil
}

// isFabricAttributeOID checks if an OID is a Fabric attribute OID
func (m *CertificateManager) isFabricAttributeOID(oid asn1.ObjectIdentifier) bool {
	// Fabric CA uses specific OIDs for embedding attributes
	// This is a simplified check - in production, use actual Fabric OIDs
	fabricOIDPrefix := []int{1, 2, 3, 4, 5, 6, 7, 8, 1}
	
	if len(oid) < len(fabricOIDPrefix) {
		return false
	}
	
	for i, component := range fabricOIDPrefix {
		if oid[i] != component {
			return false
		}
	}
	
	return true
}

// parseFabricExtension parses a Fabric certificate extension containing attributes
func (m *CertificateManager) parseFabricExtension(extensionValue []byte) (map[string]string, error) {
	attributes := make(map[string]string)
	
	// Try to parse as JSON first (common format for Fabric attributes)
	var jsonAttrs map[string]interface{}
	if err := json.Unmarshal(extensionValue, &jsonAttrs); err == nil {
		for key, value := range jsonAttrs {
			if strValue, ok := value.(string); ok {
				attributes[key] = strValue
			} else {
				attributes[key] = fmt.Sprintf("%v", value)
			}
		}
		return attributes, nil
	}
	
	// Try to parse as ASN.1 sequence
	var sequence []asn1.RawValue
	_, err := asn1.Unmarshal(extensionValue, &sequence)
	if err != nil {
		return attributes, fmt.Errorf("failed to parse extension as JSON or ASN.1: %w", err)
	}
	
	// Parse ASN.1 sequence as key-value pairs
	for i := 0; i < len(sequence)-1; i += 2 {
		if i+1 < len(sequence) {
			key := string(sequence[i].Bytes)
			value := string(sequence[i+1].Bytes)
			attributes[key] = value
		}
	}
	
	return attributes, nil
}

// validateCertificateAttributes validates that the certificate contains expected attributes
func (m *CertificateManager) validateCertificateAttributes(cert *x509.Certificate, req *rbac.EnrollmentRequest) error {
	// Extract attributes from the certificate
	extractedAttrs, err := m.ExtractUserAttributes(cert)
	if err != nil {
		return fmt.Errorf("failed to extract attributes: %w", err)
	}

	// Validate role matches
	if extractedAttrs.Role != req.Role {
		return fmt.Errorf("certificate role mismatch: expected %s, got %s", req.Role, extractedAttrs.Role)
	}

	// Validate NodeOU matches
	if len(cert.Subject.OrganizationalUnit) > 0 {
		nodeOU := cert.Subject.OrganizationalUnit[0]
		expectedNodeOU := req.NodeOU
		if expectedNodeOU == "" {
			expectedNodeOU = rbac.NodeOUMappings[req.Role]
		}
		if nodeOU != expectedNodeOU {
			return fmt.Errorf("certificate NodeOU mismatch: expected %s, got %s", expectedNodeOU, nodeOU)
		}
	}

	// Validate required attributes are present
	requiredAttrs := m.getRequiredAttributesForRole(req.Role)
	attrMap := m.attributesToMap(extractedAttrs)
	
	var missingAttrs []string
	for _, requiredAttr := range requiredAttrs {
		if _, exists := attrMap[requiredAttr]; !exists {
			missingAttrs = append(missingAttrs, requiredAttr)
		}
	}

	if len(missingAttrs) > 0 {
		return fmt.Errorf("certificate missing required attributes: %v", missingAttrs)
	}

	return nil
}

// getRequiredAttributesForRole returns required attributes for a role
func (m *CertificateManager) getRequiredAttributesForRole(role string) []string {
	baseAttrs := []string{rbac.AttributeRole, rbac.AttributeLevel, rbac.AttributeIsTrainee, rbac.AttributeIsSupervisor}
	
	switch role {
	case rbac.RoleNurse:
		return append(baseAttrs, rbac.AttributeWardAssignment)
	case rbac.RoleLabTechnician:
		return append(baseAttrs, rbac.AttributeLabOrg)
	case rbac.RoleClinicalStaff, rbac.RoleConsultingDoctor:
		return append(baseAttrs, rbac.AttributeSpecialty)
	default:
		return baseAttrs
	}
}

// validateExtractedAttributes validates extracted attributes for consistency
func (m *CertificateManager) validateExtractedAttributes(attributes *rbac.UserAttributes) error {
	// Validate role is valid
	if _, exists := rbac.NodeOUMappings[attributes.Role]; !exists {
		return fmt.Errorf("invalid role: %s", attributes.Role)
	}

	// Validate level matches role
	expectedLevel, exists := rbac.RoleLevels[attributes.Role]
	if exists && attributes.Level != expectedLevel {
		return fmt.Errorf("level mismatch for role %s: expected %d, got %d", 
			attributes.Role, expectedLevel, attributes.Level)
	}

	// Validate trainee/supervisor flags are consistent with role
	switch attributes.Role {
	case rbac.RoleMBBSStudent, rbac.RoleMDStudent:
		if !attributes.IsTrainee {
			return fmt.Errorf("student role should have IsTrainee=true")
		}
		if attributes.IsSupervisor {
			return fmt.Errorf("student role should have IsSupervisor=false")
		}
	case rbac.RoleConsultingDoctor:
		if attributes.IsTrainee {
			return fmt.Errorf("consulting doctor role should have IsTrainee=false")
		}
		if !attributes.IsSupervisor {
			return fmt.Errorf("consulting doctor role should have IsSupervisor=true")
		}
	}

	return nil
}

// storeCertificateMetadata stores certificate metadata for future reference
func (m *CertificateManager) storeCertificateMetadata(ctx context.Context, userID string, cert *x509.Certificate, enrollResponse *EnrollmentResponse) error {
	// In a real implementation, this would store certificate metadata in a database
	// For now, just log the metadata
	m.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"serial":     cert.SerialNumber.String(),
		"subject":    cert.Subject.String(),
		"issuer":     cert.Issuer.String(),
		"not_before": cert.NotBefore,
		"not_after":  cert.NotAfter,
	}).Info("Certificate metadata stored")
	
	return nil
}

// getCurrentCertificate retrieves current certificate and private key for a user
func (m *CertificateManager) getCurrentCertificate(ctx context.Context, userID string) (string, string, error) {
	// In a real implementation, this would retrieve from secure storage
	// For now, return empty strings to indicate not found
	return "", "", fmt.Errorf("certificate not found for user: %s", userID)
}

// validateAttributeUpdate validates attribute updates for certificate renewal
func (m *CertificateManager) validateAttributeUpdate(newAttrs map[string]string) error {
	// Validate that only allowed attributes are being updated
	allowedAttrs := map[string]bool{
		rbac.AttributeSpecialty:      true,
		rbac.AttributeWardAssignment: true,
		rbac.AttributeLabOrg:         true,
		rbac.AttributeDepartment:     true,
	}

	for attr := range newAttrs {
		if !allowedAttrs[attr] {
			return fmt.Errorf("attribute %s cannot be updated", attr)
		}
	}

	return nil
}

// mapAttributesToFabric converts attribute map to Fabric attributes
func (m *CertificateManager) mapAttributesToFabric(attrs map[string]string) []FabricAttribute {
	var fabricAttrs []FabricAttribute
	
	for key, value := range attrs {
		fabricAttrs = append(fabricAttrs, FabricAttribute{
			Name: key, Value: value, ECert: true,
		})
	}
	
	return fabricAttrs
}

// verifyAttributeUpdate verifies that attribute updates were correctly applied
func (m *CertificateManager) verifyAttributeUpdate(extractedAttrs *rbac.UserAttributes, expectedAttrs map[string]string) error {
	attrMap := m.attributesToMap(extractedAttrs)
	
	for key, expectedValue := range expectedAttrs {
		if actualValue, exists := attrMap[key]; !exists {
			return fmt.Errorf("expected attribute %s not found in certificate", key)
		} else if actualValue != expectedValue {
			return fmt.Errorf("attribute %s mismatch: expected %s, got %s", key, expectedValue, actualValue)
		}
	}
	
	return nil
}

// updateCertificateMetadata updates certificate metadata after renewal
func (m *CertificateManager) updateCertificateMetadata(ctx context.Context, userID string, cert *x509.Certificate, enrollResponse *EnrollmentResponse) error {
	// In a real implementation, this would update certificate metadata in a database
	m.logger.WithFields(logrus.Fields{
		"user_id":    userID,
		"new_serial": cert.SerialNumber.String(),
		"expires_at": cert.NotAfter,
	}).Info("Certificate metadata updated")
	
	return nil
}

// markCertificateRevoked marks a certificate as revoked in metadata
func (m *CertificateManager) markCertificateRevoked(ctx context.Context, userID string, reason string) error {
	// In a real implementation, this would update certificate status in a database
	m.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"reason":  reason,
		"status":  "revoked",
	}).Info("Certificate marked as revoked")
	
	return nil
}

// notifyRevocation notifies other services about certificate revocation
func (m *CertificateManager) notifyRevocation(ctx context.Context, userID string, reason string) error {
	// In a real implementation, this would notify other services via message queue or API calls
	m.logger.WithFields(logrus.Fields{
		"user_id": userID,
		"reason":  reason,
	}).Info("Certificate revocation notification sent")
	
	return nil
}

// GetCertificateInfo retrieves detailed information about a certificate
func (m *CertificateManager) GetCertificateInfo(ctx context.Context, certPEM string) (*CertificateInfo, error) {
	cert, err := m.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	attributes, err := m.ExtractUserAttributes(cert)
	if err != nil {
		return nil, fmt.Errorf("failed to extract attributes: %w", err)
	}

	info := &CertificateInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber.String(),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		IsExpired:     time.Now().After(cert.NotAfter),
		Fingerprint:   m.calculateFingerprint(cert),
		Attributes:    attributes,
		KeyUsage:      cert.KeyUsage,
		ExtKeyUsage:   cert.ExtKeyUsage,
	}

	return info, nil
}

// ValidateCertificateChain validates a certificate against the CA chain
func (m *CertificateManager) ValidateCertificateChain(ctx context.Context, certPEM string) error {
	cert, err := m.parseCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Get CA certificate chain
	caCerts, err := m.caClient.GetCACertificateChain()
	if err != nil {
		return fmt.Errorf("failed to get CA certificate chain: %w", err)
	}

	// Create certificate pool with CA certificates
	roots := x509.NewCertPool()
	for _, caCert := range caCerts {
		roots.AddCert(caCert)
	}

	// Verify certificate against CA chain
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	chains, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	m.logger.WithFields(logrus.Fields{
		"subject":     cert.Subject.String(),
		"chain_count": len(chains),
	}).Debug("Certificate chain validation successful")

	return nil
}

// CheckCertificateExpiry checks if a certificate is expired or expiring soon
func (m *CertificateManager) CheckCertificateExpiry(ctx context.Context, certPEM string, warningDays int) (*ExpiryStatus, error) {
	cert, err := m.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()
	status := &ExpiryStatus{
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsExpired:    now.After(cert.NotAfter),
		IsNotYetValid: now.Before(cert.NotBefore),
		DaysUntilExpiry: int(cert.NotAfter.Sub(now).Hours() / 24),
	}

	if status.DaysUntilExpiry <= warningDays && status.DaysUntilExpiry > 0 {
		status.IsExpiringSoon = true
	}

	return status, nil
}

// ListUserCertificates lists all certificates for a user
func (m *CertificateManager) ListUserCertificates(ctx context.Context, userID string) ([]*CertificateInfo, error) {
	// In a real implementation, this would query a database for user certificates
	// For now, return empty list
	m.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Info("Listing user certificates")

	return []*CertificateInfo{}, nil
}

// ValidateAttributeConstraints validates certificate attributes against constraints
func (m *CertificateManager) ValidateAttributeConstraints(ctx context.Context, cert *x509.Certificate, constraints []rbac.AttributeConstraint) error {
	attributes, err := m.ExtractUserAttributes(cert)
	if err != nil {
		return fmt.Errorf("failed to extract attributes: %w", err)
	}

	attrMap := m.attributesToMap(attributes)

	for _, constraint := range constraints {
		value, exists := attrMap[constraint.Attribute]
		if constraint.Required && !exists {
			return fmt.Errorf("required attribute %s not found", constraint.Attribute)
		}

		if exists {
			if err := m.validateAttributeConstraint(constraint, value); err != nil {
				return fmt.Errorf("attribute constraint validation failed for %s: %w", constraint.Attribute, err)
			}
		}
	}

	return nil
}

// validateAttributeConstraint validates a single attribute constraint
func (m *CertificateManager) validateAttributeConstraint(constraint rbac.AttributeConstraint, value string) error {
	switch constraint.Operator {
	case rbac.OperatorEquals:
		if expectedValue, ok := constraint.Value.(string); ok {
			if value != expectedValue {
				return fmt.Errorf("expected %s, got %s", expectedValue, value)
			}
		}
	case rbac.OperatorNotEquals:
		if expectedValue, ok := constraint.Value.(string); ok {
			if value == expectedValue {
				return fmt.Errorf("value should not be %s", expectedValue)
			}
		}
	case rbac.OperatorContains:
		if expectedSubstring, ok := constraint.Value.(string); ok {
			if !strings.Contains(value, expectedSubstring) {
				return fmt.Errorf("value should contain %s", expectedSubstring)
			}
		}
	case rbac.OperatorIn:
		if allowedValues, ok := constraint.Value.([]string); ok {
			found := false
			for _, allowedValue := range allowedValues {
				if value == allowedValue {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("value %s not in allowed values %v", value, allowedValues)
			}
		}
	default:
		return fmt.Errorf("unsupported operator: %s", constraint.Operator)
	}

	return nil
}

// calculateFingerprint calculates SHA-256 fingerprint of a certificate
func (m *CertificateManager) calculateFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// GetCertificateStatus returns the current status of a certificate
func (m *CertificateManager) GetCertificateStatus(ctx context.Context, certPEM string) (*CertificateStatus, error) {
	cert, err := m.parseCertificate(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	now := time.Now()
	status := &CertificateStatus{
		SerialNumber: cert.SerialNumber.String(),
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		IsValid:      now.After(cert.NotBefore) && now.Before(cert.NotAfter),
		IsExpired:    now.After(cert.NotAfter),
		IsRevoked:    false, // Would check against CRL in real implementation
	}

	// Check if certificate is in revocation list
	if err := m.checkRevocationStatus(ctx, cert); err != nil {
		m.logger.WithFields(logrus.Fields{
			"serial": cert.SerialNumber.String(),
			"error":  err.Error(),
		}).Warn("Failed to check revocation status")
	} else {
		// In real implementation, set IsRevoked based on CRL check
	}

	return status, nil
}

// checkRevocationStatus checks if a certificate is revoked
func (m *CertificateManager) checkRevocationStatus(ctx context.Context, cert *x509.Certificate) error {
	// In a real implementation, this would:
	// 1. Download the latest CRL from the CA
	// 2. Check if the certificate serial number is in the CRL
	// 3. Return appropriate status
	
	m.logger.WithFields(logrus.Fields{
		"serial": cert.SerialNumber.String(),
	}).Debug("Checking certificate revocation status")

	return nil
}

// CertificateInfo contains detailed information about a certificate
type CertificateInfo struct {
	Subject       string                `json:"subject"`
	Issuer        string                `json:"issuer"`
	SerialNumber  string                `json:"serial_number"`
	NotBefore     time.Time             `json:"not_before"`
	NotAfter      time.Time             `json:"not_after"`
	IsExpired     bool                  `json:"is_expired"`
	Fingerprint   string                `json:"fingerprint"`
	Attributes    *rbac.UserAttributes  `json:"attributes"`
	KeyUsage      x509.KeyUsage         `json:"key_usage"`
	ExtKeyUsage   []x509.ExtKeyUsage    `json:"ext_key_usage"`
}

// ExpiryStatus contains certificate expiry information
type ExpiryStatus struct {
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	IsExpired        bool      `json:"is_expired"`
	IsNotYetValid    bool      `json:"is_not_yet_valid"`
	IsExpiringSoon   bool      `json:"is_expiring_soon"`
	DaysUntilExpiry  int       `json:"days_until_expiry"`
}

// CertificateStatus contains the current status of a certificate
type CertificateStatus struct {
	SerialNumber string    `json:"serial_number"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	IsValid      bool      `json:"is_valid"`
	IsExpired    bool      `json:"is_expired"`
	IsRevoked    bool      `json:"is_revoked"`
}