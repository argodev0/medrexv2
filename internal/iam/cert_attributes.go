package iam

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/rbac"
)

// CertificateAttributeExtractor extracts attributes from X.509 certificates
type CertificateAttributeExtractor struct {
	logger logger.Logger
}

// NewCertificateAttributeExtractor creates a new certificate attribute extractor
func NewCertificateAttributeExtractor(logger logger.Logger) *CertificateAttributeExtractor {
	return &CertificateAttributeExtractor{
		logger: logger,
	}
}

// ExtractUserAttributes extracts user attributes from a certificate PEM string
func (e *CertificateAttributeExtractor) ExtractUserAttributes(certPEM string) (map[string]string, error) {
	if certPEM == "" {
		return nil, fmt.Errorf("certificate PEM is empty")
	}

	// Parse PEM block
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	// Parse X.509 certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	// Extract attributes from certificate
	attributes := make(map[string]string)

	// Extract from subject DN
	if cert.Subject.CommonName != "" {
		attributes["common_name"] = cert.Subject.CommonName
	}

	if len(cert.Subject.Organization) > 0 {
		attributes["organization"] = cert.Subject.Organization[0]
	}

	if len(cert.Subject.OrganizationalUnit) > 0 {
		attributes["organizational_unit"] = cert.Subject.OrganizationalUnit[0]
	}

	// Extract from certificate extensions (Fabric CA attributes)
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "1.2.3.4.5.6.7.8.1" { // Example OID for custom attributes
			attrString := string(ext.Value)
			e.parseAttributeString(attrString, attributes)
		}
	}

	// Extract role from organizational unit or subject
	if role := e.extractRoleFromCert(cert); role != "" {
		attributes["role"] = role
	}

	// Set derived attributes
	e.setDerivedAttributes(attributes)

	e.logger.Info("Extracted certificate attributes", "attributes", attributes)
	return attributes, nil
}

// ExtractUserAttributesStruct extracts user attributes and returns as UserAttributes struct
func (e *CertificateAttributeExtractor) ExtractUserAttributesStruct(certPEM string) (*rbac.UserAttributes, error) {
	attrs, err := e.ExtractUserAttributes(certPEM)
	if err != nil {
		return nil, err
	}

	userAttrs := &rbac.UserAttributes{}

	if role, exists := attrs["role"]; exists {
		userAttrs.Role = role
	}

	if specialty, exists := attrs["specialty"]; exists {
		userAttrs.Specialty = specialty
	}

	if dept, exists := attrs["department"]; exists {
		userAttrs.Department = dept
	}

	if ward, exists := attrs["ward_assignment"]; exists {
		userAttrs.WardAssignment = ward
	}

	if lab, exists := attrs["lab_org"]; exists {
		userAttrs.LabOrg = lab
	}

	if isTrainee, exists := attrs["is_trainee"]; exists {
		userAttrs.IsTrainee = isTrainee == "true"
	}

	if isSupervisor, exists := attrs["is_supervisor"]; exists {
		userAttrs.IsSupervisor = isSupervisor == "true"
	}

	if levelStr, exists := attrs["level"]; exists {
		if level, err := strconv.Atoi(levelStr); err == nil {
			userAttrs.Level = level
		}
	}

	return userAttrs, nil
}

// ValidateCertificateAttributes validates that certificate contains required attributes
func (e *CertificateAttributeExtractor) ValidateCertificateAttributes(certPEM string, requiredAttrs []string) error {
	attrs, err := e.ExtractUserAttributes(certPEM)
	if err != nil {
		return fmt.Errorf("failed to extract attributes: %w", err)
	}

	for _, required := range requiredAttrs {
		if _, exists := attrs[required]; !exists {
			return fmt.Errorf("required attribute '%s' not found in certificate", required)
		}
	}

	return nil
}

// extractRoleFromCert extracts role from certificate subject or extensions
func (e *CertificateAttributeExtractor) extractRoleFromCert(cert *x509.Certificate) string {
	// Try to extract from organizational unit
	for _, ou := range cert.Subject.OrganizationalUnit {
		if role := e.mapNodeOUToRole(ou); role != "" {
			return role
		}
	}

	// Try to extract from common name pattern
	cn := cert.Subject.CommonName
	if strings.Contains(cn, "@") {
		parts := strings.Split(cn, "@")
		if len(parts) > 1 {
			// Check if the part before @ matches a role pattern
			userPart := parts[0]
			for roleID := range rbac.RoleLevels {
				if strings.Contains(userPart, roleID) {
					return roleID
				}
			}
		}
	}

	return ""
}

// mapNodeOUToRole maps NodeOU to role ID
func (e *CertificateAttributeExtractor) mapNodeOUToRole(nodeOU string) string {
	for roleID, mappedNodeOU := range rbac.NodeOUMappings {
		if nodeOU == mappedNodeOU {
			return roleID
		}
	}
	return ""
}

// parseAttributeString parses attribute string from certificate extension
func (e *CertificateAttributeExtractor) parseAttributeString(attrString string, attributes map[string]string) {
	// Parse attribute string format: "attr1=value1,attr2=value2"
	pairs := strings.Split(attrString, ",")
	for _, pair := range pairs {
		if kv := strings.SplitN(pair, "=", 2); len(kv) == 2 {
			key := strings.TrimSpace(kv[0])
			value := strings.TrimSpace(kv[1])
			attributes[key] = value
		}
	}
}

// setDerivedAttributes sets derived attributes based on role and other attributes
func (e *CertificateAttributeExtractor) setDerivedAttributes(attributes map[string]string) {
	role := attributes["role"]
	
	// Set trainee status based on role
	switch role {
	case rbac.RoleMBBSStudent, rbac.RoleMDStudent:
		attributes["is_trainee"] = "true"
		attributes["is_supervisor"] = "false"
	case rbac.RoleConsultingDoctor:
		attributes["is_trainee"] = "false"
		attributes["is_supervisor"] = "true"
	default:
		if attributes["is_trainee"] == "" {
			attributes["is_trainee"] = "false"
		}
		if attributes["is_supervisor"] == "" {
			attributes["is_supervisor"] = "false"
		}
	}

	// Set level based on role
	if level, exists := rbac.RoleLevels[role]; exists {
		attributes["level"] = strconv.Itoa(level)
	}

	// Set NodeOU if not present
	if attributes["node_ou"] == "" {
		if nodeOU, exists := rbac.NodeOUMappings[role]; exists {
			attributes["node_ou"] = nodeOU
		}
	}
}

// GetCertificateInfo extracts basic certificate information
func (e *CertificateAttributeExtractor) GetCertificateInfo(certPEM string) (*CertificateInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	return &CertificateInfo{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		IsExpired:  cert.NotAfter.Before(cert.NotBefore),
	}, nil
}

// CertificateInfo contains basic certificate information
type CertificateInfo struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serial_number"`
	NotBefore    interface{} `json:"not_before"`
	NotAfter     interface{} `json:"not_after"`
	IsExpired    bool   `json:"is_expired"`
}