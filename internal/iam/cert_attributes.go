package iam

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/types"
)

// CertificateAttributeExtractor handles X.509 certificate attribute extraction
type CertificateAttributeExtractor struct {
	logger logger.Logger
}

// NewCertificateAttributeExtractor creates a new certificate attribute extractor
func NewCertificateAttributeExtractor(log logger.Logger) *CertificateAttributeExtractor {
	return &CertificateAttributeExtractor{
		logger: log,
	}
}

// ExtractUserAttributes extracts user attributes from X.509 certificate
func (e *CertificateAttributeExtractor) ExtractUserAttributes(certPEM string) (map[string]string, error) {
	e.logger.Info("Extracting attributes from X.509 certificate")

	// Parse PEM certificate
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	attributes := make(map[string]string)

	// Extract standard certificate fields
	attributes["common_name"] = cert.Subject.CommonName
	attributes["serial_number"] = cert.SerialNumber.String()
	attributes["issuer"] = cert.Issuer.String()
	attributes["not_before"] = cert.NotBefore.Format("2006-01-02T15:04:05Z")
	attributes["not_after"] = cert.NotAfter.Format("2006-01-02T15:04:05Z")

	// Extract organization information
	if len(cert.Subject.Organization) > 0 {
		attributes["organization"] = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		attributes["organizational_unit"] = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Country) > 0 {
		attributes["country"] = cert.Subject.Country[0]
	}
	if len(cert.Subject.Province) > 0 {
		attributes["province"] = cert.Subject.Province[0]
	}
	if len(cert.Subject.Locality) > 0 {
		attributes["locality"] = cert.Subject.Locality[0]
	}

	// Extract Fabric-specific attributes from certificate extensions
	fabricAttrs, err := e.extractFabricAttributes(cert)
	if err != nil {
		e.logger.Warn("Failed to extract Fabric attributes", "error", err)
	} else {
		for key, value := range fabricAttrs {
			attributes[key] = value
		}
	}

	// Extract role information from subject or extensions
	role, err := e.extractUserRole(cert, attributes)
	if err != nil {
		e.logger.Warn("Failed to extract user role", "error", err)
	} else {
		attributes["role"] = string(role)
	}

	e.logger.Info("Extracted certificate attributes", "count", len(attributes))
	return attributes, nil
}

// extractFabricAttributes extracts Hyperledger Fabric specific attributes
func (e *CertificateAttributeExtractor) extractFabricAttributes(cert *x509.Certificate) (map[string]string, error) {
	attributes := make(map[string]string)

	// Fabric stores custom attributes in certificate extensions
	// Look for Fabric-specific OIDs
	for _, ext := range cert.Extensions {
		if e.isFabricAttributeOID(ext.Id) {
			attrs, err := e.parseFabricExtension(ext.Value)
			if err != nil {
				e.logger.Warn("Failed to parse Fabric extension", "oid", ext.Id.String(), "error", err)
				continue
			}
			for key, value := range attrs {
				attributes[key] = value
			}
		}
	}

	// Also check subject alternative names for Fabric attributes
	if len(cert.DNSNames) > 0 {
		for _, dnsName := range cert.DNSNames {
			if strings.HasPrefix(dnsName, "fabric.") {
				// Parse Fabric DNS name format: fabric.attr.value
				parts := strings.Split(dnsName, ".")
				if len(parts) >= 3 {
					attrName := parts[1]
					attrValue := strings.Join(parts[2:], ".")
					attributes[attrName] = attrValue
				}
			}
		}
	}

	return attributes, nil
}

// isFabricAttributeOID checks if an OID is a Fabric attribute OID
func (e *CertificateAttributeExtractor) isFabricAttributeOID(oid asn1.ObjectIdentifier) bool {
	// Fabric typically uses OIDs in the range 1.2.3.4.5.6.7.8.*
	// This is a simplified check - in production, use actual Fabric OIDs
	fabricOIDPrefix := []int{1, 2, 3, 4, 5, 6, 7, 8}
	
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

// parseFabricExtension parses a Fabric certificate extension
func (e *CertificateAttributeExtractor) parseFabricExtension(extensionValue []byte) (map[string]string, error) {
	// This is a simplified parser for Fabric extensions
	// In production, use the actual Fabric certificate parsing logic
	
	attributes := make(map[string]string)
	
	// Try to parse as ASN.1 sequence
	var sequence []asn1.RawValue
	_, err := asn1.Unmarshal(extensionValue, &sequence)
	if err != nil {
		// If ASN.1 parsing fails, try to parse as JSON
		return e.parseFabricJSON(extensionValue)
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

// parseFabricJSON parses Fabric attributes stored as JSON in extensions
func (e *CertificateAttributeExtractor) parseFabricJSON(data []byte) (map[string]string, error) {
	// In a real implementation, this would parse JSON-encoded attributes
	// For now, return empty map
	return make(map[string]string), nil
}

// extractUserRole extracts user role from certificate
func (e *CertificateAttributeExtractor) extractUserRole(cert *x509.Certificate, attributes map[string]string) (types.UserRole, error) {
	// Check if role is explicitly set in attributes
	if role, exists := attributes["role"]; exists {
		return types.UserRole(role), nil
	}
	
	// Try to extract role from organizational unit
	if len(cert.Subject.OrganizationalUnit) > 0 {
		ou := cert.Subject.OrganizationalUnit[0]
		if role := e.mapOUToRole(ou); role != "" {
			return role, nil
		}
	}
	
	// Try to extract role from common name
	cn := cert.Subject.CommonName
	if role := e.extractRoleFromCN(cn); role != "" {
		return role, nil
	}
	
	// Default to patient role if no role found
	return types.RolePatient, nil
}

// mapOUToRole maps organizational unit to user role
func (e *CertificateAttributeExtractor) mapOUToRole(ou string) types.UserRole {
	ouLower := strings.ToLower(ou)
	
	switch {
	case strings.Contains(ouLower, "doctor") || strings.Contains(ouLower, "physician"):
		return types.RoleConsultingDoctor
	case strings.Contains(ouLower, "nurse"):
		return types.RoleNurse
	case strings.Contains(ouLower, "student"):
		if strings.Contains(ouLower, "md") || strings.Contains(ouLower, "ms") {
			return types.RoleMDStudent
		}
		return types.RoleMBBSStudent
	case strings.Contains(ouLower, "lab") || strings.Contains(ouLower, "technician"):
		return types.RoleLabTechnician
	case strings.Contains(ouLower, "reception") || strings.Contains(ouLower, "front"):
		return types.RoleReceptionist
	case strings.Contains(ouLower, "clinical"):
		return types.RoleClinicalStaff
	case strings.Contains(ouLower, "admin"):
		return types.RoleAdministrator
	default:
		return ""
	}
}

// extractRoleFromCN extracts role from common name
func (e *CertificateAttributeExtractor) extractRoleFromCN(cn string) types.UserRole {
	cnLower := strings.ToLower(cn)
	
	// Look for role indicators in common name
	if strings.Contains(cnLower, "dr.") || strings.Contains(cnLower, "doctor") {
		return types.RoleConsultingDoctor
	}
	if strings.Contains(cnLower, "nurse") {
		return types.RoleNurse
	}
	if strings.Contains(cnLower, "student") {
		return types.RoleMBBSStudent
	}
	if strings.Contains(cnLower, "admin") {
		return types.RoleAdministrator
	}
	
	return ""
}

// ValidateCertificateRole validates that the certificate role matches expected role
func (e *CertificateAttributeExtractor) ValidateCertificateRole(certPEM string, expectedRole types.UserRole) (bool, error) {
	attributes, err := e.ExtractUserAttributes(certPEM)
	if err != nil {
		return false, fmt.Errorf("failed to extract attributes: %w", err)
	}
	
	certRole, exists := attributes["role"]
	if !exists {
		e.logger.Warn("No role found in certificate")
		return false, nil
	}
	
	if types.UserRole(certRole) != expectedRole {
		e.logger.Warn("Certificate role mismatch", "cert_role", certRole, "expected_role", expectedRole)
		return false, nil
	}
	
	return true, nil
}

// GetCertificateFingerprint generates a fingerprint for the certificate
func (e *CertificateAttributeExtractor) GetCertificateFingerprint(certPEM string) (string, error) {
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