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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/rbac"
	"github.com/sirupsen/logrus"
)

// ABACEngine implements Attribute-Based Access Control functionality
type ABACEngine struct {
	config           *Config
	logger           *logrus.Logger
	policyCache      map[string]*rbac.ABACPolicy
	attributeCache   map[string]map[string]string
	contextProviders map[string]ContextProvider
	certManager      rbac.CertificateManager
}

// ContextProvider defines interface for providing contextual attributes
type ContextProvider interface {
	GetAttributes(ctx context.Context, userID string) (map[string]string, error)
}

// NewABACEngine creates a new ABAC engine with enhanced policy evaluation
func NewABACEngine(config *Config, logger *logrus.Logger, certManager rbac.CertificateManager) (*ABACEngine, error) {
	engine := &ABACEngine{
		config:           config,
		logger:           logger,
		policyCache:      make(map[string]*rbac.ABACPolicy),
		attributeCache:   make(map[string]map[string]string),
		contextProviders: make(map[string]ContextProvider),
		certManager:      certManager,
	}

	// Initialize default context providers
	engine.initializeContextProviders()

	return engine, nil
}

// initializeContextProviders sets up default context providers
func (e *ABACEngine) initializeContextProviders() {
	// Time context provider
	e.contextProviders["time"] = &TimeContextProvider{}
	
	// Location context provider
	e.contextProviders["location"] = &LocationContextProvider{}
	
	// Patient assignment context provider
	e.contextProviders["patient_assignment"] = &PatientAssignmentContextProvider{}
}

// EvaluatePolicy evaluates an ABAC policy against provided attributes with enhanced logic
func (e *ABACEngine) EvaluatePolicy(ctx context.Context, policy *rbac.ABACPolicy, attributes map[string]string) (bool, error) {
	e.logger.WithFields(logrus.Fields{
		"policy_id":   policy.ID,
		"policy_name": policy.Name,
		"effect":      policy.Effect,
		"priority":    policy.Priority,
	}).Debug("Evaluating ABAC policy")

	// Merge contextual attributes with provided attributes
	enrichedAttributes, err := e.enrichAttributesWithContext(ctx, attributes)
	if err != nil {
		return false, fmt.Errorf("failed to enrich attributes with context: %w", err)
	}

	// Evaluate rules with enhanced logic
	ruleResults := make([]bool, len(policy.Rules))
	for i, rule := range policy.Rules {
		result, err := e.evaluateRuleWithEnhancedLogic(rule, enrichedAttributes)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate rule for attribute %s: %w", rule.Attribute, err)
		}
		ruleResults[i] = result

		// Log rule evaluation for debugging
		e.logger.WithFields(logrus.Fields{
			"policy_id": policy.ID,
			"attribute": rule.Attribute,
			"operator":  rule.Operator,
			"expected":  rule.Value,
			"actual":    enrichedAttributes[rule.Attribute],
			"result":    result,
			"required":  rule.Required,
		}).Debug("ABAC rule evaluated")

		// If rule is required and fails, policy fails immediately
		if rule.Required && !result {
			e.logger.WithFields(logrus.Fields{
				"policy_id": policy.ID,
				"attribute": rule.Attribute,
			}).Debug("Required ABAC rule failed")
			return false, nil
		}
	}

	// Apply policy effect logic based on rule results
	policyResult := e.applyPolicyEffectLogic(policy.Effect, ruleResults)

	// Evaluate contextual conditions
	for _, condition := range policy.Conditions {
		result, err := e.evaluateConditionWithEnhancedLogic(ctx, condition, enrichedAttributes)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate condition %s: %w", condition.Type, err)
		}

		if !result {
			e.logger.WithFields(logrus.Fields{
				"policy_id":      policy.ID,
				"condition_type": condition.Type,
				"constraint":     condition.Constraint,
			}).Debug("ABAC condition failed")
			return false, nil
		}
	}

	e.logger.WithFields(logrus.Fields{
		"policy_id": policy.ID,
		"result":    policyResult,
	}).Debug("ABAC policy evaluation completed")

	return policyResult, nil
}

// enrichAttributesWithContext merges provided attributes with contextual attributes
func (e *ABACEngine) enrichAttributesWithContext(ctx context.Context, attributes map[string]string) (map[string]string, error) {
	enriched := make(map[string]string)
	
	// Copy provided attributes
	for k, v := range attributes {
		enriched[k] = v
	}

	// Add contextual attributes from providers
	for providerType, provider := range e.contextProviders {
		contextAttrs, err := provider.GetAttributes(ctx, attributes[rbac.AttributeRole])
		if err != nil {
			e.logger.WithFields(logrus.Fields{
				"provider_type": providerType,
				"error":         err,
			}).Warn("Failed to get contextual attributes from provider")
			continue
		}

		// Merge contextual attributes (don't override existing ones)
		for k, v := range contextAttrs {
			if _, exists := enriched[k]; !exists {
				enriched[k] = v
			}
		}
	}

	// Add system-generated attributes
	enriched[rbac.AttributeTime] = time.Now().Format(rbac.TimeFormatHourMinute)
	enriched["timestamp"] = time.Now().Format(rbac.TimeFormatDateTime)
	
	// Extract IP address from context if available
	if ipAddr := ctx.Value("ip_address"); ipAddr != nil {
		enriched[rbac.AttributeIPAddress] = ipAddr.(string)
	}

	// Extract device type from context if available
	if deviceType := ctx.Value("device_type"); deviceType != nil {
		enriched[rbac.AttributeDeviceType] = deviceType.(string)
	}

	return enriched, nil
}

// applyPolicyEffectLogic applies the policy effect based on rule results
func (e *ABACEngine) applyPolicyEffectLogic(effect rbac.PolicyEffect, ruleResults []bool) bool {
	switch effect {
	case rbac.PolicyEffectAllow:
		// For allow policies, all non-required rules must pass
		for _, result := range ruleResults {
			if !result {
				return false
			}
		}
		return true
	case rbac.PolicyEffectDeny:
		// For deny policies, any passing rule denies access
		for _, result := range ruleResults {
			if result {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// ExtractCertificateAttributes extracts attributes from X.509 certificate with enhanced integration
func (e *ABACEngine) ExtractCertificateAttributes(cert *x509.Certificate) (map[string]string, error) {
	if cert == nil {
		return nil, rbac.NewRBACError(
			rbac.ErrorTypeCertificateInvalid,
			rbac.ErrorCodeCertificateInvalid,
			"Certificate is nil",
		)
	}

	// Use certificate manager for comprehensive attribute extraction if available
	if e.certManager != nil {
		userAttrs, err := e.certManager.ExtractUserAttributes(cert)
		if err != nil {
			e.logger.WithFields(logrus.Fields{
				"subject": cert.Subject.String(),
				"error":   err.Error(),
			}).Warn("Failed to extract attributes via certificate manager, falling back to basic extraction")
		} else {
			// Convert UserAttributes to map format
			return e.convertUserAttributesToMap(userAttrs), nil
		}
	}

	// Fallback to basic attribute extraction
	attributes := make(map[string]string)

	// Extract common name
	if cert.Subject.CommonName != "" {
		attributes["common_name"] = cert.Subject.CommonName
		attributes["user_id"] = cert.Subject.CommonName // Often the user ID
	}

	// Extract organizational unit (role information)
	if len(cert.Subject.OrganizationalUnit) > 0 {
		attributes["organizational_unit"] = cert.Subject.OrganizationalUnit[0]
		
		// Map NodeOU to role
		for role, nodeOU := range rbac.NodeOUMappings {
			if nodeOU == cert.Subject.OrganizationalUnit[0] {
				attributes[rbac.AttributeRole] = role
				break
			}
		}
	}

	// Extract organization
	if len(cert.Subject.Organization) > 0 {
		attributes["organization"] = cert.Subject.Organization[0]
	}

	// Extract locality (could be ward or department)
	if len(cert.Subject.Locality) > 0 {
		attributes["locality"] = cert.Subject.Locality[0]
		// Try to map locality to ward assignment for nurses
		if attributes[rbac.AttributeRole] == rbac.RoleNurse {
			attributes[rbac.AttributeWardAssignment] = cert.Subject.Locality[0]
		}
	}

	// Extract province/state (could be department)
	if len(cert.Subject.Province) > 0 {
		attributes["province"] = cert.Subject.Province[0]
		attributes[rbac.AttributeDepartment] = cert.Subject.Province[0]
	}

	// Check certificate validity and add validity attributes
	now := time.Now()
	attributes["cert_valid"] = fmt.Sprintf("%t", now.After(cert.NotBefore) && now.Before(cert.NotAfter))
	attributes["cert_expired"] = fmt.Sprintf("%t", now.After(cert.NotAfter))
	attributes["cert_not_yet_valid"] = fmt.Sprintf("%t", now.Before(cert.NotBefore))
	attributes["cert_expires_at"] = cert.NotAfter.Format(rbac.TimeFormatDateTime)
	
	// Calculate days until expiry
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	attributes["days_until_expiry"] = fmt.Sprintf("%d", daysUntilExpiry)
	attributes["cert_expiring_soon"] = fmt.Sprintf("%t", daysUntilExpiry <= 30 && daysUntilExpiry > 0)

	// Extract custom attributes from certificate extensions
	fabricAttrs, err := e.extractFabricAttributesFromCert(cert)
	if err != nil {
		e.logger.WithFields(logrus.Fields{
			"subject": cert.Subject.String(),
			"error":   err.Error(),
		}).Debug("Failed to extract Fabric attributes from certificate extensions")
	} else {
		// Merge Fabric attributes
		for key, value := range fabricAttrs {
			attributes[key] = value
		}
	}

	// Extract role-specific attributes based on the role
	if role, exists := attributes[rbac.AttributeRole]; exists {
		e.extractRoleSpecificAttributes(role, attributes)
	}

	// Add certificate fingerprint for tracking
	attributes["cert_fingerprint"] = e.calculateCertificateFingerprint(cert)

	e.logger.WithFields(logrus.Fields{
		"subject":          cert.Subject.String(),
		"attributes_count": len(attributes),
		"role":             attributes[rbac.AttributeRole],
		"cert_valid":       attributes["cert_valid"],
	}).Debug("Extracted certificate attributes")

	return attributes, nil
}

// convertUserAttributesToMap converts UserAttributes struct to map format
func (e *ABACEngine) convertUserAttributesToMap(userAttrs *rbac.UserAttributes) map[string]string {
	attributes := make(map[string]string)

	attributes[rbac.AttributeRole] = userAttrs.Role
	attributes[rbac.AttributeLevel] = fmt.Sprintf("%d", userAttrs.Level)
	attributes[rbac.AttributeIsTrainee] = fmt.Sprintf("%t", userAttrs.IsTrainee)
	attributes[rbac.AttributeIsSupervisor] = fmt.Sprintf("%t", userAttrs.IsSupervisor)

	if userAttrs.Specialty != "" {
		attributes[rbac.AttributeSpecialty] = userAttrs.Specialty
	}
	if userAttrs.WardAssignment != "" {
		attributes[rbac.AttributeWardAssignment] = userAttrs.WardAssignment
	}
	if userAttrs.LabOrg != "" {
		attributes[rbac.AttributeLabOrg] = userAttrs.LabOrg
	}
	if userAttrs.Department != "" {
		attributes[rbac.AttributeDepartment] = userAttrs.Department
	}

	return attributes
}

// extractFabricAttributesFromCert extracts Fabric-specific attributes from certificate
func (e *ABACEngine) extractFabricAttributesFromCert(cert *x509.Certificate) (map[string]string, error) {
	attributes := make(map[string]string)

	// Look for Fabric attributes in certificate extensions
	for _, ext := range cert.Extensions {
		// Check for Fabric attribute OIDs
		if e.isFabricAttributeExtension(ext.Id) {
			attrs, err := e.parseFabricAttributeExtension(ext.Value)
			if err != nil {
				e.logger.WithFields(logrus.Fields{
					"oid":   ext.Id.String(),
					"error": err.Error(),
				}).Debug("Failed to parse Fabric attribute extension")
				continue
			}
			for key, value := range attrs {
				attributes[key] = value
			}
		}
	}

	// Also check subject alternative names for attribute encoding
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

// isFabricAttributeExtension checks if an extension contains Fabric attributes
func (e *ABACEngine) isFabricAttributeExtension(oid asn1.ObjectIdentifier) bool {
	// Fabric CA uses specific OIDs for embedding attributes
	// Common Fabric attribute OIDs (simplified for this implementation)
	fabricOIDs := [][]int{
		{1, 2, 3, 4, 5, 6, 7, 8, 1}, // Example Fabric attribute OID
		{1, 3, 6, 1, 4, 1, 311, 20, 2}, // Microsoft certificate template (sometimes used)
	}

	for _, fabricOID := range fabricOIDs {
		if len(oid) >= len(fabricOID) {
			match := true
			for i, component := range fabricOID {
				if oid[i] != component {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}

	return false
}

// parseFabricAttributeExtension parses Fabric attribute extension data
func (e *ABACEngine) parseFabricAttributeExtension(extensionValue []byte) (map[string]string, error) {
	attributes := make(map[string]string)

	// Try JSON parsing first (common in Fabric CA)
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

	// Try ASN.1 parsing
	var sequence []asn1.RawValue
	_, err := asn1.Unmarshal(extensionValue, &sequence)
	if err != nil {
		// Try as simple string
		attributes["raw_extension"] = string(extensionValue)
		return attributes, nil
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

// calculateCertificateFingerprint calculates SHA-256 fingerprint of certificate
func (e *ABACEngine) calculateCertificateFingerprint(cert *x509.Certificate) string {
	hash := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(hash[:])
}

// ValidateAttributeConstraints validates attributes against constraints with enhanced validation
func (e *ABACEngine) ValidateAttributeConstraints(attributes map[string]string, constraints []rbac.AttributeConstraint) error {
	var validationErrors []string

	for _, constraint := range constraints {
		value, exists := attributes[constraint.Attribute]
		
		if constraint.Required && !exists {
			validationErrors = append(validationErrors, fmt.Sprintf("Required attribute %s is missing", constraint.Attribute))
			continue
		}

		if exists {
			valid, err := e.validateAttributeValueWithEnhancedLogic(value, constraint.Operator, constraint.Value)
			if err != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("Failed to validate attribute %s: %v", constraint.Attribute, err))
				continue
			}

			if !valid {
				validationErrors = append(validationErrors, fmt.Sprintf("Attribute %s (value: %s) does not meet constraint %s %v", 
					constraint.Attribute, value, constraint.Operator, constraint.Value))
			}
		}
	}

	if len(validationErrors) > 0 {
		return rbac.NewRBACError(
			rbac.ErrorTypeAttributeValidation,
			rbac.ErrorCodeAttributeValidation,
			fmt.Sprintf("Attribute validation failed: %s", strings.Join(validationErrors, "; ")),
		)
	}

	return nil
}

// ValidateAttributesWithCertificate validates attributes extracted from certificate in real-time
func (e *ABACEngine) ValidateAttributesWithCertificate(ctx context.Context, cert *x509.Certificate, constraints []rbac.AttributeConstraint) error {
	if cert == nil {
		return rbac.NewRBACError(
			rbac.ErrorTypeCertificateInvalid,
			rbac.ErrorCodeCertificateInvalid,
			"Certificate is required for attribute validation",
		)
	}

	// Extract attributes from certificate
	attributes, err := e.ExtractCertificateAttributes(cert)
	if err != nil {
		return fmt.Errorf("failed to extract certificate attributes: %w", err)
	}

	// Enrich with contextual attributes
	enrichedAttributes, err := e.enrichAttributesWithContext(ctx, attributes)
	if err != nil {
		return fmt.Errorf("failed to enrich attributes with context: %w", err)
	}

	// Validate against constraints
	if err := e.ValidateAttributeConstraints(enrichedAttributes, constraints); err != nil {
		return err
	}

	// Additional certificate-specific validations
	if err := e.validateCertificateSpecificConstraints(cert, enrichedAttributes); err != nil {
		return err
	}

	e.logger.WithFields(logrus.Fields{
		"subject":           cert.Subject.String(),
		"attributes_count":  len(enrichedAttributes),
		"constraints_count": len(constraints),
	}).Debug("Certificate attribute validation completed successfully")

	return nil
}

// validateCertificateSpecificConstraints performs certificate-specific validations
func (e *ABACEngine) validateCertificateSpecificConstraints(cert *x509.Certificate, attributes map[string]string) error {
	now := time.Now()

	// Check certificate validity period
	if now.Before(cert.NotBefore) {
		return rbac.NewRBACError(
			rbac.ErrorTypeCertificateInvalid,
			rbac.ErrorCodeCertificateInvalid,
			"Certificate is not yet valid",
		)
	}

	if now.After(cert.NotAfter) {
		return rbac.NewRBACError(
			rbac.ErrorTypeCertificateInvalid,
			rbac.ErrorCodeCertificateInvalid,
			"Certificate has expired",
		)
	}

	// Check if certificate is expiring soon (within 7 days)
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)
	if daysUntilExpiry <= 7 && daysUntilExpiry > 0 {
		e.logger.WithFields(logrus.Fields{
			"subject":           cert.Subject.String(),
			"days_until_expiry": daysUntilExpiry,
		}).Warn("Certificate is expiring soon")
	}

	// Additional certificate validation could be added here
	// For now, we rely on the basic certificate validity checks above

	// Validate role consistency
	role, roleExists := attributes[rbac.AttributeRole]
	if roleExists {
		if err := e.validateRoleConsistency(cert, role); err != nil {
			return err
		}
	}

	return nil
}

// validateRoleConsistency validates that certificate NodeOU matches the extracted role
func (e *ABACEngine) validateRoleConsistency(cert *x509.Certificate, role string) error {
	if len(cert.Subject.OrganizationalUnit) == 0 {
		return rbac.NewRBACError(
			rbac.ErrorTypeCertificateInvalid,
			rbac.ErrorCodeCertificateInvalid,
			"Certificate missing organizational unit (NodeOU)",
		)
	}

	nodeOU := cert.Subject.OrganizationalUnit[0]
	expectedNodeOU, exists := rbac.NodeOUMappings[role]
	if !exists {
		return rbac.NewRBACError(
			rbac.ErrorTypeInvalidRole,
			rbac.ErrorCodeInvalidRole,
			fmt.Sprintf("Unknown role: %s", role),
		)
	}

	if nodeOU != expectedNodeOU {
		return rbac.NewRBACError(
			rbac.ErrorTypeCertificateInvalid,
			rbac.ErrorCodeCertificateInvalid,
			fmt.Sprintf("Certificate NodeOU (%s) does not match role (%s) expected NodeOU (%s)", 
				nodeOU, role, expectedNodeOU),
		)
	}

	return nil
}

// certificateToPEM converts X.509 certificate to PEM format
func (e *ABACEngine) certificateToPEM(cert *x509.Certificate) string {
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(certPEM)
}

// CacheAttributesForUser caches extracted attributes for a user to improve performance
func (e *ABACEngine) CacheAttributesForUser(userID string, attributes map[string]string, ttl time.Duration) {
	// Add timestamp for TTL management
	attributes["cached_at"] = time.Now().Format(rbac.TimeFormatDateTime)
	attributes["cache_ttl"] = ttl.String()
	
	e.attributeCache[userID] = attributes
	
	e.logger.WithFields(logrus.Fields{
		"user_id":           userID,
		"attributes_count":  len(attributes),
		"cache_ttl":         ttl,
	}).Debug("Cached user attributes")
}

// GetCachedAttributesForUser retrieves cached attributes for a user
func (e *ABACEngine) GetCachedAttributesForUser(userID string) (map[string]string, bool) {
	attributes, exists := e.attributeCache[userID]
	if !exists {
		return nil, false
	}

	// Check if cache has expired
	if cachedAtStr, exists := attributes["cached_at"]; exists {
		cachedAt, err := time.Parse(rbac.TimeFormatDateTime, cachedAtStr)
		if err == nil {
			ttlStr, ttlExists := attributes["cache_ttl"]
			if ttlExists {
				ttl, err := time.ParseDuration(ttlStr)
				if err == nil && time.Since(cachedAt) > ttl {
					// Cache expired, remove it
					delete(e.attributeCache, userID)
					e.logger.WithFields(logrus.Fields{
						"user_id": userID,
						"cached_at": cachedAt,
						"ttl": ttl,
					}).Debug("Cached attributes expired")
					return nil, false
				}
			}
		}
	}

	e.logger.WithFields(logrus.Fields{
		"user_id":          userID,
		"attributes_count": len(attributes),
	}).Debug("Retrieved cached user attributes")

	return attributes, true
}

// InvalidateAttributeCache invalidates cached attributes for a user
func (e *ABACEngine) InvalidateAttributeCache(userID string) {
	delete(e.attributeCache, userID)
	e.logger.WithFields(logrus.Fields{
		"user_id": userID,
	}).Debug("Invalidated cached user attributes")
}

// GetContextualAttributes retrieves contextual attributes for a user
func (e *ABACEngine) GetContextualAttributes(ctx context.Context, userID string) (map[string]string, error) {
	attributes := make(map[string]string)

	// Add timestamp
	attributes[rbac.AttributeTime] = ctx.Value("timestamp").(string)

	// Add IP address if available
	if ipAddr := ctx.Value("ip_address"); ipAddr != nil {
		attributes[rbac.AttributeIPAddress] = ipAddr.(string)
	}

	// Add location if available
	if location := ctx.Value("location"); location != nil {
		attributes[rbac.AttributeLocation] = location.(string)
	}

	// Add device type if available
	if deviceType := ctx.Value("device_type"); deviceType != nil {
		attributes[rbac.AttributeDeviceType] = deviceType.(string)
	}

	// In a real implementation, this would query user assignments, ward assignments, etc.
	// For now, we'll add some placeholder contextual data

	return attributes, nil
}

// Helper methods

// evaluateRuleWithEnhancedLogic evaluates a single ABAC rule with enhanced logic
func (e *ABACEngine) evaluateRuleWithEnhancedLogic(rule rbac.ABACRule, attributes map[string]string) (bool, error) {
	value, exists := attributes[rule.Attribute]
	if !exists {
		// If attribute doesn't exist and rule is not required, it passes
		if !rule.Required {
			return true, nil
		}
		// If attribute doesn't exist and rule is required, it fails
		return false, nil
	}

	return e.validateAttributeValueWithEnhancedLogic(value, rule.Operator, rule.Value)
}

// Legacy method for backward compatibility
func (e *ABACEngine) evaluateRule(rule rbac.ABACRule, attributes map[string]string) (bool, error) {
	return e.evaluateRuleWithEnhancedLogic(rule, attributes)
}

// evaluateConditionWithEnhancedLogic evaluates contextual conditions with enhanced logic
func (e *ABACEngine) evaluateConditionWithEnhancedLogic(ctx context.Context, condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	switch condition.Type {
	case "time":
		return e.evaluateTimeConditionWithEnhancedLogic(condition, attributes)
	case "location":
		return e.evaluateLocationConditionWithEnhancedLogic(condition, attributes)
	case "patient_assignment":
		return e.evaluatePatientAssignmentConditionWithEnhancedLogic(ctx, condition, attributes)
	case "ward_assignment":
		return e.evaluateWardAssignmentCondition(condition, attributes)
	case "specialty_match":
		return e.evaluateSpecialtyMatchCondition(condition, attributes)
	case "supervision_required":
		return e.evaluateSupervisionRequiredCondition(condition, attributes)
	case "business_hours":
		return e.evaluateBusinessHoursCondition(condition, attributes)
	case "device_restriction":
		return e.evaluateDeviceRestrictionCondition(condition, attributes)
	default:
		e.logger.WithField("condition_type", condition.Type).Warn("Unknown condition type")
		return true, nil // Default to allow for unknown conditions
	}
}

// Legacy method for backward compatibility
func (e *ABACEngine) evaluateCondition(ctx context.Context, condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	return e.evaluateConditionWithEnhancedLogic(ctx, condition, attributes)
}

// evaluateTimeConditionWithEnhancedLogic evaluates time-based conditions with enhanced logic
func (e *ABACEngine) evaluateTimeConditionWithEnhancedLogic(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	switch condition.Constraint {
	case "business_hours":
		return e.evaluateBusinessHoursCondition(condition, attributes)
	case "after_hours":
		result, err := e.evaluateBusinessHoursCondition(condition, attributes)
		return !result, err
	case "weekend":
		return e.evaluateWeekendCondition(attributes)
	case "weekday":
		result, err := e.evaluateWeekendCondition(attributes)
		return !result, err
	case "time_range":
		return e.evaluateTimeRangeCondition(condition, attributes)
	default:
		e.logger.WithField("constraint", condition.Constraint).Warn("Unknown time constraint")
		return true, nil
	}
}

// evaluateBusinessHoursCondition checks if current time is within business hours
func (e *ABACEngine) evaluateBusinessHoursCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	timeStr, exists := attributes[rbac.AttributeTime]
	if !exists {
		timeStr = time.Now().Format(rbac.TimeFormatHourMinute)
	}

	// Parse business hours from condition value or use defaults
	startTime := "09:00"
	endTime := "17:00"
	
	if condition.Value != nil {
		if timeRange, ok := condition.Value.(map[string]interface{}); ok {
			if start, exists := timeRange["start"]; exists {
				startTime = fmt.Sprintf("%v", start)
			}
			if end, exists := timeRange["end"]; exists {
				endTime = fmt.Sprintf("%v", end)
			}
		}
	}

	return timeStr >= startTime && timeStr <= endTime, nil
}

// evaluateWeekendCondition checks if current day is weekend
func (e *ABACEngine) evaluateWeekendCondition(attributes map[string]string) (bool, error) {
	now := time.Now()
	weekday := now.Weekday()
	return weekday == time.Saturday || weekday == time.Sunday, nil
}

// evaluateTimeRangeCondition evaluates custom time range conditions
func (e *ABACEngine) evaluateTimeRangeCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	timeStr, exists := attributes[rbac.AttributeTime]
	if !exists {
		timeStr = time.Now().Format(rbac.TimeFormatHourMinute)
	}

	if condition.Value == nil {
		return false, fmt.Errorf("time_range condition requires value specification")
	}

	timeRange, ok := condition.Value.(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("time_range condition value must be a map")
	}

	startTime, startExists := timeRange["start"]
	endTime, endExists := timeRange["end"]

	if !startExists || !endExists {
		return false, fmt.Errorf("time_range condition requires both start and end times")
	}

	startStr := fmt.Sprintf("%v", startTime)
	endStr := fmt.Sprintf("%v", endTime)

	return timeStr >= startStr && timeStr <= endStr, nil
}

// Legacy method for backward compatibility
func (e *ABACEngine) evaluateTimeCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	return e.evaluateTimeConditionWithEnhancedLogic(condition, attributes)
}

// evaluateLocationConditionWithEnhancedLogic evaluates location-based conditions with enhanced logic
func (e *ABACEngine) evaluateLocationConditionWithEnhancedLogic(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	_, exists := attributes[rbac.AttributeLocation]
	if !exists {
		// If location is not provided, check if it's required
		if condition.Constraint == "required" {
			return false, nil
		}
		return true, nil // Default to allow if location not required
	}

	switch condition.Constraint {
	case "ward_assignment":
		return e.evaluateWardAssignmentCondition(condition, attributes)
	case "department_match":
		return e.evaluateDepartmentMatchCondition(condition, attributes)
	case "facility_bounds":
		return e.evaluateFacilityBoundsCondition(condition, attributes)
	case "allowed_locations":
		return e.evaluateAllowedLocationsCondition(condition, attributes)
	default:
		e.logger.WithField("constraint", condition.Constraint).Warn("Unknown location constraint")
		return true, nil
	}
}

// evaluateWardAssignmentCondition checks if user location matches ward assignment
func (e *ABACEngine) evaluateWardAssignmentCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	location, locationExists := attributes[rbac.AttributeLocation]
	wardAssignment, wardExists := attributes[rbac.AttributeWardAssignment]
	
	if !locationExists || !wardExists {
		return false, nil
	}

	return location == wardAssignment, nil
}

// evaluateDepartmentMatchCondition checks if location matches user's department
func (e *ABACEngine) evaluateDepartmentMatchCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	location, locationExists := attributes[rbac.AttributeLocation]
	department, deptExists := attributes[rbac.AttributeDepartment]
	
	if !locationExists || !deptExists {
		return false, nil
	}

	// Check if location contains department name or matches department code
	return strings.Contains(strings.ToLower(location), strings.ToLower(department)), nil
}

// evaluateFacilityBoundsCondition checks if location is within facility bounds
func (e *ABACEngine) evaluateFacilityBoundsCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	location, exists := attributes[rbac.AttributeLocation]
	if !exists {
		return false, nil
	}

	// In a real implementation, this would check GPS coordinates or facility zones
	// For now, we'll check if location starts with facility prefix
	facilityPrefix := "MEDREX_"
	return strings.HasPrefix(strings.ToUpper(location), facilityPrefix), nil
}

// evaluateAllowedLocationsCondition checks if location is in allowed list
func (e *ABACEngine) evaluateAllowedLocationsCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	location, exists := attributes[rbac.AttributeLocation]
	if !exists {
		return false, nil
	}

	if condition.Value == nil {
		return false, fmt.Errorf("allowed_locations condition requires value specification")
	}

	return e.validateIn(location, condition.Value)
}

// Legacy method for backward compatibility
func (e *ABACEngine) evaluateLocationCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	return e.evaluateLocationConditionWithEnhancedLogic(condition, attributes)
}

// evaluatePatientAssignmentConditionWithEnhancedLogic evaluates patient assignment conditions with enhanced logic
func (e *ABACEngine) evaluatePatientAssignmentConditionWithEnhancedLogic(ctx context.Context, condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	patientID, patientExists := attributes[rbac.AttributePatientID]
	_, roleExists := attributes[rbac.AttributeRole]
	
	if !patientExists || !roleExists {
		return false, nil
	}

	switch condition.Constraint {
	case "assigned_patients":
		return e.checkPatientAssignment(ctx, attributes, patientID)
	case "own_data_only":
		return e.checkOwnDataAccess(attributes, patientID)
	case "ward_patients":
		return e.checkWardPatientAccess(attributes, patientID)
	case "specialty_patients":
		return e.checkSpecialtyPatientAccess(attributes, patientID)
	default:
		e.logger.WithField("constraint", condition.Constraint).Warn("Unknown patient assignment constraint")
		return true, nil
	}
}

// checkPatientAssignment checks if user is assigned to the patient
func (e *ABACEngine) checkPatientAssignment(ctx context.Context, attributes map[string]string, patientID string) (bool, error) {
	// In a real implementation, this would query the patient assignment database
	// For now, we'll use a simple heuristic based on user attributes
	
	userRole := attributes[rbac.AttributeRole]
	
	// Consulting doctors and clinical staff typically have broader access
	if userRole == rbac.RoleConsultingDoctor || userRole == rbac.RoleClinicalStaff {
		return true, nil
	}
	
	// Nurses have access to patients in their ward
	if userRole == rbac.RoleNurse {
		return e.checkWardPatientAccess(attributes, patientID)
	}
	
	// Trainees need supervisor assignment
	if userRole == rbac.RoleMBBSStudent || userRole == rbac.RoleMDStudent {
		return e.checkTraineePatientAccess(attributes, patientID)
	}
	
	return false, nil
}

// checkOwnDataAccess checks if patient is accessing their own data
func (e *ABACEngine) checkOwnDataAccess(attributes map[string]string, patientID string) (bool, error) {
	userRole := attributes[rbac.AttributeRole]
	
	// Only patients can access their own data
	if userRole != rbac.RolePatient {
		return false, nil
	}
	
	// In a real implementation, this would verify the patient ID matches the user ID
	// For now, we'll assume the check passes if role is patient
	return true, nil
}

// checkWardPatientAccess checks if user has access to patients in their ward
func (e *ABACEngine) checkWardPatientAccess(attributes map[string]string, patientID string) (bool, error) {
	wardAssignment, exists := attributes[rbac.AttributeWardAssignment]
	if !exists {
		return false, nil
	}
	
	// In a real implementation, this would query the patient's current ward
	// For now, we'll assume access is granted if user has ward assignment
	return wardAssignment != "", nil
}

// checkSpecialtyPatientAccess checks if user has access to patients in their specialty
func (e *ABACEngine) checkSpecialtyPatientAccess(attributes map[string]string, patientID string) (bool, error) {
	specialty, exists := attributes[rbac.AttributeSpecialty]
	if !exists {
		return false, nil
	}
	
	// In a real implementation, this would query the patient's treatment specialty
	// For now, we'll assume access is granted if user has specialty
	return specialty != "", nil
}

// checkTraineePatientAccess checks if trainee has supervised access to patient
func (e *ABACEngine) checkTraineePatientAccess(attributes map[string]string, patientID string) (bool, error) {
	// Trainees need supervisor assignment for patient access
	// In a real implementation, this would check supervision workflow
	
	// For MBBS students, only allow access to de-identified training data
	if attributes[rbac.AttributeRole] == rbac.RoleMBBSStudent {
		// Check if this is training data access
		if strings.Contains(patientID, "training_") {
			return true, nil
		}
		return false, nil
	}
	
	// For MD/MS students, allow supervised access
	if attributes[rbac.AttributeRole] == rbac.RoleMDStudent {
		// In a real implementation, check if supervisor is assigned
		return true, nil // Placeholder - assume supervised access
	}
	
	return false, nil
}

// evaluateSpecialtyMatchCondition checks if user specialty matches requirement
func (e *ABACEngine) evaluateSpecialtyMatchCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	userSpecialty, exists := attributes[rbac.AttributeSpecialty]
	if !exists {
		return false, nil
	}

	if condition.Value == nil {
		return false, fmt.Errorf("specialty_match condition requires value specification")
	}

	return e.validateIn(userSpecialty, condition.Value)
}

// evaluateSupervisionRequiredCondition checks if supervision is required
func (e *ABACEngine) evaluateSupervisionRequiredCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	isTrainee, exists := attributes[rbac.AttributeIsTrainee]
	if !exists {
		return false, nil
	}

	// If user is a trainee, supervision is required
	if isTrainee == "true" {
		// Check if supervisor is assigned
		_, supervisorExists := attributes["supervisor_id"]
		return supervisorExists, nil
	}

	return true, nil // Non-trainees don't need supervision
}

// evaluateDeviceRestrictionCondition checks device-based restrictions
func (e *ABACEngine) evaluateDeviceRestrictionCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	deviceType, exists := attributes[rbac.AttributeDeviceType]
	if !exists {
		return false, nil
	}

	if condition.Value == nil {
		return false, fmt.Errorf("device_restriction condition requires value specification")
	}

	return e.validateIn(deviceType, condition.Value)
}

// Legacy method for backward compatibility
func (e *ABACEngine) evaluatePatientAssignmentCondition(condition rbac.AttributeCondition, attributes map[string]string) (bool, error) {
	return e.evaluatePatientAssignmentConditionWithEnhancedLogic(context.Background(), condition, attributes)
}

// validateAttributeValueWithEnhancedLogic validates attribute values with enhanced operators
func (e *ABACEngine) validateAttributeValueWithEnhancedLogic(value string, operator string, expected interface{}) (bool, error) {
	switch operator {
	case rbac.OperatorEquals:
		return e.validateEquals(value, expected)
	case rbac.OperatorNotEquals:
		result, err := e.validateEquals(value, expected)
		return !result, err
	case rbac.OperatorContains:
		return e.validateContains(value, expected)
	case rbac.OperatorNotContains:
		result, err := e.validateContains(value, expected)
		return !result, err
	case rbac.OperatorIn:
		return e.validateIn(value, expected)
	case rbac.OperatorNotIn:
		result, err := e.validateIn(value, expected)
		return !result, err
	case rbac.OperatorGreaterThan:
		return e.validateGreaterThan(value, expected)
	case rbac.OperatorLessThan:
		return e.validateLessThan(value, expected)
	case rbac.OperatorMatches:
		return e.validateMatches(value, expected)
	case rbac.OperatorNotMatches:
		result, err := e.validateMatches(value, expected)
		return !result, err
	default:
		return false, fmt.Errorf("unsupported operator: %s", operator)
	}
}

// validateEquals checks if values are equal
func (e *ABACEngine) validateEquals(value string, expected interface{}) (bool, error) {
	expectedStr := fmt.Sprintf("%v", expected)
	return value == expectedStr, nil
}

// validateContains checks if value contains expected substring
func (e *ABACEngine) validateContains(value string, expected interface{}) (bool, error) {
	expectedStr := fmt.Sprintf("%v", expected)
	return strings.Contains(value, expectedStr), nil
}

// validateIn checks if value is in a list of expected values
func (e *ABACEngine) validateIn(value string, expected interface{}) (bool, error) {
	switch exp := expected.(type) {
	case []string:
		for _, item := range exp {
			if value == item {
				return true, nil
			}
		}
		return false, nil
	case []interface{}:
		for _, item := range exp {
			if value == fmt.Sprintf("%v", item) {
				return true, nil
			}
		}
		return false, nil
	case string:
		// Handle comma-separated values
		items := strings.Split(exp, ",")
		for _, item := range items {
			if value == strings.TrimSpace(item) {
				return true, nil
			}
		}
		return false, nil
	default:
		return value == fmt.Sprintf("%v", expected), nil
	}
}

// validateGreaterThan checks if numeric value is greater than expected
func (e *ABACEngine) validateGreaterThan(value string, expected interface{}) (bool, error) {
	valueNum, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false, fmt.Errorf("cannot parse value as number: %s", value)
	}

	expectedNum, err := strconv.ParseFloat(fmt.Sprintf("%v", expected), 64)
	if err != nil {
		return false, fmt.Errorf("cannot parse expected value as number: %v", expected)
	}

	return valueNum > expectedNum, nil
}

// validateLessThan checks if numeric value is less than expected
func (e *ABACEngine) validateLessThan(value string, expected interface{}) (bool, error) {
	valueNum, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return false, fmt.Errorf("cannot parse value as number: %s", value)
	}

	expectedNum, err := strconv.ParseFloat(fmt.Sprintf("%v", expected), 64)
	if err != nil {
		return false, fmt.Errorf("cannot parse expected value as number: %v", expected)
	}

	return valueNum < expectedNum, nil
}

// validateMatches checks if value matches a regular expression pattern
func (e *ABACEngine) validateMatches(value string, expected interface{}) (bool, error) {
	pattern := fmt.Sprintf("%v", expected)
	matched, err := regexp.MatchString(pattern, value)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %s", pattern)
	}
	return matched, nil
}

// Legacy method for backward compatibility
func (e *ABACEngine) validateAttributeValue(value string, operator string, expected interface{}) (bool, error) {
	return e.validateAttributeValueWithEnhancedLogic(value, operator, expected)
}

func (e *ABACEngine) extractRoleSpecificAttributes(role string, attributes map[string]string) {
	// Extract role-specific attributes based on the role type
	switch role {
	case rbac.RoleMBBSStudent, rbac.RoleMDStudent:
		attributes[rbac.AttributeIsTrainee] = "true"
		attributes[rbac.AttributeIsSupervisor] = "false"
	case rbac.RoleConsultingDoctor:
		attributes[rbac.AttributeIsTrainee] = "false"
		attributes[rbac.AttributeIsSupervisor] = "true"
	case rbac.RoleNurse:
		// Nurses typically have ward assignments - only set default if not already present
		if _, exists := attributes[rbac.AttributeWardAssignment]; !exists {
			attributes[rbac.AttributeWardAssignment] = "general_ward" // Placeholder
		}
	case rbac.RoleLabTechnician:
		// Lab technicians have lab organization assignments - only set default if not already present
		if _, exists := attributes[rbac.AttributeLabOrg]; !exists {
			attributes[rbac.AttributeLabOrg] = "central_lab" // Placeholder
		}
	default:
		attributes[rbac.AttributeIsTrainee] = "false"
		attributes[rbac.AttributeIsSupervisor] = "false"
	}

	// Set level based on role
	if level, exists := rbac.RoleLevels[role]; exists {
		attributes[rbac.AttributeLevel] = fmt.Sprintf("%d", level)
	}
}

// Context Provider Implementations

// TimeContextProvider provides time-based contextual attributes
type TimeContextProvider struct{}

func (p *TimeContextProvider) GetAttributes(ctx context.Context, userID string) (map[string]string, error) {
	now := time.Now()
	attributes := map[string]string{
		rbac.AttributeTime: now.Format(rbac.TimeFormatHourMinute),
		"timestamp":        now.Format(rbac.TimeFormatDateTime),
		"day_of_week":      strings.ToLower(now.Weekday().String()),
		"is_weekend":       fmt.Sprintf("%t", now.Weekday() == time.Saturday || now.Weekday() == time.Sunday),
		"hour":             fmt.Sprintf("%d", now.Hour()),
		"minute":           fmt.Sprintf("%d", now.Minute()),
	}
	
	// Add business hours indicator
	hour := now.Hour()
	attributes["is_business_hours"] = fmt.Sprintf("%t", hour >= 9 && hour <= 17)
	
	return attributes, nil
}

// LocationContextProvider provides location-based contextual attributes
type LocationContextProvider struct{}

func (p *LocationContextProvider) GetAttributes(ctx context.Context, userID string) (map[string]string, error) {
	attributes := make(map[string]string)
	
	// Extract location from context if available
	if location := ctx.Value("location"); location != nil {
		attributes[rbac.AttributeLocation] = location.(string)
	}
	
	// Extract IP address from context if available
	if ipAddr := ctx.Value("ip_address"); ipAddr != nil {
		attributes[rbac.AttributeIPAddress] = ipAddr.(string)
		
		// In a real implementation, this would do IP geolocation
		// For now, we'll add placeholder location data
		if strings.HasPrefix(ipAddr.(string), "192.168.") {
			attributes["network_type"] = "internal"
			attributes["location_verified"] = "true"
		} else {
			attributes["network_type"] = "external"
			attributes["location_verified"] = "false"
		}
	}
	
	return attributes, nil
}

// PatientAssignmentContextProvider provides patient assignment contextual attributes
type PatientAssignmentContextProvider struct{}

func (p *PatientAssignmentContextProvider) GetAttributes(ctx context.Context, userID string) (map[string]string, error) {
	attributes := make(map[string]string)
	
	// In a real implementation, this would query the patient assignment database
	// For now, we'll add placeholder assignment data based on user role
	
	if userRole := ctx.Value("user_role"); userRole != nil {
		role := userRole.(string)
		
		switch role {
		case rbac.RoleNurse:
			attributes[rbac.AttributeWardAssignment] = "general_ward"
			attributes["shift"] = "day"
		case rbac.RoleLabTechnician:
			attributes[rbac.AttributeLabOrg] = "central_lab"
			attributes["lab_section"] = "hematology"
		case rbac.RoleConsultingDoctor:
			attributes[rbac.AttributeSpecialty] = "internal_medicine"
			attributes[rbac.AttributeIsSupervisor] = "true"
		case rbac.RoleClinicalStaff:
			attributes[rbac.AttributeSpecialty] = "radiology"
			attributes[rbac.AttributeDepartment] = "diagnostic_imaging"
		case rbac.RoleMBBSStudent, rbac.RoleMDStudent:
			attributes[rbac.AttributeIsTrainee] = "true"
			attributes["supervisor_id"] = "supervisor_123"
		}
	}
	
	return attributes, nil
}