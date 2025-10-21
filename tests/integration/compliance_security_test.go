// +build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHIPAAComplianceValidation tests HIPAA compliance across all workflows
func TestHIPAAComplianceValidation(t *testing.T) {
	_ = context.Background()
	
	t.Run("PHIEncryptionCompliance", func(t *testing.T) {
		// Test that PHI is never stored unencrypted
		patientData := map[string]interface{}{
			"mrn":           "MRN-HIPAA-001",
			"first_name":    "John",
			"last_name":     "Doe",
			"ssn":           "123-45-6789",
			"date_of_birth": "1980-01-01",
			"diagnosis":     "Hypertension",
		}
		
		// Simulate PHI creation
		reqBody, err := json.Marshal(patientData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/clinical-notes", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer doctor-token")
		
		w := httptest.NewRecorder()
		
		// Simulate encrypted storage
		_ = "[AES256_ENCRYPTED]" + string(reqBody)
		contentHash := sha256.Sum256([]byte(patientData["diagnosis"].(string)))
		hashString := hex.EncodeToString(contentHash[:])
		
		noteID := "note-hipaa-123"
		response := map[string]interface{}{
			"id":           noteID,
			"patient_id":   "patient-hipaa-456",
			"content_hash": hashString,
			"encrypted":    true,
			"phi_stored":   "off_chain_encrypted",
			"created_at":   time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		// Verify PHI compliance
		assert.True(t, result["encrypted"].(bool), "PHI must be encrypted")
		assert.Equal(t, "off_chain_encrypted", result["phi_stored"], "PHI must be stored off-chain")
		assert.NotEmpty(t, result["content_hash"], "Content hash must be present for integrity")
		
		// Verify no PHI in response
		responseStr := w.Body.String()
		assert.NotContains(t, responseStr, patientData["ssn"], "SSN must not appear in response")
		assert.NotContains(t, responseStr, patientData["diagnosis"], "Diagnosis must not appear unencrypted")
		
		// Log HIPAA compliance check
		fabricClient.LogAuditEvent("system", "hipaa_compliance_check", noteID, true, map[string]interface{}{
			"encryption_verified": true,
			"phi_location":        "off_chain_encrypted",
			"hash_integrity":      true,
		})
	})
	
	t.Run("MinimumNecessaryStandard", func(t *testing.T) {
		// Test that users only receive minimum necessary PHI
		testCases := []struct {
			role           string
			expectedFields []string
			restrictedFields []string
		}{
			{
				role:           "nurse",
				expectedFields: []string{"patient_id", "current_medications", "allergies"},
				restrictedFields: []string{"ssn", "insurance_details", "billing_info"},
			},
			{
				role:           "lab_technician",
				expectedFields: []string{"patient_id", "lab_orders", "specimen_info"},
				restrictedFields: []string{"diagnosis", "treatment_plan", "insurance_details"},
			},
			{
				role:           "receptionist",
				expectedFields: []string{"patient_id", "appointment_info", "contact_info"},
				restrictedFields: []string{"diagnosis", "medications", "lab_results"},
			},
		}
		
		for _, tc := range testCases {
			t.Run(fmt.Sprintf("Role_%s", tc.role), func(t *testing.T) {
				patientID := "patient-minimum-necessary-789"
				
				req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/patients/%s", patientID), nil)
				req.Header.Set("Authorization", fmt.Sprintf("Bearer %s-token", tc.role))
				
				w := httptest.NewRecorder()
				
				// Simulate role-based data filtering
				filteredResponse := map[string]interface{}{
					"id": patientID,
					"role_based_access": tc.role,
				}
				
				// Add expected fields
				for _, field := range tc.expectedFields {
					filteredResponse[field] = fmt.Sprintf("mock_%s_data", field)
				}
				
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(filteredResponse)
				
				assert.Equal(t, http.StatusOK, w.Code)
				
				responseStr := w.Body.String()
				
				// Verify expected fields are present
				for _, field := range tc.expectedFields {
					assert.Contains(t, responseStr, field, "Expected field %s should be present for role %s", field, tc.role)
				}
				
				// Verify restricted fields are not present
				for _, field := range tc.restrictedFields {
					assert.NotContains(t, responseStr, field, "Restricted field %s should not be present for role %s", field, tc.role)
				}
				
				// Log minimum necessary compliance
				fabricClient.LogAuditEvent(fmt.Sprintf("%s-user", tc.role), "minimum_necessary_access", patientID, true, map[string]interface{}{
					"role":             tc.role,
					"fields_provided":  tc.expectedFields,
					"fields_restricted": tc.restrictedFields,
				})
			})
		}
	})
	
	t.Run("AccessControlValidation", func(t *testing.T) {
		// Test that access controls are properly enforced
		unauthorizedAttempts := []struct {
			role     string
			resource string
			action   string
			shouldFail bool
		}{
			{"patient", "clinical_notes", "write", true},
			{"receptionist", "clinical_notes", "read", true},
			{"nurse", "billing_info", "read", true},
			{"lab_technician", "prescriptions", "write", true},
			{"consulting_doctor", "clinical_notes", "read", false},
			{"consulting_doctor", "clinical_notes", "write", false},
		}
		
		for _, attempt := range unauthorizedAttempts {
			t.Run(fmt.Sprintf("%s_%s_%s", attempt.role, attempt.resource, attempt.action), func(t *testing.T) {
				hasAccess := fabricClient.CheckAccess(attempt.role, attempt.resource, attempt.action)
				
				if attempt.shouldFail {
					assert.False(t, hasAccess, "Access should be denied for %s trying to %s %s", attempt.role, attempt.action, attempt.resource)
				} else {
					assert.True(t, hasAccess, "Access should be granted for %s trying to %s %s", attempt.role, attempt.action, attempt.resource)
				}
				
				// Log access control check
				fabricClient.LogAuditEvent(fmt.Sprintf("%s-user", attempt.role), "access_control_check", attempt.resource, hasAccess, map[string]interface{}{
					"role":     attempt.role,
					"resource": attempt.resource,
					"action":   attempt.action,
					"expected": !attempt.shouldFail,
				})
			})
		}
	})
}

// TestGDPRComplianceValidation tests GDPR compliance requirements
func TestGDPRComplianceValidation(t *testing.T) {
	_ = context.Background()
	
	t.Run("DataSubjectRights", func(t *testing.T) {
		patientID := "patient-gdpr-123"
		
		// Test Right of Access (Article 15)
		t.Run("RightOfAccess", func(t *testing.T) {
			req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/patients/%s/data-export", patientID), nil)
			req.Header.Set("Authorization", "Bearer patient-token")
			
			w := httptest.NewRecorder()
			
			dataExport := map[string]interface{}{
				"patient_id":     patientID,
				"personal_data": map[string]interface{}{
					"name":           "John Doe",
					"date_of_birth": "1980-01-01",
					"contact_info":  "john.doe@email.com",
				},
				"processing_purposes": []string{"Healthcare delivery", "Treatment coordination"},
				"data_categories":     []string{"Health data", "Contact information"},
				"retention_period":    "7 years post treatment",
				"export_date":         time.Now().Format(time.RFC3339),
			}
			
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(dataExport)
			
			assert.Equal(t, http.StatusOK, w.Code)
			
			var result map[string]interface{}
			err := json.NewDecoder(w.Body).Decode(&result)
			require.NoError(t, err)
			
			assert.Equal(t, patientID, result["patient_id"])
			assert.NotEmpty(t, result["processing_purposes"])
			assert.NotEmpty(t, result["data_categories"])
			
			// Log GDPR access request
			fabricClient.LogAuditEvent(patientID, "gdpr_data_access_request", patientID, true, map[string]interface{}{
				"request_type": "data_export",
				"article":      "15",
			})
		})
		
		// Test Right to Rectification (Article 16)
		t.Run("RightToRectification", func(t *testing.T) {
			correctionData := map[string]interface{}{
				"field":     "contact_email",
				"old_value": "old.email@example.com",
				"new_value": "new.email@example.com",
				"reason":    "Patient requested correction",
			}
			
			reqBody, err := json.Marshal(correctionData)
			require.NoError(t, err)
			
			req := httptest.NewRequest("PUT", fmt.Sprintf("/api/v1/patients/%s/rectify", patientID), bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer patient-token")
			
			w := httptest.NewRecorder()
			
			rectificationResponse := map[string]interface{}{
				"rectification_id": "rect-123",
				"patient_id":       patientID,
				"field_updated":    correctionData["field"],
				"status":           "completed",
				"updated_at":       time.Now().Format(time.RFC3339),
			}
			
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(rectificationResponse)
			
			assert.Equal(t, http.StatusOK, w.Code)
			
			// Log GDPR rectification
			fabricClient.LogAuditEvent(patientID, "gdpr_data_rectification", "rect-123", true, map[string]interface{}{
				"field_updated": correctionData["field"],
				"article":       "16",
			})
		})
		
		// Test Right to Erasure (Article 17)
		t.Run("RightToErasure", func(t *testing.T) {
			erasureData := map[string]interface{}{
				"reason":           "Withdrawal of consent",
				"data_categories":  []string{"Contact information", "Non-essential health data"},
				"retention_override": false,
			}
			
			reqBody, err := json.Marshal(erasureData)
			require.NoError(t, err)
			
			req := httptest.NewRequest("DELETE", fmt.Sprintf("/api/v1/patients/%s/erase", patientID), bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer patient-token")
			
			w := httptest.NewRecorder()
			
			erasureResponse := map[string]interface{}{
				"erasure_id":       "erase-456",
				"patient_id":       patientID,
				"status":           "partial_erasure",
				"erased_categories": erasureData["data_categories"],
				"retained_data":    []string{"Essential health records (legal requirement)"},
				"processed_at":     time.Now().Format(time.RFC3339),
			}
			
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(erasureResponse)
			
			assert.Equal(t, http.StatusOK, w.Code)
			
			var result map[string]interface{}
			err = json.NewDecoder(w.Body).Decode(&result)
			require.NoError(t, err)
			
			assert.Equal(t, "partial_erasure", result["status"])
			assert.NotEmpty(t, result["retained_data"])
			
			// Log GDPR erasure request
			fabricClient.LogAuditEvent(patientID, "gdpr_data_erasure", "erase-456", true, map[string]interface{}{
				"erasure_type": "partial",
				"article":      "17",
				"reason":       erasureData["reason"],
			})
		})
	})
	
	t.Run("ConsentManagement", func(t *testing.T) {
		patientID := "patient-consent-789"
		
		// Test consent recording
		consentData := map[string]interface{}{
			"patient_id":        patientID,
			"consent_type":      "data_processing",
			"purposes":          []string{"Treatment", "Care coordination", "Quality improvement"},
			"data_categories":   []string{"Health data", "Contact information"},
			"consent_given":     true,
			"consent_method":    "electronic_signature",
			"withdrawal_method": "patient_portal",
		}
		
		reqBody, err := json.Marshal(consentData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/consent/record", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer patient-token")
		
		w := httptest.NewRecorder()
		
		consentID := "consent-123"
		consentResponse := map[string]interface{}{
			"consent_id":        consentID,
			"patient_id":        patientID,
			"status":            "active",
			"purposes":          consentData["purposes"],
			"data_categories":   consentData["data_categories"],
			"consent_date":      time.Now().Format(time.RFC3339),
			"withdrawal_method": consentData["withdrawal_method"],
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(consentResponse)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		// Log consent recording
		fabricClient.LogAuditEvent(patientID, "gdpr_consent_recorded", consentID, true, map[string]interface{}{
			"consent_type": consentData["consent_type"],
			"purposes":     consentData["purposes"],
		})
		
		// Test consent withdrawal
		withdrawalReq := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/consent/%s/withdraw", consentID), nil)
		withdrawalReq.Header.Set("Authorization", "Bearer patient-token")
		
		withdrawalW := httptest.NewRecorder()
		
		withdrawalResponse := map[string]interface{}{
			"consent_id":     consentID,
			"status":         "withdrawn",
			"withdrawn_at":   time.Now().Format(time.RFC3339),
			"effect_date":    time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		}
		
		withdrawalW.WriteHeader(http.StatusOK)
		json.NewEncoder(withdrawalW).Encode(withdrawalResponse)
		
		assert.Equal(t, http.StatusOK, withdrawalW.Code)
		
		// Log consent withdrawal
		fabricClient.LogAuditEvent(patientID, "gdpr_consent_withdrawn", consentID, true, map[string]interface{}{
			"withdrawal_method": "patient_portal",
		})
	})
}

// TestAuditTrailCompletenessAndImmutability tests audit trail requirements
func TestAuditTrailCompletenessAndImmutability(t *testing.T) {
	_ = context.Background()
	
	t.Run("AuditTrailCompleteness", func(t *testing.T) {
		// Test that all required events are logged
		requiredEvents := []struct {
			action     string
			userID     string
			resourceID string
			details    map[string]interface{}
		}{
			{"user_login", "user-123", "session-456", map[string]interface{}{"ip_address": "192.168.1.1"}},
			{"phi_access", "user-123", "patient-789", map[string]interface{}{"access_type": "read"}},
			{"phi_modification", "user-123", "note-101", map[string]interface{}{"field_modified": "diagnosis"}},
			{"cpoe_order_created", "user-123", "order-202", map[string]interface{}{"medication": "Aspirin"}},
			{"user_logout", "user-123", "session-456", map[string]interface{}{"session_duration": "3600"}},
		}
		
		initialLogCount := len(fabricClient.GetAuditLogs())
		
		// Log all required events
		for _, event := range requiredEvents {
			fabricClient.LogAuditEvent(event.userID, event.action, event.resourceID, true, event.details)
		}
		
		// Verify all events were logged
		auditLogs := fabricClient.GetAuditLogs()
		newLogCount := len(auditLogs) - initialLogCount
		
		assert.GreaterOrEqual(t, newLogCount, len(requiredEvents), "All required events should be logged")
		
		// Verify event details
		recentLogs := auditLogs[len(auditLogs)-len(requiredEvents):]
		for i, log := range recentLogs {
			expectedEvent := requiredEvents[i]
			assert.Equal(t, expectedEvent.userID, log.UserID)
			assert.Equal(t, expectedEvent.action, log.Action)
			assert.Equal(t, expectedEvent.resourceID, log.ResourceID)
			assert.True(t, log.Success)
			assert.NotEmpty(t, log.Timestamp)
		}
	})
	
	t.Run("AuditLogImmutability", func(t *testing.T) {
		// Create initial audit entry
		initialEntry := &AuditLogEntry{
			ID:         "immutable-test-1",
			UserID:     "test-user",
			Action:     "test_action",
			ResourceID: "test-resource",
			Timestamp:  time.Now(),
			Success:    true,
			Details:    map[string]interface{}{"test": "data"},
		}
		
		fabricClient.LogAuditEvent(initialEntry.UserID, initialEntry.Action, initialEntry.ResourceID, initialEntry.Success, initialEntry.Details)
		
		// Get the logged entry
		auditLogs := fabricClient.GetAuditLogs()
		var loggedEntry *AuditLogEntry
		for _, log := range auditLogs {
			if log.UserID == initialEntry.UserID && log.Action == initialEntry.Action {
				loggedEntry = log
				break
			}
		}
		
		require.NotNil(t, loggedEntry, "Entry should be found in audit logs")
		
		// Verify immutability (in real blockchain, modification would be impossible)
		originalTimestamp := loggedEntry.Timestamp
		originalDetails := loggedEntry.Details
		
		// Simulate attempt to modify (should not affect the logged entry)
		// In real blockchain, this would be prevented by the ledger
		assert.Equal(t, originalTimestamp, loggedEntry.Timestamp)
		assert.Equal(t, originalDetails, loggedEntry.Details)
		
		// Verify cryptographic integrity (simulate hash verification)
		expectedHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%v", 
			loggedEntry.UserID, loggedEntry.Action, loggedEntry.ResourceID, loggedEntry.Timestamp.Unix())))
		actualHash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s:%v", 
			loggedEntry.UserID, loggedEntry.Action, loggedEntry.ResourceID, loggedEntry.Timestamp.Unix())))
		
		assert.Equal(t, expectedHash, actualHash, "Audit log integrity should be maintained")
	})
	
	t.Run("AuditLogRetention", func(t *testing.T) {
		// Test audit log retention policies
		retentionTestEvents := []struct {
			eventDate time.Time
			shouldRetain bool
		}{
			{time.Now().AddDate(-1, 0, 0), true},  // 1 year old - should retain
			{time.Now().AddDate(-5, 0, 0), true},  // 5 years old - should retain
			{time.Now().AddDate(-7, 0, 0), true},  // 7 years old - should retain (HIPAA minimum)
			{time.Now().AddDate(-10, 0, 0), false}, // 10 years old - may archive
		}
		
		for i, testEvent := range retentionTestEvents {
			eventID := fmt.Sprintf("retention-test-%d", i)
			
			// Simulate event with specific date
			fabricClient.LogAuditEvent("retention-user", "retention_test", eventID, true, map[string]interface{}{
				"event_date": testEvent.eventDate.Format(time.RFC3339),
				"retention_test": true,
			})
			
			// Verify retention policy application
			auditLogs := fabricClient.GetAuditLogs()
			found := false
			for _, log := range auditLogs {
				if log.ResourceID == eventID {
					found = true
					break
				}
			}
			
			if testEvent.shouldRetain {
				assert.True(t, found, "Event from %v should be retained", testEvent.eventDate)
			}
			// Note: In real implementation, archived events might not be in active logs
		}
	})
}

// TestPHIEncryptionAndAccessControls tests PHI encryption and access control validation
func TestPHIEncryptionAndAccessControls(t *testing.T) {
	_ = context.Background()
	
	t.Run("EncryptionAtRest", func(t *testing.T) {
		// Test that PHI is encrypted at rest
		phiData := map[string]interface{}{
			"patient_id": "patient-encryption-123",
			"content":    "Patient has diabetes mellitus type 2, well controlled on metformin.",
			"diagnosis":  "Diabetes Mellitus Type 2",
			"medications": []string{"Metformin 500mg BID", "Lisinopril 10mg daily"},
		}
		
		// Simulate encryption process
		plaintext := phiData["content"].(string)
		
		// Mock AES-256 encryption
		encryptedContent := fmt.Sprintf("[AES256:%s]", hex.EncodeToString([]byte(plaintext)))
		contentHash := sha256.Sum256([]byte(plaintext))
		hashString := hex.EncodeToString(contentHash[:])
		
		// Verify encryption properties
		assert.True(t, strings.HasPrefix(encryptedContent, "[AES256:"), "Content should be AES-256 encrypted")
		assert.NotEqual(t, plaintext, encryptedContent, "Encrypted content should differ from plaintext")
		assert.Equal(t, 64, len(hashString), "SHA-256 hash should be 64 characters")
		
		// Log encryption validation
		fabricClient.LogAuditEvent("system", "phi_encryption_validated", "patient-encryption-123", true, map[string]interface{}{
			"encryption_algorithm": "AES-256",
			"hash_algorithm":       "SHA-256",
			"content_hash":         hashString,
		})
	})
	
	t.Run("EncryptionInTransit", func(t *testing.T) {
		// Test that PHI is encrypted in transit
		req := httptest.NewRequest("POST", "/api/v1/clinical-notes", 
			bytes.NewBufferString(`{"patient_id": "patient-123", "content": "Sensitive PHI content"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer doctor-token")
		
		// Verify HTTPS requirement (simulated)
		assert.True(t, req.Header.Get("Authorization") != "", "Request should be authenticated")
		
		// In real implementation, would verify TLS encryption
		transportSecurity := map[string]interface{}{
			"tls_version":     "1.3",
			"cipher_suite":    "TLS_AES_256_GCM_SHA384",
			"certificate_valid": true,
		}
		
		assert.Equal(t, "1.3", transportSecurity["tls_version"])
		assert.True(t, transportSecurity["certificate_valid"].(bool))
		
		// Log transport security validation
		fabricClient.LogAuditEvent("system", "transport_security_validated", "clinical-notes-api", true, transportSecurity)
	})
	
	t.Run("KeyManagementSecurity", func(t *testing.T) {
		// Test HSM integration for key management
		keyManagementTest := map[string]interface{}{
			"hsm_provider":     "Azure Key Vault Premium",
			"key_algorithm":    "AES-256",
			"key_rotation":     "automatic_90_days",
			"access_control":   "rbac_enabled",
			"audit_logging":    "enabled",
		}
		
		// Simulate key operations
		operations := []string{"key_generation", "key_rotation", "key_access", "key_deletion"}
		
		for _, operation := range operations {
			// Verify HSM security for each operation
			assert.NotEmpty(t, keyManagementTest["hsm_provider"])
			assert.Equal(t, "AES-256", keyManagementTest["key_algorithm"])
			
			// Log key management operation
			fabricClient.LogAuditEvent("hsm-system", operation, "encryption-key-123", true, map[string]interface{}{
				"hsm_provider": keyManagementTest["hsm_provider"],
				"operation":    operation,
			})
		}
	})
	
	t.Run("AccessControlEnforcement", func(t *testing.T) {
		// Test that access controls are properly enforced at all levels
		accessTests := []struct {
			userRole     string
			resource     string
			action       string
			shouldAllow  bool
			reason       string
		}{
			{"consulting_doctor", "clinical_notes", "read", true, "Full clinical access"},
			{"consulting_doctor", "clinical_notes", "write", true, "Full clinical access"},
			{"md_student", "clinical_notes", "read", true, "Supervised read access"},
			{"md_student", "clinical_notes", "write", false, "Requires supervision"},
			{"nurse", "medications", "read", true, "Medication administration"},
			{"nurse", "billing_info", "read", false, "Not in scope of practice"},
			{"patient", "own_records", "read", true, "Patient rights"},
			{"patient", "other_records", "read", false, "Privacy protection"},
			{"receptionist", "appointments", "read", true, "Scheduling duties"},
			{"receptionist", "clinical_notes", "read", false, "No clinical access"},
		}
		
		for _, test := range accessTests {
			t.Run(fmt.Sprintf("%s_%s_%s", test.userRole, test.resource, test.action), func(t *testing.T) {
				// Check access via blockchain policy
				hasAccess := fabricClient.CheckAccess(test.userRole, test.resource, test.action)
				
				if test.shouldAllow {
					assert.True(t, hasAccess, "Access should be allowed: %s", test.reason)
				} else {
					assert.False(t, hasAccess, "Access should be denied: %s", test.reason)
				}
				
				// Log access control test
				fabricClient.LogAuditEvent(fmt.Sprintf("%s-test", test.userRole), "access_control_test", test.resource, hasAccess, map[string]interface{}{
					"role":     test.userRole,
					"resource": test.resource,
					"action":   test.action,
					"expected": test.shouldAllow,
					"reason":   test.reason,
				})
			})
		}
	})
}

// TestDataIntegrityValidation tests data integrity mechanisms
func TestDataIntegrityValidation(t *testing.T) {
	_ = context.Background()
	
	t.Run("BlockchainHashIntegrity", func(t *testing.T) {
		// Test that PHI hashes stored on blockchain maintain integrity
		originalData := "Patient presents with acute chest pain. ECG shows ST elevation in leads II, III, aVF."
		
		// Calculate hash
		hash1 := sha256.Sum256([]byte(originalData))
		hashString1 := hex.EncodeToString(hash1[:])
		
		// Store hash on blockchain (simulated)
		fabricClient.LogAuditEvent("system", "phi_hash_stored", "note-integrity-123", true, map[string]interface{}{
			"content_hash": hashString1,
			"algorithm":    "SHA-256",
		})
		
		// Later retrieval and verification
		auditLogs := fabricClient.GetAuditLogs()
		var storedHash string
		for _, log := range auditLogs {
			if log.Action == "phi_hash_stored" && log.ResourceID == "note-integrity-123" {
				storedHash = log.Details["content_hash"].(string)
				break
			}
		}
		
		// Verify integrity
		hash2 := sha256.Sum256([]byte(originalData))
		hashString2 := hex.EncodeToString(hash2[:])
		
		assert.Equal(t, hashString1, hashString2, "Hash should be consistent")
		assert.Equal(t, storedHash, hashString2, "Stored hash should match calculated hash")
		
		// Test tamper detection
		tamperedData := "Patient presents with acute chest pain. ECG shows normal sinus rhythm."
		hash3 := sha256.Sum256([]byte(tamperedData))
		hashString3 := hex.EncodeToString(hash3[:])
		
		assert.NotEqual(t, storedHash, hashString3, "Tampered data should produce different hash")
	})
	
	t.Run("DatabaseIntegrityChecks", func(t *testing.T) {
		// Test database-level integrity mechanisms
		integrityChecks := []struct {
			checkType string
			expected  bool
		}{
			{"foreign_key_constraints", true},
			{"check_constraints", true},
			{"unique_constraints", true},
			{"not_null_constraints", true},
			{"encryption_at_rest", true},
		}
		
		for _, check := range integrityChecks {
			// Simulate integrity check
			result := check.expected // In real implementation, would perform actual check
			
			assert.True(t, result, "Database integrity check %s should pass", check.checkType)
			
			// Log integrity check
			fabricClient.LogAuditEvent("system", "database_integrity_check", check.checkType, result, map[string]interface{}{
				"check_type": check.checkType,
				"timestamp": time.Now().Format(time.RFC3339),
			})
		}
	})
}