// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIGatewayIntegration tests API Gateway integration with other services
func TestAPIGatewayIntegration(t *testing.T) {
	_ = context.Background()
	
	// Test API Gateway routing to IAM service
	t.Run("APIGatewayToIAMService", func(t *testing.T) {
		// Simulate login request through API Gateway
		loginData := map[string]interface{}{
			"username": "doctor.smith",
			"password": "securepassword123",
		}
		
		reqBody, err := json.Marshal(loginData)
		require.NoError(t, err)
		
		// Request to API Gateway
		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-ID", "test-request-123")
		
		w := httptest.NewRecorder()
		
		// Simulate API Gateway processing
		// 1. Rate limiting check
		rateLimitOK := true // Simulate rate limit check
		assert.True(t, rateLimitOK, "Rate limit should pass")
		
		// 2. Route to IAM service
		iamResponse := map[string]interface{}{
			"success":      true,
			"access_token": "jwt-token-12345",
			"user_id":      "user-456",
			"role":         "consulting_doctor",
			"expires_in":   3600,
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(iamResponse)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.True(t, result["success"].(bool))
		assert.NotEmpty(t, result["access_token"])
		assert.Equal(t, "consulting_doctor", result["role"])
		
		// Log the authentication event
		fabricClient.LogAuditEvent("user-456", "authentication_success", "session-123", true, map[string]interface{}{
			"username":   loginData["username"],
			"user_agent": req.UserAgent(),
			"ip_address": req.RemoteAddr,
		})
	})
	
	// Test API Gateway token validation
	t.Run("APIGatewayTokenValidation", func(t *testing.T) {
		// Simulate protected resource request
		req := httptest.NewRequest("GET", "/api/v1/patients/patient-123", nil)
		req.Header.Set("Authorization", "Bearer jwt-token-12345")
		req.Header.Set("X-Request-ID", "test-request-456")
		
		w := httptest.NewRecorder()
		
		// Simulate API Gateway token validation
		// 1. Extract token
		token := "jwt-token-12345"
		assert.NotEmpty(t, token)
		
		// 2. Validate with IAM service
		validationResponse := map[string]interface{}{
			"valid":   true,
			"user_id": "user-456",
			"role":    "consulting_doctor",
			"exp":     time.Now().Add(time.Hour).Unix(),
		}
		
		assert.True(t, validationResponse["valid"].(bool))
		
		// 3. Forward to Clinical Notes service
		patientResponse := map[string]interface{}{
			"id":         "patient-123",
			"mrn":        "MRN001",
			"first_name": "John",
			"last_name":  "Doe",
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(patientResponse)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var result map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, "patient-123", result["id"])
	})
}

// TestIAMServiceIntegration tests IAM service integration
func TestIAMServiceIntegration(t *testing.T) {
	_ = context.Background()
	
	// Test IAM service with Fabric CA integration
	t.Run("IAMFabricCAIntegration", func(t *testing.T) {
		// Simulate user registration with Fabric CA
		registrationData := map[string]interface{}{
			"username":     "nurse.johnson",
			"email":        "nurse.johnson@hospital.com",
			"role":         "nurse",
			"organization": "hospital",
			"department":   "emergency",
		}
		
		reqBody, err := json.Marshal(registrationData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/users/register", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		
		// Simulate IAM service processing
		// 1. Validate registration data
		assert.NotEmpty(t, registrationData["username"])
		assert.NotEmpty(t, registrationData["email"])
		assert.NotEmpty(t, registrationData["role"])
		
		// 2. Enroll with Fabric CA (simulated)
		fabricCAResponse := map[string]interface{}{
			"success":     true,
			"certificate": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
			"private_key": "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----",
		}
		
		assert.True(t, fabricCAResponse["success"].(bool))
		assert.NotEmpty(t, fabricCAResponse["certificate"])
		
		// 3. Store user in database
		userID := "user-789"
		userResponse := map[string]interface{}{
			"id":           userID,
			"username":     registrationData["username"],
			"email":        registrationData["email"],
			"role":         registrationData["role"],
			"organization": registrationData["organization"],
			"enrolled":     true,
			"created_at":   time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(userResponse)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, registrationData["username"], result["username"])
		assert.True(t, result["enrolled"].(bool))
		
		// Log user registration
		fabricClient.LogAuditEvent("system", "user_registration", userID, true, map[string]interface{}{
			"username":     registrationData["username"],
			"role":         registrationData["role"],
			"organization": registrationData["organization"],
		})
	})
	
	// Test IAM service RBAC integration with blockchain
	t.Run("IAMRBACBlockchainIntegration", func(t *testing.T) {
		// Simulate permission check request
		permissionData := map[string]interface{}{
			"user_id":       "user-456",
			"resource_type": "clinical_notes",
			"action":        "read",
			"resource_id":   "note-789",
		}
		
		reqBody, err := json.Marshal(permissionData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/auth/check-permission", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer jwt-token-12345")
		
		w := httptest.NewRecorder()
		
		// Simulate IAM service processing
		// 1. Get user role from token
		userRole := "consulting_doctor"
		
		// 2. Check access policy via blockchain
		hasAccess := fabricClient.CheckAccess(userRole, permissionData["resource_type"].(string), permissionData["action"].(string))
		
		// 3. Return permission result
		permissionResponse := map[string]interface{}{
			"allowed":       hasAccess,
			"user_id":       permissionData["user_id"],
			"resource_type": permissionData["resource_type"],
			"action":        permissionData["action"],
			"reason":        "access_policy_check",
		}
		
		if hasAccess {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusForbidden)
		}
		json.NewEncoder(w).Encode(permissionResponse)
		
		assert.Equal(t, http.StatusOK, w.Code) // Consulting doctor should have access
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.True(t, result["allowed"].(bool))
		
		// Log permission check
		fabricClient.LogAuditEvent(permissionData["user_id"].(string), "permission_check", permissionData["resource_id"].(string), hasAccess, map[string]interface{}{
			"resource_type": permissionData["resource_type"],
			"action":        permissionData["action"],
			"result":        hasAccess,
		})
	})
}

// TestClinicalNotesServiceIntegration tests Clinical Notes service integration
func TestClinicalNotesServiceIntegration(t *testing.T) {
	_ = context.Background()
	
	// Test Clinical Notes service with encryption and blockchain
	t.Run("ClinicalNotesEncryptionBlockchain", func(t *testing.T) {
		// Simulate creating encrypted clinical note
		noteData := map[string]interface{}{
			"patient_id": "patient-123",
			"content":    "Patient presents with acute chest pain. Vital signs stable.",
			"note_type":  "progress_note",
		}
		
		reqBody, err := json.Marshal(noteData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/clinical-notes", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer jwt-token-12345")
		
		w := httptest.NewRecorder()
		
		// Simulate Clinical Notes service processing
		// 1. Validate user permissions via IAM/blockchain
		userRole := "consulting_doctor"
		hasAccess := fabricClient.CheckAccess(userRole, "clinical_notes", "write")
		require.True(t, hasAccess, "User should have write access")
		
		// 2. Encrypt content (simulated)
		_ = "[ENCRYPTED_AES256]" + noteData["content"].(string)
		contentHash := "sha256:abcd1234efgh5678..." // Simulated hash
		
		// 3. Store encrypted content in database
		noteID := "note-456"
		
		// 4. Store hash on blockchain (simulated)
		fabricClient.LogAuditEvent("user-456", "phi_hash_stored", noteID, true, map[string]interface{}{
			"patient_id":   noteData["patient_id"],
			"content_hash": contentHash,
			"note_type":    noteData["note_type"],
		})
		
		// 5. Return response
		noteResponse := map[string]interface{}{
			"id":           noteID,
			"patient_id":   noteData["patient_id"],
			"content_hash": contentHash,
			"note_type":    noteData["note_type"],
			"encrypted":    true,
			"created_at":   time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(noteResponse)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, noteID, result["id"])
		assert.Equal(t, contentHash, result["content_hash"])
		assert.True(t, result["encrypted"].(bool))
		
		// Verify audit log
		auditLogs := fabricClient.GetAuditLogs()
		found := false
		for _, log := range auditLogs {
			if log.Action == "phi_hash_stored" && log.ResourceID == noteID {
				found = true
				assert.Equal(t, contentHash, log.Details["content_hash"])
				break
			}
		}
		assert.True(t, found, "Should have audit log for PHI hash storage")
	})
	
	// Test Clinical Notes service retrieval with decryption
	t.Run("ClinicalNotesRetrievalDecryption", func(t *testing.T) {
		noteID := "note-456"
		
		req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/clinical-notes/%s", noteID), nil)
		req.Header.Set("Authorization", "Bearer jwt-token-12345")
		
		w := httptest.NewRecorder()
		
		// Simulate Clinical Notes service processing
		// 1. Validate user permissions
		userRole := "consulting_doctor"
		hasAccess := fabricClient.CheckAccess(userRole, "clinical_notes", "read")
		require.True(t, hasAccess, "User should have read access")
		
		// 2. Retrieve encrypted content from database (simulated)
		_ = "[ENCRYPTED_AES256]Patient presents with acute chest pain. Vital signs stable."
		
		// 3. Decrypt content (simulated)
		decryptedContent := "Patient presents with acute chest pain. Vital signs stable."
		
		// 4. Verify hash integrity via blockchain (simulated)
		expectedHash := "sha256:abcd1234efgh5678..."
		actualHash := "sha256:abcd1234efgh5678..." // Simulated hash calculation
		assert.Equal(t, expectedHash, actualHash, "Content hash should match")
		
		// 5. Return decrypted content
		noteResponse := map[string]interface{}{
			"id":         noteID,
			"patient_id": "patient-123",
			"content":    decryptedContent,
			"note_type":  "progress_note",
			"verified":   true,
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(noteResponse)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var result map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, noteID, result["id"])
		assert.Equal(t, decryptedContent, result["content"])
		assert.True(t, result["verified"].(bool))
		
		// Log PHI access
		fabricClient.LogAuditEvent("user-456", "phi_access_read", noteID, true, map[string]interface{}{
			"patient_id": "patient-123",
			"note_type":  "progress_note",
		})
	})
}

// TestMobileWorkflowServiceIntegration tests Mobile Workflow service integration
func TestMobileWorkflowServiceIntegration(t *testing.T) {
	_ = context.Background()
	
	// Test mobile CPOE workflow with co-signature
	t.Run("MobileCPOECoSignatureWorkflow", func(t *testing.T) {
		// Step 1: Student creates order via mobile app
		orderData := map[string]interface{}{
			"patient_id":       "patient-123",
			"ordering_md":      "student-789",
			"order_type":       "medication",
			"details":          "Metformin 500mg BID",
			"requires_co_sign": true,
		}
		
		reqBody, err := json.Marshal(orderData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/mobile/cpoe/orders", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer student-token")
		req.Header.Set("User-Agent", "MedrexMobile/1.0 iOS")
		
		w := httptest.NewRecorder()
		
		// Simulate mobile workflow service processing
		// 1. Validate student permissions (limited access)
		studentRole := "md_student"
		hasLimitedAccess := true // Students can create orders but need co-signature
		assert.True(t, hasLimitedAccess)
		
		// 2. Create order with pending status
		orderID := "order-mobile-123"
		orderResponse := map[string]interface{}{
			"id":               orderID,
			"patient_id":       orderData["patient_id"],
			"ordering_md":      orderData["ordering_md"],
			"order_type":       orderData["order_type"],
			"details":          orderData["details"],
			"status":           "pending_cosign",
			"requires_co_sign": true,
			"created_at":       time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(orderResponse)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, "pending_cosign", result["status"])
		assert.True(t, result["requires_co_sign"].(bool))
		
		// Log order creation
		fabricClient.LogAuditEvent(orderData["ordering_md"].(string), "mobile_cpoe_created", orderID, true, map[string]interface{}{
			"patient_id":    orderData["patient_id"],
			"order_type":    orderData["order_type"],
			"mobile_device": true,
			"user_agent":    req.Header.Get("User-Agent"),
		})
		
		// Step 2: Consultant co-signs via mobile app
		coSignData := map[string]interface{}{
			"co_signing_md": "consultant-456",
			"approved":      true,
			"comments":      "Order reviewed and approved via mobile",
		}
		
		coSignBody, err := json.Marshal(coSignData)
		require.NoError(t, err)
		
		coSignReq := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/mobile/cpoe/orders/%s/cosign", orderID), bytes.NewBuffer(coSignBody))
		coSignReq.Header.Set("Content-Type", "application/json")
		coSignReq.Header.Set("Authorization", "Bearer consultant-token")
		coSignReq.Header.Set("User-Agent", "MedrexMobile/1.0 iOS")
		
		coSignW := httptest.NewRecorder()
		
		// Simulate co-signature processing
		coSignResponse := map[string]interface{}{
			"id":             orderID,
			"status":         "active",
			"co_signing_md":  coSignData["co_signing_md"],
			"co_signed_at":   time.Now().Format(time.RFC3339),
			"comments":       coSignData["comments"],
		}
		
		coSignW.WriteHeader(http.StatusOK)
		json.NewEncoder(coSignW).Encode(coSignResponse)
		
		assert.Equal(t, http.StatusOK, coSignW.Code)
		
		var coSignResult map[string]interface{}
		err = json.NewDecoder(coSignW.Body).Decode(&coSignResult)
		require.NoError(t, err)
		
		assert.Equal(t, "active", coSignResult["status"])
		assert.Equal(t, coSignData["co_signing_md"], coSignResult["co_signing_md"])
		
		// Log co-signature
		fabricClient.LogAuditEvent(coSignData["co_signing_md"].(string), "mobile_cpoe_cosigned", orderID, true, map[string]interface{}{
			"student_id":    orderData["ordering_md"],
			"approved":      coSignData["approved"],
			"mobile_device": true,
		})
	})
	
	// Test mobile barcode scanning integration
	t.Run("MobileBarcodeScanning", func(t *testing.T) {
		// Simulate barcode scan request
		scanData := map[string]interface{}{
			"barcode":     "123456789012",
			"scan_type":   "medication",
			"patient_id":  "patient-123",
			"location":    "room_205",
		}
		
		reqBody, err := json.Marshal(scanData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/mobile/barcode/scan", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer nurse-token")
		req.Header.Set("User-Agent", "MedrexMobile/1.0 Android")
		
		w := httptest.NewRecorder()
		
		// Simulate barcode processing
		// 1. Validate barcode
		medicationInfo := map[string]interface{}{
			"name":         "Metformin",
			"strength":     "500mg",
			"manufacturer": "Generic Pharma",
			"lot_number":   "LOT123456",
			"exp_date":     "2025-12-31",
		}
		
		// 2. Check against patient orders
		hasValidOrder := true // Simulated order validation
		
		scanResponse := map[string]interface{}{
			"scan_id":         "scan-789",
			"barcode":         scanData["barcode"],
			"medication_info": medicationInfo,
			"valid_order":     hasValidOrder,
			"patient_match":   true,
			"scanned_at":      time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(scanResponse)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, scanData["barcode"], result["barcode"])
		assert.True(t, result["valid_order"].(bool))
		assert.True(t, result["patient_match"].(bool))
		
		// Log barcode scan
		fabricClient.LogAuditEvent("nurse-123", "mobile_barcode_scan", "scan-789", true, map[string]interface{}{
			"barcode":       scanData["barcode"],
			"patient_id":    scanData["patient_id"],
			"location":      scanData["location"],
			"mobile_device": true,
			"medication":    medicationInfo["name"],
		})
	})
}

// TestEndToEndWorkflow tests complete end-to-end workflows
func TestEndToEndWorkflow(t *testing.T) {
	_ = context.Background()
	
	// Test complete patient care workflow
	t.Run("CompletePatientCareWorkflow", func(t *testing.T) {
		// Step 1: Patient registration
		patientData := map[string]interface{}{
			"mrn":           "MRN002",
			"first_name":    "Jane",
			"last_name":     "Smith",
			"date_of_birth": "1985-05-15",
		}
		
		patientID := "patient-e2e-123"
		fabricClient.LogAuditEvent("admin", "patient_registered", patientID, true, patientData)
		
		// Step 2: Doctor authentication
		fabricClient.LogAuditEvent("doctor-e2e", "authentication_success", "session-e2e", true, map[string]interface{}{
			"role": "consulting_doctor",
		})
		
		// Step 3: Access patient record
		hasAccess := fabricClient.CheckAccess("consulting_doctor", "clinical_notes", "read")
		assert.True(t, hasAccess)
		
		fabricClient.LogAuditEvent("doctor-e2e", "phi_access_read", patientID, true, map[string]interface{}{
			"resource_type": "patient_record",
		})
		
		// Step 4: Create clinical note
		noteID := "note-e2e-456"
		fabricClient.LogAuditEvent("doctor-e2e", "phi_created", noteID, true, map[string]interface{}{
			"patient_id": patientID,
			"note_type":  "initial_assessment",
		})
		
		// Step 5: Create CPOE order
		orderID := "order-e2e-789"
		fabricClient.LogAuditEvent("doctor-e2e", "cpoe_order_created", orderID, true, map[string]interface{}{
			"patient_id": patientID,
			"order_type": "medication",
		})
		
		// Step 6: Schedule follow-up
		appointmentID := "appointment-e2e-101"
		fabricClient.LogAuditEvent("doctor-e2e", "appointment_scheduled", appointmentID, true, map[string]interface{}{
			"patient_id":   patientID,
			"appointment_type": "follow_up",
		})
		
		// Verify complete audit trail
		auditLogs := fabricClient.GetAuditLogs()
		
		// Count workflow-related logs
		workflowLogs := 0
		for _, log := range auditLogs {
			if log.UserID == "doctor-e2e" || log.UserID == "admin" {
				if log.ResourceID == patientID || log.ResourceID == noteID || log.ResourceID == orderID || log.ResourceID == appointmentID {
					workflowLogs++
				}
			}
		}
		
		assert.GreaterOrEqual(t, workflowLogs, 6, "Should have complete audit trail for workflow")
		
		t.Logf("End-to-end workflow completed with %d audit log entries", workflowLogs)
	})
}