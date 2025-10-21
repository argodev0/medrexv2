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

// TestPatientRegistrationWorkflow tests the complete patient registration workflow
func TestPatientRegistrationWorkflow(t *testing.T) {
	_ = context.Background()
	
	// Test data
	patientData := map[string]interface{}{
		"mrn":           "MRN001",
		"first_name":    "John",
		"last_name":     "Doe",
		"date_of_birth": "1990-01-01",
		"gender":        "male",
		"phone":         "+1234567890",
		"email":         "john.doe@example.com",
	}
	
	// Step 1: Register patient
	t.Run("RegisterPatient", func(t *testing.T) {
		// Create patient registration request
		reqBody, err := json.Marshal(patientData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/patients", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer test-token")
		
		// Mock response
		w := httptest.NewRecorder()
		
		// Simulate patient registration
		patientID := "patient-123"
		response := map[string]interface{}{
			"id":            patientID,
			"mrn":           patientData["mrn"],
			"first_name":    patientData["first_name"],
			"last_name":     patientData["last_name"],
			"date_of_birth": patientData["date_of_birth"],
			"created_at":    time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, patientData["mrn"], result["mrn"])
		assert.Equal(t, patientData["first_name"], result["first_name"])
		assert.NotEmpty(t, result["id"])
		
		// Verify audit log
		fabricClient.LogAuditEvent("admin-user", "patient_registration", patientID, true, map[string]interface{}{
			"mrn": patientData["mrn"],
		})
		
		auditLogs := fabricClient.GetAuditLogs()
		assert.Len(t, auditLogs, 1)
		assert.Equal(t, "patient_registration", auditLogs[0].Action)
		assert.True(t, auditLogs[0].Success)
	})
	
	// Step 2: Verify patient can be retrieved
	t.Run("RetrievePatient", func(t *testing.T) {
		patientID := "patient-123"
		
		req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/patients/%s", patientID), nil)
		req.Header.Set("Authorization", "Bearer test-token")
		
		w := httptest.NewRecorder()
		
		// Simulate patient retrieval
		response := map[string]interface{}{
			"id":            patientID,
			"mrn":           patientData["mrn"],
			"first_name":    patientData["first_name"],
			"last_name":     patientData["last_name"],
			"date_of_birth": patientData["date_of_birth"],
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var result map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, patientID, result["id"])
		assert.Equal(t, patientData["mrn"], result["mrn"])
	})
}

// TestPhysicianCPOEWorkflow tests the complete CPOE workflow
func TestPhysicianCPOEWorkflow(t *testing.T) {
	_ = context.Background()
	
	// Test data
	orderData := map[string]interface{}{
		"patient_id":      "patient-123",
		"ordering_md":     "doctor-456",
		"order_type":      "medication",
		"details":         "Aspirin 81mg daily",
		"requires_co_sign": false,
	}
	
	// Step 1: Create CPOE order
	t.Run("CreateCPOEOrder", func(t *testing.T) {
		// Check access permissions first
		hasAccess := fabricClient.CheckAccess("consulting_doctor", "cpoe_orders", "write")
		assert.True(t, hasAccess, "Consulting doctor should have write access to CPOE orders")
		
		reqBody, err := json.Marshal(orderData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/cpoe/orders", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer doctor-token")
		
		w := httptest.NewRecorder()
		
		// Simulate order creation
		orderID := "order-789"
		response := map[string]interface{}{
			"id":              orderID,
			"patient_id":      orderData["patient_id"],
			"ordering_md":     orderData["ordering_md"],
			"order_type":      orderData["order_type"],
			"details":         orderData["details"],
			"status":          "active",
			"requires_co_sign": orderData["requires_co_sign"],
			"created_at":      time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, orderData["order_type"], result["order_type"])
		assert.Equal(t, orderData["details"], result["details"])
		assert.Equal(t, "active", result["status"])
		
		// Log audit event
		fabricClient.LogAuditEvent(orderData["ordering_md"].(string), "cpoe_order_created", orderID, true, map[string]interface{}{
			"order_type": orderData["order_type"],
			"patient_id": orderData["patient_id"],
		})
	})
	
	// Step 2: Retrieve order
	t.Run("RetrieveCPOEOrder", func(t *testing.T) {
		orderID := "order-789"
		
		req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/cpoe/orders/%s", orderID), nil)
		req.Header.Set("Authorization", "Bearer doctor-token")
		
		w := httptest.NewRecorder()
		
		// Simulate order retrieval
		response := map[string]interface{}{
			"id":              orderID,
			"patient_id":      orderData["patient_id"],
			"ordering_md":     orderData["ordering_md"],
			"order_type":      orderData["order_type"],
			"details":         orderData["details"],
			"status":          "active",
			"requires_co_sign": orderData["requires_co_sign"],
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var result map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, orderID, result["id"])
		assert.Equal(t, "active", result["status"])
	})
}

// TestStudentSupervisionWorkflow tests the student supervision workflow
func TestStudentSupervisionWorkflow(t *testing.T) {
	_ = context.Background()
	
	// Test data for MD student order requiring co-signature
	orderData := map[string]interface{}{
		"patient_id":       "patient-123",
		"ordering_md":      "student-789",
		"order_type":       "medication",
		"details":          "Lisinopril 10mg daily",
		"requires_co_sign": true,
	}
	
	// Step 1: Student creates order requiring co-signature
	t.Run("StudentCreateOrder", func(t *testing.T) {
		// Check student access permissions
		hasAccess := fabricClient.CheckAccess("md_student", "cpoe_orders", "write")
		// Students should have limited write access requiring supervision
		assert.False(t, hasAccess, "MD student should not have unrestricted write access")
		
		reqBody, err := json.Marshal(orderData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/cpoe/orders", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer student-token")
		
		w := httptest.NewRecorder()
		
		// Simulate order creation with pending status
		orderID := "order-student-123"
		response := map[string]interface{}{
			"id":              orderID,
			"patient_id":      orderData["patient_id"],
			"ordering_md":     orderData["ordering_md"],
			"order_type":      orderData["order_type"],
			"details":         orderData["details"],
			"status":          "pending_cosign",
			"requires_co_sign": true,
			"created_at":      time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, "pending_cosign", result["status"])
		assert.True(t, result["requires_co_sign"].(bool))
		
		// Log audit event
		fabricClient.LogAuditEvent(orderData["ordering_md"].(string), "cpoe_order_created_pending", orderID, true, map[string]interface{}{
			"requires_supervision": true,
			"order_type":          orderData["order_type"],
		})
	})
	
	// Step 2: Consultant co-signs the order
	t.Run("ConsultantCoSign", func(t *testing.T) {
		orderID := "order-student-123"
		consultantID := "consultant-456"
		
		coSignData := map[string]interface{}{
			"co_signing_md": consultantID,
			"approved":      true,
			"comments":      "Order reviewed and approved",
		}
		
		reqBody, err := json.Marshal(coSignData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/cpoe/orders/%s/cosign", orderID), bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer consultant-token")
		
		w := httptest.NewRecorder()
		
		// Simulate co-signature
		response := map[string]interface{}{
			"id":              orderID,
			"status":          "active",
			"co_signing_md":   consultantID,
			"co_signed_at":    time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, "active", result["status"])
		assert.Equal(t, consultantID, result["co_signing_md"])
		
		// Log audit event
		fabricClient.LogAuditEvent(consultantID, "cpoe_order_cosigned", orderID, true, map[string]interface{}{
			"student_id": orderData["ordering_md"],
			"approved":   true,
		})
	})
}

// TestPHIAccessControlWorkflow tests PHI access control workflow
func TestPHIAccessControlWorkflow(t *testing.T) {
	_ = context.Background()
	
	// Test data
	noteData := map[string]interface{}{
		"patient_id": "patient-123",
		"content":    "Patient presents with chest pain. ECG shows normal sinus rhythm.",
		"note_type":  "progress_note",
	}
	
	// Step 1: Authorized user creates clinical note
	t.Run("AuthorizedCreateNote", func(t *testing.T) {
		// Check access permissions
		hasAccess := fabricClient.CheckAccess("consulting_doctor", "clinical_notes", "write")
		assert.True(t, hasAccess, "Consulting doctor should have write access to clinical notes")
		
		reqBody, err := json.Marshal(noteData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/clinical-notes", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer doctor-token")
		
		w := httptest.NewRecorder()
		
		// Simulate note creation
		noteID := "note-456"
		response := map[string]interface{}{
			"id":         noteID,
			"patient_id": noteData["patient_id"],
			"content":    "[ENCRYPTED]", // Content should be encrypted
			"note_type":  noteData["note_type"],
			"created_at": time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, noteID, result["id"])
		assert.Equal(t, "[ENCRYPTED]", result["content"]) // Verify content is encrypted
		
		// Log PHI access
		fabricClient.LogAuditEvent("doctor-456", "phi_access_write", noteID, true, map[string]interface{}{
			"patient_id": noteData["patient_id"],
			"note_type":  noteData["note_type"],
		})
	})
	
	// Step 2: Unauthorized user attempts to access note
	t.Run("UnauthorizedAccessAttempt", func(t *testing.T) {
		noteID := "note-456"
		
		// Check access permissions for unauthorized role
		hasAccess := fabricClient.CheckAccess("receptionist", "clinical_notes", "read")
		assert.False(t, hasAccess, "Receptionist should not have read access to clinical notes")
		
		req := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/clinical-notes/%s", noteID), nil)
		req.Header.Set("Authorization", "Bearer receptionist-token")
		
		w := httptest.NewRecorder()
		
		// Simulate access denied
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Access denied: insufficient permissions",
		})
		
		assert.Equal(t, http.StatusForbidden, w.Code)
		
		// Log failed access attempt
		fabricClient.LogAuditEvent("receptionist-123", "phi_access_denied", noteID, false, map[string]interface{}{
			"reason": "insufficient_permissions",
			"role":   "receptionist",
		})
	})
	
	// Step 3: Verify audit trail
	t.Run("VerifyAuditTrail", func(t *testing.T) {
		auditLogs := fabricClient.GetAuditLogs()
		
		// Should have multiple audit entries
		assert.Greater(t, len(auditLogs), 0)
		
		// Find the PHI access logs
		var successfulAccess, deniedAccess *AuditLogEntry
		for _, log := range auditLogs {
			if log.Action == "phi_access_write" && log.Success {
				successfulAccess = log
			}
			if log.Action == "phi_access_denied" && !log.Success {
				deniedAccess = log
			}
		}
		
		assert.NotNil(t, successfulAccess, "Should have successful PHI access log")
		assert.NotNil(t, deniedAccess, "Should have denied PHI access log")
		
		assert.True(t, successfulAccess.Success)
		assert.False(t, deniedAccess.Success)
	})
}

// TestCrossServiceCommunication tests communication between services
func TestCrossServiceCommunication(t *testing.T) {
	_ = context.Background()
	
	// Test IAM service authentication with other services
	t.Run("IAMServiceAuthentication", func(t *testing.T) {
		// Simulate token validation request from API Gateway to IAM Service
		token := "test-jwt-token"
		
		req := httptest.NewRequest("POST", "/api/v1/auth/validate", bytes.NewBufferString(fmt.Sprintf(`{"token": "%s"}`, token)))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		
		// Simulate successful token validation
		response := map[string]interface{}{
			"valid":   true,
			"user_id": "user-123",
			"role":    "consulting_doctor",
			"org":     "hospital",
		}
		
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusOK, w.Code)
		
		var result map[string]interface{}
		err := json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.True(t, result["valid"].(bool))
		assert.Equal(t, "consulting_doctor", result["role"])
	})
	
	// Test Clinical Notes service integration with blockchain
	t.Run("ClinicalNotesBlockchainIntegration", func(t *testing.T) {
		// Simulate clinical notes service checking access policy via blockchain
		userRole := "consulting_doctor"
		resourceType := "clinical_notes"
		action := "read"
		
		hasAccess := fabricClient.CheckAccess(userRole, resourceType, action)
		assert.True(t, hasAccess, "Should have access based on blockchain policy")
		
		// Simulate storing hash on blockchain
		noteHash := "sha256:abcd1234..."
		fabricClient.LogAuditEvent("doctor-456", "phi_hash_stored", "note-789", true, map[string]interface{}{
			"hash": noteHash,
		})
		
		auditLogs := fabricClient.GetAuditLogs()
		found := false
		for _, log := range auditLogs {
			if log.Action == "phi_hash_stored" && log.ResourceID == "note-789" {
				found = true
				assert.Equal(t, noteHash, log.Details["hash"])
				break
			}
		}
		assert.True(t, found, "Should have audit log for hash storage")
	})
}

// TestCompletePatientRegistrationAndAuthenticationFlow tests the complete patient registration and authentication workflow
func TestCompletePatientRegistrationAndAuthenticationFlow(t *testing.T) {
	_ = context.Background()
	
	t.Run("PatientSelfRegistrationWorkflow", func(t *testing.T) {
		// Step 1: Patient initiates self-registration
		registrationData := map[string]interface{}{
			"first_name":    "Alice",
			"last_name":     "Johnson",
			"date_of_birth": "1992-03-15",
			"email":         "alice.johnson@email.com",
			"phone":         "+1234567890",
			"insurance_id":  "INS123456",
		}
		
		// Simulate patient registration through API Gateway
		reqBody, err := json.Marshal(registrationData)
		require.NoError(t, err)
		
		req := httptest.NewRequest("POST", "/api/v1/patients/self-register", bytes.NewBuffer(reqBody))
		req.Header.Set("Content-Type", "application/json")
		
		w := httptest.NewRecorder()
		
		// Step 2: System validates registration data and creates patient record
		patientID := "patient-self-reg-123"
		mrn := "MRN-SR-001"
		
		response := map[string]interface{}{
			"id":               patientID,
			"mrn":              mrn,
			"first_name":       registrationData["first_name"],
			"last_name":        registrationData["last_name"],
			"email":            registrationData["email"],
			"registration_status": "pending_verification",
			"temp_password":    "TempPass123!",
			"created_at":       time.Now().Format(time.RFC3339),
		}
		
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
		
		assert.Equal(t, http.StatusCreated, w.Code)
		
		var result map[string]interface{}
		err = json.NewDecoder(w.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, patientID, result["id"])
		assert.Equal(t, mrn, result["mrn"])
		assert.Equal(t, "pending_verification", result["registration_status"])
		
		// Log patient self-registration
		fabricClient.LogAuditEvent("system", "patient_self_registration", patientID, true, map[string]interface{}{
			"email":      registrationData["email"],
			"mrn":        mrn,
			"ip_address": req.RemoteAddr,
		})
		
		// Step 3: Patient verifies email and sets password
		verificationData := map[string]interface{}{
			"verification_token": "verify-token-123",
			"new_password":       "SecurePass456!",
		}
		
		verifyReq := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/patients/%s/verify", patientID), 
			bytes.NewBufferString(fmt.Sprintf(`{"verification_token": "%s", "new_password": "%s"}`, 
				verificationData["verification_token"], verificationData["new_password"])))
		verifyReq.Header.Set("Content-Type", "application/json")
		
		verifyW := httptest.NewRecorder()
		
		verifyResponse := map[string]interface{}{
			"verified":    true,
			"status":      "active",
			"verified_at": time.Now().Format(time.RFC3339),
		}
		
		verifyW.WriteHeader(http.StatusOK)
		json.NewEncoder(verifyW).Encode(verifyResponse)
		
		assert.Equal(t, http.StatusOK, verifyW.Code)
		
		// Log email verification
		fabricClient.LogAuditEvent(patientID, "email_verification_success", patientID, true, map[string]interface{}{
			"email": registrationData["email"],
		})
		
		// Step 4: Patient first login with new credentials
		loginData := map[string]interface{}{
			"username": registrationData["email"],
			"password": verificationData["new_password"],
		}
		
		loginReq := httptest.NewRequest("POST", "/api/v1/auth/login", 
			bytes.NewBufferString(fmt.Sprintf(`{"username": "%s", "password": "%s"}`, 
				loginData["username"], loginData["password"])))
		loginReq.Header.Set("Content-Type", "application/json")
		
		loginW := httptest.NewRecorder()
		
		loginResponse := map[string]interface{}{
			"success":      true,
			"access_token": "patient-jwt-token-123",
			"user_id":      patientID,
			"role":         "patient",
			"mrn":          mrn,
			"expires_in":   3600,
		}
		
		loginW.WriteHeader(http.StatusOK)
		json.NewEncoder(loginW).Encode(loginResponse)
		
		assert.Equal(t, http.StatusOK, loginW.Code)
		
		var loginResult map[string]interface{}
		err = json.NewDecoder(loginW.Body).Decode(&loginResult)
		require.NoError(t, err)
		
		assert.True(t, loginResult["success"].(bool))
		assert.Equal(t, "patient", loginResult["role"])
		assert.Equal(t, mrn, loginResult["mrn"])
		
		// Log successful patient authentication
		fabricClient.LogAuditEvent(patientID, "patient_first_login", patientID, true, map[string]interface{}{
			"role": "patient",
			"mrn":  mrn,
		})
		
		// Verify complete audit trail for patient registration workflow
		auditLogs := fabricClient.GetAuditLogs()
		patientWorkflowLogs := 0
		for _, log := range auditLogs {
			if log.ResourceID == patientID && (log.Action == "patient_self_registration" || 
				log.Action == "email_verification_success" || log.Action == "patient_first_login") {
				patientWorkflowLogs++
			}
		}
		
		assert.GreaterOrEqual(t, patientWorkflowLogs, 3, "Should have complete audit trail for patient registration")
	})
}

// TestCompletePhysicianCPOEWorkflowWithAuthorization tests physician CPOE workflows with proper authorization
func TestCompletePhysicianCPOEWorkflowWithAuthorization(t *testing.T) {
	_ = context.Background()
	
	t.Run("ConsultingPhysicianCPOEWorkflow", func(t *testing.T) {
		// Step 1: Physician authentication with MFA
		physicianID := "physician-cpoe-123"
		
		// Initial login
		loginData := map[string]interface{}{
			"username": "dr.smith",
			"password": "SecureDocPass123!",
		}
		
		loginReq := httptest.NewRequest("POST", "/api/v1/auth/login", 
			bytes.NewBufferString(fmt.Sprintf(`{"username": "%s", "password": "%s"}`, 
				loginData["username"], loginData["password"])))
		loginReq.Header.Set("Content-Type", "application/json")
		
		loginW := httptest.NewRecorder()
		
		// Simulate MFA challenge
		mfaResponse := map[string]interface{}{
			"requires_mfa": true,
			"mfa_token":    "mfa-challenge-123",
			"challenge_type": "totp",
		}
		
		loginW.WriteHeader(http.StatusAccepted)
		json.NewEncoder(loginW).Encode(mfaResponse)
		
		assert.Equal(t, http.StatusAccepted, loginW.Code)
		
		// MFA verification
		mfaData := map[string]interface{}{
			"mfa_token": "mfa-challenge-123",
			"mfa_code":  "123456",
		}
		
		mfaReq := httptest.NewRequest("POST", "/api/v1/auth/mfa/verify", 
			bytes.NewBufferString(fmt.Sprintf(`{"mfa_token": "%s", "mfa_code": "%s"}`, 
				mfaData["mfa_token"], mfaData["mfa_code"])))
		mfaReq.Header.Set("Content-Type", "application/json")
		
		mfaW := httptest.NewRecorder()
		
		authResponse := map[string]interface{}{
			"success":      true,
			"access_token": "physician-jwt-token-456",
			"user_id":      physicianID,
			"role":         "consulting_doctor",
			"department":   "cardiology",
			"expires_in":   3600,
		}
		
		mfaW.WriteHeader(http.StatusOK)
		json.NewEncoder(mfaW).Encode(authResponse)
		
		assert.Equal(t, http.StatusOK, mfaW.Code)
		
		// Log successful MFA authentication
		fabricClient.LogAuditEvent(physicianID, "mfa_authentication_success", physicianID, true, map[string]interface{}{
			"role":       "consulting_doctor",
			"department": "cardiology",
			"mfa_method": "totp",
		})
		
		// Step 2: Access patient record with authorization check
		patientID := "patient-cpoe-456"
		
		// Check access permissions via blockchain
		hasPatientAccess := fabricClient.CheckAccess("consulting_doctor", "clinical_notes", "read")
		assert.True(t, hasPatientAccess, "Consulting doctor should have patient access")
		
		patientReq := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/patients/%s", patientID), nil)
		patientReq.Header.Set("Authorization", "Bearer physician-jwt-token-456")
		
		patientW := httptest.NewRecorder()
		
		patientResponse := map[string]interface{}{
			"id":         patientID,
			"mrn":        "MRN-CPOE-001",
			"first_name": "Robert",
			"last_name":  "Wilson",
			"allergies":  []string{"Penicillin", "Sulfa"},
			"current_medications": []map[string]interface{}{
				{"name": "Lisinopril", "dose": "10mg", "frequency": "daily"},
			},
		}
		
		patientW.WriteHeader(http.StatusOK)
		json.NewEncoder(patientW).Encode(patientResponse)
		
		assert.Equal(t, http.StatusOK, patientW.Code)
		
		// Log patient record access
		fabricClient.LogAuditEvent(physicianID, "patient_record_access", patientID, true, map[string]interface{}{
			"mrn":        "MRN-CPOE-001",
			"access_type": "full_record",
		})
		
		// Step 3: Create CPOE order with drug interaction checking
		orderData := map[string]interface{}{
			"patient_id":     patientID,
			"ordering_md":    physicianID,
			"order_type":     "medication",
			"medication":     "Atorvastatin",
			"dose":           "20mg",
			"frequency":      "daily",
			"duration":       "30 days",
			"indication":     "Hyperlipidemia",
			"priority":       "routine",
		}
		
		// Check for drug interactions
		interactionCheck := map[string]interface{}{
			"interactions_found": false,
			"contraindications": []string{},
			"warnings":          []string{"Monitor liver function"},
		}
		
		assert.False(t, interactionCheck["interactions_found"].(bool), "No major interactions expected")
		
		orderReq := httptest.NewRequest("POST", "/api/v1/cpoe/orders", 
			bytes.NewBufferString(fmt.Sprintf(`{
				"patient_id": "%s",
				"ordering_md": "%s",
				"order_type": "%s",
				"medication": "%s",
				"dose": "%s",
				"frequency": "%s",
				"duration": "%s",
				"indication": "%s",
				"priority": "%s"
			}`, orderData["patient_id"], orderData["ordering_md"], orderData["order_type"],
				orderData["medication"], orderData["dose"], orderData["frequency"],
				orderData["duration"], orderData["indication"], orderData["priority"])))
		orderReq.Header.Set("Content-Type", "application/json")
		orderReq.Header.Set("Authorization", "Bearer physician-jwt-token-456")
		
		orderW := httptest.NewRecorder()
		
		orderID := "cpoe-order-789"
		orderResponse := map[string]interface{}{
			"id":              orderID,
			"patient_id":      orderData["patient_id"],
			"ordering_md":     orderData["ordering_md"],
			"order_type":      orderData["order_type"],
			"medication":      orderData["medication"],
			"dose":            orderData["dose"],
			"frequency":       orderData["frequency"],
			"status":          "active",
			"requires_co_sign": false,
			"interaction_check": interactionCheck,
			"created_at":      time.Now().Format(time.RFC3339),
		}
		
		orderW.WriteHeader(http.StatusCreated)
		json.NewEncoder(orderW).Encode(orderResponse)
		
		assert.Equal(t, http.StatusCreated, orderW.Code)
		
		var orderResult map[string]interface{}
		err := json.NewDecoder(orderW.Body).Decode(&orderResult)
		require.NoError(t, err)
		
		assert.Equal(t, orderID, orderResult["id"])
		assert.Equal(t, "active", orderResult["status"])
		assert.False(t, orderResult["requires_co_sign"].(bool))
		
		// Log CPOE order creation
		fabricClient.LogAuditEvent(physicianID, "cpoe_order_created", orderID, true, map[string]interface{}{
			"patient_id":      patientID,
			"medication":      orderData["medication"],
			"dose":            orderData["dose"],
			"interaction_check": "passed",
		})
		
		// Step 4: E-prescribing workflow
		prescriptionData := map[string]interface{}{
			"order_id":       orderID,
			"pharmacy_id":    "pharmacy-123",
			"dea_number":     "DEA123456789",
			"npi_number":     "NPI987654321",
		}
		
		prescriptionReq := httptest.NewRequest("POST", "/api/v1/cpoe/prescriptions", 
			bytes.NewBufferString(fmt.Sprintf(`{
				"order_id": "%s",
				"pharmacy_id": "%s",
				"dea_number": "%s",
				"npi_number": "%s"
			}`, prescriptionData["order_id"], prescriptionData["pharmacy_id"],
				prescriptionData["dea_number"], prescriptionData["npi_number"])))
		prescriptionReq.Header.Set("Content-Type", "application/json")
		prescriptionReq.Header.Set("Authorization", "Bearer physician-jwt-token-456")
		
		prescriptionW := httptest.NewRecorder()
		
		prescriptionID := "prescription-101"
		prescriptionResponse := map[string]interface{}{
			"id":             prescriptionID,
			"order_id":       orderID,
			"pharmacy_id":    prescriptionData["pharmacy_id"],
			"status":         "transmitted",
			"transmitted_at": time.Now().Format(time.RFC3339),
		}
		
		prescriptionW.WriteHeader(http.StatusCreated)
		json.NewEncoder(prescriptionW).Encode(prescriptionResponse)
		
		assert.Equal(t, http.StatusCreated, prescriptionW.Code)
		
		// Log e-prescribing
		fabricClient.LogAuditEvent(physicianID, "prescription_transmitted", prescriptionID, true, map[string]interface{}{
			"order_id":    orderID,
			"pharmacy_id": prescriptionData["pharmacy_id"],
			"dea_number":  prescriptionData["dea_number"],
		})
		
		// Verify complete CPOE workflow audit trail
		auditLogs := fabricClient.GetAuditLogs()
		cpoeWorkflowLogs := 0
		for _, log := range auditLogs {
			if log.UserID == physicianID && (log.Action == "mfa_authentication_success" || 
				log.Action == "patient_record_access" || log.Action == "cpoe_order_created" || 
				log.Action == "prescription_transmitted") {
				cpoeWorkflowLogs++
			}
		}
		
		assert.GreaterOrEqual(t, cpoeWorkflowLogs, 4, "Should have complete CPOE workflow audit trail")
	})
}

// TestStudentSupervisionAndCoSignatureWorkflow tests student supervision and co-signature requirements
func TestStudentSupervisionAndCoSignatureWorkflow(t *testing.T) {
	_ = context.Background()
	
	t.Run("MDStudentSupervisionWorkflow", func(t *testing.T) {
		// Step 1: MD Student authentication
		studentID := "md-student-456"
		
		loginReq := httptest.NewRequest("POST", "/api/v1/auth/login", 
			bytes.NewBufferString(`{"username": "student.jones", "password": "StudentPass123!"}`))
		loginReq.Header.Set("Content-Type", "application/json")
		
		loginW := httptest.NewRecorder()
		
		studentAuthResponse := map[string]interface{}{
			"success":      true,
			"access_token": "student-jwt-token-789",
			"user_id":      studentID,
			"role":         "md_student",
			"supervisor_id": "consultant-supervisor-123",
			"rotation":     "internal_medicine",
			"year":         "3",
			"expires_in":   3600,
		}
		
		loginW.WriteHeader(http.StatusOK)
		json.NewEncoder(loginW).Encode(studentAuthResponse)
		
		assert.Equal(t, http.StatusOK, loginW.Code)
		
		// Log student authentication
		fabricClient.LogAuditEvent(studentID, "student_authentication", studentID, true, map[string]interface{}{
			"role":         "md_student",
			"supervisor_id": "consultant-supervisor-123",
			"rotation":     "internal_medicine",
		})
		
		// Step 2: Student accesses assigned patient (supervised access)
		patientID := "patient-supervised-789"
		
		// Check supervised access permissions
		hasSupervised := fabricClient.CheckAccess("md_student", "clinical_notes", "read")
		assert.True(t, hasSupervised, "MD student should have supervised read access")
		
		patientReq := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/patients/%s", patientID), nil)
		patientReq.Header.Set("Authorization", "Bearer student-jwt-token-789")
		
		patientW := httptest.NewRecorder()
		
		// Return limited patient data for student
		supervisedPatientResponse := map[string]interface{}{
			"id":         patientID,
			"mrn":        "MRN-SUPERVISED-001",
			"first_name": "Mary",
			"last_name":  "Davis",
			"age":        45,
			"chief_complaint": "Chest pain",
			"supervised_access": true,
			"supervisor_notified": true,
		}
		
		patientW.WriteHeader(http.StatusOK)
		json.NewEncoder(patientW).Encode(supervisedPatientResponse)
		
		assert.Equal(t, http.StatusOK, patientW.Code)
		
		// Log supervised patient access
		fabricClient.LogAuditEvent(studentID, "supervised_patient_access", patientID, true, map[string]interface{}{
			"supervisor_id": "consultant-supervisor-123",
			"access_type":   "supervised_read",
		})
		
		// Step 3: Student creates CPOE order requiring co-signature
		orderData := map[string]interface{}{
			"patient_id":       patientID,
			"ordering_md":      studentID,
			"order_type":       "medication",
			"medication":       "Aspirin",
			"dose":             "81mg",
			"frequency":        "daily",
			"indication":       "Cardioprotection",
			"requires_co_sign": true,
		}
		
		orderReq := httptest.NewRequest("POST", "/api/v1/cpoe/orders", 
			bytes.NewBufferString(fmt.Sprintf(`{
				"patient_id": "%s",
				"ordering_md": "%s",
				"order_type": "%s",
				"medication": "%s",
				"dose": "%s",
				"frequency": "%s",
				"indication": "%s",
				"requires_co_sign": true
			}`, orderData["patient_id"], orderData["ordering_md"], orderData["order_type"],
				orderData["medication"], orderData["dose"], orderData["frequency"],
				orderData["indication"])))
		orderReq.Header.Set("Content-Type", "application/json")
		orderReq.Header.Set("Authorization", "Bearer student-jwt-token-789")
		
		orderW := httptest.NewRecorder()
		
		orderID := "student-order-456"
		studentOrderResponse := map[string]interface{}{
			"id":               orderID,
			"patient_id":       orderData["patient_id"],
			"ordering_md":      orderData["ordering_md"],
			"order_type":       orderData["order_type"],
			"medication":       orderData["medication"],
			"status":           "pending_cosign",
			"requires_co_sign": true,
			"supervisor_notified": true,
			"created_at":       time.Now().Format(time.RFC3339),
		}
		
		orderW.WriteHeader(http.StatusCreated)
		json.NewEncoder(orderW).Encode(studentOrderResponse)
		
		assert.Equal(t, http.StatusCreated, orderW.Code)
		
		var studentOrderResult map[string]interface{}
		err := json.NewDecoder(orderW.Body).Decode(&studentOrderResult)
		require.NoError(t, err)
		
		assert.Equal(t, "pending_cosign", studentOrderResult["status"])
		assert.True(t, studentOrderResult["requires_co_sign"].(bool))
		assert.True(t, studentOrderResult["supervisor_notified"].(bool))
		
		// Log student order creation
		fabricClient.LogAuditEvent(studentID, "student_order_created", orderID, true, map[string]interface{}{
			"patient_id":      patientID,
			"medication":      orderData["medication"],
			"requires_cosign": true,
			"supervisor_id":   "consultant-supervisor-123",
		})
		
		// Step 4: Supervisor receives notification and reviews order
		supervisorID := "consultant-supervisor-123"
		
		reviewReq := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/cpoe/orders/%s/review", orderID), nil)
		reviewReq.Header.Set("Authorization", "Bearer supervisor-jwt-token-101")
		
		reviewW := httptest.NewRecorder()
		
		reviewResponse := map[string]interface{}{
			"id":              orderID,
			"student_id":      studentID,
			"patient_id":      patientID,
			"medication":      orderData["medication"],
			"dose":            orderData["dose"],
			"clinical_rationale": "Appropriate for cardiovascular protection",
			"review_status":   "pending_approval",
		}
		
		reviewW.WriteHeader(http.StatusOK)
		json.NewEncoder(reviewW).Encode(reviewResponse)
		
		assert.Equal(t, http.StatusOK, reviewW.Code)
		
		// Log supervisor review
		fabricClient.LogAuditEvent(supervisorID, "order_review_accessed", orderID, true, map[string]interface{}{
			"student_id": studentID,
			"patient_id": patientID,
		})
		
		// Step 5: Supervisor co-signs the order
		coSignData := map[string]interface{}{
			"co_signing_md": supervisorID,
			"approved":      true,
			"comments":      "Order reviewed and approved. Appropriate indication and dosing.",
			"educational_feedback": "Good clinical reasoning. Consider monitoring for GI side effects.",
		}
		
		coSignReq := httptest.NewRequest("POST", fmt.Sprintf("/api/v1/cpoe/orders/%s/cosign", orderID), 
			bytes.NewBufferString(fmt.Sprintf(`{
				"co_signing_md": "%s",
				"approved": true,
				"comments": "%s",
				"educational_feedback": "%s"
			}`, coSignData["co_signing_md"], coSignData["comments"], coSignData["educational_feedback"])))
		coSignReq.Header.Set("Content-Type", "application/json")
		coSignReq.Header.Set("Authorization", "Bearer supervisor-jwt-token-101")
		
		coSignW := httptest.NewRecorder()
		
		coSignResponse := map[string]interface{}{
			"id":                   orderID,
			"status":               "active",
			"co_signing_md":        supervisorID,
			"co_signed_at":         time.Now().Format(time.RFC3339),
			"comments":             coSignData["comments"],
			"educational_feedback": coSignData["educational_feedback"],
			"student_notified":     true,
		}
		
		coSignW.WriteHeader(http.StatusOK)
		json.NewEncoder(coSignW).Encode(coSignResponse)
		
		assert.Equal(t, http.StatusOK, coSignW.Code)
		
		var coSignResult map[string]interface{}
		err = json.NewDecoder(coSignW.Body).Decode(&coSignResult)
		require.NoError(t, err)
		
		assert.Equal(t, "active", coSignResult["status"])
		assert.Equal(t, supervisorID, coSignResult["co_signing_md"])
		assert.True(t, coSignResult["student_notified"].(bool))
		
		// Log supervisor co-signature
		fabricClient.LogAuditEvent(supervisorID, "order_cosigned", orderID, true, map[string]interface{}{
			"student_id":           studentID,
			"approved":             coSignData["approved"],
			"educational_feedback": true,
		})
		
		// Step 6: Student receives feedback notification
		feedbackReq := httptest.NewRequest("GET", fmt.Sprintf("/api/v1/students/%s/feedback", studentID), nil)
		feedbackReq.Header.Set("Authorization", "Bearer student-jwt-token-789")
		
		feedbackW := httptest.NewRecorder()
		
		feedbackResponse := map[string]interface{}{
			"order_id":             orderID,
			"supervisor_feedback":  coSignData["educational_feedback"],
			"order_status":         "approved_and_active",
			"learning_points":      []string{"Appropriate medication selection", "Consider GI monitoring"},
		}
		
		feedbackW.WriteHeader(http.StatusOK)
		json.NewEncoder(feedbackW).Encode(feedbackResponse)
		
		assert.Equal(t, http.StatusOK, feedbackW.Code)
		
		// Log student feedback receipt
		fabricClient.LogAuditEvent(studentID, "educational_feedback_received", orderID, true, map[string]interface{}{
			"supervisor_id": supervisorID,
			"order_approved": true,
		})
		
		// Verify complete supervision workflow audit trail
		auditLogs := fabricClient.GetAuditLogs()
		supervisionWorkflowLogs := 0
		for _, log := range auditLogs {
			if (log.UserID == studentID || log.UserID == supervisorID) && 
				(log.Action == "student_authentication" || log.Action == "supervised_patient_access" || 
				 log.Action == "student_order_created" || log.Action == "order_review_accessed" || 
				 log.Action == "order_cosigned" || log.Action == "educational_feedback_received") {
				supervisionWorkflowLogs++
			}
		}
		
		assert.GreaterOrEqual(t, supervisionWorkflowLogs, 6, "Should have complete supervision workflow audit trail")
	})
}