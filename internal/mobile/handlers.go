package mobile

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/types"
)

// Handlers provides HTTP handlers for mobile workflow operations
type Handlers struct {
	service interfaces.MobileWorkflowService
}

// NewHandlers creates new mobile workflow handlers
func NewHandlers(service interfaces.MobileWorkflowService) *Handlers {
	return &Handlers{
		service: service,
	}
}

// RegisterRoutes registers all mobile workflow routes
func (h *Handlers) RegisterRoutes(router *mux.Router) {
	// CPOE routes
	router.HandleFunc("/cpoe/orders", h.CreateOrder).Methods("POST")
	router.HandleFunc("/cpoe/orders/{id}", h.GetOrder).Methods("GET")
	router.HandleFunc("/cpoe/orders/{id}", h.UpdateOrder).Methods("PUT")
	router.HandleFunc("/cpoe/orders/{id}/cancel", h.CancelOrder).Methods("POST")
	
	// Co-signature routes
	router.HandleFunc("/cpoe/orders/{id}/request-cosign", h.RequestCoSignature).Methods("POST")
	router.HandleFunc("/cpoe/orders/{id}/approve", h.ApproveOrder).Methods("POST")
	router.HandleFunc("/cpoe/orders/{id}/reject", h.RejectOrder).Methods("POST")
	router.HandleFunc("/cpoe/pending-cosignatures", h.GetPendingCoSignatures).Methods("GET")
	
	// Barcode scanning routes
	router.HandleFunc("/scan/barcode", h.ScanBarcode).Methods("POST")
	router.HandleFunc("/scan/validate", h.ValidateScan).Methods("POST")
	router.HandleFunc("/scan/process", h.ProcessScanResult).Methods("POST")
	
	// Medication administration routes
	router.HandleFunc("/medication/admin", h.RecordMedicationAdmin).Methods("POST")
	router.HandleFunc("/medication/schedule/{patientId}", h.GetMedicationSchedule).Methods("GET")
	router.HandleFunc("/medication/verify", h.VerifyMedication).Methods("POST")
	
	// Lab results routes
	router.HandleFunc("/lab/results", h.EnterLabResult).Methods("POST")
	router.HandleFunc("/lab/results/{patientId}", h.GetLabResults).Methods("GET")
	router.HandleFunc("/lab/results/{id}/verify", h.VerifyLabResult).Methods("POST")
	
	// Offline sync routes
	router.HandleFunc("/sync/data", h.SyncOfflineData).Methods("POST")
	router.HandleFunc("/sync/data", h.GetOfflineData).Methods("GET")
	router.HandleFunc("/sync/status", h.MarkDataSynced).Methods("POST")
	
	// Mobile config routes
	router.HandleFunc("/config", h.GetMobileConfig).Methods("GET")
	router.HandleFunc("/preferences", h.UpdateMobilePreferences).Methods("PUT")
}

// CPOE Handlers

// CreateOrder handles CPOE order creation
func (h *Handlers) CreateOrder(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var order types.CPOEOrder
	if err := json.NewDecoder(r.Body).Decode(&order); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	createdOrder, err := h.service.CreateOrder(&order, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(createdOrder)
}

// GetOrder handles CPOE order retrieval
func (h *Handlers) GetOrder(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	orderID := vars["id"]

	order, err := h.service.GetOrder(orderID, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

// UpdateOrder handles CPOE order updates
func (h *Handlers) UpdateOrder(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	orderID := vars["id"]

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.UpdateOrder(orderID, updates, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// CancelOrder handles CPOE order cancellation
func (h *Handlers) CancelOrder(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	orderID := vars["id"]

	if err := h.service.CancelOrder(orderID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Co-signature Handlers

// RequestCoSignature handles co-signature requests
func (h *Handlers) RequestCoSignature(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	orderID := vars["id"]

	var request struct {
		ConsultantID string `json:"consultant_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.RequestCoSignature(orderID, request.ConsultantID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ApproveOrder handles order approval
func (h *Handlers) ApproveOrder(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	orderID := vars["id"]

	if err := h.service.ApproveOrder(orderID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// RejectOrder handles order rejection
func (h *Handlers) RejectOrder(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	orderID := vars["id"]

	var request struct {
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.RejectOrder(orderID, userID, request.Reason); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetPendingCoSignatures handles retrieval of pending co-signatures
func (h *Handlers) GetPendingCoSignatures(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	orders, err := h.service.GetPendingCoSignatures(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(orders)
}

// Barcode Scanning Handlers

// ScanBarcode handles barcode scanning
func (h *Handlers) ScanBarcode(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var request struct {
		Barcode string `json:"barcode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	result, err := h.service.ScanBarcode(request.Barcode, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ValidateScan handles scan validation
func (h *Handlers) ValidateScan(w http.ResponseWriter, r *http.Request) {
	var scanResult types.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&scanResult); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	isValid, err := h.service.ValidateScan(&scanResult)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]bool{"valid": isValid}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// ProcessScanResult handles scan result processing
func (h *Handlers) ProcessScanResult(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var scanResult types.ScanResult
	if err := json.NewDecoder(r.Body).Decode(&scanResult); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.ProcessScanResult(&scanResult, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Medication Administration Handlers

// RecordMedicationAdmin handles medication administration recording
func (h *Handlers) RecordMedicationAdmin(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var admin types.MedicationAdministration
	if err := json.NewDecoder(r.Body).Decode(&admin); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.RecordMedicationAdmin(&admin, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// GetMedicationSchedule handles medication schedule retrieval
func (h *Handlers) GetMedicationSchedule(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	patientID := vars["patientId"]

	schedule, err := h.service.GetMedicationSchedule(patientID, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(schedule)
}

// VerifyMedication handles medication verification
func (h *Handlers) VerifyMedication(w http.ResponseWriter, r *http.Request) {
	var request struct {
		MedicationID string `json:"medication_id"`
		PatientID    string `json:"patient_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	isValid, err := h.service.VerifyMedication(request.MedicationID, request.PatientID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := map[string]bool{"valid": isValid}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Lab Results Handlers

// EnterLabResult handles lab result entry
func (h *Handlers) EnterLabResult(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var result types.LabResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.EnterLabResult(&result, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

// GetLabResults handles lab results retrieval
func (h *Handlers) GetLabResults(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	patientID := vars["patientId"]

	results, err := h.service.GetLabResults(patientID, userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

// VerifyLabResult handles lab result verification
func (h *Handlers) VerifyLabResult(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	vars := mux.Vars(r)
	resultID := vars["id"]

	if err := h.service.VerifyLabResult(resultID, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Offline Sync Handlers

// SyncOfflineData handles offline data synchronization
func (h *Handlers) SyncOfflineData(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var data types.OfflineData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.SyncOfflineData(&data, userID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GetOfflineData handles offline data retrieval
func (h *Handlers) GetOfflineData(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	deviceID := r.URL.Query().Get("device_id")
	if deviceID == "" {
		http.Error(w, "device_id parameter is required", http.StatusBadRequest)
		return
	}

	data, err := h.service.GetOfflineData(userID, deviceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// MarkDataSynced handles marking data as synced
func (h *Handlers) MarkDataSynced(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var request struct {
		DeviceID string `json:"device_id"`
		SyncedAt string `json:"synced_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.MarkDataSynced(userID, request.DeviceID, request.SyncedAt); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Mobile Config Handlers

// GetMobileConfig handles mobile configuration retrieval
func (h *Handlers) GetMobileConfig(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	config, err := h.service.GetMobileConfig(userID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// UpdateMobilePreferences handles mobile preferences updates
func (h *Handlers) UpdateMobilePreferences(w http.ResponseWriter, r *http.Request) {
	userID := h.getUserID(r)
	if userID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var preferences map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&preferences); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.service.UpdateMobilePreferences(userID, preferences); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Helper methods

// getUserID extracts user ID from request context or headers
func (h *Handlers) getUserID(r *http.Request) string {
	// This would typically extract the user ID from JWT token or session
	// For now, return from header for testing
	return r.Header.Get("X-User-ID")
}

// respondWithError sends an error response
func (h *Handlers) respondWithError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// respondWithJSON sends a JSON response
func (h *Handlers) respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}