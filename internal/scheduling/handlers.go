package scheduling

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/medrex/dlt-emr/pkg/types"
)

// setupRoutes configures HTTP routes for the scheduling service
func (s *Service) setupRoutes(router *mux.Router) {
	api := router.PathPrefix("/api/v1").Subrouter()

	// Appointment routes
	api.HandleFunc("/appointments", s.createAppointmentHandler).Methods("POST")
	api.HandleFunc("/appointments/{id}", s.getAppointmentHandler).Methods("GET")
	api.HandleFunc("/appointments/{id}", s.updateAppointmentHandler).Methods("PUT")
	api.HandleFunc("/appointments/{id}", s.cancelAppointmentHandler).Methods("DELETE")
	api.HandleFunc("/appointments", s.getAppointmentsHandler).Methods("GET")

	// Patient appointments
	api.HandleFunc("/patients/{patientId}/appointments", s.getPatientAppointmentsHandler).Methods("GET")

	// Provider routes
	api.HandleFunc("/providers", s.createProviderHandler).Methods("POST")
	api.HandleFunc("/providers/{id}", s.getProviderHandler).Methods("GET")
	api.HandleFunc("/providers/{id}", s.updateProviderHandler).Methods("PUT")
	api.HandleFunc("/providers", s.getProvidersHandler).Methods("GET")

	// Provider appointments and availability
	api.HandleFunc("/providers/{providerId}/appointments", s.getProviderAppointmentsHandler).Methods("GET")
	api.HandleFunc("/providers/{providerId}/availability", s.checkAvailabilityHandler).Methods("POST")
	api.HandleFunc("/providers/{providerId}/available-slots", s.getAvailableSlotsHandler).Methods("GET")
	api.HandleFunc("/providers/{providerId}/block-time", s.blockTimeSlotHandler).Methods("POST")
	api.HandleFunc("/providers/{providerId}/unblock-time", s.unblockTimeSlotHandler).Methods("POST")

	// Notification routes
	api.HandleFunc("/appointments/{id}/reminder", s.sendReminderHandler).Methods("POST")
	api.HandleFunc("/appointments/{id}/confirmation", s.sendConfirmationHandler).Methods("POST")

	// Calendar integration routes
	api.HandleFunc("/providers/{providerId}/calendar/connect", s.connectCalendarHandler).Methods("POST")
	api.HandleFunc("/providers/{providerId}/calendar/disconnect", s.disconnectCalendarHandler).Methods("POST")
	api.HandleFunc("/providers/{providerId}/calendar/sync", s.syncCalendarHandler).Methods("POST")
	api.HandleFunc("/providers/{providerId}/calendar/conflicts", s.getCalendarConflictsHandler).Methods("GET")

	// Health check
	api.HandleFunc("/health", s.healthCheckHandler).Methods("GET")

	s.logger.Info("Scheduling service routes configured")
}

// createAppointmentHandler handles appointment creation
func (s *Service) createAppointmentHandler(w http.ResponseWriter, r *http.Request) {
	var apt types.Appointment
	if err := json.NewDecoder(r.Body).Decode(&apt); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	userID := s.getUserIDFromRequest(r)
	createdApt, err := s.CreateAppointment(&apt, userID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to create appointment", err)
		return
	}

	s.writeJSONResponse(w, http.StatusCreated, createdApt)
}

// getAppointmentHandler handles appointment retrieval
func (s *Service) getAppointmentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	aptID := vars["id"]

	userID := s.getUserIDFromRequest(r)
	apt, err := s.GetAppointment(aptID, userID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Appointment not found", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, apt)
}

// updateAppointmentHandler handles appointment updates
func (s *Service) updateAppointmentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	aptID := vars["id"]

	var updates types.AppointmentUpdates
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	userID := s.getUserIDFromRequest(r)
	if err := s.UpdateAppointment(aptID, &updates, userID); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to update appointment", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Appointment updated successfully"})
}

// cancelAppointmentHandler handles appointment cancellation
func (s *Service) cancelAppointmentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	aptID := vars["id"]

	userID := s.getUserIDFromRequest(r)
	if err := s.CancelAppointment(aptID, userID); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to cancel appointment", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Appointment cancelled successfully"})
}

// getAppointmentsHandler handles appointment listing with filters
func (s *Service) getAppointmentsHandler(w http.ResponseWriter, r *http.Request) {
	filters := s.parseAppointmentFilters(r)
	userID := s.getUserIDFromRequest(r)

	appointments, err := s.GetAppointments(userID, filters)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get appointments", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, appointments)
}

// getPatientAppointmentsHandler handles patient-specific appointment retrieval
func (s *Service) getPatientAppointmentsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	patientID := vars["patientId"]

	userID := s.getUserIDFromRequest(r)
	appointments, err := s.GetPatientAppointments(patientID, userID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get patient appointments", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, appointments)
}

// createProviderHandler handles provider creation
func (s *Service) createProviderHandler(w http.ResponseWriter, r *http.Request) {
	var provider types.Provider
	if err := json.NewDecoder(r.Body).Decode(&provider); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	userID := s.getUserIDFromRequest(r)
	createdProvider, err := s.CreateProvider(&provider, userID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to create provider", err)
		return
	}

	s.writeJSONResponse(w, http.StatusCreated, createdProvider)
}

// getProviderHandler handles provider retrieval
func (s *Service) getProviderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["id"]

	userID := s.getUserIDFromRequest(r)
	provider, err := s.GetProvider(providerID, userID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Provider not found", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, provider)
}

// updateProviderHandler handles provider updates
func (s *Service) updateProviderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["id"]

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	userID := s.getUserIDFromRequest(r)
	if err := s.UpdateProvider(providerID, updates, userID); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to update provider", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Provider updated successfully"})
}

// getProvidersHandler handles provider listing
func (s *Service) getProvidersHandler(w http.ResponseWriter, r *http.Request) {
	filters := s.parseProviderFilters(r)
	userID := s.getUserIDFromRequest(r)

	providers, err := s.GetProviders(filters, userID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get providers", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, providers)
}

// getProviderAppointmentsHandler handles provider-specific appointment retrieval
func (s *Service) getProviderAppointmentsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	userID := s.getUserIDFromRequest(r)
	appointments, err := s.GetProviderAppointments(providerID, userID)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get provider appointments", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, appointments)
}

// checkAvailabilityHandler handles availability checking
func (s *Service) checkAvailabilityHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	var timeSlot types.TimeSlot
	if err := json.NewDecoder(r.Body).Decode(&timeSlot); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	available, err := s.CheckAvailability(providerID, &timeSlot)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to check availability", err)
		return
	}

	response := map[string]interface{}{
		"available":  available,
		"provider_id": providerID,
		"time_slot":  timeSlot,
	}

	s.writeJSONResponse(w, http.StatusOK, response)
}

// getAvailableSlotsHandler handles available slots retrieval
func (s *Service) getAvailableSlotsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	date := r.URL.Query().Get("date")
	if date == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Date parameter is required", nil)
		return
	}

	slots, err := s.GetAvailableSlots(providerID, date)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get available slots", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, slots)
}

// blockTimeSlotHandler handles time slot blocking
func (s *Service) blockTimeSlotHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	var request struct {
		TimeSlot types.TimeSlot `json:"time_slot"`
		Reason   string         `json:"reason"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.BlockTimeSlot(providerID, &request.TimeSlot, request.Reason); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to block time slot", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Time slot blocked successfully"})
}

// unblockTimeSlotHandler handles time slot unblocking
func (s *Service) unblockTimeSlotHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	var timeSlot types.TimeSlot
	if err := json.NewDecoder(r.Body).Decode(&timeSlot); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.UnblockTimeSlot(providerID, &timeSlot); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to unblock time slot", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Time slot unblocked successfully"})
}

// sendReminderHandler handles appointment reminder sending
func (s *Service) sendReminderHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	aptID := vars["id"]

	if err := s.SendAppointmentReminder(aptID); err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to send reminder", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Reminder sent successfully"})
}

// sendConfirmationHandler handles appointment confirmation sending
func (s *Service) sendConfirmationHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	aptID := vars["id"]

	if err := s.SendAppointmentConfirmation(aptID); err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to send confirmation", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Confirmation sent successfully"})
}

// connectCalendarHandler handles calendar connection
func (s *Service) connectCalendarHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	var request struct {
		CalendarType string `json:"calendar_type"`
		Credentials  string `json:"credentials"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", err)
		return
	}

	if err := s.calendarService.ConnectCalendar(providerID, request.CalendarType, request.Credentials); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to connect calendar", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Calendar connected successfully"})
}

// disconnectCalendarHandler handles calendar disconnection
func (s *Service) disconnectCalendarHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	if err := s.calendarService.DisconnectCalendar(providerID); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to disconnect calendar", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Calendar disconnected successfully"})
}

// syncCalendarHandler handles calendar synchronization
func (s *Service) syncCalendarHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	if err := s.calendarService.SyncProviderAvailability(providerID); err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to sync calendar", err)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, map[string]string{"message": "Calendar synced successfully"})
}

// getCalendarConflictsHandler handles calendar conflict detection
func (s *Service) getCalendarConflictsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	providerID := vars["providerId"]

	date := r.URL.Query().Get("date")
	if date == "" {
		date = time.Now().Format("2006-01-02")
	}

	conflicts, err := s.calendarManager.DetectConflicts(providerID, date)
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to detect conflicts", err)
		return
	}

	response := map[string]interface{}{
		"provider_id": providerID,
		"date":        date,
		"conflicts":   conflicts,
		"count":       len(conflicts),
	}

	s.writeJSONResponse(w, http.StatusOK, response)
}

// healthCheckHandler handles health check requests
func (s *Service) healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"status":    "healthy",
		"service":   "scheduling",
		"timestamp": time.Now().UTC(),
	}

	s.writeJSONResponse(w, http.StatusOK, response)
}

// Helper methods

// getUserIDFromRequest extracts user ID from request (placeholder implementation)
func (s *Service) getUserIDFromRequest(r *http.Request) string {
	// TODO: Extract user ID from JWT token or session
	// For now, return a placeholder
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = "anonymous"
	}
	return userID
}

// parseAppointmentFilters parses query parameters into appointment filters
func (s *Service) parseAppointmentFilters(r *http.Request) *types.AppointmentFilters {
	filters := &types.AppointmentFilters{}

	if patientID := r.URL.Query().Get("patient_id"); patientID != "" {
		filters.PatientID = patientID
	}

	if providerID := r.URL.Query().Get("provider_id"); providerID != "" {
		filters.ProviderID = providerID
	}

	if status := r.URL.Query().Get("status"); status != "" {
		filters.Status = types.AppointmentStatus(status)
	}

	if aptType := r.URL.Query().Get("type"); aptType != "" {
		filters.Type = types.AppointmentType(aptType)
	}

	if fromDate := r.URL.Query().Get("from_date"); fromDate != "" {
		if parsed, err := time.Parse("2006-01-02", fromDate); err == nil {
			filters.FromDate = parsed
		}
	}

	if toDate := r.URL.Query().Get("to_date"); toDate != "" {
		if parsed, err := time.Parse("2006-01-02", toDate); err == nil {
			filters.ToDate = parsed
		}
	}

	if location := r.URL.Query().Get("location"); location != "" {
		filters.Location = location
	}

	if limit := r.URL.Query().Get("limit"); limit != "" {
		if parsed, err := strconv.Atoi(limit); err == nil {
			filters.Limit = parsed
		}
	}

	if offset := r.URL.Query().Get("offset"); offset != "" {
		if parsed, err := strconv.Atoi(offset); err == nil {
			filters.Offset = parsed
		}
	}

	return filters
}

// parseProviderFilters parses query parameters into provider filters
func (s *Service) parseProviderFilters(r *http.Request) map[string]interface{} {
	filters := make(map[string]interface{})

	if specialty := r.URL.Query().Get("specialty"); specialty != "" {
		filters["specialty"] = specialty
	}

	if department := r.URL.Query().Get("department"); department != "" {
		filters["department"] = department
	}

	if isActive := r.URL.Query().Get("is_active"); isActive != "" {
		if parsed, err := strconv.ParseBool(isActive); err == nil {
			filters["is_active"] = parsed
		}
	}

	return filters
}

// writeJSONResponse writes a JSON response
func (s *Service) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Failed to encode JSON response: %v", err)
	}
}

// writeErrorResponse writes an error response
func (s *Service) writeErrorResponse(w http.ResponseWriter, statusCode int, message string, err error) {
	s.logger.Error("%s: %v", message, err)

	response := map[string]interface{}{
		"error":   message,
		"status":  statusCode,
	}

	if err != nil {
		response["details"] = err.Error()
	}

	s.writeJSONResponse(w, statusCode, response)
}