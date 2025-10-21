package gateway

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/medrex/dlt-emr/pkg/types"
)

// handleHealth handles health check requests
func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.HealthCheck(); err != nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "service unhealthy: "+err.Error())
		return
	}

	response := map[string]interface{}{
		"status":    "healthy",
		"timestamp": "2024-01-01T00:00:00Z", // Use actual timestamp
		"services":  s.getServiceStatus(),
	}

	s.writeJSONResponse(w, http.StatusOK, response)
}

// handleListServices lists all registered services
func (s *Service) handleListServices(w http.ResponseWriter, r *http.Request) {
	s.servicesMux.RLock()
	services := make(map[string]string)
	for name, url := range s.services {
		services[name] = url.String()
	}
	s.servicesMux.RUnlock()

	response := map[string]interface{}{
		"services": services,
		"count":    len(services),
	}

	s.writeJSONResponse(w, http.StatusOK, response)
}

// handleRegisterService registers a new service
func (s *Service) handleRegisterService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceName := vars["name"]

	var req struct {
		URL string `json:"url"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.RegisterService(serviceName, req.URL); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "failed to register service: "+err.Error())
		return
	}

	response := map[string]interface{}{
		"message": "service registered successfully",
		"service": serviceName,
		"url":     req.URL,
	}

	s.writeJSONResponse(w, http.StatusCreated, response)
}

// handleUnregisterService unregisters a service
func (s *Service) handleUnregisterService(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serviceName := vars["name"]

	if err := s.UnregisterService(serviceName); err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to unregister service: "+err.Error())
		return
	}

	response := map[string]interface{}{
		"message": "service unregistered successfully",
		"service": serviceName,
	}

	s.writeJSONResponse(w, http.StatusOK, response)
}

// handleProxy handles proxying requests to microservices
func (s *Service) handleProxy(w http.ResponseWriter, r *http.Request) {
	// Route the request to the appropriate service
	resp, err := s.RouteRequest(r)
	if err != nil {
		s.logger.Error("Failed to route request", "error", err, "path", r.URL.Path)
		s.writeErrorResponse(w, http.StatusBadGateway, "service unavailable")
		return
	}

	// Log the request/response
	s.LogRequest(r, resp)

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(resp.StatusCode)

	// Copy response body if available
	if resp.Body != nil {
		defer resp.Body.Close()
		// In a real implementation, you would copy the body content
		// For now, we'll just write a success message
		if resp.StatusCode == http.StatusOK {
			s.writeJSONResponse(w, resp.StatusCode, map[string]string{
				"message": "request processed successfully",
			})
		}
	}
}

// getServiceStatus returns the status of all registered services
func (s *Service) getServiceStatus() map[string]string {
	status := make(map[string]string)
	
	s.servicesMux.RLock()
	defer s.servicesMux.RUnlock()

	for name, serviceURL := range s.services {
		healthURL := serviceURL.String() + "/health"
		resp, err := http.Get(healthURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			status[name] = "unhealthy"
		} else {
			status[name] = "healthy"
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	return status
}

// writeJSONResponse writes a JSON response
func (s *Service) writeJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	
	if err := json.NewEncoder(w).Encode(data); err != nil {
		s.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeErrorResponse writes an error response
func (s *Service) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	errorResponse := &types.MedrexError{
		Type:    getErrorType(statusCode),
		Code:    http.StatusText(statusCode),
		Message: message,
	}

	s.writeJSONResponse(w, statusCode, errorResponse)
}

// getErrorType maps HTTP status codes to error types
func getErrorType(statusCode int) types.ErrorType {
	switch statusCode {
	case http.StatusBadRequest:
		return types.ErrorTypeValidation
	case http.StatusUnauthorized, http.StatusForbidden:
		return types.ErrorTypeAuthorization
	case http.StatusNotFound:
		return types.ErrorTypeNotFound
	case http.StatusTooManyRequests:
		return types.ErrorTypeExternal
	default:
		return types.ErrorTypeInternal
	}
}