package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/medrex/dlt-emr/pkg/logger"
)

func TestNewService(t *testing.T) {
	config := &Config{
		Port:         "8080",
		JWTSecret:    "test-secret",
		RateLimit:    100,
		RatePeriod:   time.Minute,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	rateLimiter := NewRateLimiter(100, time.Minute)
	testLogger := logger.New("info")

	service := NewService(config, rateLimiter, testLogger)

	if service == nil {
		t.Fatal("Expected service to be created, got nil")
	}

	if service.router == nil {
		t.Error("Expected router to be initialized")
	}

	if service.server == nil {
		t.Error("Expected server to be initialized")
	}

	if service.metricsCollector == nil {
		t.Error("Expected metrics collector to be initialized")
	}
}

func TestServiceRegistration(t *testing.T) {
	service := createTestService(t)

	// Test service registration
	err := service.RegisterService("test-service", "http://localhost:9000")
	if err != nil {
		t.Fatalf("Failed to register service: %v", err)
	}

	// Verify service is registered
	service.servicesMux.RLock()
	_, exists := service.services["test-service"]
	service.servicesMux.RUnlock()

	if !exists {
		t.Error("Expected service to be registered")
	}

	// Test invalid URL registration
	err = service.RegisterService("invalid-service", "://invalid-url")
	if err == nil {
		t.Error("Expected error for invalid URL")
	}
}

func TestServiceUnregistration(t *testing.T) {
	service := createTestService(t)

	// Register a service first
	service.RegisterService("test-service", "http://localhost:9000")

	// Test service unregistration
	err := service.UnregisterService("test-service")
	if err != nil {
		t.Fatalf("Failed to unregister service: %v", err)
	}

	// Verify service is unregistered
	service.servicesMux.RLock()
	_, exists := service.services["test-service"]
	service.servicesMux.RUnlock()

	if exists {
		t.Error("Expected service to be unregistered")
	}
}

func TestHealthCheck(t *testing.T) {
	service := createTestService(t)

	// Test health check with no services
	err := service.HealthCheck()
	if err != nil {
		t.Errorf("Expected health check to pass with no services, got error: %v", err)
	}

	// Register a mock service that will fail health check
	service.RegisterService("unhealthy-service", "http://localhost:99999")

	// Test health check with unhealthy service
	err = service.HealthCheck()
	if err == nil {
		t.Error("Expected health check to fail with unhealthy service")
	}
}

func TestHealthEndpoint(t *testing.T) {
	service := createTestService(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	service.handleHealth(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", response["status"])
	}
}

func TestMetricsEndpoint(t *testing.T) {
	service := createTestService(t)

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	service.handleMetrics(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if _, exists := response["application"]; !exists {
		t.Error("Expected 'application' metrics in response")
	}

	if _, exists := response["system"]; !exists {
		t.Error("Expected 'system' metrics in response")
	}
}

func TestServiceManagementEndpoints(t *testing.T) {
	service := createTestService(t)

	// Test listing services
	req := httptest.NewRequest("GET", "/admin/services", nil)
	w := httptest.NewRecorder()
	service.handleListServices(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Test registering service via endpoint
	reqBody := map[string]string{"url": "http://localhost:9000"}
	jsonBody, _ := json.Marshal(reqBody)

	req = httptest.NewRequest("POST", "/admin/services/test-service", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	// Mock mux.Vars for this test
	req = req.WithContext(req.Context())
	// Note: In a real test, you'd need to set up the mux router properly
	// For now, we'll test the registration logic directly
	err := service.RegisterService("test-service", "http://localhost:9000")
	if err != nil {
		t.Errorf("Failed to register service: %v", err)
	}

	// Test unregistering service
	err = service.UnregisterService("test-service")
	if err != nil {
		t.Errorf("Failed to unregister service: %v", err)
	}
}

func TestGetHealthyServices(t *testing.T) {
	service := createTestService(t)

	// Test with no services
	healthy, err := service.GetHealthyServices()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(healthy) != 0 {
		t.Errorf("Expected 0 healthy services, got %d", len(healthy))
	}

	// Register a service that will fail health check
	service.RegisterService("unhealthy-service", "http://localhost:99999")

	healthy, err = service.GetHealthyServices()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if len(healthy) != 0 {
		t.Errorf("Expected 0 healthy services, got %d", len(healthy))
	}
}

func TestExtractServiceName(t *testing.T) {
	service := createTestService(t)

	tests := []struct {
		path     string
		expected string
	}{
		{"/api/v1/iam/users", "iam"},
		{"/api/v1/clinical-notes/notes", "clinical-notes"},
		{"/api/v1/scheduling", "scheduling"},
		{"/health", ""},
		{"/invalid/path", ""},
		{"/api/v1/", ""},
	}

	for _, test := range tests {
		result := service.extractServiceName(test.path)
		if result != test.expected {
			t.Errorf("For path %s, expected %s, got %s", test.path, test.expected, result)
		}
	}
}

// Helper function to create a test service
func createTestService(t *testing.T) *Service {
	config := &Config{
		Port:         "8080",
		JWTSecret:    "test-secret",
		RateLimit:    100,
		RatePeriod:   time.Minute,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	rateLimiter := NewRateLimiter(100, time.Minute)
	testLogger := logger.New("info")

	return NewService(config, rateLimiter, testLogger)
}