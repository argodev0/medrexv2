package gateway

import (
	"net/http"
	"sync"
	"time"
)

// MetricsCollector collects and stores metrics for the API Gateway
type MetricsCollector struct {
	requestCount    map[string]int64
	responseTime    map[string]time.Duration
	statusCodes     map[int]int64
	totalRequests   int64
	totalErrors     int64
	startTime       time.Time
	mutex           sync.RWMutex
}

// RequestMetrics represents metrics for a specific request
type RequestMetrics struct {
	Method       string        `json:"method"`
	Path         string        `json:"path"`
	StatusCode   int           `json:"status_code"`
	ResponseTime time.Duration `json:"response_time"`
	Timestamp    time.Time     `json:"timestamp"`
}

// GatewayMetrics represents overall gateway metrics
type GatewayMetrics struct {
	TotalRequests   int64                    `json:"total_requests"`
	TotalErrors     int64                    `json:"total_errors"`
	RequestsByPath  map[string]int64         `json:"requests_by_path"`
	StatusCodes     map[int]int64            `json:"status_codes"`
	AverageResponse map[string]time.Duration `json:"average_response_time"`
	Uptime          time.Duration            `json:"uptime"`
	StartTime       time.Time                `json:"start_time"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		requestCount: make(map[string]int64),
		responseTime: make(map[string]time.Duration),
		statusCodes:  make(map[int]int64),
		startTime:    time.Now(),
	}
}

// RecordRequest records metrics for a request
func (mc *MetricsCollector) RecordRequest(method, path string, statusCode int, duration time.Duration) {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	key := method + " " + path
	mc.requestCount[key]++
	mc.responseTime[key] = duration
	mc.statusCodes[statusCode]++
	mc.totalRequests++

	if statusCode >= 400 {
		mc.totalErrors++
	}
}

// GetMetrics returns current metrics
func (mc *MetricsCollector) GetMetrics() *GatewayMetrics {
	mc.mutex.RLock()
	defer mc.mutex.RUnlock()

	// Calculate average response times
	avgResponse := make(map[string]time.Duration)
	for path, duration := range mc.responseTime {
		avgResponse[path] = duration
	}

	return &GatewayMetrics{
		TotalRequests:   mc.totalRequests,
		TotalErrors:     mc.totalErrors,
		RequestsByPath:  copyMap(mc.requestCount),
		StatusCodes:     copyIntMap(mc.statusCodes),
		AverageResponse: avgResponse,
		Uptime:          time.Since(mc.startTime),
		StartTime:       mc.startTime,
	}
}

// Reset resets all metrics
func (mc *MetricsCollector) Reset() {
	mc.mutex.Lock()
	defer mc.mutex.Unlock()

	mc.requestCount = make(map[string]int64)
	mc.responseTime = make(map[string]time.Duration)
	mc.statusCodes = make(map[int]int64)
	mc.totalRequests = 0
	mc.totalErrors = 0
	mc.startTime = time.Now()
}

// handleMetrics handles metrics endpoint requests
func (s *Service) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if s.metricsCollector == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "metrics collector not available")
		return
	}

	metrics := s.metricsCollector.GetMetrics()
	s.writeJSONResponse(w, http.StatusOK, metrics)
}

// handleDetailedHealth handles detailed health check requests
func (s *Service) handleDetailedHealth(w http.ResponseWriter, r *http.Request) {
	healthStatus := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"uptime":    time.Since(s.startTime).String(),
		"services":  s.getServiceStatus(),
	}

	// Add metrics if available
	if s.metricsCollector != nil {
		metrics := s.metricsCollector.GetMetrics()
		healthStatus["metrics"] = map[string]interface{}{
			"total_requests": metrics.TotalRequests,
			"total_errors":   metrics.TotalErrors,
			"error_rate":     float64(metrics.TotalErrors) / float64(metrics.TotalRequests) * 100,
		}
	}

	// Check overall health
	if err := s.HealthCheck(); err != nil {
		healthStatus["status"] = "unhealthy"
		healthStatus["error"] = err.Error()
		s.writeJSONResponse(w, http.StatusServiceUnavailable, healthStatus)
		return
	}

	s.writeJSONResponse(w, http.StatusOK, healthStatus)
}

// Helper functions
func copyMap(original map[string]int64) map[string]int64 {
	copy := make(map[string]int64)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

func copyIntMap(original map[int]int64) map[int]int64 {
	copy := make(map[int]int64)
	for k, v := range original {
		copy[k] = v
	}
	return copy
}