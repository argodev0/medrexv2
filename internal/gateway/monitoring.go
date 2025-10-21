package gateway

import (
	"net/http"
	"runtime"
	"sync"
	"time"
)

// Metrics holds various metrics for monitoring
type Metrics struct {
	RequestCount    int64             `json:"request_count"`
	ErrorCount      int64             `json:"error_count"`
	ResponseTimes   []time.Duration   `json:"-"`
	AvgResponseTime time.Duration     `json:"avg_response_time"`
	StatusCodes     map[int]int64     `json:"status_codes"`
	ServiceHealth   map[string]string `json:"service_health"`
	Uptime          time.Duration     `json:"uptime"`
	StartTime       time.Time         `json:"start_time"`
	mutex           sync.RWMutex
}

// MetricsCollector collects and manages metrics
type MetricsCollector struct {
	metrics   *Metrics
	startTime time.Time
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: &Metrics{
			StatusCodes:   make(map[int]int64),
			ServiceHealth: make(map[string]string),
			StartTime:     time.Now(),
		},
		startTime: time.Now(),
	}
}

// RecordRequest records a request metric
func (mc *MetricsCollector) RecordRequest(statusCode int, duration time.Duration) {
	mc.metrics.mutex.Lock()
	defer mc.metrics.mutex.Unlock()

	mc.metrics.RequestCount++
	mc.metrics.StatusCodes[statusCode]++

	if statusCode >= 400 {
		mc.metrics.ErrorCount++
	}

	// Keep only last 1000 response times for average calculation
	mc.metrics.ResponseTimes = append(mc.metrics.ResponseTimes, duration)
	if len(mc.metrics.ResponseTimes) > 1000 {
		mc.metrics.ResponseTimes = mc.metrics.ResponseTimes[1:]
	}

	// Calculate average response time
	var total time.Duration
	for _, rt := range mc.metrics.ResponseTimes {
		total += rt
	}
	if len(mc.metrics.ResponseTimes) > 0 {
		mc.metrics.AvgResponseTime = total / time.Duration(len(mc.metrics.ResponseTimes))
	}

	mc.metrics.Uptime = time.Since(mc.startTime)
}

// UpdateServiceHealth updates the health status of a service
func (mc *MetricsCollector) UpdateServiceHealth(serviceName, status string) {
	mc.metrics.mutex.Lock()
	defer mc.metrics.mutex.Unlock()

	mc.metrics.ServiceHealth[serviceName] = status
}

// GetMetrics returns current metrics
func (mc *MetricsCollector) GetMetrics() *Metrics {
	mc.metrics.mutex.RLock()
	defer mc.metrics.mutex.RUnlock()

	// Create a copy to avoid race conditions
	metricsCopy := &Metrics{
		RequestCount:    mc.metrics.RequestCount,
		ErrorCount:      mc.metrics.ErrorCount,
		AvgResponseTime: mc.metrics.AvgResponseTime,
		StatusCodes:     make(map[int]int64),
		ServiceHealth:   make(map[string]string),
		Uptime:          time.Since(mc.startTime),
		StartTime:       mc.metrics.StartTime,
	}

	for k, v := range mc.metrics.StatusCodes {
		metricsCopy.StatusCodes[k] = v
	}

	for k, v := range mc.metrics.ServiceHealth {
		metricsCopy.ServiceHealth[k] = v
	}

	return metricsCopy
}

// Add metrics collector to the Service struct and update the service
func (s *Service) addMetricsCollector() {
	s.metricsCollector = NewMetricsCollector()
}

// handleMetrics handles metrics endpoint requests
func (s *Service) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := s.metricsCollector.GetMetrics()
	
	// Add system metrics
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	systemMetrics := map[string]interface{}{
		"memory": map[string]interface{}{
			"alloc":       m.Alloc,
			"total_alloc": m.TotalAlloc,
			"sys":         m.Sys,
			"num_gc":      m.NumGC,
		},
		"goroutines": runtime.NumGoroutine(),
	}

	response := map[string]interface{}{
		"application": metrics,
		"system":      systemMetrics,
		"timestamp":   time.Now().UTC(),
	}

	s.writeJSONResponse(w, http.StatusOK, response)
}

// Enhanced health check with detailed service status
func (s *Service) handleDetailedHealth(w http.ResponseWriter, r *http.Request) {
	overallHealth := "healthy"
	services := make(map[string]interface{})

	s.servicesMux.RLock()
	for name, serviceURL := range s.services {
		healthURL := serviceURL.String() + "/health"
		
		start := time.Now()
		resp, err := http.Get(healthURL)
		duration := time.Since(start)

		serviceStatus := map[string]interface{}{
			"url":           serviceURL.String(),
			"response_time": duration.Milliseconds(),
		}

		if err != nil {
			serviceStatus["status"] = "unhealthy"
			serviceStatus["error"] = err.Error()
			overallHealth = "degraded"
		} else {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				serviceStatus["status"] = "healthy"
			} else {
				serviceStatus["status"] = "unhealthy"
				serviceStatus["status_code"] = resp.StatusCode
				overallHealth = "degraded"
			}
		}

		services[name] = serviceStatus
		
		// Update metrics
		if s.metricsCollector != nil {
			status := serviceStatus["status"].(string)
			s.metricsCollector.UpdateServiceHealth(name, status)
		}
	}
	s.servicesMux.RUnlock()

	response := map[string]interface{}{
		"status":    overallHealth,
		"timestamp": time.Now().UTC(),
		"services":  services,
		"gateway": map[string]interface{}{
			"status": "healthy",
			"uptime": time.Since(s.startTime).String(),
		},
	}

	statusCode := http.StatusOK
	if overallHealth == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}

	s.writeJSONResponse(w, statusCode, response)
}

// Add audit logging for security events
func (s *Service) logSecurityEvent(eventType, userID, details string) {
	s.logger.Warn("Security Event",
		"event_type", eventType,
		"user_id", userID,
		"details", details,
		"timestamp", time.Now().UTC(),
		"remote_addr", "", // Would be populated from request context
	)
}

// Enhanced middleware with metrics collection
func (s *Service) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		recorder := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(recorder, r)

		duration := time.Since(start)
		
		if s.metricsCollector != nil {
			s.metricsCollector.RecordRequest(recorder.statusCode, duration)
		}
	})
}