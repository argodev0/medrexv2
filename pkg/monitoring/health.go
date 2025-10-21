package monitoring

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HealthStatus represents the health status of a component
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusDegraded  HealthStatus = "degraded"
)

// HealthCheck represents a single health check
type HealthCheck struct {
	Name        string                 `json:"name"`
	Status      HealthStatus           `json:"status"`
	Message     string                 `json:"message,omitempty"`
	LastChecked time.Time              `json:"last_checked"`
	Duration    time.Duration          `json:"duration"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// HealthReport represents the overall health report
type HealthReport struct {
	Status      HealthStatus   `json:"status"`
	Timestamp   time.Time      `json:"timestamp"`
	Service     string         `json:"service"`
	Version     string         `json:"version"`
	Checks      []HealthCheck  `json:"checks"`
	Summary     map[string]int `json:"summary"`
}

// HealthChecker interface for health check implementations
type HealthChecker interface {
	Check(ctx context.Context) HealthCheck
}

// HealthManager manages health checks
type HealthManager struct {
	serviceName    string
	serviceVersion string
	checkers       map[string]HealthChecker
	mu             sync.RWMutex
	timeout        time.Duration
}

// NewHealthManager creates a new health manager
func NewHealthManager(serviceName, serviceVersion string) *HealthManager {
	return &HealthManager{
		serviceName:    serviceName,
		serviceVersion: serviceVersion,
		checkers:       make(map[string]HealthChecker),
		timeout:        30 * time.Second,
	}
}

// RegisterChecker registers a health checker
func (hm *HealthManager) RegisterChecker(name string, checker HealthChecker) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.checkers[name] = checker
}

// SetTimeout sets the timeout for health checks
func (hm *HealthManager) SetTimeout(timeout time.Duration) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.timeout = timeout
}

// CheckHealth performs all health checks and returns a report
func (hm *HealthManager) CheckHealth(ctx context.Context) *HealthReport {
	hm.mu.RLock()
	checkers := make(map[string]HealthChecker)
	for name, checker := range hm.checkers {
		checkers[name] = checker
	}
	timeout := hm.timeout
	hm.mu.RUnlock()

	report := &HealthReport{
		Service:   hm.serviceName,
		Version:   hm.serviceVersion,
		Timestamp: time.Now(),
		Checks:    make([]HealthCheck, 0, len(checkers)),
		Summary:   make(map[string]int),
	}

	// Run health checks concurrently
	checkChan := make(chan HealthCheck, len(checkers))
	var wg sync.WaitGroup

	for name, checker := range checkers {
		wg.Add(1)
		go func(name string, checker HealthChecker) {
			defer wg.Done()
			
			checkCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			
			start := time.Now()
			check := checker.Check(checkCtx)
			check.Name = name
			check.LastChecked = start
			check.Duration = time.Since(start)
			
			checkChan <- check
		}(name, checker)
	}

	// Wait for all checks to complete
	go func() {
		wg.Wait()
		close(checkChan)
	}()

	// Collect results
	for check := range checkChan {
		report.Checks = append(report.Checks, check)
		report.Summary[string(check.Status)]++
	}

	// Determine overall status
	if report.Summary[string(HealthStatusUnhealthy)] > 0 {
		report.Status = HealthStatusUnhealthy
	} else if report.Summary[string(HealthStatusDegraded)] > 0 {
		report.Status = HealthStatusDegraded
	} else {
		report.Status = HealthStatusHealthy
	}

	return report
}

// HTTPHandler returns an HTTP handler for health checks
func (hm *HealthManager) HTTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		report := hm.CheckHealth(ctx)

		w.Header().Set("Content-Type", "application/json")
		
		// Set HTTP status based on health status
		switch report.Status {
		case HealthStatusHealthy:
			w.WriteHeader(http.StatusOK)
		case HealthStatusDegraded:
			w.WriteHeader(http.StatusOK) // Still OK but with warnings
		case HealthStatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(report)
	}
}

// DatabaseHealthChecker checks database connectivity
type DatabaseHealthChecker struct {
	db *sql.DB
}

// NewDatabaseHealthChecker creates a new database health checker
func NewDatabaseHealthChecker(db *sql.DB) *DatabaseHealthChecker {
	return &DatabaseHealthChecker{db: db}
}

// Check performs the database health check
func (dhc *DatabaseHealthChecker) Check(ctx context.Context) HealthCheck {
	check := HealthCheck{
		Details: make(map[string]interface{}),
	}

	// Test database connection
	err := dhc.db.PingContext(ctx)
	if err != nil {
		check.Status = HealthStatusUnhealthy
		check.Message = fmt.Sprintf("Database connection failed: %v", err)
		return check
	}

	// Get database stats
	stats := dhc.db.Stats()
	check.Details["open_connections"] = stats.OpenConnections
	check.Details["in_use"] = stats.InUse
	check.Details["idle"] = stats.Idle
	check.Details["wait_count"] = stats.WaitCount
	check.Details["wait_duration"] = stats.WaitDuration.String()

	// Check if we're running out of connections
	if stats.OpenConnections >= stats.MaxOpenConnections-5 && stats.MaxOpenConnections > 0 {
		check.Status = HealthStatusDegraded
		check.Message = "Database connection pool nearly exhausted"
	} else {
		check.Status = HealthStatusHealthy
		check.Message = "Database connection healthy"
	}

	return check
}

// HTTPHealthChecker checks HTTP service connectivity
type HTTPHealthChecker struct {
	url    string
	client *http.Client
}

// NewHTTPHealthChecker creates a new HTTP health checker
func NewHTTPHealthChecker(url string, timeout time.Duration) *HTTPHealthChecker {
	return &HTTPHealthChecker{
		url: url,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Check performs the HTTP health check
func (hhc *HTTPHealthChecker) Check(ctx context.Context) HealthCheck {
	check := HealthCheck{
		Details: make(map[string]interface{}),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", hhc.url, nil)
	if err != nil {
		check.Status = HealthStatusUnhealthy
		check.Message = fmt.Sprintf("Failed to create request: %v", err)
		return check
	}

	resp, err := hhc.client.Do(req)
	if err != nil {
		check.Status = HealthStatusUnhealthy
		check.Message = fmt.Sprintf("HTTP request failed: %v", err)
		return check
	}
	defer resp.Body.Close()

	check.Details["status_code"] = resp.StatusCode
	check.Details["url"] = hhc.url

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		check.Status = HealthStatusHealthy
		check.Message = "HTTP service healthy"
	} else if resp.StatusCode >= 500 {
		check.Status = HealthStatusUnhealthy
		check.Message = fmt.Sprintf("HTTP service returned %d", resp.StatusCode)
	} else {
		check.Status = HealthStatusDegraded
		check.Message = fmt.Sprintf("HTTP service returned %d", resp.StatusCode)
	}

	return check
}

// CustomHealthChecker allows custom health check implementations
type CustomHealthChecker struct {
	checkFunc func(ctx context.Context) HealthCheck
}

// NewCustomHealthChecker creates a new custom health checker
func NewCustomHealthChecker(checkFunc func(ctx context.Context) HealthCheck) *CustomHealthChecker {
	return &CustomHealthChecker{checkFunc: checkFunc}
}

// Check performs the custom health check
func (chc *CustomHealthChecker) Check(ctx context.Context) HealthCheck {
	return chc.checkFunc(ctx)
}