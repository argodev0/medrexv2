package monitoring

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP request metrics
	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint", "status_code", "service"},
	)

	httpRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "endpoint", "service"},
	)

	// Database metrics
	dbConnectionsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "db_connections_active",
			Help: "Number of active database connections",
		},
		[]string{"database", "service"},
	)

	dbQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "db_query_duration_seconds",
			Help:    "Duration of database queries in seconds",
			Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0},
		},
		[]string{"query_type", "service"},
	)

	// Blockchain metrics
	blockchainTransactionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blockchain_transactions_total",
			Help: "Total number of blockchain transactions",
		},
		[]string{"chaincode", "function", "status", "service"},
	)

	blockchainTransactionDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "blockchain_transaction_duration_seconds",
			Help:    "Duration of blockchain transactions in seconds",
			Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0},
		},
		[]string{"chaincode", "function", "service"},
	)

	// Authentication metrics
	authAttemptsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"method", "status", "service"},
	)

	// PHI access metrics
	phiAccessTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "phi_access_total",
			Help: "Total number of PHI access attempts",
		},
		[]string{"user_role", "resource_type", "status", "service"},
	)

	// Audit log metrics
	auditEventsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "audit_events_total",
			Help: "Total number of audit events",
		},
		[]string{"event_type", "success", "service"},
	)

	// System metrics
	systemErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "system_errors_total",
			Help: "Total number of system errors",
		},
		[]string{"error_type", "service", "component"},
	)

	// Compliance metrics
	complianceViolations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "compliance_violations_total",
			Help: "Total number of compliance violations",
		},
		[]string{"violation_type", "severity", "service"},
	)
)

// MetricsCollector handles Prometheus metrics collection
type MetricsCollector struct {
	serviceName string
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(serviceName string) *MetricsCollector {
	// Register metrics
	prometheus.MustRegister(
		httpRequestsTotal,
		httpRequestDuration,
		dbConnectionsActive,
		dbQueryDuration,
		blockchainTransactionsTotal,
		blockchainTransactionDuration,
		authAttemptsTotal,
		phiAccessTotal,
		auditEventsTotal,
		systemErrors,
		complianceViolations,
	)

	return &MetricsCollector{
		serviceName: serviceName,
	}
}

// RecordHTTPRequest records HTTP request metrics
func (m *MetricsCollector) RecordHTTPRequest(method, endpoint, statusCode string, duration time.Duration) {
	httpRequestsTotal.WithLabelValues(method, endpoint, statusCode, m.serviceName).Inc()
	httpRequestDuration.WithLabelValues(method, endpoint, m.serviceName).Observe(duration.Seconds())
}

// RecordDBConnection records database connection metrics
func (m *MetricsCollector) RecordDBConnection(database string, activeConnections int) {
	dbConnectionsActive.WithLabelValues(database, m.serviceName).Set(float64(activeConnections))
}

// RecordDBQuery records database query metrics
func (m *MetricsCollector) RecordDBQuery(queryType string, duration time.Duration) {
	dbQueryDuration.WithLabelValues(queryType, m.serviceName).Observe(duration.Seconds())
}

// RecordBlockchainTransaction records blockchain transaction metrics
func (m *MetricsCollector) RecordBlockchainTransaction(chaincode, function, status string, duration time.Duration) {
	blockchainTransactionsTotal.WithLabelValues(chaincode, function, status, m.serviceName).Inc()
	blockchainTransactionDuration.WithLabelValues(chaincode, function, m.serviceName).Observe(duration.Seconds())
}

// RecordAuthAttempt records authentication attempt metrics
func (m *MetricsCollector) RecordAuthAttempt(method, status string) {
	authAttemptsTotal.WithLabelValues(method, status, m.serviceName).Inc()
}

// RecordPHIAccess records PHI access metrics
func (m *MetricsCollector) RecordPHIAccess(userRole, resourceType, status string) {
	phiAccessTotal.WithLabelValues(userRole, resourceType, status, m.serviceName).Inc()
}

// RecordAuditEvent records audit event metrics
func (m *MetricsCollector) RecordAuditEvent(eventType string, success bool) {
	successStr := strconv.FormatBool(success)
	auditEventsTotal.WithLabelValues(eventType, successStr, m.serviceName).Inc()
}

// RecordSystemError records system error metrics
func (m *MetricsCollector) RecordSystemError(errorType, component string) {
	systemErrors.WithLabelValues(errorType, m.serviceName, component).Inc()
}

// RecordComplianceViolation records compliance violation metrics
func (m *MetricsCollector) RecordComplianceViolation(violationType, severity string) {
	complianceViolations.WithLabelValues(violationType, severity, m.serviceName).Inc()
}

// Handler returns the Prometheus metrics HTTP handler
func (m *MetricsCollector) Handler() http.Handler {
	return promhttp.Handler()
}

// HTTPMiddleware creates middleware for HTTP request metrics
func (m *MetricsCollector) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Create a response writer wrapper to capture status code
		wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		
		next.ServeHTTP(wrapper, r)
		
		duration := time.Since(start)
		statusCode := strconv.Itoa(wrapper.statusCode)
		
		m.RecordHTTPRequest(r.Method, r.URL.Path, statusCode, duration)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}