package monitoring

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// MonitoringMiddleware combines metrics, tracing, and logging
type MonitoringMiddleware struct {
	metrics *MetricsCollector
	tracing *TracingManager
	logger  Logger
}

// Logger interface for the monitoring middleware
type Logger interface {
	HTTPRequest(ctx context.Context, method, path, userAgent, clientIP string, statusCode int, duration int64, details map[string]interface{})
	WithContext(ctx context.Context) interface{}
}

// NewMonitoringMiddleware creates a new monitoring middleware
func NewMonitoringMiddleware(metrics *MetricsCollector, tracing *TracingManager, logger Logger) *MonitoringMiddleware {
	return &MonitoringMiddleware{
		metrics: metrics,
		tracing: tracing,
		logger:  logger,
	}
}

// HTTPMiddleware creates comprehensive HTTP monitoring middleware
func (mm *MonitoringMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		
		// Generate request ID if not present
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = uuid.New().String()
		}
		
		// Add request ID to context
		ctx := context.WithValue(r.Context(), "request_id", requestID)
		
		// Extract or create trace context
		ctx = mm.tracing.ExtractTraceContext(ctx, r.Header)
		
		// Start tracing span
		ctx, span := mm.tracing.StartHTTPSpan(ctx, r.Method, r.URL.Path)
		defer span.End()
		
		// Add span attributes
		span.SetAttributes(
			attribute.String("http.method", r.Method),
			attribute.String("http.url", r.URL.String()),
			attribute.String("http.user_agent", r.UserAgent()),
			attribute.String("http.remote_addr", r.RemoteAddr),
			attribute.String("request.id", requestID),
		)
		
		// Create response writer wrapper
		wrapper := &monitoringResponseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}
		
		// Add request ID to response headers
		wrapper.Header().Set("X-Request-ID", requestID)
		
		// Inject trace context into response headers
		mm.tracing.InjectTraceContext(ctx, wrapper.Header())
		
		// Call next handler
		next.ServeHTTP(wrapper, r.WithContext(ctx))
		
		// Calculate duration
		duration := time.Since(start)
		
		// Record metrics
		statusCode := strconv.Itoa(wrapper.statusCode)
		mm.metrics.RecordHTTPRequest(r.Method, r.URL.Path, statusCode, duration)
		
		// Add response attributes to span
		span.SetAttributes(
			attribute.Int("http.status_code", wrapper.statusCode),
			attribute.Int64("http.response_size", wrapper.bytesWritten),
		)
		
		// Set span status based on HTTP status code
		if wrapper.statusCode >= 400 {
			span.SetStatus(trace.Status{
				Code:        trace.StatusCodeError,
				Description: http.StatusText(wrapper.statusCode),
			})
		}
		
		// Log the request
		details := map[string]interface{}{
			"request_id":     requestID,
			"bytes_written":  wrapper.bytesWritten,
			"trace_id":       mm.tracing.TraceIDFromContext(ctx),
			"span_id":        mm.tracing.SpanIDFromContext(ctx),
		}
		
		mm.logger.HTTPRequest(
			ctx,
			r.Method,
			r.URL.Path,
			r.UserAgent(),
			r.RemoteAddr,
			wrapper.statusCode,
			duration.Milliseconds(),
			details,
		)
	})
}

// DatabaseMiddleware creates middleware for database operations
func (mm *MonitoringMiddleware) DatabaseMiddleware(operation, table string) func(context.Context, func() error) error {
	return func(ctx context.Context, dbFunc func() error) error {
		start := time.Now()
		
		// Start tracing span
		ctx, span := mm.tracing.StartDatabaseSpan(ctx, operation, table)
		defer span.End()
		
		// Execute database operation
		err := dbFunc()
		
		// Calculate duration
		duration := time.Since(start)
		
		// Record metrics
		mm.metrics.RecordDBQuery(operation, duration)
		
		// Add span attributes
		span.SetAttributes(
			attribute.String("db.operation", operation),
			attribute.String("db.table", table),
		)
		
		// Handle error
		if err != nil {
			mm.tracing.RecordError(span, err)
			mm.metrics.RecordSystemError("database_error", "database")
		}
		
		return err
	}
}

// BlockchainMiddleware creates middleware for blockchain operations
func (mm *MonitoringMiddleware) BlockchainMiddleware(chaincode, function string) func(context.Context, func() error) error {
	return func(ctx context.Context, blockchainFunc func() error) error {
		start := time.Now()
		
		// Start tracing span
		ctx, span := mm.tracing.StartBlockchainSpan(ctx, chaincode, function)
		defer span.End()
		
		// Execute blockchain operation
		err := blockchainFunc()
		
		// Calculate duration
		duration := time.Since(start)
		
		// Determine status
		status := "success"
		if err != nil {
			status = "failed"
		}
		
		// Record metrics
		mm.metrics.RecordBlockchainTransaction(chaincode, function, status, duration)
		
		// Add span attributes
		span.SetAttributes(
			attribute.String("blockchain.chaincode", chaincode),
			attribute.String("blockchain.function", function),
			attribute.String("blockchain.status", status),
		)
		
		// Handle error
		if err != nil {
			mm.tracing.RecordError(span, err)
			mm.metrics.RecordSystemError("blockchain_error", "blockchain")
		}
		
		return err
	}
}

// AuthMiddleware creates middleware for authentication operations
func (mm *MonitoringMiddleware) AuthMiddleware(method string) func(context.Context, func() error) error {
	return func(ctx context.Context, authFunc func() error) error {
		// Start tracing span
		ctx, span := mm.tracing.StartAuthSpan(ctx, method)
		defer span.End()
		
		// Execute authentication operation
		err := authFunc()
		
		// Determine status
		status := "success"
		if err != nil {
			status = "failed"
		}
		
		// Record metrics
		mm.metrics.RecordAuthAttempt(method, status)
		
		// Add span attributes
		span.SetAttributes(
			attribute.String("auth.method", method),
			attribute.String("auth.status", status),
		)
		
		// Handle error
		if err != nil {
			mm.tracing.RecordError(span, err)
			mm.metrics.RecordSystemError("auth_error", "authentication")
		}
		
		return err
	}
}

// PHIMiddleware creates middleware for PHI operations
func (mm *MonitoringMiddleware) PHIMiddleware(operation, resourceType string) func(context.Context, string, func() error) error {
	return func(ctx context.Context, userRole string, phiFunc func() error) error {
		// Start tracing span
		ctx, span := mm.tracing.StartPHISpan(ctx, operation, resourceType)
		defer span.End()
		
		// Execute PHI operation
		err := phiFunc()
		
		// Determine status
		status := "granted"
		if err != nil {
			status = "denied"
		}
		
		// Record metrics
		mm.metrics.RecordPHIAccess(userRole, resourceType, status)
		
		// Add span attributes
		span.SetAttributes(
			attribute.String("phi.operation", operation),
			attribute.String("phi.resource_type", resourceType),
			attribute.String("phi.user_role", userRole),
			attribute.String("phi.status", status),
			attribute.Bool("phi.sensitive", true),
		)
		
		// Handle error
		if err != nil {
			mm.tracing.RecordError(span, err)
			mm.metrics.RecordSystemError("phi_access_error", "phi")
		}
		
		return err
	}
}

// monitoringResponseWriter wraps http.ResponseWriter to capture metrics
type monitoringResponseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (mrw *monitoringResponseWriter) WriteHeader(code int) {
	mrw.statusCode = code
	mrw.ResponseWriter.WriteHeader(code)
}

func (mrw *monitoringResponseWriter) Write(b []byte) (int, error) {
	n, err := mrw.ResponseWriter.Write(b)
	mrw.bytesWritten += int64(n)
	return n, err
}

// ExtractTraceContext extracts trace context from HTTP headers
func (tm *TracingManager) ExtractTraceContext(ctx context.Context, headers http.Header) context.Context {
	// This would be implemented based on the tracing library being used
	// For now, return the original context
	return ctx
}

// InjectTraceContext injects trace context into HTTP headers
func (tm *TracingManager) InjectTraceContext(ctx context.Context, headers http.Header) {
	// This would be implemented based on the tracing library being used
	// For now, this is a placeholder
}