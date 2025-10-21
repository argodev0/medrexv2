package monitoring

import (
	"context"
	"fmt"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// TracingConfig holds tracing configuration
type TracingConfig struct {
	ServiceName     string
	ServiceVersion  string
	JaegerEndpoint  string
	Environment     string
	SamplingRate    float64
}

// TracingManager handles distributed tracing
type TracingManager struct {
	tracer   trace.Tracer
	config   *TracingConfig
	provider *sdktrace.TracerProvider
}

// NewTracingManager creates a new tracing manager
func NewTracingManager(config *TracingConfig) (*TracingManager, error) {
	// Create Jaeger exporter
	exp, err := jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(config.JaegerEndpoint)))
	if err != nil {
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create resource
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(config.ServiceName),
			semconv.ServiceVersion(config.ServiceVersion),
			semconv.DeploymentEnvironment(config.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(config.SamplingRate)),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	tracer := tp.Tracer(config.ServiceName)

	return &TracingManager{
		tracer:   tracer,
		config:   config,
		provider: tp,
	}, nil
}

// StartSpan starts a new span
func (tm *TracingManager) StartSpan(ctx context.Context, operationName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tm.tracer.Start(ctx, operationName, opts...)
}

// StartHTTPSpan starts a span for HTTP requests
func (tm *TracingManager) StartHTTPSpan(ctx context.Context, method, path string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("%s %s", method, path)
	ctx, span := tm.tracer.Start(ctx, spanName,
		trace.WithAttributes(
			semconv.HTTPMethod(method),
			semconv.HTTPRoute(path),
			semconv.HTTPScheme("http"),
		),
	)
	return ctx, span
}

// StartDatabaseSpan starts a span for database operations
func (tm *TracingManager) StartDatabaseSpan(ctx context.Context, operation, table string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("db.%s", operation)
	ctx, span := tm.tracer.Start(ctx, spanName,
		trace.WithAttributes(
			semconv.DBSystem("postgresql"),
			semconv.DBOperation(operation),
			semconv.DBSQLTable(table),
		),
	)
	return ctx, span
}

// StartBlockchainSpan starts a span for blockchain operations
func (tm *TracingManager) StartBlockchainSpan(ctx context.Context, chaincode, function string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("blockchain.%s.%s", chaincode, function)
	ctx, span := tm.tracer.Start(ctx, spanName,
		trace.WithAttributes(
			attribute.String("blockchain.network", "hyperledger-fabric"),
			attribute.String("blockchain.chaincode", chaincode),
			attribute.String("blockchain.function", function),
		),
	)
	return ctx, span
}

// StartAuthSpan starts a span for authentication operations
func (tm *TracingManager) StartAuthSpan(ctx context.Context, operation string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("auth.%s", operation)
	ctx, span := tm.tracer.Start(ctx, spanName,
		trace.WithAttributes(
			attribute.String("auth.operation", operation),
		),
	)
	return ctx, span
}

// StartPHISpan starts a span for PHI operations
func (tm *TracingManager) StartPHISpan(ctx context.Context, operation, resourceType string) (context.Context, trace.Span) {
	spanName := fmt.Sprintf("phi.%s", operation)
	ctx, span := tm.tracer.Start(ctx, spanName,
		trace.WithAttributes(
			attribute.String("phi.operation", operation),
			attribute.String("phi.resource_type", resourceType),
			attribute.Bool("phi.sensitive", true),
		),
	)
	return ctx, span
}

// AddSpanAttributes adds attributes to the current span
func (tm *TracingManager) AddSpanAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(attrs...)
}

// AddSpanEvent adds an event to the current span
func (tm *TracingManager) AddSpanEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// RecordError records an error in the span
func (tm *TracingManager) RecordError(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(trace.Status{Code: trace.StatusCodeError, Description: err.Error()})
}

// HTTPMiddleware creates middleware for HTTP request tracing
func (tm *TracingManager) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract trace context from headers
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		
		// Start span
		ctx, span := tm.StartHTTPSpan(ctx, r.Method, r.URL.Path)
		defer span.End()

		// Add request attributes
		span.SetAttributes(
			semconv.HTTPUserAgent(r.UserAgent()),
			semconv.HTTPClientIP(r.RemoteAddr),
		)

		// Inject trace context into response headers
		otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(w.Header()))

		// Create wrapper to capture response status
		wrapper := &tracingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call next handler with traced context
		next.ServeHTTP(wrapper, r.WithContext(ctx))

		// Add response attributes
		span.SetAttributes(semconv.HTTPStatusCode(wrapper.statusCode))
		
		// Set span status based on HTTP status code
		if wrapper.statusCode >= 400 {
			span.SetStatus(trace.Status{
				Code:        trace.StatusCodeError,
				Description: fmt.Sprintf("HTTP %d", wrapper.statusCode),
			})
		}
	})
}

// tracingResponseWriter wraps http.ResponseWriter to capture status code
type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (trw *tracingResponseWriter) WriteHeader(code int) {
	trw.statusCode = code
	trw.ResponseWriter.WriteHeader(code)
}

// Shutdown gracefully shuts down the tracing provider
func (tm *TracingManager) Shutdown(ctx context.Context) error {
	return tm.provider.Shutdown(ctx)
}

// TraceIDFromContext extracts trace ID from context
func (tm *TracingManager) TraceIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().TraceID().String()
	}
	return ""
}

// SpanIDFromContext extracts span ID from context
func (tm *TracingManager) SpanIDFromContext(ctx context.Context) string {
	span := trace.SpanFromContext(ctx)
	if span.SpanContext().IsValid() {
		return span.SpanContext().SpanID().String()
	}
	return ""
}