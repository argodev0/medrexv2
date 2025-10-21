package mobile

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MobileMiddleware provides mobile-specific optimizations
type MobileMiddleware struct {
	compressionEnabled bool
	cachingEnabled     bool
	rateLimitEnabled   bool
}

// NewMobileMiddleware creates new mobile middleware
func NewMobileMiddleware() *MobileMiddleware {
	return &MobileMiddleware{
		compressionEnabled: true,
		cachingEnabled:     true,
		rateLimitEnabled:   true,
	}
}

// CompressionMiddleware adds response compression for mobile clients
func (m *MobileMiddleware) CompressionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.compressionEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// Check if client accepts gzip compression
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		// Create gzip writer
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")

		gzipWriter := gzip.NewWriter(w)
		defer gzipWriter.Close()

		// Create wrapper that writes to gzip writer
		gzipResponseWriter := &gzipResponseWriter{
			ResponseWriter: w,
			Writer:         gzipWriter,
		}

		next.ServeHTTP(gzipResponseWriter, r)
	})
}

// CachingMiddleware adds appropriate caching headers for mobile optimization
func (m *MobileMiddleware) CachingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.cachingEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// Set caching headers based on request path
		path := r.URL.Path
		
		if strings.Contains(path, "/config") || strings.Contains(path, "/preferences") {
			// Cache configuration data for 5 minutes
			w.Header().Set("Cache-Control", "public, max-age=300")
		} else if strings.Contains(path, "/medication/schedule") || strings.Contains(path, "/lab/results") {
			// Cache medical data for 1 minute
			w.Header().Set("Cache-Control", "private, max-age=60")
		} else if r.Method == "GET" {
			// Default caching for GET requests
			w.Header().Set("Cache-Control", "private, max-age=30")
		} else {
			// No caching for POST/PUT/DELETE requests
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		}

		// Add ETag for conditional requests
		if r.Method == "GET" {
			etag := m.generateETag(r)
			w.Header().Set("ETag", etag)
			
			// Check if client has cached version
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// MobileOptimizationMiddleware adds mobile-specific optimizations
func (m *MobileMiddleware) MobileOptimizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add mobile-specific headers
		w.Header().Set("X-Mobile-Optimized", "true")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		// Check for mobile client
		userAgent := r.Header.Get("User-Agent")
		isMobile := m.isMobileClient(userAgent)
		
		if isMobile {
			// Add mobile-specific optimizations
			w.Header().Set("X-Mobile-Client", "true")
			
			// Reduce response size for mobile clients
			r.Header.Set("X-Mobile-Response", "compact")
		}

		// Add request timing
		start := time.Now()
		
		// Wrap response writer to capture response size
		wrappedWriter := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(wrappedWriter, r)

		// Log mobile-specific metrics
		duration := time.Since(start)
		m.logMobileMetrics(r, wrappedWriter, duration, isMobile)
	})
}

// DataMinimizationMiddleware reduces response payload for mobile clients
func (m *MobileMiddleware) DataMinimizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if mobile client requested compact response
		if r.Header.Get("X-Mobile-Response") == "compact" {
			// Wrap response writer to modify response
			compactWriter := &compactResponseWriter{
				ResponseWriter: w,
				request:        r,
			}
			next.ServeHTTP(compactWriter, r)
		} else {
			next.ServeHTTP(w, r)
		}
	})
}

// OfflineMiddleware adds offline support headers
func (m *MobileMiddleware) OfflineMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Add offline support headers
		w.Header().Set("X-Offline-Support", "true")
		
		// Check for offline sync requests
		if r.Header.Get("X-Offline-Sync") == "true" {
			w.Header().Set("X-Sync-Timestamp", time.Now().Format(time.RFC3339))
		}

		// Add conflict resolution headers
		if r.Method == "POST" || r.Method == "PUT" {
			w.Header().Set("X-Conflict-Resolution", "server-wins")
		}

		next.ServeHTTP(w, r)
	})
}

// BandwidthOptimizationMiddleware optimizes for low bandwidth connections
func (m *MobileMiddleware) BandwidthOptimizationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check connection quality header
		connectionQuality := r.Header.Get("X-Connection-Quality")
		
		switch connectionQuality {
		case "poor":
			// Aggressive optimization for poor connections
			w.Header().Set("X-Response-Format", "minimal")
			r.Header.Set("X-Bandwidth-Mode", "low")
		case "good":
			// Standard optimization
			w.Header().Set("X-Response-Format", "standard")
			r.Header.Set("X-Bandwidth-Mode", "normal")
		default:
			// Auto-detect based on request size and timing
			w.Header().Set("X-Response-Format", "auto")
		}

		next.ServeHTTP(w, r)
	})
}

// Helper types and methods

type gzipResponseWriter struct {
	http.ResponseWriter
	Writer io.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	responseSize int
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(b []byte) (int, error) {
	size, err := w.ResponseWriter.Write(b)
	w.responseSize += size
	return size, err
}

type compactResponseWriter struct {
	http.ResponseWriter
	request *http.Request
}

func (w *compactResponseWriter) Write(b []byte) (int, error) {
	// Try to parse and compact JSON responses
	var data interface{}
	if err := json.Unmarshal(b, &data); err == nil {
		// Successfully parsed JSON, create compact version
		compactData := w.compactData(data)
		compactBytes, err := json.Marshal(compactData)
		if err == nil {
			return w.ResponseWriter.Write(compactBytes)
		}
	}
	
	// If not JSON or compaction failed, write original data
	return w.ResponseWriter.Write(b)
}

func (w *compactResponseWriter) compactData(data interface{}) interface{} {
	switch v := data.(type) {
	case map[string]interface{}:
		return w.compactObject(v)
	case []interface{}:
		return w.compactArray(v)
	default:
		return data
	}
}

func (w *compactResponseWriter) compactObject(obj map[string]interface{}) map[string]interface{} {
	compact := make(map[string]interface{})
	
	// Define essential fields for different object types
	essentialFields := map[string][]string{
		"cpoe_order": {"id", "patient_id", "order_type", "status", "created_at"},
		"scan_result": {"code", "type", "is_valid", "scanned_at"},
		"medication_admin": {"id", "medication_id", "dose", "administered_at"},
		"lab_result": {"id", "test_name", "result", "status"},
	}

	// Determine object type and extract essential fields
	objectType := w.determineObjectType(obj)
	if fields, exists := essentialFields[objectType]; exists {
		for _, field := range fields {
			if value, exists := obj[field]; exists {
				compact[field] = value
			}
		}
	} else {
		// If type unknown, include all fields but compact nested objects
		for key, value := range obj {
			compact[key] = w.compactData(value)
		}
	}

	return compact
}

func (w *compactResponseWriter) compactArray(arr []interface{}) []interface{} {
	compact := make([]interface{}, len(arr))
	for i, item := range arr {
		compact[i] = w.compactData(item)
	}
	return compact
}

func (w *compactResponseWriter) determineObjectType(obj map[string]interface{}) string {
	if _, exists := obj["order_type"]; exists {
		return "cpoe_order"
	}
	if _, exists := obj["scanned_at"]; exists {
		return "scan_result"
	}
	if _, exists := obj["administered_at"]; exists {
		return "medication_admin"
	}
	if _, exists := obj["test_name"]; exists {
		return "lab_result"
	}
	return "unknown"
}

// Helper methods

func (m *MobileMiddleware) isMobileClient(userAgent string) bool {
	mobileKeywords := []string{
		"Mobile", "Android", "iPhone", "iPad", "iPod",
		"BlackBerry", "Windows Phone", "Opera Mini",
	}
	
	userAgent = strings.ToLower(userAgent)
	for _, keyword := range mobileKeywords {
		if strings.Contains(userAgent, strings.ToLower(keyword)) {
			return true
		}
	}
	
	return false
}

func (m *MobileMiddleware) generateETag(r *http.Request) string {
	// Generate simple ETag based on path and query parameters
	path := r.URL.Path
	query := r.URL.RawQuery
	timestamp := time.Now().Truncate(time.Minute).Unix()
	
	return fmt.Sprintf(`"%s-%s-%d"`, path, query, timestamp)
}

func (m *MobileMiddleware) logMobileMetrics(r *http.Request, w *responseWriter, duration time.Duration, isMobile bool) {
	// Log mobile-specific metrics
	metrics := map[string]interface{}{
		"path":          r.URL.Path,
		"method":        r.Method,
		"status_code":   w.statusCode,
		"response_size": w.responseSize,
		"duration_ms":   duration.Milliseconds(),
		"is_mobile":     isMobile,
		"user_agent":    r.Header.Get("User-Agent"),
	}
	
	// In a real implementation, this would send metrics to a monitoring system
	fmt.Printf("Mobile API Metrics: %+v\n", metrics)
}

// Middleware chain builder

// BuildMobileMiddlewareChain builds the complete mobile middleware chain
func (m *MobileMiddleware) BuildMobileMiddlewareChain(handler http.Handler) http.Handler {
	// Apply middleware in reverse order (last applied is executed first)
	chain := handler
	chain = m.DataMinimizationMiddleware(chain)
	chain = m.BandwidthOptimizationMiddleware(chain)
	chain = m.OfflineMiddleware(chain)
	chain = m.MobileOptimizationMiddleware(chain)
	chain = m.CachingMiddleware(chain)
	chain = m.CompressionMiddleware(chain)
	
	return chain
}