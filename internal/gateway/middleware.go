package gateway

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/medrex/dlt-emr/pkg/types"
)

// UserClaims is an alias for types.UserClaims for convenience
type UserClaims = types.UserClaims

// corsMiddleware handles CORS headers
func (s *Service) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*") // Configure appropriately for production
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware adds security headers
func (s *Service) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs requests and responses
func (s *Service) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a response recorder to capture status code
		recorder := &responseRecorder{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
		}

		next.ServeHTTP(recorder, r)

		duration := time.Since(start)

		s.logger.Info("Request processed",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
			"status_code", recorder.statusCode,
			"duration_ms", duration.Milliseconds(),
		)
	})
}

// authMiddleware validates JWT tokens
func (s *Service) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip authentication for health checks and admin endpoints
		if r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/admin/") {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			s.writeErrorResponse(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		// Check Bearer token format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			s.writeErrorResponse(w, http.StatusUnauthorized, "invalid authorization header format")
			return
		}

		token := parts[1]

		// Validate token
		claims, err := s.ValidateToken(token)
		if err != nil {
			s.logger.Error("Token validation failed", "error", err)
			s.writeErrorResponse(w, http.StatusUnauthorized, "invalid token")
			return
		}

		// Add user claims to request context
		ctx := context.WithValue(r.Context(), "user_claims", claims)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware applies rate limiting
func (s *Service) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip rate limiting for health checks and admin endpoints
		if r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/admin/") {
			next.ServeHTTP(w, r)
			return
		}

		// Get user claims from context
		claims, ok := r.Context().Value("user_claims").(*UserClaims)
		if !ok {
			s.writeErrorResponse(w, http.StatusInternalServerError, "user claims not found in context")
			return
		}

		// Apply rate limiting
		if err := s.ApplyRateLimit(claims.UserID); err != nil {
			s.logger.Warn("Rate limit exceeded", "user_id", claims.UserID, "error", err)
			s.writeErrorResponse(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// responseRecorder captures response status code
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Result() *http.Response {
	return &http.Response{
		StatusCode: r.statusCode,
		Header:     r.ResponseWriter.Header(),
	}
}

// httpResponseWriter implements http.ResponseWriter for response recording
type httpResponseWriter struct {
	header     http.Header
	statusCode int
	body       []byte
}

func (w *httpResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *httpResponseWriter) Write(data []byte) (int, error) {
	w.body = append(w.body, data...)
	return len(data), nil
}

func (w *httpResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
}