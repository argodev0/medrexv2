package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/medrex/dlt-emr/pkg/types"
)

func TestCORSMiddleware(t *testing.T) {
	service := createTestService(t)

	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with CORS middleware
	corsHandler := service.corsMiddleware(handler)

	// Test regular request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	corsHandler.ServeHTTP(w, req)

	// Check CORS headers
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("Expected Access-Control-Allow-Origin header")
	}

	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Expected Access-Control-Allow-Methods header")
	}

	if w.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("Expected Access-Control-Allow-Headers header")
	}

	// Test OPTIONS request (preflight)
	req = httptest.NewRequest("OPTIONS", "/test", nil)
	w = httptest.NewRecorder()
	corsHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for OPTIONS request, got %d", w.Code)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	securityHandler := service.securityHeadersMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	securityHandler.ServeHTTP(w, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":   "nosniff",
		"X-Frame-Options":          "DENY",
		"X-XSS-Protection":         "1; mode=block",
		"Strict-Transport-Security": "max-age=31536000; includeSubDomains",
		"Content-Security-Policy":  "default-src 'self'",
		"Referrer-Policy":          "strict-origin-when-cross-origin",
	}

	for header, expectedValue := range expectedHeaders {
		if w.Header().Get(header) != expectedValue {
			t.Errorf("Expected %s header to be '%s', got '%s'", header, expectedValue, w.Header().Get(header))
		}
	}
}

func TestLoggingMiddleware(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	loggingHandler := service.loggingMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// This should not panic and should log the request
	loggingHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	service := createTestService(t)

	// Create a valid token
	claims := &JWTClaims{
		UserID:   "user123",
		Username: "testuser",
		Role:     "consulting_doctor",
		OrgID:    "org123",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test-secret"))

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if user claims are in context
		userClaims, ok := r.Context().Value("user_claims").(*types.UserClaims)
		if !ok {
			t.Error("Expected user claims in context")
			return
		}

		if userClaims.UserID != "user123" {
			t.Errorf("Expected UserID 'user123', got '%s'", userClaims.UserID)
		}

		w.WriteHeader(http.StatusOK)
	})

	authHandler := service.authMiddleware(handler)

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)
	w := httptest.NewRecorder()

	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := service.authMiddleware(handler)

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()

	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := service.authMiddleware(handler)

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestAuthMiddleware_SkipHealthEndpoint(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := service.authMiddleware(handler)

	// Test health endpoint (should skip auth)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for health endpoint, got %d", w.Code)
	}

	// Test admin endpoint (should skip auth)
	req = httptest.NewRequest("GET", "/admin/services", nil)
	w = httptest.NewRecorder()

	authHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for admin endpoint, got %d", w.Code)
	}
}

func TestAuthMiddleware_InvalidAuthHeader(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	authHandler := service.authMiddleware(handler)

	tests := []string{
		"InvalidFormat",
		"Basic dGVzdDp0ZXN0", // Basic auth instead of Bearer
		"Bearer",             // Missing token
	}

	for _, authHeader := range tests {
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req.Header.Set("Authorization", authHeader)
		w := httptest.NewRecorder()

		authHandler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for auth header '%s', got %d", authHeader, w.Code)
		}
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitHandler := service.rateLimitMiddleware(handler)

	// Create user claims in context
	userClaims := &types.UserClaims{
		UserID: "user123",
	}
	ctx := context.WithValue(context.Background(), "user_claims", userClaims)

	// Test rate limiting
	for i := 0; i < 100; i++ { // Should be within limit
		req := httptest.NewRequest("GET", "/api/v1/test", nil)
		req = req.WithContext(ctx)
		w := httptest.NewRecorder()

		rateLimitHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d should be allowed, got status %d", i+1, w.Code)
			break
		}
	}

	// Next request should be rate limited
	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	rateLimitHandler.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429 for rate limited request, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_SkipEndpoints(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitHandler := service.rateLimitMiddleware(handler)

	// Test health endpoint (should skip rate limiting)
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	rateLimitHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for health endpoint, got %d", w.Code)
	}

	// Test admin endpoint (should skip rate limiting)
	req = httptest.NewRequest("GET", "/admin/services", nil)
	w = httptest.NewRecorder()

	rateLimitHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for admin endpoint, got %d", w.Code)
	}
}

func TestRateLimitMiddleware_MissingUserClaims(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rateLimitHandler := service.rateLimitMiddleware(handler)

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	w := httptest.NewRecorder()

	rateLimitHandler.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500 for missing user claims, got %d", w.Code)
	}
}

func TestResponseRecorder(t *testing.T) {
	w := httptest.NewRecorder()
	recorder := &responseRecorder{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}

	// Test WriteHeader
	recorder.WriteHeader(http.StatusCreated)
	if recorder.statusCode != http.StatusCreated {
		t.Errorf("Expected status code 201, got %d", recorder.statusCode)
	}

	// Test Result
	result := recorder.Result()
	if result.StatusCode != http.StatusCreated {
		t.Errorf("Expected result status code 201, got %d", result.StatusCode)
	}
}

func TestMetricsMiddleware(t *testing.T) {
	service := createTestService(t)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond) // Simulate some processing time
		w.WriteHeader(http.StatusOK)
	})

	metricsHandler := service.metricsMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	metricsHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check that metrics were recorded
	metrics := service.metricsCollector.GetMetrics()
	if metrics.RequestCount != 1 {
		t.Errorf("Expected request count 1, got %d", metrics.RequestCount)
	}

	if metrics.StatusCodes[http.StatusOK] != 1 {
		t.Errorf("Expected 1 request with status 200, got %d", metrics.StatusCodes[http.StatusOK])
	}
}