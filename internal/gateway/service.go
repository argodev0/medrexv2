package gateway

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/medrex/dlt-emr/pkg/interfaces"
	"github.com/medrex/dlt-emr/pkg/logger"
)

// Service implements the API Gateway
type Service struct {
	router           *mux.Router
	server           *http.Server
	rateLimiter      interfaces.RateLimiter
	tokenValidator   interfaces.TokenValidator
	services         map[string]*url.URL
	servicesMux      sync.RWMutex
	logger           logger.Logger
	jwtSecret        []byte
	metricsCollector *MetricsCollector
	startTime        time.Time
}

// Config holds the gateway configuration
type Config struct {
	Port         string
	JWTSecret    string
	RateLimit    int
	RatePeriod   time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// NewService creates a new API Gateway service
func NewService(config *Config, rateLimiter interfaces.RateLimiter, logger logger.Logger) *Service {
	s := &Service{
		router:           mux.NewRouter(),
		rateLimiter:      rateLimiter,
		services:         make(map[string]*url.URL),
		logger:           logger,
		jwtSecret:        []byte(config.JWTSecret),
		metricsCollector: NewMetricsCollector(),
		startTime:        time.Now(),
	}

	s.tokenValidator = NewTokenValidator(config.JWTSecret)
	s.setupRoutes()
	s.setupMiddleware()

	s.server = &http.Server{
		Addr:         ":" + config.Port,
		Handler:      s.router,
		ReadTimeout:  config.ReadTimeout,
		WriteTimeout: config.WriteTimeout,
	}

	return s
}

// ValidateToken validates JWT token and returns user claims
func (s *Service) ValidateToken(tokenString string) (*UserClaims, error) {
	return s.tokenValidator.ValidateJWT(tokenString)
}

// RouteRequest routes the request to appropriate microservice
func (s *Service) RouteRequest(req *http.Request) (*http.Response, error) {
	serviceName := s.extractServiceName(req.URL.Path)
	if serviceName == "" {
		return nil, fmt.Errorf("unable to determine target service")
	}

	s.servicesMux.RLock()
	targetURL, exists := s.services[serviceName]
	s.servicesMux.RUnlock()

	if !exists {
		return nil, fmt.Errorf("service %s not registered", serviceName)
	}

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	
	// Modify request path to remove service prefix
	originalPath := req.URL.Path
	req.URL.Path = strings.TrimPrefix(originalPath, "/api/v1/"+serviceName)
	if req.URL.Path == "" {
		req.URL.Path = "/"
	}

	// Create response recorder to capture response
	recorder := &responseRecorder{
		ResponseWriter: &httpResponseWriter{},
		statusCode:     http.StatusOK,
	}

	proxy.ServeHTTP(recorder, req)

	// Restore original path
	req.URL.Path = originalPath

	return recorder.Result(), nil
}

// ApplyRateLimit applies rate limiting for a user
func (s *Service) ApplyRateLimit(userID string) error {
	allowed, err := s.rateLimiter.Allow(userID)
	if err != nil {
		return fmt.Errorf("rate limit check failed: %w", err)
	}
	if !allowed {
		return fmt.Errorf("rate limit exceeded for user %s", userID)
	}
	return nil
}

// LogRequest logs the request and response for audit trails
func (s *Service) LogRequest(req *http.Request, resp *http.Response) {
	s.logger.Info("API Gateway Request",
		"method", req.Method,
		"path", req.URL.Path,
		"remote_addr", req.RemoteAddr,
		"user_agent", req.UserAgent(),
		"status_code", resp.StatusCode,
		"content_length", resp.ContentLength,
	)
}

// HealthCheck performs health check
func (s *Service) HealthCheck() error {
	// Check if all registered services are healthy
	s.servicesMux.RLock()
	defer s.servicesMux.RUnlock()

	for name, serviceURL := range s.services {
		healthURL := fmt.Sprintf("%s/health", serviceURL.String())
		resp, err := http.Get(healthURL)
		if err != nil || resp.StatusCode != http.StatusOK {
			return fmt.Errorf("service %s is unhealthy", name)
		}
		resp.Body.Close()
	}

	return nil
}

// Start starts the API Gateway server
func (s *Service) Start(addr string) error {
	if addr != "" {
		s.server.Addr = addr
	}

	s.logger.Info("Starting API Gateway", "addr", s.server.Addr)
	return s.server.ListenAndServe()
}

// Stop stops the API Gateway server
func (s *Service) Stop() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s.logger.Info("Stopping API Gateway")
	return s.server.Shutdown(ctx)
}

// RegisterService registers a microservice
func (s *Service) RegisterService(name, serviceURL string) error {
	parsedURL, err := url.Parse(serviceURL)
	if err != nil {
		return fmt.Errorf("invalid service URL: %w", err)
	}

	s.servicesMux.Lock()
	s.services[name] = parsedURL
	s.servicesMux.Unlock()

	s.logger.Info("Registered service", "name", name, "url", serviceURL)
	return nil
}

// UnregisterService unregisters a microservice
func (s *Service) UnregisterService(name string) error {
	s.servicesMux.Lock()
	delete(s.services, name)
	s.servicesMux.Unlock()

	s.logger.Info("Unregistered service", "name", name)
	return nil
}

// GetHealthyServices returns list of healthy services
func (s *Service) GetHealthyServices() ([]string, error) {
	var healthy []string

	s.servicesMux.RLock()
	defer s.servicesMux.RUnlock()

	for name, serviceURL := range s.services {
		healthURL := fmt.Sprintf("%s/health", serviceURL.String())
		resp, err := http.Get(healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			healthy = append(healthy, name)
		}
		if resp != nil {
			resp.Body.Close()
		}
	}

	return healthy, nil
}

// extractServiceName extracts service name from URL path
func (s *Service) extractServiceName(path string) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "api" && parts[1] == "v1" {
		return parts[2]
	}
	return ""
}

// setupRoutes sets up the routing
func (s *Service) setupRoutes() {
	// Health check endpoints
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	s.router.HandleFunc("/health/detailed", s.handleDetailedHealth).Methods("GET")
	
	// Metrics endpoint
	s.router.HandleFunc("/metrics", s.handleMetrics).Methods("GET")
	
	// Service management endpoints
	s.router.HandleFunc("/admin/services", s.handleListServices).Methods("GET")
	s.router.HandleFunc("/admin/services/{name}", s.handleRegisterService).Methods("POST")
	s.router.HandleFunc("/admin/services/{name}", s.handleUnregisterService).Methods("DELETE")
	
	// Main API routes - all requests go through the proxy handler
	s.router.PathPrefix("/api/v1/").HandlerFunc(s.handleProxy)
}

// setupMiddleware sets up middleware
func (s *Service) setupMiddleware() {
	s.router.Use(s.corsMiddleware)
	s.router.Use(s.securityHeadersMiddleware)
	s.router.Use(s.metricsMiddleware)
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.authMiddleware)
	s.router.Use(s.rateLimitMiddleware)
}