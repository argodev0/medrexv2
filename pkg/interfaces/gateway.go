package interfaces

import (
	"net/http"

	"github.com/medrex/dlt-emr/pkg/types"
)

// APIGateway defines the interface for the API Gateway service
type APIGateway interface {
	// Authentication and authorization
	ValidateToken(token string) (*types.UserClaims, error)
	
	// Request routing and handling
	RouteRequest(req *http.Request) (*http.Response, error)
	
	// Rate limiting
	ApplyRateLimit(userID string) error
	CheckRateLimit(userID string) (bool, error)
	
	// Logging and monitoring
	LogRequest(req *http.Request, resp *http.Response)
	
	// Health checks
	HealthCheck() error
	
	// Service management
	Start(addr string) error
	Stop() error
}

// TokenValidator defines the interface for token validation
type TokenValidator interface {
	ValidateJWT(token string) (*types.UserClaims, error)
	RefreshToken(token string) (*types.AuthToken, error)
	RevokeToken(token string) error
}

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	Allow(userID string) (bool, error)
	Reset(userID string) error
	GetLimits(userID string) (int, int, error) // current, limit
}

// RequestRouter defines the interface for request routing
type RequestRouter interface {
	Route(req *http.Request) (string, error) // returns target service URL
	RegisterService(name, url string) error
	UnregisterService(name string) error
	GetHealthyServices() ([]string, error)
}