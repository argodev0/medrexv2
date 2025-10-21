package gateway

// This package implements the API Gateway service for the Medrex DLT EMR system.
// The gateway provides:
// - OAuth 2.0/JWT token validation
// - Request routing to microservices  
// - Rate limiting and throttling
// - CORS handling and security headers
// - Request/response logging for audit trails
// - Health check endpoints