package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	
	"github.com/medrex/dlt-emr/internal/mobile"
	"github.com/medrex/dlt-emr/pkg/logger"
)

func main() {
	// Initialize logger
	logger := logger.New("mobile-workflow-service")
	
	// Initialize repository (would be properly initialized in production)
	var repo *mobile.Repository = nil

	// Initialize mobile workflow service with nil dependencies for now
	// In production, these would be properly initialized
	service := mobile.NewService(
		repo,
		nil, // barcodeService
		nil, // offlineSync
		nil, // workflowEngine
		nil, // iamService
		nil, // auditService
	)

	// Initialize handlers
	handlers := mobile.NewHandlers(service)

	// Setup router
	router := mux.NewRouter()
	
	// Register mobile workflow routes
	mobileRouter := router.PathPrefix("/api/v1/mobile").Subrouter()
	handlers.RegisterRoutes(mobileRouter)

	// Add middleware
	router.Use(loggingMiddleware(logger))
	router.Use(corsMiddleware)

	// Health check endpoint
	router.HandleFunc("/health", healthCheckHandler).Methods("GET")

	// Get port from environment or use default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8084"
	}

	logger.Info("Starting Mobile Workflow Service", map[string]interface{}{
		"port": port,
	})

	// Start server
	if err := http.ListenAndServe(":"+port, router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(logger *logger.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Info("HTTP Request", map[string]interface{}{
				"method": r.Method,
				"path":   r.URL.Path,
				"remote": r.RemoteAddr,
			})
			next.ServeHTTP(w, r)
		})
	}
}

// corsMiddleware handles CORS headers
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-User-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// healthCheckHandler handles health check requests
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "healthy", "service": "mobile-workflow-service"}`))
}