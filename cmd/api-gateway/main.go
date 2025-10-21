package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/medrex/dlt-emr/internal/gateway"
	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger := logger.New(cfg.LogLevel)

	// Create gateway configuration
	gatewayConfig := &gateway.Config{
		Port:         getEnvOrDefault("GATEWAY_PORT", "8080"),
		JWTSecret:    getEnvOrDefault("JWT_SECRET", "your-secret-key"),
		RateLimit:    100, // 100 requests per period
		RatePeriod:   time.Minute,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// Create rate limiter
	rateLimiter := gateway.NewRateLimiter(gatewayConfig.RateLimit, gatewayConfig.RatePeriod)
	rateLimiter.StartCleanup(time.Hour) // Cleanup every hour

	// Create and configure the gateway service
	gatewayService := gateway.NewService(gatewayConfig, rateLimiter, logger)

	// Register default services (these would typically come from service discovery)
	registerDefaultServices(gatewayService, logger)

	// Start the server in a goroutine
	go func() {
		logger.Info("Starting API Gateway server", "port", gatewayConfig.Port)
		if err := gatewayService.Start(""); err != nil {
			logger.Error("Failed to start server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down API Gateway server...")

	// Graceful shutdown
	if err := gatewayService.Stop(); err != nil {
		logger.Error("Failed to shutdown server gracefully", "error", err)
		os.Exit(1)
	}

	logger.Info("API Gateway server stopped")
}

// registerDefaultServices registers the default microservices
func registerDefaultServices(gateway *gateway.Service, logger logger.Logger) {
	services := map[string]string{
		"iam":              getEnvOrDefault("IAM_SERVICE_URL", "http://localhost:8081"),
		"clinical-notes":   getEnvOrDefault("CLINICAL_NOTES_SERVICE_URL", "http://localhost:8082"),
		"scheduling":       getEnvOrDefault("SCHEDULING_SERVICE_URL", "http://localhost:8083"),
		"mobile-workflow":  getEnvOrDefault("MOBILE_WORKFLOW_SERVICE_URL", "http://localhost:8084"),
	}

	for name, url := range services {
		if err := gateway.RegisterService(name, url); err != nil {
			logger.Error("Failed to register service", "service", name, "url", url, "error", err)
		} else {
			logger.Info("Registered service", "service", name, "url", url)
		}
	}
}

// getEnvOrDefault returns environment variable value or default if not set
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}