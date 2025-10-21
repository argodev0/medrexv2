package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/medrex/dlt-emr/internal/scheduling"
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

	// Initialize Scheduling Service
	service := scheduling.New(cfg, logger)
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8083"
	}

	// Start service in a goroutine
	go func() {
		logger.Infof("Starting Scheduling Service on port %s", port)
		if err := service.Start(":" + port); err != nil {
			logger.Fatalf("Failed to start Scheduling Service: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down Scheduling Service...")
	if err := service.Stop(); err != nil {
		logger.Errorf("Error during shutdown: %v", err)
	}
	logger.Info("Scheduling Service stopped")
}