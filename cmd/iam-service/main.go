package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"github.com/medrex/dlt-emr/internal/iam"
	"github.com/medrex/dlt-emr/internal/rbac"
	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/database"
	"github.com/medrex/dlt-emr/pkg/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.New(cfg.LogLevel)
	log.Info("Starting IAM Service", "version", "1.0.0")

	// Initialize database connection
	db, err := database.NewConnection(&cfg.Database, log)
	if err != nil {
		log.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Database schema is already created by init scripts
	log.Info("Database schema already initialized")

	// Initialize IAM components
	passwordManager := iam.NewPasswordManager()
	mfaProvider := iam.NewMFAProvider(log, cfg.JWT.Issuer)
	certManager := iam.NewCertificateManager(&cfg.Fabric, log)
	userRepo := iam.NewUserRepository(db, log)

	// Initialize IAM service
	// Create RBAC components
	rbacConfig := &rbac.Config{
		CacheTTL:                     time.Hour,
		SupervisionTimeout:           30 * time.Minute,
		CertificateValidity:          24 * time.Hour,
		AuditRetentionDays:           90,
		MaxPolicyVersions:            10,
		EnableEmergencyOverride:      false,
		FabricNetworkConfig:          "",
		DatabaseURL:                  "",
		AccessMonitorBufferSize:      1000,
		AlertBufferSize:              100,
		PerformanceBufferSize:        1000,
		DecisionCacheSize:            10000,
		RolePermCacheSize:            5000,
	}
	
	rbacLogger := logrus.New()
	rbacLogger.SetLevel(logrus.InfoLevel)
	
	rbacEngine, err := rbac.NewRBACCoreEngine(rbacConfig, rbacLogger)
	if err != nil {
		log.Error("Failed to create RBAC engine", "error", err)
		os.Exit(1)
	}
	
	abacEngine, err := rbac.NewABACEngine(rbacConfig, rbacLogger, nil)
	if err != nil {
		log.Error("Failed to create ABAC engine", "error", err)
		os.Exit(1)
	}
	
	// Create certificate manager for RBAC
	certManagerConfig := &rbac.CertManagerConfig{
		OrgMSP:         "HospitalOrgMSP",
		CAURL:          "http://localhost:7054",
		TLSEnabled:     false,
		CACertPath:     "",
		ClientCertPath: "",
		ClientKeyPath:  "",
	}
	
	rbacCertManager, err := rbac.NewCertificateManager(certManagerConfig, rbacLogger, nil)
	if err != nil {
		log.Error("Failed to create RBAC certificate manager", "error", err)
		os.Exit(1)
	}

	iamService := iam.NewService(
		cfg,
		log,
		userRepo,
		certManager,
		mfaProvider,
		passwordManager,
		rbacEngine,
		abacEngine,
		rbacCertManager,
	)

	// Initialize HTTP handlers
	handlers := iam.NewHandlers(iamService, log)

	// Setup Gin router
	if cfg.LogLevel != "debug" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Add CORS middleware
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":    "healthy",
			"service":   "iam-service",
			"timestamp": time.Now().UTC(),
		})
	})

	// Register IAM routes
	handlers.RegisterRoutes(router)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Starting HTTP server", "address", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Failed to start HTTP server", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down IAM Service...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
		os.Exit(1)
	}

	log.Info("IAM Service stopped")
}