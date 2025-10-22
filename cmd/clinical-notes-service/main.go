package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/sirupsen/logrus"
	
	"github.com/medrex/dlt-emr/internal/clinical"
	"github.com/medrex/dlt-emr/internal/rbac"
	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/database"
	"github.com/medrex/dlt-emr/pkg/encryption"
	pkgLogger "github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/repository"
)

func main() {
	// Initialize logger
	logger := pkgLogger.New("info")
	logger.Info("Starting Clinical Notes Service")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize database connection
	db, err := database.NewConnection(&cfg.Database, logger)
	if err != nil {
		logger.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		logger.Error("Failed to ping database", "error", err)
		os.Exit(1)
	}
	logger.Info("Database connection established")

	// Initialize encryption service
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		logger.Error("ENCRYPTION_KEY environment variable is required")
		os.Exit(1)
	}

	aesEncryption, err := encryption.NewAESEncryption(encryptionKey)
	if err != nil {
		logger.Error("Failed to initialize AES encryption", "error", err)
		os.Exit(1)
	}

	// Initialize PRE service (mock HSM and KeyStore for development)
	mockHSM := &MockHSMClient{}
	mockKeyStore := &MockKeyStore{}
	preService := encryption.NewPREService(mockHSM, mockKeyStore)

	// Initialize repositories
	clinicalRepo := repository.NewClinicalNotesRepository(db.DB, aesEncryption, logger)
	patientRepo := repository.NewPatientRepository(db.DB, aesEncryption, logger)

	// Initialize blockchain client
	blockchainClient := clinical.NewBlockchainClient(&cfg.Fabric, logger)

	// Create RBAC components
	rbacConfig := &rbac.Config{
		CacheTTL:                     time.Hour,
		SupervisionTimeout:           30 * time.Minute,
		CertificateValidity:          24 * time.Hour,
		AuditRetentionDays:           90,
		MaxPolicyVersions:            10,
		EnableEmergencyOverride:      false,
		FabricNetworkConfig:          "",
		DatabaseURL:                  fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s", 
			cfg.Database.User, cfg.Database.Password, cfg.Database.Host, 
			cfg.Database.Port, cfg.Database.Name, cfg.Database.SSLMode),
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
		logger.Error("Failed to create RBAC engine", "error", err)
		os.Exit(1)
	}
	
	auditLogger, err := rbac.NewAuditLogger(rbacConfig, rbacLogger)
	if err != nil {
		logger.Error("Failed to create audit logger", "error", err)
		os.Exit(1)
	}

	// Create encryption service wrapper
	encryptionService := &EncryptionServiceWrapper{aes: aesEncryption}

	// Initialize clinical notes service
	clinicalService := clinical.NewClinicalNotesService(
		clinicalRepo,
		patientRepo,
		encryptionService,
		blockchainClient,
		preService,
		rbacEngine,
		auditLogger,
		logger,
	)

	// Initialize HTTP handlers
	handlers := clinical.NewHandlers(clinicalService, logger)

	// Setup HTTP router
	router := mux.NewRouter()
	
	// Add middleware
	router.Use(loggingMiddleware(logger))
	router.Use(corsMiddleware)
	
	// Register routes
	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	handlers.RegisterAllRoutes(apiRouter)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info("Starting HTTP server", "port", cfg.Server.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start HTTP server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("Shutting down Clinical Notes Service")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("Failed to shutdown server gracefully", "error", err)
	}

	logger.Info("Clinical Notes Service stopped")
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(log pkgLogger.Logger) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// Create a response writer wrapper to capture status code
			wrapper := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			
			next.ServeHTTP(wrapper, r)
			
			log.Info("HTTP request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapper.statusCode,
				"duration", time.Since(start),
				"remote_addr", r.RemoteAddr,
				"user_agent", r.UserAgent(),
			)
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

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// MockHSMClient implements HSMClient interface for development
type MockHSMClient struct{}

func (m *MockHSMClient) GenerateKey(keyType string) (*encryption.HSMKey, error) {
	return &encryption.HSMKey{
		ID:        fmt.Sprintf("mock-hsm-key-%d", time.Now().Unix()),
		Type:      keyType,
		CreatedAt: time.Now(),
	}, nil
}

func (m *MockHSMClient) Sign(keyID string, data []byte) ([]byte, error) {
	// Mock signature
	return []byte(fmt.Sprintf("mock-signature-%s", keyID)), nil
}

func (m *MockHSMClient) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	// Mock decryption - in real implementation, this would use HSM
	return []byte("mock-decrypted-data"), nil
}

func (m *MockHSMClient) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	// Mock public key - in real implementation, this would retrieve from HSM
	return nil, fmt.Errorf("mock HSM: public key retrieval not implemented")
}

// MockKeyStore implements KeyStore interface for development
type MockKeyStore struct {
	keys map[string]*encryption.EncryptionKey
}

func (m *MockKeyStore) StoreKey(key *encryption.EncryptionKey) error {
	if m.keys == nil {
		m.keys = make(map[string]*encryption.EncryptionKey)
	}
	m.keys[key.ID] = key
	return nil
}

func (m *MockKeyStore) GetKey(keyID string) (*encryption.EncryptionKey, error) {
	if m.keys == nil {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	
	key, exists := m.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	
	return key, nil
}

func (m *MockKeyStore) GetActiveKey(userID string) (*encryption.EncryptionKey, error) {
	// Mock active key for user
	return &encryption.EncryptionKey{
		ID:         fmt.Sprintf("mock-key-%s", userID),
		UserID:     userID,
		KeyType:    "RSA-2048",
		HSMKeyID:   fmt.Sprintf("mock-hsm-%s", userID),
		KeyVersion: 1,
		CreatedAt:  time.Now(),
		IsActive:   true,
	}, nil
}

func (m *MockKeyStore) RevokeKey(keyID string) error {
	if m.keys == nil {
		return fmt.Errorf("key not found: %s", keyID)
	}
	
	key, exists := m.keys[keyID]
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}
	
	key.IsActive = false
	return nil
}

// EncryptionServiceWrapper wraps AESEncryption to implement EncryptionService interface
type EncryptionServiceWrapper struct {
	aes *encryption.AESEncryption
}

func (w *EncryptionServiceWrapper) Encrypt(plaintext string) (string, error) {
	encrypted, err := w.aes.Encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return string(encrypted), nil
}

func (w *EncryptionServiceWrapper) Decrypt(ciphertext string) (string, error) {
	decrypted, err := w.aes.Decrypt([]byte(ciphertext))
	if err != nil {
		return "", err
	}
	return string(decrypted), nil
}

func (w *EncryptionServiceWrapper) GenerateKey() (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (w *EncryptionServiceWrapper) RotateKey(oldKey, newKey string) error {
	return fmt.Errorf("not implemented")
}

func (w *EncryptionServiceWrapper) GenerateReEncryptionToken(fromKey, toKey string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (w *EncryptionServiceWrapper) ReEncrypt(ciphertext, token string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (w *EncryptionServiceWrapper) GenerateHash(data string) (string, error) {
	return "", fmt.Errorf("not implemented")
}

func (w *EncryptionServiceWrapper) VerifyHash(data, hash string) (bool, error) {
	return false, fmt.Errorf("not implemented")
}