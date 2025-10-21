package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	
	"github.com/medrex/dlt-emr/internal/clinical"
	"github.com/medrex/dlt-emr/pkg/config"
	"github.com/medrex/dlt-emr/pkg/database"
	"github.com/medrex/dlt-emr/pkg/encryption"
	"github.com/medrex/dlt-emr/pkg/logger"
	"github.com/medrex/dlt-emr/pkg/repository"
)

func main() {
	// Initialize logger
	log := logger.New("clinical-notes-service", "info")
	log.Info("Starting Clinical Notes Service")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load configuration", "error", err)
	}

	// Initialize database connection
	db, err := database.NewConnection(&cfg.Database)
	if err != nil {
		log.Fatal("Failed to connect to database", "error", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatal("Failed to ping database", "error", err)
	}
	log.Info("Database connection established")

	// Initialize encryption service
	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		log.Fatal("ENCRYPTION_KEY environment variable is required")
	}

	aesEncryption, err := encryption.NewAESEncryption(encryptionKey)
	if err != nil {
		log.Fatal("Failed to initialize AES encryption", "error", err)
	}

	// Initialize PRE service (mock HSM and KeyStore for development)
	mockHSM := &MockHSMClient{}
	mockKeyStore := &MockKeyStore{}
	preService := encryption.NewPREService(mockHSM, mockKeyStore)

	// Initialize repositories
	clinicalRepo := repository.NewClinicalNotesRepository(db, aesEncryption, log)
	patientRepo := repository.NewPatientRepository(db, aesEncryption, log)

	// Initialize blockchain client
	blockchainClient := clinical.NewBlockchainClient(&cfg.Fabric, log)

	// Initialize clinical notes service
	clinicalService := clinical.NewClinicalNotesService(
		clinicalRepo,
		patientRepo,
		aesEncryption,
		blockchainClient,
		preService,
		log,
	)

	// Initialize HTTP handlers
	handlers := clinical.NewHandlers(clinicalService, log)

	// Setup HTTP router
	router := mux.NewRouter()
	
	// Add middleware
	router.Use(loggingMiddleware(log))
	router.Use(corsMiddleware)
	
	// Register routes
	apiRouter := router.PathPrefix("/api/v1").Subrouter()
	handlers.RegisterAllRoutes(apiRouter)

	// Setup HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Services.ClinicalNotes.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Info("Starting HTTP server", "port", cfg.Services.ClinicalNotes.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start HTTP server", "error", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down Clinical Notes Service")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Failed to shutdown server gracefully", "error", err)
	}

	log.Info("Clinical Notes Service stopped")
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(log *logger.Logger) mux.MiddlewareFunc {
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