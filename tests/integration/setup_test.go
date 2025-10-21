// +build integration

package integration

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	_ "github.com/lib/pq"
)

var (
	testDB       *sql.DB
	testDBURL    string
	fabricClient *FabricTestClient
)

// TestMain sets up the test environment
func TestMain(m *testing.M) {
	ctx := context.Background()
	
	// Setup test database
	if err := setupTestDatabase(ctx); err != nil {
		log.Fatalf("Failed to setup test database: %v", err)
	}
	
	// Setup Fabric network
	if err := setupFabricNetwork(ctx); err != nil {
		log.Fatalf("Failed to setup Fabric network: %v", err)
	}
	
	// Run tests
	code := m.Run()
	
	// Cleanup
	cleanup(ctx)
	
	os.Exit(code)
}

// setupTestDatabase creates a PostgreSQL container for testing
func setupTestDatabase(ctx context.Context) error {
	req := testcontainers.ContainerRequest{
		Image:        "postgres:15",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_DB":       "medrex_test",
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "testpass",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}
	
	postgres, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return fmt.Errorf("failed to start postgres container: %w", err)
	}
	
	host, err := postgres.Host(ctx)
	if err != nil {
		return fmt.Errorf("failed to get postgres host: %w", err)
	}
	
	port, err := postgres.MappedPort(ctx, "5432")
	if err != nil {
		return fmt.Errorf("failed to get postgres port: %w", err)
	}
	
	testDBURL = fmt.Sprintf("postgres://test:testpass@%s:%s/medrex_test?sslmode=disable", host, port.Port())
	
	// Connect to database
	testDB, err = sql.Open("postgres", testDBURL)
	if err != nil {
		return fmt.Errorf("failed to connect to test database: %w", err)
	}
	
	// Wait for database to be ready
	for i := 0; i < 30; i++ {
		if err := testDB.Ping(); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	
	// Create test schema
	if err := createTestSchema(); err != nil {
		return fmt.Errorf("failed to create test schema: %w", err)
	}
	
	return nil
}

// setupFabricNetwork sets up a test Fabric network
func setupFabricNetwork(ctx context.Context) error {
	// For integration tests, we'll use a simplified Fabric setup
	// In a real scenario, this would start the full Fabric network
	fabricClient = &FabricTestClient{
		accessPolicies: make(map[string]*AccessPolicy),
		auditLogs:      make([]*AuditLogEntry, 0),
	}
	
	// Initialize with test data
	fabricClient.InitializeTestData()
	
	return nil
}

// createTestSchema creates the database schema for testing
func createTestSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(255) UNIQUE NOT NULL,
		email VARCHAR(255) UNIQUE NOT NULL,
		role VARCHAR(50) NOT NULL,
		organization VARCHAR(255) NOT NULL,
		certificate TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS patients (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		mrn VARCHAR(50) UNIQUE NOT NULL,
		first_name VARCHAR(255) NOT NULL,
		last_name VARCHAR(255) NOT NULL,
		date_of_birth DATE NOT NULL,
		gender VARCHAR(10),
		phone VARCHAR(20),
		email VARCHAR(255),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS clinical_notes (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		patient_id UUID REFERENCES patients(id),
		author_id UUID REFERENCES users(id),
		content TEXT NOT NULL,
		content_hash VARCHAR(64) NOT NULL,
		encrypted BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS appointments (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		patient_id UUID REFERENCES patients(id),
		provider_id UUID REFERENCES users(id),
		start_time TIMESTAMP NOT NULL,
		end_time TIMESTAMP NOT NULL,
		type VARCHAR(100) NOT NULL,
		status VARCHAR(50) DEFAULT 'scheduled',
		notes TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS cpoe_orders (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		patient_id UUID REFERENCES patients(id),
		ordering_md UUID REFERENCES users(id),
		co_signing_md UUID REFERENCES users(id),
		order_type VARCHAR(100) NOT NULL,
		details TEXT NOT NULL,
		status VARCHAR(50) DEFAULT 'pending',
		requires_co_sign BOOLEAN DEFAULT false,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`
	
	_, err := testDB.Exec(schema)
	return err
}

// cleanup cleans up test resources
func cleanup(ctx context.Context) {
	if testDB != nil {
		testDB.Close()
	}
}

// FabricTestClient is a mock Fabric client for testing
type FabricTestClient struct {
	accessPolicies map[string]*AccessPolicy
	auditLogs      []*AuditLogEntry
}

// AccessPolicy represents an access policy
type AccessPolicy struct {
	ID           string            `json:"id"`
	ResourceType string            `json:"resource_type"`
	UserRole     string            `json:"user_role"`
	Actions      []string          `json:"actions"`
	Conditions   map[string]string `json:"conditions"`
}

// AuditLogEntry represents an audit log entry
type AuditLogEntry struct {
	ID         string                 `json:"id"`
	UserID     string                 `json:"user_id"`
	Action     string                 `json:"action"`
	ResourceID string                 `json:"resource_id"`
	Timestamp  time.Time              `json:"timestamp"`
	Success    bool                   `json:"success"`
	Details    map[string]interface{} `json:"details"`
}

// InitializeTestData initializes the test client with sample data
func (f *FabricTestClient) InitializeTestData() {
	// Add test access policies
	f.accessPolicies["policy1"] = &AccessPolicy{
		ID:           "policy1",
		ResourceType: "clinical_notes",
		UserRole:     "consulting_doctor",
		Actions:      []string{"read", "write", "update"},
		Conditions:   map[string]string{"department": "cardiology"},
	}
	
	f.accessPolicies["policy2"] = &AccessPolicy{
		ID:           "policy2",
		ResourceType: "clinical_notes",
		UserRole:     "md_student",
		Actions:      []string{"read"},
		Conditions:   map[string]string{"supervised": "true"},
	}
}

// CheckAccess simulates access policy checking
func (f *FabricTestClient) CheckAccess(userRole, resourceType, action string) bool {
	for _, policy := range f.accessPolicies {
		if policy.UserRole == userRole && policy.ResourceType == resourceType {
			for _, allowedAction := range policy.Actions {
				if allowedAction == action {
					return true
				}
			}
		}
	}
	return false
}

// LogAuditEvent simulates audit logging
func (f *FabricTestClient) LogAuditEvent(userID, action, resourceID string, success bool, details map[string]interface{}) {
	entry := &AuditLogEntry{
		ID:         fmt.Sprintf("audit_%d", len(f.auditLogs)+1),
		UserID:     userID,
		Action:     action,
		ResourceID: resourceID,
		Timestamp:  time.Now(),
		Success:    success,
		Details:    details,
	}
	f.auditLogs = append(f.auditLogs, entry)
}

// GetAuditLogs returns all audit logs
func (f *FabricTestClient) GetAuditLogs() []*AuditLogEntry {
	return f.auditLogs
}