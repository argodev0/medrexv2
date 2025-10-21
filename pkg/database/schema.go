package database

import (
	"context"
	"fmt"
)

// CreateSchema creates the database schema for PHI storage
func (db *DB) CreateSchema(ctx context.Context) error {
	db.logger.Info("Creating database schema...")

	// Create extension for UUID generation
	if err := db.createExtensions(ctx); err != nil {
		return fmt.Errorf("failed to create extensions: %w", err)
	}

	// Create tables
	tables := []string{
		createPatientsTable,
		createClinicalNotesTable,
		createAppointmentsTable,
		createProvidersTable,
		createCPOEOrdersTable,
		createAuditLogsTable,
		createUsersTable,
		createEncryptionKeysTable,
	}

	for _, table := range tables {
		if _, err := db.ExecContext(ctx, table); err != nil {
			return fmt.Errorf("failed to create table: %w", err)
		}
	}

	// Create indexes
	indexes := []string{
		createPatientsIndexes,
		createClinicalNotesIndexes,
		createAppointmentsIndexes,
		createProvidersIndexes,
		createCPOEOrdersIndexes,
		createAuditLogsIndexes,
		createUsersIndexes,
	}

	for _, index := range indexes {
		if _, err := db.ExecContext(ctx, index); err != nil {
			return fmt.Errorf("failed to create indexes: %w", err)
		}
	}

	db.logger.Info("Database schema created successfully")
	return nil
}

// createExtensions creates required PostgreSQL extensions
func (db *DB) createExtensions(ctx context.Context) error {
	extensions := []string{
		`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`,
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`,
	}

	for _, ext := range extensions {
		if _, err := db.ExecContext(ctx, ext); err != nil {
			return fmt.Errorf("failed to create extension: %w", err)
		}
	}

	return nil
}

// SQL DDL statements for table creation
const (
	createPatientsTable = `
		CREATE TABLE IF NOT EXISTS patients (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			mrn VARCHAR(50) UNIQUE NOT NULL,
			encrypted_demographics BYTEA NOT NULL,
			encrypted_insurance BYTEA,
			data_hash VARCHAR(64) NOT NULL,
			encryption_key_id UUID NOT NULL,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_by UUID NOT NULL,
			updated_by UUID NOT NULL
		);`

	createClinicalNotesTable = `
		CREATE TABLE IF NOT EXISTS clinical_notes (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			patient_id UUID NOT NULL REFERENCES patients(id),
			author_id UUID NOT NULL,
			note_type VARCHAR(50) NOT NULL,
			encrypted_content BYTEA NOT NULL,
			content_hash VARCHAR(64) NOT NULL,
			encrypted_metadata BYTEA,
			encryption_key_id UUID NOT NULL,
			blockchain_tx_id VARCHAR(100),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			version INTEGER DEFAULT 1,
			is_deleted BOOLEAN DEFAULT FALSE
		);`

	createAppointmentsTable = `
		CREATE TABLE IF NOT EXISTS appointments (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			patient_id UUID NOT NULL REFERENCES patients(id),
			provider_id UUID NOT NULL,
			appointment_type VARCHAR(50) NOT NULL,
			start_time TIMESTAMP WITH TIME ZONE NOT NULL,
			end_time TIMESTAMP WITH TIME ZONE NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'scheduled',
			location VARCHAR(200),
			encrypted_notes BYTEA,
			encryption_key_id UUID,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			created_by UUID NOT NULL,
			updated_by UUID NOT NULL
		);`

	createProvidersTable = `
		CREATE TABLE IF NOT EXISTS providers (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID NOT NULL UNIQUE,
			specialty VARCHAR(100) NOT NULL,
			license_number VARCHAR(50) UNIQUE NOT NULL,
			department VARCHAR(100) NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`

	createCPOEOrdersTable = `
		CREATE TABLE IF NOT EXISTS cpoe_orders (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			patient_id UUID NOT NULL REFERENCES patients(id),
			ordering_provider_id UUID NOT NULL,
			co_signing_provider_id UUID,
			order_type VARCHAR(50) NOT NULL,
			encrypted_details BYTEA NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'pending',
			requires_co_signature BOOLEAN DEFAULT FALSE,
			co_signed_at TIMESTAMP WITH TIME ZONE,
			encryption_key_id UUID NOT NULL,
			blockchain_tx_id VARCHAR(100),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`

	createAuditLogsTable = `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			user_id UUID NOT NULL,
			action VARCHAR(100) NOT NULL,
			resource_type VARCHAR(50) NOT NULL,
			resource_id UUID,
			encrypted_details BYTEA,
			ip_address INET,
			user_agent TEXT,
			success BOOLEAN NOT NULL,
			error_message TEXT,
			blockchain_tx_id VARCHAR(100),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`

	createUsersTable = `
		CREATE TABLE IF NOT EXISTS users (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			username VARCHAR(100) UNIQUE NOT NULL,
			encrypted_email BYTEA NOT NULL,
			role VARCHAR(50) NOT NULL,
			organization_id VARCHAR(100) NOT NULL,
			fabric_cert_id VARCHAR(200),
			encrypted_personal_info BYTEA,
			encryption_key_id UUID NOT NULL,
			is_active BOOLEAN DEFAULT TRUE,
			last_login TIMESTAMP WITH TIME ZONE,
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
		);`

	createEncryptionKeysTable = `
		CREATE TABLE IF NOT EXISTS encryption_keys (
			id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
			key_type VARCHAR(20) NOT NULL,
			encrypted_key BYTEA NOT NULL,
			key_version INTEGER NOT NULL DEFAULT 1,
			hsm_key_id VARCHAR(200),
			created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
			expires_at TIMESTAMP WITH TIME ZONE,
			is_active BOOLEAN DEFAULT TRUE
		);`
)

// SQL DDL statements for index creation
const (
	createPatientsIndexes = `
		CREATE INDEX IF NOT EXISTS idx_patients_mrn ON patients(mrn);
		CREATE INDEX IF NOT EXISTS idx_patients_created_at ON patients(created_at);
		CREATE INDEX IF NOT EXISTS idx_patients_data_hash ON patients(data_hash);`

	createClinicalNotesIndexes = `
		CREATE INDEX IF NOT EXISTS idx_clinical_notes_patient_id ON clinical_notes(patient_id);
		CREATE INDEX IF NOT EXISTS idx_clinical_notes_author_id ON clinical_notes(author_id);
		CREATE INDEX IF NOT EXISTS idx_clinical_notes_created_at ON clinical_notes(created_at);
		CREATE INDEX IF NOT EXISTS idx_clinical_notes_note_type ON clinical_notes(note_type);
		CREATE INDEX IF NOT EXISTS idx_clinical_notes_content_hash ON clinical_notes(content_hash);`

	createAppointmentsIndexes = `
		CREATE INDEX IF NOT EXISTS idx_appointments_patient_id ON appointments(patient_id);
		CREATE INDEX IF NOT EXISTS idx_appointments_provider_id ON appointments(provider_id);
		CREATE INDEX IF NOT EXISTS idx_appointments_start_time ON appointments(start_time);
		CREATE INDEX IF NOT EXISTS idx_appointments_status ON appointments(status);`

	createProvidersIndexes = `
		CREATE INDEX IF NOT EXISTS idx_providers_user_id ON providers(user_id);
		CREATE INDEX IF NOT EXISTS idx_providers_specialty ON providers(specialty);
		CREATE INDEX IF NOT EXISTS idx_providers_department ON providers(department);
		CREATE INDEX IF NOT EXISTS idx_providers_license_number ON providers(license_number);`

	createCPOEOrdersIndexes = `
		CREATE INDEX IF NOT EXISTS idx_cpoe_orders_patient_id ON cpoe_orders(patient_id);
		CREATE INDEX IF NOT EXISTS idx_cpoe_orders_ordering_provider ON cpoe_orders(ordering_provider_id);
		CREATE INDEX IF NOT EXISTS idx_cpoe_orders_status ON cpoe_orders(status);
		CREATE INDEX IF NOT EXISTS idx_cpoe_orders_created_at ON cpoe_orders(created_at);`

	createAuditLogsIndexes = `
		CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs(resource_type);
		CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);`

	createUsersIndexes = `
		CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
		CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
		CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id);
		CREATE INDEX IF NOT EXISTS idx_users_fabric_cert_id ON users(fabric_cert_id);`
)