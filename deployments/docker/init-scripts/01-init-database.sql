-- Medrex DLT EMR Database Initialization Script
-- This script sets up the basic database structure for development

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS clinical;
CREATE SCHEMA IF NOT EXISTS scheduling;
CREATE SCHEMA IF NOT EXISTS mobile;
CREATE SCHEMA IF NOT EXISTS audit;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('patient', 'mbbs_student', 'md_student', 'consulting_doctor', 'nurse', 'lab_technician', 'receptionist', 'clinical_staff', 'administrator')),
    organization VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Patients table
CREATE TABLE IF NOT EXISTS clinical.patients (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    mrn VARCHAR(50) UNIQUE NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    gender VARCHAR(20),
    phone VARCHAR(20),
    email VARCHAR(255),
    address JSONB,
    insurance_info JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Clinical notes table (encrypted PHI)
CREATE TABLE IF NOT EXISTS clinical.notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID NOT NULL REFERENCES clinical.patients(id),
    author_id UUID NOT NULL REFERENCES users(id),
    note_type VARCHAR(50) NOT NULL,
    content_encrypted BYTEA NOT NULL,
    content_hash VARCHAR(64) NOT NULL,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Appointments table
CREATE TABLE IF NOT EXISTS scheduling.appointments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID NOT NULL REFERENCES clinical.patients(id),
    provider_id UUID NOT NULL REFERENCES users(id),
    appointment_type VARCHAR(100) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(50) DEFAULT 'scheduled' CHECK (status IN ('scheduled', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show')),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- CPOE Orders table
CREATE TABLE IF NOT EXISTS mobile.cpoe_orders (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    patient_id UUID NOT NULL REFERENCES clinical.patients(id),
    ordering_provider_id UUID NOT NULL REFERENCES users(id),
    co_signing_provider_id UUID REFERENCES users(id),
    order_type VARCHAR(100) NOT NULL,
    order_details JSONB NOT NULL,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'completed', 'cancelled')),
    requires_co_signature BOOLEAN DEFAULT false,
    co_signed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit.system_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100),
    resource_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Blockchain transaction references
CREATE TABLE IF NOT EXISTS audit.blockchain_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    transaction_id VARCHAR(255) UNIQUE NOT NULL,
    chaincode VARCHAR(100) NOT NULL,
    function_name VARCHAR(100) NOT NULL,
    arguments JSONB,
    block_number BIGINT,
    transaction_hash VARCHAR(255),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_patients_mrn ON clinical.patients(mrn);
CREATE INDEX IF NOT EXISTS idx_notes_patient_id ON clinical.notes(patient_id);
CREATE INDEX IF NOT EXISTS idx_notes_author_id ON clinical.notes(author_id);
CREATE INDEX IF NOT EXISTS idx_appointments_patient_id ON scheduling.appointments(patient_id);
CREATE INDEX IF NOT EXISTS idx_appointments_provider_id ON scheduling.appointments(provider_id);
CREATE INDEX IF NOT EXISTS idx_appointments_start_time ON scheduling.appointments(start_time);
CREATE INDEX IF NOT EXISTS idx_cpoe_orders_patient_id ON mobile.cpoe_orders(patient_id);
CREATE INDEX IF NOT EXISTS idx_cpoe_orders_ordering_provider ON mobile.cpoe_orders(ordering_provider_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit.system_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit.system_logs(created_at);

-- Insert sample data for development
INSERT INTO users (username, email, password_hash, role, organization) VALUES
('admin', 'admin@medrex.com', '$2a$10$N9qo8uLOickgx2ZMRZoMye1VdCFyPdL2mpg4f8YzVTwn6r8W8qjqe', 'administrator', 'HospitalOrg'),
('dr.smith', 'dr.smith@hospital.com', '$2a$10$N9qo8uLOickgx2ZMRZoMye1VdCFyPdL2mpg4f8YzVTwn6r8W8qjqe', 'consulting_doctor', 'HospitalOrg'),
('nurse.jane', 'nurse.jane@hospital.com', '$2a$10$N9qo8uLOickgx2ZMRZoMye1VdCFyPdL2mpg4f8YzVTwn6r8W8qjqe', 'nurse', 'HospitalOrg'),
('student.john', 'student.john@medschool.edu', '$2a$10$N9qo8uLOickgx2ZMRZoMye1VdCFyPdL2mpg4f8YzVTwn6r8W8qjqe', 'md_student', 'HospitalOrg'),
('patient.doe', 'john.doe@email.com', '$2a$10$N9qo8uLOickgx2ZMRZoMye1VdCFyPdL2mpg4f8YzVTwn6r8W8qjqe', 'patient', 'HospitalOrg')
ON CONFLICT (username) DO NOTHING;

-- Insert sample patient
INSERT INTO clinical.patients (mrn, first_name, last_name, date_of_birth, gender, phone, email) VALUES
('MRN001', 'John', 'Doe', '1980-01-15', 'Male', '+1-555-0123', 'john.doe@email.com'),
('MRN002', 'Jane', 'Smith', '1975-05-20', 'Female', '+1-555-0124', 'jane.smith@email.com')
ON CONFLICT (mrn) DO NOTHING;

-- Create a function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_patients_updated_at BEFORE UPDATE ON clinical.patients FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_notes_updated_at BEFORE UPDATE ON clinical.notes FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_appointments_updated_at BEFORE UPDATE ON scheduling.appointments FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_cpoe_orders_updated_at BEFORE UPDATE ON mobile.cpoe_orders FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();