# Medrex DLT EMR System

A comprehensive Electronic Medical Records system built on Hyperledger Fabric with hybrid blockchain architecture for secure, compliant healthcare data management.

## Architecture Overview

The Medrex DLT EMR system implements a microservices architecture with the following components:

- **API Gateway**: Single entry point for all client requests
- **IAM Service**: Identity and Access Management with Fabric CA integration
- **Clinical Notes Service**: Secure PHI management with off-chain storage
- **Scheduling Service**: Appointment and resource management
- **Mobile Workflow Service**: Mobile-optimized workflows for CPOE and scanning

## Project Structure

```
.
├── cmd/                          # Application entry points
│   ├── api-gateway/             # API Gateway service
│   ├── iam-service/             # IAM service
│   ├── clinical-notes-service/  # Clinical Notes service
│   ├── scheduling-service/      # Scheduling service
│   └── mobile-workflow-service/ # Mobile Workflow service
├── internal/                    # Private application code
│   ├── gateway/                # API Gateway implementation
│   ├── iam/                    # IAM service implementation
│   ├── clinical/               # Clinical Notes implementation
│   ├── scheduling/             # Scheduling implementation
│   └── mobile/                 # Mobile Workflow implementation
├── pkg/                        # Public packages
│   ├── types/                  # Shared data types
│   ├── interfaces/             # Service interfaces
│   ├── config/                 # Configuration management
│   └── logger/                 # Logging utilities
├── chaincode/                  # Hyperledger Fabric chaincodes
│   ├── access-policy/          # Access control chaincode
│   └── audit-log/              # Audit logging chaincode
├── deployments/                # Deployment configurations
│   ├── docker/                 # Docker configurations
│   ├── kubernetes/             # Kubernetes manifests
│   └── terraform/              # Infrastructure as Code
├── scripts/                    # Build and deployment scripts
├── docs/                       # Documentation
└── tests/                      # Test files
```

## Key Features

### Security & Compliance
- HIPAA/GDPR compliant architecture
- PHI stored off-chain with 256-bit AES encryption
- Immutable audit trails on blockchain
- Role-based access control (RBAC)
- X.509 certificate-based authentication

### Blockchain Integration
- Hyperledger Fabric v2.5 LTS with Raft consensus
- Multi-organization support (Hospital, Pharmacy)
- Smart contracts for access control and audit logging
- Proxy Re-Encryption (PRE) for secure key management

### Microservices Architecture
- Container-first design with Docker
- Kubernetes-ready deployment
- Service discovery and load balancing
- Comprehensive monitoring and logging

## Getting Started

### Prerequisites

- Go 1.21 or later
- Docker and Docker Compose
- PostgreSQL 13+
- Redis 6+
- Hyperledger Fabric 2.5 LTS

### Building the Project

```bash
# Download dependencies
make deps

# Run tests
make test

# Build all services
make build

# Build Docker images
make docker-build
```

### Configuration

Configuration is managed through YAML files and environment variables. See `pkg/config/config.go` for available options.

### Running Services

Each service can be run independently:

```bash
# API Gateway
./build/api-gateway

# IAM Service
./build/iam-service

# Clinical Notes Service
./build/clinical-notes-service

# Scheduling Service
./build/scheduling-service

# Mobile Workflow Service
./build/mobile-workflow-service
```

## Development Guidelines

### Code Standards
- Follow Go best practices and conventions
- Maintain 85% minimum test coverage
- Use structured logging for all operations
- Implement comprehensive error handling

### Security Requirements
- Never store PHI on blockchain
- Use HSM for cryptographic operations
- Implement proper input validation
- Follow principle of least privilege

### Testing
- Unit tests for all business logic
- Integration tests for service interactions
- Chaincode tests for smart contracts
- End-to-end tests for user workflows

## Documentation

- [Requirements](/.kiro/specs/medrex-dlt-emr/requirements.md)
- [Design](/.kiro/specs/medrex-dlt-emr/design.md)
- [Implementation Tasks](/.kiro/specs/medrex-dlt-emr/tasks.md)

## License

This project is proprietary software. All rights reserved.