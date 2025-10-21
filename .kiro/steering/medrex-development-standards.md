---
inclusion: always
---

# Medrex Development Standards and Guidelines

## Language and Technology Mandates

### Backend Development
- **Mandatory Language**: Go for all backend microservices and chaincode
- **Performance Requirement**: Optimize for high performance and minimal latency
- **Database**: PostgreSQL with mandatory 256-bit AES encryption at rest
- **DLT Platform**: Hyperledger Fabric v2.5 LTS with Raft consensus

### Frontend Development
- **Web Portal**: React
- **Mobile Applications**: React Native
- **Authentication**: OAuth 2.0/JWT validation

## Security and Compliance Requirements

### PHI Handling
- **Critical Rule**: PHI MUST NEVER be stored on blockchain ledger
- **Storage Location**: PHI resides exclusively in encrypted PostgreSQL database
- **On-Chain Data**: Only cryptographic hashes (SHA-256), metadata, and access policies
- **Encryption**: 256-bit AES encryption at rest for all PHI data

### Key Management
- **HSM Integration**: Use managed Hardware Security Module (e.g., Azure Key Vault Premium)
- **Encryption Method**: Implement Proxy Re-Encryption (PRE) principles
- **Certificate Management**: X.509 certificates with organizational role attributes

### Compliance Standards
- **HIPAA Compliance**: All PHI handling must meet HIPAA requirements
- **GDPR Compliance**: Implement data protection by design principles
- **Audit Requirements**: Immutable audit trails for all system activities

## Code Quality Standards

### Testing Requirements
- **Minimum Coverage**: 85% unit test coverage for all microservices
- **Test Types**: Unit tests, integration tests, chaincode tests
- **Security Testing**: Validate RBAC enforcement and encryption workflows

### Code Review Process
- **Chaincode Review**: All smart contracts require mandatory human review
- **Expert Co-signature**: Required before deployment to staging environment
- **Traceability**: All code commits must include agent identity and timestamps

### Development Practices
- **Container-First**: All services must be containerized
- **Cloud-Native**: Follow microservices architecture patterns
- **Infrastructure as Code**: Use Kubernetes, Docker Compose, and Terraform

## Architecture Guidelines

### Microservices Design
- **Single Responsibility**: Each service handles one business domain
- **API Gateway Pattern**: Single entry point for all client requests
- **Service Communication**: Use secure inter-service communication
- **Rate Limiting**: Implement appropriate rate limiting and throttling

### Hyperledger Fabric Network
- **Minimum Nodes**: Three ordering nodes for fault tolerance
- **Organizations**: Support multiple organizations (HospitalOrg, PharmacyOrg)
- **Consensus**: Use Raft consensus mechanism
- **State Database**: CouchDB for world state storage

### Data Flow Architecture
1. Client requests through API Gateway
2. Authentication via IAM Service
3. Authorization check against AccessPolicy Chaincode
4. PHI access via Clinical Notes Service (if authorized)
5. All activities logged via AuditLog Chaincode

## Role-Based Access Control Implementation

### Access Matrix Enforcement
- Extract user roles from X.509 certificate attributes
- Validate permissions against stored RBAC policies
- Release PRE tokens only upon successful authorization
- Log all access attempts for audit compliance

### User Role Categories
1. **Patient**: Own EHR access, appointment scheduling
2. **Students**: Supervised access with restrictions
3. **Physicians**: Full clinical access based on role level
4. **Staff**: Role-specific access to relevant data
5. **Administrators**: System management capabilities

## Deployment and Operations

### Environment Management
- **Development**: Local Docker Compose setup
- **Staging**: Kubernetes cluster with full HF network
- **Production**: Enterprise-grade deployment with HSM integration

### Monitoring and Alerting
- **Performance Monitoring**: Track microservice performance metrics
- **Security Monitoring**: Monitor for unauthorized access attempts
- **Audit Monitoring**: Ensure audit log completeness and integrity

### Backup and Recovery
- **Database Backups**: Encrypted backups of PostgreSQL PHI data
- **Blockchain State**: Regular snapshots of HF network state
- **Key Recovery**: Secure key backup and recovery procedures

## Development Workflow

### Code Development
1. Follow Go best practices and conventions
2. Implement comprehensive error handling
3. Use structured logging for debugging and monitoring
4. Write tests alongside implementation code

### Deployment Process
1. Code review and approval
2. Automated testing pipeline
3. Security scanning and validation
4. Staged deployment with rollback capability

### Documentation Requirements
- **API Documentation**: Complete OpenAPI specifications
- **Architecture Documentation**: System design and data flow diagrams
- **Deployment Documentation**: Step-by-step deployment guides
- **User Documentation**: Role-specific user guides