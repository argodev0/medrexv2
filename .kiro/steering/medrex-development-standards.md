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
- **MVCC Conflict Mitigation**: Implement sophisticated Composite Key Design Strategy
- **Performance Optimization**: Target 1000+ TPS with >95% transaction goodput
- **Post-Quantum Readiness**: Implement quantum-resistant cryptography using ML-KEM and ML-DSA

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

### Nine-Role Hierarchical RBAC System
The system MUST implement a sophisticated nine-role hierarchical access control system with Attribute-Based Access Control (ABAC) integration:

1. **Patient**: Own EHR access, appointment scheduling, secure communications
2. **MBBS UG Student/Intern**: Query de-identified data, read_training_data=true attribute
3. **MD/MS PG Student/Intern**: Propose CPOE with is_trainee=true, requires Faculty co-signature
4. **Consulting Doctor/Faculty**: Write Clinical Notes, full CPOE, is_supervisor=true attribute
5. **Nursing Staff**: Log Medication Administration, ward assignment attributes
6. **Lab Technician**: Submit Lab Result Hash, lab organization attributes
7. **Receptionist/Front Desk**: Patient Registration via IAM, hf.Registrar.Roles attribute
8. **Clinical/Paraclinical Staff**: Order Specialized Service, specialty_code attribute
9. **Administrative (C-Suite)**: Update MSP/Channel Config, hf.Admin=true attribute

### Advanced Access Control Features
- **NodeOU Mapping**: Use Node Organizational Units for identity classification (e.g., Client-Doctor-Faculty)
- **ABAC Integration**: Embed attribute name/value pairs in X.509 Enrollment Certificates
- **State-Based Endorsement (SBE)**: Implement complex workflow governance for clinical supervision
- **Certificate Attributes**: Extract roles and attributes using Client Identity Chaincode Library
- **Least Privilege Principle**: Ensure doctors only access assigned patients through ABAC attributes

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
## 
Performance and Scalability Requirements

### MVCC Conflict Mitigation Strategies
- **Composite Key Design**: Implement intelligent key structures to minimize collisions
- **Key Separation**: Separate high-contention data (vitals, financial) into distinct key spaces
- **Time-Series Keys**: Use timestamp-based keys for append-only operations
- **Dependency Analysis**: Implement transaction dependency flagging during endorsement
- **DAG Block Construction**: Optimize block construction using Directed Acyclic Graph principles

### Chaincode Performance Guidelines
```go
// Example key structures for MVCC mitigation:
// Patient Master Hash: PMH:{PatientID}
// Financial Balance: FINANCE:{PatientID}:BALANCE
// Vitals Stream: VITAL:{PatientID}:{DeviceID}:{Timestamp}
// Appointment Status: APPOINTMENT:{ApptID}
```

### Performance Targets
- **Throughput**: Minimum 1000 transactions per second (TPS)
- **Goodput**: Maintain >95% successful transaction rate
- **Latency**: Sub-second response times for PHI access
- **Availability**: 99.9% uptime for clinical operations

## Advanced Security Requirements

### Post-Quantum Cryptography Implementation
- **Algorithm Selection**: Use NIST-approved ML-KEM and ML-DSA algorithms
- **Hybrid Approach**: Implement dual classical/post-quantum cryptographic schemes
- **Migration Strategy**: Plan phased migration from classical to quantum-resistant algorithms
- **Library Integration**: Use liboqs library for standardized implementations
- **Performance Optimization**: Minimize impact on clinical workflow performance

### State-Based Endorsement (SBE) Policies
- **Clinical Governance**: Implement SBE for complex clinical workflows
- **Trainee Supervision**: Require Faculty co-signature for PG Student CPOE orders
- **Dynamic Policies**: Apply SBE policies to specific ledger keys based on context
- **Non-Repudiation**: Ensure cryptographic binding of supervisory actions

### Hardware Security Module (HSM) Integration
- **FIPS 140-2 Level 3**: Use certified HSMs for critical key management
- **Key Protection**: Secure master keys for PHI encryption and transaction signing
- **Automated Rotation**: Implement automated key rotation policies
- **Cryptographic Erasure**: Support GDPR "Right to Erasure" through key destruction

## API Gateway Security Architecture

### Server-Side Facade Pattern
- **Credential Isolation**: Never expose Fabric SDK credentials to client applications
- **Identity Orchestration**: Map external OAuth/JWT identities to Fabric X.509 certificates
- **Hybrid Workflow Management**: Orchestrate multi-step PHI retrieval processes
- **Mutual TLS**: Implement mTLS for Gateway-to-Fabric communication

### Security Layers
1. **Client-to-Gateway**: TLS 1.3 for all external communications
2. **Gateway-to-Services**: Secure inter-service communication
3. **Service-to-Fabric**: Mutual TLS with certificate validation
4. **Fabric-to-Database**: Encrypted connections with PRE token validation

## Compliance and Audit Enhancement

### Immutable Audit Trails
- **Comprehensive Logging**: Log all user activities and system events on blockchain
- **Non-Repudiation**: Cryptographically sign all audit entries
- **Real-Time Monitoring**: Implement real-time security monitoring and alerting
- **Regulatory Reporting**: Automated compliance report generation

### Data Classification and Handling
- **PHI Classification**: Implement four-level PHI classification system
- **Handling Procedures**: Automated data classification and labeling
- **Transmission Controls**: Appropriate controls for each classification level
- **Disposal Procedures**: Secure data disposal through cryptographic erasure

## Development and Testing Standards

### Chaincode Development Best Practices
- **Deterministic Logic**: Ensure chaincode functions are deterministic
- **Input Validation**: Comprehensive validation of all input parameters
- **Error Handling**: Implement robust error handling and logging
- **Security Review**: Mandatory security review for all chaincode
- **Performance Testing**: Test under high-contention scenarios

### Testing Requirements
- **Unit Testing**: Minimum 85% code coverage with comprehensive test suites
- **Integration Testing**: Test blockchain network interactions and cross-service communication
- **Performance Testing**: Validate MVCC mitigation strategies under load
- **Security Testing**: Comprehensive security validation including penetration testing
- **Compliance Testing**: Validate HIPAA/GDPR compliance across all workflows