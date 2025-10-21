---
inclusion: fileMatch
fileMatchPattern: '*chaincode*|*fabric*|*hyperledger*'
---

# Hyperledger Fabric Development Guidelines

## Network Architecture Requirements

### Ordering Service Configuration
- **Consensus Algorithm**: Raft consensus (mandatory)
- **Minimum Nodes**: 3 ordering nodes for fault tolerance
- **Node Distribution**: Distribute across availability zones
- **TLS Configuration**: Enable mutual TLS for all communications

### Peer Configuration
- **Organizations**: Minimum 2 organizations (HospitalOrg, PharmacyOrg)
- **Peers per Org**: At least 2 peers for redundancy
- **State Database**: CouchDB for rich queries and JSON document support
- **Storage**: High-IOPS storage for performance optimization

### Certificate Authority Setup
- **Dedicated CAs**: One CA per organization
- **Certificate Attributes**: Include organizational roles (Physician, Pharmacist, etc.)
- **Certificate Lifecycle**: Implement certificate renewal and revocation
- **Root CA Security**: Secure root CA private keys with HSM

## Chaincode Development Standards

### AccessPolicy Chaincode Requirements
```go
// Core functions that must be implemented:
// - ValidateUserAccess(userID, resourceID, action) -> bool
// - GetAccessPolicy(resourceType, userRole) -> Policy
// - UpdateAccessPolicy(policy) -> error (admin only)
// - IssueAccessToken(userID, resourceID) -> Token
```

### AuditLog Chaincode Requirements
```go
// Core functions that must be implemented:
// - LogUserActivity(userID, action, resourceID, timestamp) -> error
// - LogSystemEvent(eventType, details, timestamp) -> error
// - QueryAuditLogs(userID, startTime, endTime) -> []AuditEntry
// - GetAuditTrail(resourceID) -> []AuditEntry
```

### Chaincode Security Guidelines
- **Input Validation**: Validate all input parameters
- **Access Control**: Check caller identity and permissions
- **Error Handling**: Implement comprehensive error handling
- **Logging**: Log all significant operations for debugging

### Data Structures
```go
type AccessPolicy struct {
    ResourceType string            `json:"resourceType"`
    UserRole     string            `json:"userRole"`
    Permissions  []string          `json:"permissions"`
    Conditions   map[string]string `json:"conditions"`
}

type AuditEntry struct {
    ID          string    `json:"id"`
    UserID      string    `json:"userID"`
    Action      string    `json:"action"`
    ResourceID  string    `json:"resourceID"`
    Timestamp   time.Time `json:"timestamp"`
    Success     bool      `json:"success"`
    Details     string    `json:"details"`
}
```

## Channel Configuration

### Channel Design
- **Dedicated Channel**: Create dedicated channel for healthcare data
- **Channel Members**: Include all participating organizations
- **Endorsement Policy**: Require endorsement from majority of organizations
- **Private Data**: Use private data collections for sensitive metadata

### Transaction Flow
1. Client submits transaction proposal
2. Peers execute chaincode and return proposal response
3. Client collects endorsements and submits transaction
4. Ordering service orders transactions into blocks
5. Peers validate and commit transactions to ledger

## Integration Patterns

### Off-Chain Data Integration
- **Hash Storage**: Store SHA-256 hashes of PHI records on-chain
- **Metadata Storage**: Store non-sensitive metadata on-chain
- **Reference Pointers**: Use blockchain to store references to off-chain data
- **Integrity Verification**: Verify off-chain data integrity using on-chain hashes

### Key Management Integration
- **PRE Implementation**: Implement Proxy Re-Encryption for secure data sharing
- **HSM Integration**: Use HSM for key generation and storage
- **Key Rotation**: Implement automated key rotation policies
- **Access Tokens**: Generate time-limited access tokens for PHI access

## Performance Optimization

### Transaction Optimization
- **Batch Processing**: Batch multiple operations where possible
- **Parallel Execution**: Design chaincode for parallel execution
- **State Caching**: Implement efficient state caching strategies
- **Query Optimization**: Optimize CouchDB queries for performance

### Network Optimization
- **Connection Pooling**: Use connection pooling for peer connections
- **Load Balancing**: Implement load balancing across peers
- **Caching**: Cache frequently accessed data
- **Compression**: Enable transaction compression where appropriate

## Monitoring and Maintenance

### Network Monitoring
- **Peer Health**: Monitor peer availability and performance
- **Transaction Metrics**: Track transaction throughput and latency
- **Block Production**: Monitor block production and consensus health
- **Certificate Expiry**: Monitor certificate expiration dates

### Chaincode Monitoring
- **Execution Metrics**: Track chaincode execution time and success rates
- **Error Rates**: Monitor chaincode error rates and types
- **Resource Usage**: Monitor CPU and memory usage
- **State Growth**: Monitor world state database growth

## Security Best Practices

### Network Security
- **TLS Everywhere**: Enable TLS for all network communications
- **Firewall Rules**: Implement strict firewall rules
- **Network Segmentation**: Segment blockchain network from other systems
- **VPN Access**: Use VPN for administrative access

### Chaincode Security
- **Code Review**: Mandatory code review for all chaincode
- **Static Analysis**: Use static analysis tools for security scanning
- **Dependency Scanning**: Scan dependencies for vulnerabilities
- **Penetration Testing**: Regular penetration testing of chaincode

### Operational Security
- **Access Control**: Implement strict access control for network administration
- **Audit Logging**: Enable comprehensive audit logging
- **Backup Security**: Secure backup and recovery procedures
- **Incident Response**: Implement incident response procedures

## Development Workflow

### Local Development
- **Test Network**: Use Hyperledger Fabric test network for development
- **Docker Compose**: Provide Docker Compose files for local setup
- **Mock Services**: Create mock services for external dependencies
- **Unit Testing**: Implement comprehensive unit tests for chaincode

### CI/CD Pipeline
- **Automated Testing**: Run chaincode tests in CI pipeline
- **Security Scanning**: Automated security scanning of chaincode
- **Deployment Automation**: Automated deployment to test environments
- **Rollback Procedures**: Implement automated rollback procedures