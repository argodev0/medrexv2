---
inclusion: fileMatch
fileMatchPattern: '*chaincode*|*fabric*|*performance*|*rbac*|*architecture*'
---

# Advanced Architecture Patterns for Medrex V2.0

## Hybrid DLT Model Implementation

### Core Architectural Principle
The Medrex V2.0 system implements a Hybrid DLT Model where:
- **PHI Storage**: All Protected Health Information resides off-chain in encrypted PostgreSQL
- **Blockchain Storage**: Only cryptographic hashes (SHA-256), metadata, and access policies
- **Integrity Verification**: Every PHI retrieval must verify data integrity against blockchain hashes
- **Access Control**: Blockchain enforces access policies before releasing PHI access tokens

### Multi-Step PHI Retrieval Process
```
1. Client Request → API Gateway
2. Authentication → IAM Service (OAuth/JWT validation)
3. Authorization → AccessPolicy Chaincode (role/attribute validation)
4. Token Generation → PRE service (re-encryption token creation)
5. PHI Retrieval → Clinical Notes Service (encrypted database query)
6. Hash Verification → Compare retrieved data hash with blockchain record
7. Decryption → PRE-based decryption using authorized token
8. Audit Logging → AuditLog Chaincode (immutable activity record)
```

## State-Based Endorsement (SBE) Architecture

### Clinical Governance Implementation
State-Based Endorsement policies enforce complex clinical workflows directly in chaincode:

```go
// Example SBE policy for CPOE orders requiring supervision
func (c *ClinicalChaincode) SubmitCPOEOrder(ctx contractapi.TransactionContextInterface, 
    orderID string, orderDetails string) error {
    
    // Extract submitter identity and attributes
    submitter, err := ctx.GetClientIdentity().GetID()
    if err != nil {
        return err
    }
    
    // Check if submitter is a trainee requiring supervision
    isTrainee, err := ctx.GetClientIdentity().GetAttributeValue("is_trainee")
    if err != nil {
        return err
    }
    
    if isTrainee == "true" {
        // Apply State-Based Endorsement policy requiring supervisor co-signature
        sbePolicy := &SBEPolicy{
            RequiredEndorsers: []string{"supervisor"},
            AttributeRequirements: map[string]string{
                "is_supervisor": "true",
                "specialty": "matching_specialty",
            },
        }
        
        // Set SBE policy on the specific ledger key
        err = ctx.GetStub().SetStateBasedEndorsement(orderID, sbePolicy)
        if err != nil {
            return err
        }
    }
    
    // Store order with appropriate governance
    return ctx.GetStub().PutState(orderID, []byte(orderDetails))
}
```

### SBE Policy Patterns
- **Trainee Supervision**: MD/MS students require Faculty co-signature for CPOE
- **High-Risk Procedures**: Critical procedures require multiple specialist endorsements
- **Emergency Override**: Emergency procedures with enhanced audit logging
- **Time-Based Policies**: Policies that change based on time of day or shift patterns

## MVCC Conflict Mitigation Strategies

### Composite Key Design Patterns

#### High-Contention Data Separation
```go
// WRONG: Single key for all patient data (causes MVCC conflicts)
patientKey := fmt.Sprintf("PATIENT:%s", patientID)

// CORRECT: Separate keys for different data types
patientMasterKey := fmt.Sprintf("PMH:%s", patientID)           // Low volatility
financialKey := fmt.Sprintf("FINANCE:%s:BALANCE", patientID)  // High volatility
vitalKey := fmt.Sprintf("VITAL:%s:%s:%d", patientID, deviceID, timestamp) // Very high volatility
appointmentKey := fmt.Sprintf("APPOINTMENT:%s", appointmentID) // Moderate volatility
```

#### Time-Series Key Patterns
```go
// Append-only operations using timestamp-based keys
func (c *VitalsChaincode) RecordVitalSigns(ctx contractapi.TransactionContextInterface,
    patientID string, deviceID string, vitals string) error {
    
    timestamp := time.Now().Unix()
    vitalKey := ctx.GetStub().CreateCompositeKey("VITAL", []string{
        patientID, deviceID, fmt.Sprintf("%d", timestamp),
    })
    
    // This creates a unique key for each measurement, avoiding MVCC conflicts
    return ctx.GetStub().PutState(vitalKey, []byte(vitals))
}
```

### Dependency-Aware Transaction Processing
```go
type TransactionDependency struct {
    TransactionID string   `json:"transaction_id"`
    ReadSet       []string `json:"read_set"`
    WriteSet      []string `json:"write_set"`
    Dependencies  []string `json:"dependencies"`
}

// Flag dependencies during endorsement phase
func (c *DependencyChaincode) FlagDependencies(ctx contractapi.TransactionContextInterface,
    txID string, readKeys []string, writeKeys []string) error {
    
    dependency := TransactionDependency{
        TransactionID: txID,
        ReadSet:       readKeys,
        WriteSet:      writeKeys,
        Dependencies:  c.analyzeDependencies(readKeys, writeKeys),
    }
    
    dependencyKey := fmt.Sprintf("DEPENDENCY:%s", txID)
    dependencyJSON, _ := json.Marshal(dependency)
    
    return ctx.GetStub().PutState(dependencyKey, dependencyJSON)
}
```

## Advanced Identity and Certificate Management

### X.509 Certificate Attribute Embedding
```go
// Certificate attributes for role-based access control
type CertificateAttributes struct {
    Role           string `json:"role"`           // "consulting_doctor", "md_student", etc.
    Specialty      string `json:"specialty"`      // "cardiology", "pediatrics", etc.
    IsTrainee      bool   `json:"is_trainee"`     // Requires supervision
    IsSupervisor   bool   `json:"is_supervisor"`  // Can provide supervision
    WardAssignment string `json:"ward_assignment"` // For nursing staff
    LabOrg         string `json:"lab_org"`        // For lab technicians
}

// Extract and validate attributes in chaincode
func (c *AccessChaincode) ValidateAccess(ctx contractapi.TransactionContextInterface,
    resourceID string, action string) (bool, error) {
    
    clientID := ctx.GetClientIdentity()
    
    // Extract role from certificate
    role, err := clientID.GetAttributeValue("role")
    if err != nil {
        return false, err
    }
    
    // Extract additional attributes for ABAC
    specialty, _ := clientID.GetAttributeValue("specialty")
    isTrainee, _ := clientID.GetAttributeValue("is_trainee")
    
    // Implement complex access logic based on attributes
    return c.evaluateAccessPolicy(role, specialty, isTrainee, resourceID, action), nil
}
```

### NodeOU Configuration
```yaml
# Fabric CA configuration for NodeOUs
NodeOUs:
  Enable: true
  ClientOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: client
  PeerOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: peer
  AdminOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: admin
  OrdererOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: orderer
  # Custom OUs for healthcare roles
  DoctorOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: doctor
  StudentOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: student
  NurseOUIdentifier:
    Certificate: cacerts/ca-cert.pem
    OrganizationalUnitIdentifier: nurse
```

## Proxy Re-Encryption (PRE) Integration

### PRE Workflow Architecture
```go
type PREService struct {
    masterKeys    map[string]*ecdsa.PrivateKey
    reEncryptKeys map[string]*ReEncryptionKey
    hsm          HSMInterface
}

// Generate re-encryption token for authorized access
func (p *PREService) GenerateReEncryptionToken(patientID string, 
    requesterPublicKey *ecdsa.PublicKey, accessToken string) (*ReEncryptionKey, error) {
    
    // Validate access token from blockchain
    if !p.validateAccessToken(accessToken) {
        return nil, errors.New("invalid access token")
    }
    
    // Generate PRE key using HSM
    patientPrivateKey, err := p.hsm.GetPatientKey(patientID)
    if err != nil {
        return nil, err
    }
    
    reEncryptKey := p.generatePREKey(patientPrivateKey, requesterPublicKey)
    
    // Store with expiration
    p.reEncryptKeys[accessToken] = reEncryptKey
    
    return reEncryptKey, nil
}

// Re-encrypt data for authorized requester
func (p *PREService) ReEncryptData(encryptedData []byte, 
    reEncryptKey *ReEncryptionKey) ([]byte, error) {
    
    // Perform proxy re-encryption
    reEncryptedData, err := p.proxyReEncrypt(encryptedData, reEncryptKey)
    if err != nil {
        return nil, err
    }
    
    return reEncryptedData, nil
}
```

## Performance Monitoring and Optimization

### Real-Time Performance Metrics
```go
type PerformanceMetrics struct {
    TPS              float64 `json:"tps"`              // Transactions per second
    Goodput          float64 `json:"goodput"`          // Successful transaction rate
    MVCCConflictRate float64 `json:"mvcc_conflict_rate"` // MVCC conflict percentage
    AvgLatency       float64 `json:"avg_latency"`      // Average transaction latency
    BlockSize        int     `json:"block_size"`       // Average block size
    EndorsementTime  float64 `json:"endorsement_time"` // Average endorsement time
}

// Monitor and alert on performance thresholds
func (m *PerformanceMonitor) CheckThresholds(metrics *PerformanceMetrics) {
    if metrics.TPS < 1000 {
        m.alertManager.SendAlert("TPS below target", metrics)
    }
    
    if metrics.Goodput < 0.95 {
        m.alertManager.SendAlert("Goodput below 95%", metrics)
    }
    
    if metrics.MVCCConflictRate > 0.05 {
        m.alertManager.SendAlert("High MVCC conflict rate", metrics)
    }
}
```

### Automated Performance Optimization
```go
// Automatic key design recommendations based on contention analysis
func (o *PerformanceOptimizer) AnalyzeKeyContention() *OptimizationRecommendations {
    contentionData := o.collectContentionMetrics()
    
    recommendations := &OptimizationRecommendations{}
    
    for key, conflictRate := range contentionData {
        if conflictRate > 0.1 { // 10% conflict rate threshold
            recommendations.HighContentionKeys = append(
                recommendations.HighContentionKeys,
                KeyOptimization{
                    Key: key,
                    ConflictRate: conflictRate,
                    Recommendation: o.generateKeyOptimization(key),
                },
            )
        }
    }
    
    return recommendations
}
```

## Security Architecture Patterns

### Defense in Depth Implementation
```
Layer 1: Network Security (TLS 1.3, mTLS, VPN)
Layer 2: Identity & Access (X.509 certificates, RBAC/ABAC)
Layer 3: Application Security (Input validation, secure coding)
Layer 4: Data Security (AES-256 encryption, PRE)
Layer 5: Infrastructure Security (HSM, secure enclaves)
Layer 6: Monitoring & Audit (Real-time monitoring, immutable logs)
```

### Cryptographic Agility Framework
```go
type CryptoConfig struct {
    EncryptionAlgorithm string `json:"encryption_algorithm"` // "AES-256" or "ML-KEM"
    SignatureAlgorithm  string `json:"signature_algorithm"`  // "ECDSA" or "ML-DSA"
    HashAlgorithm       string `json:"hash_algorithm"`       // "SHA-256" or "SHA-3"
    KeyDerivation       string `json:"key_derivation"`       // "PBKDF2" or "Argon2"
}

// Support algorithm transitions
func (c *CryptoManager) TransitionAlgorithm(oldAlg, newAlg string) error {
    // Implement gradual algorithm transition
    // Support hybrid modes during transition
    // Maintain backward compatibility
    return c.performAlgorithmTransition(oldAlg, newAlg)
}
```

This advanced architecture ensures the Medrex V2.0 system meets enterprise healthcare requirements while providing the scalability, security, and compliance needed for modern healthcare environments.