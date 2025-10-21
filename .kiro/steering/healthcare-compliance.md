---
inclusion: fileMatch
fileMatchPattern: '*phi*|*hipaa*|*gdpr*|*compliance*|*audit*|*clinical*'
---

# Healthcare Compliance and Security Guidelines

## HIPAA Compliance Requirements

### PHI Protection Mandates
- **Storage Prohibition**: PHI MUST NEVER be stored on blockchain ledger
- **Encryption at Rest**: All PHI must use 256-bit AES encryption in PostgreSQL
- **Encryption in Transit**: All PHI transmissions must use TLS 1.3 or higher
- **Access Logging**: Every PHI access must be logged with user identity and timestamp

### Administrative Safeguards
- **Access Management**: Implement unique user identification and automatic logoff
- **Workforce Training**: Ensure all users understand PHI handling requirements
- **Incident Response**: Establish procedures for security incident response
- **Business Associate Agreements**: Ensure all third-party integrations have BAAs

### Physical Safeguards
- **Facility Access**: Restrict physical access to systems containing PHI
- **Workstation Security**: Implement workstation access controls
- **Media Controls**: Secure handling of electronic media containing PHI
- **Device Controls**: Control access to hardware and software

### Technical Safeguards
- **Access Control**: Unique user identification and role-based access
- **Audit Controls**: Comprehensive logging of PHI access and modifications
- **Integrity**: Ensure PHI is not improperly altered or destroyed
- **Transmission Security**: Secure PHI during electronic transmission

## GDPR Compliance Requirements

### Data Protection by Design
- **Privacy by Default**: Implement privacy-protective defaults
- **Data Minimization**: Process only necessary personal data
- **Purpose Limitation**: Use data only for specified, legitimate purposes
- **Storage Limitation**: Retain data only as long as necessary

### Individual Rights
- **Right to Access**: Provide individuals access to their personal data
- **Right to Rectification**: Allow correction of inaccurate personal data
- **Right to Erasure**: Implement data deletion capabilities
- **Right to Portability**: Enable data export in machine-readable format

### Consent Management
- **Explicit Consent**: Obtain clear, specific consent for data processing
- **Consent Withdrawal**: Allow easy withdrawal of consent
- **Consent Records**: Maintain records of consent given and withdrawn
- **Granular Consent**: Provide granular consent options where applicable

## Role-Based Access Control (RBAC) Implementation

### User Role Definitions
```
1. Patient: Own EHR access, appointment scheduling, secure communications
2. MBBS Student/Intern: De-identified training data, supervised patient charts
3. MD/MS Student: Assigned patient charts, restricted CPOE with co-sign
4. Consulting Doctor: Full patient access, full CPOE, research data control
5. Nursing Staff: Ward patient access, medication administration
6. Lab Technician: Relevant orders, lab results management
7. Receptionist: Demographics, appointments, basic billing
8. Clinical Staff: Specific patient data, specialized service orders
9. Administrator: Aggregated data, user management, full audit access
```

### Access Control Matrix
- **Create (C)**: Permission to create new records
- **Read (R)**: Permission to view existing records
- **Update (U)**: Permission to modify existing records
- **Delete (D)**: Permission to remove records
- **View (V)**: Read-only access to sensitive data

### Permission Enforcement
- **Certificate-Based**: Extract roles from X.509 certificate attributes
- **Real-Time Validation**: Validate permissions for each access request
- **Token-Based Access**: Issue time-limited access tokens for authorized requests
- **Audit Trail**: Log all permission checks and access attempts

## Audit and Compliance Monitoring

### Audit Log Requirements
- **Comprehensive Logging**: Log all user activities and system events
- **Immutable Records**: Use blockchain for tamper-proof audit trails
- **Real-Time Monitoring**: Implement real-time security monitoring
- **Retention Policies**: Maintain audit logs per regulatory requirements

### Audit Events to Capture
```go
type AuditEventType string

const (
    UserLogin          AuditEventType = "USER_LOGIN"
    UserLogout         AuditEventType = "USER_LOGOUT"
    PHIAccess          AuditEventType = "PHI_ACCESS"
    PHIModification    AuditEventType = "PHI_MODIFICATION"
    CPOEEntry          AuditEventType = "CPOE_ENTRY"
    AccessDenied       AuditEventType = "ACCESS_DENIED"
    SystemError        AuditEventType = "SYSTEM_ERROR"
    ConfigChange       AuditEventType = "CONFIG_CHANGE"
    DataExport         AuditEventType = "DATA_EXPORT"
    ConsentChange      AuditEventType = "CONSENT_CHANGE"
)
```

### Compliance Reporting
- **Automated Reports**: Generate compliance reports automatically
- **Breach Detection**: Implement automated breach detection
- **Risk Assessment**: Regular security risk assessments
- **Regulatory Reporting**: Prepare reports for regulatory authorities

## Data Classification and Handling

### PHI Classification Levels
- **Level 1 - Public**: Non-sensitive healthcare information
- **Level 2 - Internal**: De-identified research data
- **Level 3 - Confidential**: Identified patient data
- **Level 4 - Restricted**: Highly sensitive PHI (mental health, substance abuse)

### Data Handling Procedures
- **Classification Labeling**: Automatically classify and label all data
- **Handling Instructions**: Provide clear handling instructions for each level
- **Transmission Controls**: Implement appropriate transmission controls
- **Disposal Procedures**: Secure data disposal and destruction procedures

## Security Incident Response

### Incident Classification
- **Category 1**: Minor security events (failed login attempts)
- **Category 2**: Moderate incidents (unauthorized access attempts)
- **Category 3**: Major incidents (successful unauthorized access)
- **Category 4**: Critical incidents (PHI breach or system compromise)

### Response Procedures
1. **Detection**: Automated monitoring and alerting systems
2. **Assessment**: Rapid assessment of incident scope and impact
3. **Containment**: Immediate containment of security threats
4. **Investigation**: Thorough investigation of incident causes
5. **Recovery**: System recovery and service restoration
6. **Reporting**: Regulatory reporting as required by law

### Breach Notification Requirements
- **HIPAA Timeline**: Notify HHS within 60 days, individuals within 60 days
- **GDPR Timeline**: Notify supervisory authority within 72 hours
- **Documentation**: Maintain detailed breach documentation
- **Remediation**: Implement remediation measures to prevent recurrence

## Clinical Decision Support Compliance

### CPOE (Computerized Provider Order Entry) Requirements
- **Drug Interaction Checking**: Implement comprehensive drug interaction alerts
- **Allergy Checking**: Check patient allergies before medication orders
- **Dosage Validation**: Validate medication dosages against patient parameters
- **Co-signature Requirements**: Implement co-signature workflows for trainees

### Clinical Documentation
- **Structured Data**: Use standardized clinical terminologies (ICD-10, SNOMED)
- **Template Compliance**: Ensure documentation templates meet regulatory requirements
- **Signature Requirements**: Implement electronic signature requirements
- **Amendment Tracking**: Track all amendments to clinical documentation

## Quality Assurance and Testing

### Security Testing Requirements
- **Penetration Testing**: Regular penetration testing of all systems
- **Vulnerability Scanning**: Automated vulnerability scanning
- **Code Security Review**: Security-focused code reviews
- **Compliance Testing**: Regular compliance validation testing

### Test Data Management
- **De-identification**: Use only de-identified data for testing
- **Synthetic Data**: Generate synthetic test data when possible
- **Data Masking**: Implement data masking for non-production environments
- **Test Environment Security**: Secure test environments appropriately

### Validation and Verification
- **Requirements Traceability**: Trace all requirements to test cases
- **Risk-Based Testing**: Focus testing on high-risk areas
- **Regression Testing**: Comprehensive regression testing for changes
- **User Acceptance Testing**: Include compliance validation in UAT