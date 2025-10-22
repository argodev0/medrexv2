# Medrex DLT EMR - Quick Launch Guide

## 🚀 Quick Start

### Prerequisites
- Go 1.21 or later
- PostgreSQL database (optional for basic testing)
- Git

### 1. Build the Project
```bash
make build
```

### 2. Launch All Services
```bash
./scripts/launch-services.sh
```

### 3. Verify Services are Running
Check the health endpoints:
- API Gateway: http://localhost:8090/health
- IAM Service: http://localhost:8081/health
- Clinical Notes: http://localhost:8082/health
- Scheduling: http://localhost:8083/health
- Mobile Workflow: http://localhost:8084/health

### 4. Stop All Services
```bash
./scripts/stop-services.sh
```

## 🏥 Service Architecture

The Medrex DLT EMR system consists of 5 microservices:

1. **API Gateway** (Port 8090) - Main entry point, routes requests to other services
2. **IAM Service** (Port 8081) - Identity and Access Management, user authentication
3. **Clinical Notes Service** (Port 8082) - PHI data management with encryption
4. **Scheduling Service** (Port 8083) - Appointment scheduling and calendar management
5. **Mobile Workflow Service** (Port 8084) - Mobile device workflows and barcode scanning

## 🔧 Configuration

### Environment Variables
The launch script sets default values, but you can override them:

```bash
# Database Configuration
export DATABASE_HOST=localhost
export DATABASE_PORT=5432
export DATABASE_NAME=medrex
export DATABASE_USERNAME=medrex
export DATABASE_PASSWORD=medrex123
export DATABASE_SSL_MODE=disable

# Security Configuration
export JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
export ENCRYPTION_KEY=your-32-byte-encryption-key-here

# Service Ports
export API_GATEWAY_PORT=8090
export IAM_SERVICE_PORT=8081
export CLINICAL_NOTES_PORT=8082
export SCHEDULING_PORT=8083
export MOBILE_WORKFLOW_PORT=8084

# Logging
export LOG_LEVEL=info
```

## 📊 Monitoring

### Logs
Service logs are stored in the `logs/` directory:
- `logs/API Gateway.log`
- `logs/IAM Service.log`
- `logs/Clinical Notes Service.log`
- `logs/Scheduling Service.log`
- `logs/Mobile Workflow Service.log`

### Health Checks
Each service provides a health endpoint at `/health` that returns service status.

## 🔒 Security Features

- **RBAC (Role-Based Access Control)**: 9-role hierarchical system
- **PHI Encryption**: 256-bit AES encryption for sensitive data
- **JWT Authentication**: Secure token-based authentication
- **Audit Logging**: Comprehensive audit trails for compliance

## 🏗️ Development

### Building Individual Services
```bash
make build-api-gateway
make build-iam
make build-clinical
make build-scheduling
make build-mobile
```

### Cleaning Build Artifacts
```bash
make clean
```

### Running Tests (if available)
```bash
make test
```

## 📚 API Documentation

Once the services are running, API documentation is available at:
- Main API: http://localhost:8090/docs
- Individual service endpoints at their respective ports

## 🐛 Troubleshooting

### Services Won't Start
1. Check if ports are already in use
2. Verify environment variables are set correctly
3. Check logs in the `logs/` directory
4. Ensure database is accessible (if configured)

### Database Connection Issues
The services will start without a database connection but some features may not work. For full functionality:
1. Install and start PostgreSQL
2. Create a database named `medrex`
3. Set the correct database credentials in environment variables

### Permission Issues
Make sure the launch scripts are executable:
```bash
chmod +x scripts/launch-services.sh scripts/stop-services.sh
```

## 🔗 Next Steps

1. **Database Setup**: Configure PostgreSQL for persistent data storage
2. **Hyperledger Fabric**: Set up blockchain network for audit trails
3. **Frontend Integration**: Connect React/React Native applications
4. **Production Deployment**: Use Docker and Kubernetes configurations in `deployments/`

## 📞 Support

For issues and questions:
1. Check the logs in `logs/` directory
2. Review the main README.md for detailed architecture information
3. Check the `docs/` directory for additional documentation