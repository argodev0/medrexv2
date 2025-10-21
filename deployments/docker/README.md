# Medrex DLT EMR Docker Development Environment

This directory contains Docker Compose configurations for running the complete Medrex DLT EMR system in a development environment.

## Overview

The development environment includes:

- **Complete Microservices Stack**: All Medrex services running in containers
- **Hyperledger Fabric Network**: Simplified 2-organization network for development
- **PostgreSQL Database**: With sample data and proper schema
- **Redis Cache**: For session management and caching
- **Monitoring Stack**: Prometheus, Grafana, and Jaeger
- **Development Tools**: MailHog for email testing, Nginx for reverse proxy
- **Hot Reload Support**: Services can be rebuilt and restarted individually

## Quick Start

1. **Prerequisites:**
   ```bash
   # Ensure Docker and Docker Compose are installed
   docker --version
   docker-compose --version
   ```

2. **Start the development environment:**
   ```bash
   cd deployments/docker
   ./scripts/dev-start.sh
   ```

3. **Access the services:**
   - API Gateway: http://localhost:8000
   - Grafana Dashboard: http://localhost:3000 (admin/admin)
   - Prometheus: http://localhost:9090
   - Jaeger Tracing: http://localhost:16686
   - MailHog: http://localhost:8025

4. **Stop the environment:**
   ```bash
   ./scripts/dev-stop.sh
   ```

## Architecture

### Service Ports

| Service | Port | Description |
|---------|------|-------------|
| Nginx Proxy | 80 | Main entry point |
| API Gateway | 8000 | Application API gateway |
| IAM Service | 8080 | Identity and access management |
| Clinical Notes | 8081 | PHI management service |
| Scheduling | 8082 | Appointment scheduling |
| Mobile Workflow | 8083 | Mobile-optimized workflows |
| PostgreSQL | 5432 | Main database |
| Redis | 6379 | Cache and sessions |
| Fabric Orderer | 7050 | Blockchain ordering service |
| Hospital Peer | 7051 | Hospital organization peer |
| Pharmacy Peer | 8051 | Pharmacy organization peer |
| Hospital CA | 7054 | Hospital certificate authority |
| Pharmacy CA | 8054 | Pharmacy certificate authority |
| CouchDB Hospital | 5984 | Hospital peer state database |
| CouchDB Pharmacy | 6984 | Pharmacy peer state database |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3000 | Monitoring dashboard |
| Jaeger | 16686 | Distributed tracing |
| MailHog | 8025 | Email testing |

### Network Architecture

```
┌─────────────────┐    ┌─────────────────┐
│   Web Client    │    │  Mobile Client  │
└─────────┬───────┘    └─────────┬───────┘
          │                      │
          └──────────┬───────────┘
                     │
              ┌──────▼──────┐
              │    Nginx    │
              │   Proxy     │
              └──────┬──────┘
                     │
              ┌──────▼──────┐
              │ API Gateway │
              └──────┬──────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
┌───▼───┐    ┌──────▼──────┐    ┌────▼────┐
│  IAM  │    │  Clinical   │    │ Mobile  │
│Service│    │   Notes     │    │Workflow │
└───┬───┘    └──────┬──────┘    └────┬────┘
    │               │                │
    └───────────────┼────────────────┘
                    │
         ┌──────────▼──────────┐
         │ Hyperledger Fabric  │
         │      Network        │
         └──────────┬──────────┘
                    │
         ┌──────────▼──────────┐
         │    PostgreSQL       │
         │     Database        │
         └─────────────────────┘
```

## Configuration Files

### Docker Compose Files

- `docker-compose.yaml`: Production Fabric network (existing)
- `docker-compose.dev.yaml`: Complete development environment
- `docker-compose.override.yaml`: Local overrides (optional)

### Configuration Directories

- `config/`: Service configuration files
- `init-scripts/`: Database initialization scripts
- `monitoring/`: Prometheus and Grafana configurations
- `nginx/`: Nginx reverse proxy configuration
- `scripts/`: Development utility scripts

## Development Workflow

### Starting Development

1. **Full Environment:**
   ```bash
   ./scripts/dev-start.sh
   ```

2. **Individual Services:**
   ```bash
   docker-compose -f docker-compose.dev.yaml up -d postgres redis
   docker-compose -f docker-compose.dev.yaml up -d iam-service
   ```

### Viewing Logs

```bash
# All services
./scripts/dev-logs.sh

# Specific service
./scripts/dev-logs.sh --service iam-service --follow

# Application services only
./scripts/dev-logs.sh --service app --follow

# Fabric network only
./scripts/dev-logs.sh --service fabric
```

### Rebuilding Services

```bash
# Rebuild specific service
docker-compose -f docker-compose.dev.yaml build iam-service
docker-compose -f docker-compose.dev.yaml up -d iam-service

# Rebuild all services
docker-compose -f docker-compose.dev.yaml build
docker-compose -f docker-compose.dev.yaml up -d
```

### Database Management

```bash
# Connect to PostgreSQL
docker-compose -f docker-compose.dev.yaml exec postgres psql -U medrex_user -d medrex_emr

# Run database migrations
docker-compose -f docker-compose.dev.yaml exec postgres psql -U medrex_user -d medrex_emr -f /docker-entrypoint-initdb.d/01-init-database.sql

# Backup database
docker-compose -f docker-compose.dev.yaml exec postgres pg_dump -U medrex_user medrex_emr > backup.sql

# Restore database
docker-compose -f docker-compose.dev.yaml exec -T postgres psql -U medrex_user -d medrex_emr < backup.sql
```

### Fabric Network Management

```bash
# Access Fabric CLI
docker-compose -f docker-compose.dev.yaml exec dev-tools sh

# Check peer status
docker-compose -f docker-compose.dev.yaml exec peer-hospital peer node status

# View chaincode logs
docker-compose -f docker-compose.dev.yaml logs peer-hospital
```

## Environment Variables

Create a `.env` file in the docker directory to customize the environment:

```bash
# Database Configuration
POSTGRES_DB=medrex_emr
POSTGRES_USER=medrex_user
POSTGRES_PASSWORD=your_secure_password

# Application Configuration
JWT_SECRET_KEY=your-jwt-secret-key
ENCRYPTION_KEY=your-32-character-encryption-key
LOG_LEVEL=debug
ENVIRONMENT=development

# Monitoring Configuration
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=your_grafana_password
```

## Monitoring and Debugging

### Health Checks

All services include health checks accessible via:

```bash
# Check all service health
curl http://localhost:8000/health

# Individual service health
curl http://localhost:8080/health  # IAM Service
curl http://localhost:8081/health  # Clinical Notes
curl http://localhost:8082/health  # Scheduling
curl http://localhost:8083/health  # Mobile Workflow
```

### Metrics and Monitoring

- **Prometheus**: http://localhost:9090
  - Metrics collection from all services
  - Custom healthcare-specific metrics
  - Alert rules for system monitoring

- **Grafana**: http://localhost:3000
  - Pre-configured dashboards
  - Service performance metrics
  - Database and Fabric network monitoring

- **Jaeger**: http://localhost:16686
  - Distributed tracing
  - Request flow visualization
  - Performance bottleneck identification

### Log Aggregation

Logs are centralized and can be viewed through:

```bash
# Real-time logs for all services
docker-compose -f docker-compose.dev.yaml logs -f

# Filtered logs
docker-compose -f docker-compose.dev.yaml logs -f api-gateway iam-service

# Search logs
docker-compose -f docker-compose.dev.yaml logs | grep "ERROR"
```

## Testing

### API Testing

```bash
# Test authentication
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Test with authentication token
TOKEN="your-jwt-token"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/clinical/notes
```

### Load Testing

```bash
# Install Apache Bench
sudo apt-get install apache2-utils

# Basic load test
ab -n 1000 -c 10 http://localhost:8000/health

# Authenticated endpoint test
ab -n 100 -c 5 -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/api/clinical/notes
```

### Integration Testing

```bash
# Run integration tests
docker-compose -f docker-compose.dev.yaml exec dev-tools \
  go test ./tests/integration/...

# Run specific test suite
docker-compose -f docker-compose.dev.yaml exec dev-tools \
  go test ./tests/integration/auth_test.go -v
```

## Troubleshooting

### Common Issues

1. **Port Conflicts:**
   ```bash
   # Check what's using a port
   lsof -i :8080
   
   # Kill process using port
   kill -9 $(lsof -t -i:8080)
   ```

2. **Database Connection Issues:**
   ```bash
   # Check PostgreSQL logs
   docker-compose -f docker-compose.dev.yaml logs postgres
   
   # Verify database is accessible
   docker-compose -f docker-compose.dev.yaml exec postgres pg_isready
   ```

3. **Fabric Network Issues:**
   ```bash
   # Check peer connectivity
   docker-compose -f docker-compose.dev.yaml exec peer-hospital peer node status
   
   # Verify orderer is running
   docker-compose -f docker-compose.dev.yaml logs orderer
   ```

4. **Service Build Failures:**
   ```bash
   # Clean build cache
   docker-compose -f docker-compose.dev.yaml build --no-cache
   
   # Remove old images
   docker image prune -f
   ```

### Performance Issues

1. **Slow Database Queries:**
   - Check `pg_stat_activity` for long-running queries
   - Review database logs for performance issues
   - Monitor Grafana dashboards for database metrics

2. **High Memory Usage:**
   - Monitor container resource usage: `docker stats`
   - Adjust memory limits in docker-compose.dev.yaml
   - Check for memory leaks in application logs

3. **Network Latency:**
   - Use Jaeger to identify slow requests
   - Check inter-service communication patterns
   - Monitor network metrics in Grafana

### Debugging Steps

1. **Check Service Status:**
   ```bash
   docker-compose -f docker-compose.dev.yaml ps
   ```

2. **Inspect Service Configuration:**
   ```bash
   docker-compose -f docker-compose.dev.yaml config
   ```

3. **Access Service Shell:**
   ```bash
   docker-compose -f docker-compose.dev.yaml exec iam-service sh
   ```

4. **Check Resource Usage:**
   ```bash
   docker stats
   ```

## Cleanup

### Partial Cleanup

```bash
# Stop services but keep data
./scripts/dev-stop.sh

# Remove containers but keep volumes
docker-compose -f docker-compose.dev.yaml down
```

### Full Cleanup

```bash
# Remove everything including data
./scripts/dev-stop.sh --clean-all

# Manual cleanup
docker-compose -f docker-compose.dev.yaml down -v
docker system prune -f
```

## Production Considerations

This development environment is **not suitable for production**. For production deployment:

1. Use the Kubernetes manifests in `../kubernetes/`
2. Use the Terraform infrastructure in `../terraform/`
3. Implement proper secrets management
4. Configure TLS/SSL certificates
5. Set up proper backup and recovery procedures
6. Implement comprehensive monitoring and alerting
7. Configure proper network security and firewalls

## Support

For issues with the development environment:

1. Check the logs using `./scripts/dev-logs.sh`
2. Verify all services are healthy
3. Check Docker and Docker Compose versions
4. Review the troubleshooting section above
5. Check the main project documentation