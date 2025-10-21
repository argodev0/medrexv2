#!/bin/bash

# Medrex DLT EMR Development Environment Startup Script
# This script starts the complete development environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[MEDREX]${NC} $1"
}

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    print_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    print_error "Docker Compose is not installed or not in PATH"
    exit 1
fi

# Change to the docker directory
cd "$(dirname "$0")/.."

print_header "Starting Medrex DLT EMR Development Environment"

# Check if .env file exists, create if not
if [ ! -f .env ]; then
    print_warning ".env file not found, creating from template..."
    cat > .env << EOF
# Medrex DLT EMR Development Environment Variables

# Database Configuration
POSTGRES_DB=medrex_emr
POSTGRES_USER=medrex_user
POSTGRES_PASSWORD=medrex_dev_password

# Redis Configuration
REDIS_PASSWORD=

# JWT Configuration
JWT_SECRET_KEY=dev-jwt-secret-key-change-in-production

# Encryption Configuration
ENCRYPTION_KEY=dev-encryption-key-32-chars-long

# Environment
ENVIRONMENT=development
LOG_LEVEL=debug

# Fabric Configuration
FABRIC_CA_ADMIN_USER=admin
FABRIC_CA_ADMIN_PASSWORD=adminpw

# Monitoring Configuration
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=admin
EOF
    print_status "Created .env file with default values"
fi

# Build services
print_status "Building Docker images..."
docker-compose -f docker-compose.dev.yaml build

# Start infrastructure services first
print_status "Starting infrastructure services..."
docker-compose -f docker-compose.dev.yaml up -d postgres redis

# Wait for database to be ready
print_status "Waiting for PostgreSQL to be ready..."
timeout=60
counter=0
while ! docker-compose -f docker-compose.dev.yaml exec -T postgres pg_isready -U medrex_user -d medrex_emr > /dev/null 2>&1; do
    if [ $counter -ge $timeout ]; then
        print_error "PostgreSQL failed to start within $timeout seconds"
        exit 1
    fi
    sleep 1
    counter=$((counter + 1))
done
print_status "PostgreSQL is ready"

# Start Fabric network
print_status "Starting Hyperledger Fabric network..."
docker-compose -f docker-compose.dev.yaml up -d ca-hospital ca-pharmacy orderer couchdb-hospital couchdb-pharmacy

# Wait for CAs to be ready
print_status "Waiting for Fabric CAs to be ready..."
sleep 10

# Start peers
docker-compose -f docker-compose.dev.yaml up -d peer-hospital peer-pharmacy

# Wait for peers to be ready
print_status "Waiting for Fabric peers to be ready..."
sleep 15

# Start application services
print_status "Starting application services..."
docker-compose -f docker-compose.dev.yaml up -d iam-service

# Wait for IAM service to be ready
print_status "Waiting for IAM service to be ready..."
timeout=60
counter=0
while ! curl -f http://localhost:8080/health > /dev/null 2>&1; do
    if [ $counter -ge $timeout ]; then
        print_error "IAM service failed to start within $timeout seconds"
        exit 1
    fi
    sleep 1
    counter=$((counter + 1))
done
print_status "IAM service is ready"

# Start remaining services
docker-compose -f docker-compose.dev.yaml up -d clinical-notes-service scheduling-service mobile-workflow-service api-gateway

# Start monitoring and development tools
print_status "Starting monitoring and development tools..."
docker-compose -f docker-compose.dev.yaml up -d prometheus grafana jaeger mailhog nginx

# Wait for all services to be healthy
print_status "Waiting for all services to be healthy..."
sleep 30

# Display service status
print_header "Development Environment Status"

echo ""
print_status "Core Services:"
echo "  PostgreSQL:     http://localhost:5432"
echo "  Redis:          http://localhost:6379"

echo ""
print_status "Hyperledger Fabric Network:"
echo "  CA Hospital:    http://localhost:7054"
echo "  CA Pharmacy:    http://localhost:8054"
echo "  Orderer:        http://localhost:7050"
echo "  Peer Hospital:  http://localhost:7051"
echo "  Peer Pharmacy:  http://localhost:8051"
echo "  CouchDB Hospital: http://localhost:5984"
echo "  CouchDB Pharmacy: http://localhost:6984"

echo ""
print_status "Application Services:"
echo "  API Gateway:    http://localhost:8000"
echo "  IAM Service:    http://localhost:8080"
echo "  Clinical Notes: http://localhost:8081"
echo "  Scheduling:     http://localhost:8082"
echo "  Mobile Workflow: http://localhost:8083"

echo ""
print_status "Development Tools:"
echo "  Nginx Proxy:    http://localhost:80"
echo "  Prometheus:     http://localhost:9090"
echo "  Grafana:        http://localhost:3000 (admin/admin)"
echo "  Jaeger:         http://localhost:16686"
echo "  MailHog:        http://localhost:8025"

echo ""
print_status "API Endpoints:"
echo "  Health Check:   http://localhost:8000/health"
echo "  API Docs:       http://localhost:8000/docs"
echo "  Authentication: http://localhost:8000/api/auth"

echo ""
print_header "Development Environment Started Successfully!"
print_status "You can now start developing with the Medrex DLT EMR system"
print_warning "Remember to run './dev-stop.sh' when you're done to clean up resources"

# Show logs for the main services
echo ""
print_status "Showing recent logs (press Ctrl+C to stop):"
docker-compose -f docker-compose.dev.yaml logs -f --tail=50 api-gateway iam-service clinical-notes-service