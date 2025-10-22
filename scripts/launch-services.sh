#!/bin/bash

# Medrex DLT EMR Services Launch Script
# This script starts all microservices for the Medrex DLT EMR system

set -e

echo "🚀 Starting Medrex DLT EMR Services..."

# Set default environment variables if not set
export DATABASE_HOST=${DATABASE_HOST:-localhost}
export DATABASE_PORT=${DATABASE_PORT:-5432}
export DATABASE_NAME=${DATABASE_NAME:-medrex}
export DATABASE_USERNAME=${DATABASE_USERNAME:-medrex}
export DATABASE_PASSWORD=${DATABASE_PASSWORD:-medrex123}
export DATABASE_SSL_MODE=${DATABASE_SSL_MODE:-disable}

export JWT_SECRET_KEY=${JWT_SECRET_KEY:-your-super-secret-jwt-key-change-this-in-production}
export ENCRYPTION_KEY=${ENCRYPTION_KEY:-your-32-byte-encryption-key-here}

export LOG_LEVEL=${LOG_LEVEL:-info}

# Service ports
export API_GATEWAY_PORT=${API_GATEWAY_PORT:-8090}
export IAM_SERVICE_PORT=${IAM_SERVICE_PORT:-8081}
export CLINICAL_NOTES_PORT=${CLINICAL_NOTES_PORT:-8082}
export SCHEDULING_PORT=${SCHEDULING_PORT:-8083}
export MOBILE_WORKFLOW_PORT=${MOBILE_WORKFLOW_PORT:-8084}

# Create logs directory
mkdir -p logs

echo "📊 Environment Configuration:"
echo "  Database: ${DATABASE_HOST}:${DATABASE_PORT}/${DATABASE_NAME}"
echo "  Log Level: ${LOG_LEVEL}"
echo "  API Gateway: http://localhost:${API_GATEWAY_PORT}"
echo "  IAM Service: http://localhost:${IAM_SERVICE_PORT}"
echo "  Clinical Notes: http://localhost:${CLINICAL_NOTES_PORT}"
echo "  Scheduling: http://localhost:${SCHEDULING_PORT}"
echo "  Mobile Workflow: http://localhost:${MOBILE_WORKFLOW_PORT}"
echo ""

# Function to start a service
start_service() {
    local service_name=$1
    local binary_path=$2
    local port=$3
    
    echo "🔄 Starting ${service_name}..."
    
    # Set PORT environment variable for the service
    PORT=$port nohup $binary_path > "logs/${service_name}.log" 2>&1 &
    local pid=$!
    echo $pid > "logs/${service_name}.pid"
    
    echo "✅ ${service_name} started (PID: $pid, Port: $port)"
    
    # Give the service a moment to start
    sleep 2
}

# Start services in order
echo "🏥 Starting Medrex DLT EMR Microservices..."
echo ""

# Start IAM Service first (other services may depend on it)
start_service "IAM Service" "./build/iam-service" $IAM_SERVICE_PORT

# Start Clinical Notes Service
start_service "Clinical Notes Service" "./build/clinical-notes-service" $CLINICAL_NOTES_PORT

# Start Scheduling Service
start_service "Scheduling Service" "./build/scheduling-service" $SCHEDULING_PORT

# Start Mobile Workflow Service
start_service "Mobile Workflow Service" "./build/mobile-workflow-service" $MOBILE_WORKFLOW_PORT

# Start API Gateway last (it routes to other services)
start_service "API Gateway" "./build/api-gateway" $API_GATEWAY_PORT

echo ""
echo "🎉 All Medrex DLT EMR services are now running!"
echo ""
echo "📋 Service Status:"
echo "  API Gateway:      http://localhost:${API_GATEWAY_PORT}/health"
echo "  IAM Service:      http://localhost:${IAM_SERVICE_PORT}/health"
echo "  Clinical Notes:   http://localhost:${CLINICAL_NOTES_PORT}/health"
echo "  Scheduling:       http://localhost:${SCHEDULING_PORT}/health"
echo "  Mobile Workflow:  http://localhost:${MOBILE_WORKFLOW_PORT}/health"
echo ""
echo "📝 Logs are available in the 'logs/' directory"
echo "🛑 To stop all services, run: ./scripts/stop-services.sh"
echo ""
echo "🔗 Main API Gateway: http://localhost:${API_GATEWAY_PORT}"
echo "📖 API Documentation: http://localhost:${API_GATEWAY_PORT}/docs"