#!/bin/bash

# Medrex DLT EMR Development Environment Logs Script
# This script helps view logs from various services

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

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}[MEDREX]${NC} $1"
}

# Change to the docker directory
cd "$(dirname "$0")/.."

# Default values
SERVICE=""
FOLLOW=false
TAIL_LINES=50

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--service)
            SERVICE="$2"
            shift 2
            ;;
        -f|--follow)
            FOLLOW=true
            shift
            ;;
        -n|--tail)
            TAIL_LINES="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -s, --service SERVICE  Show logs for specific service"
            echo "  -f, --follow          Follow log output"
            echo "  -n, --tail LINES      Number of lines to show (default: 50)"
            echo "  -h, --help            Show this help message"
            echo ""
            echo "Available services:"
            echo "  all                   All services"
            echo "  app                   Application services only"
            echo "  fabric                Hyperledger Fabric services only"
            echo "  infra                 Infrastructure services only"
            echo "  api-gateway           API Gateway service"
            echo "  iam-service           IAM service"
            echo "  clinical-notes-service Clinical Notes service"
            echo "  scheduling-service    Scheduling service"
            echo "  mobile-workflow-service Mobile Workflow service"
            echo "  postgres              PostgreSQL database"
            echo "  redis                 Redis cache"
            echo "  orderer               Fabric orderer"
            echo "  peer-hospital         Hospital peer"
            echo "  peer-pharmacy         Pharmacy peer"
            echo "  ca-hospital           Hospital CA"
            echo "  ca-pharmacy           Pharmacy CA"
            echo "  prometheus            Prometheus monitoring"
            echo "  grafana               Grafana dashboard"
            echo "  jaeger                Jaeger tracing"
            echo "  nginx                 Nginx proxy"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Build docker-compose command
COMPOSE_CMD="docker-compose -f docker-compose.dev.yaml logs"

if [ "$FOLLOW" = true ]; then
    COMPOSE_CMD="$COMPOSE_CMD -f"
fi

COMPOSE_CMD="$COMPOSE_CMD --tail=$TAIL_LINES"

# Determine which services to show logs for
case $SERVICE in
    ""|"all")
        print_header "Showing logs for all services"
        $COMPOSE_CMD
        ;;
    "app")
        print_header "Showing logs for application services"
        $COMPOSE_CMD api-gateway iam-service clinical-notes-service scheduling-service mobile-workflow-service
        ;;
    "fabric")
        print_header "Showing logs for Hyperledger Fabric services"
        $COMPOSE_CMD orderer peer-hospital peer-pharmacy ca-hospital ca-pharmacy couchdb-hospital couchdb-pharmacy
        ;;
    "infra")
        print_header "Showing logs for infrastructure services"
        $COMPOSE_CMD postgres redis prometheus grafana jaeger nginx
        ;;
    "api-gateway"|"iam-service"|"clinical-notes-service"|"scheduling-service"|"mobile-workflow-service"|"postgres"|"redis"|"orderer"|"peer-hospital"|"peer-pharmacy"|"ca-hospital"|"ca-pharmacy"|"couchdb-hospital"|"couchdb-pharmacy"|"prometheus"|"grafana"|"jaeger"|"nginx"|"mailhog")
        print_header "Showing logs for $SERVICE"
        $COMPOSE_CMD $SERVICE
        ;;
    *)
        print_error "Unknown service: $SERVICE"
        echo "Use --help to see available services"
        exit 1
        ;;
esac