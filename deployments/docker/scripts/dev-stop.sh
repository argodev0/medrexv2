#!/bin/bash

# Medrex DLT EMR Development Environment Stop Script
# This script stops and cleans up the development environment

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

# Change to the docker directory
cd "$(dirname "$0")/.."

print_header "Stopping Medrex DLT EMR Development Environment"

# Parse command line arguments
CLEAN_VOLUMES=false
CLEAN_IMAGES=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean-volumes)
            CLEAN_VOLUMES=true
            shift
            ;;
        --clean-images)
            CLEAN_IMAGES=true
            shift
            ;;
        --clean-all)
            CLEAN_VOLUMES=true
            CLEAN_IMAGES=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --clean-volumes    Remove all Docker volumes (data will be lost)"
            echo "  --clean-images     Remove built Docker images"
            echo "  --clean-all        Remove both volumes and images"
            echo "  -h, --help         Show this help message"
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Stop all services
print_status "Stopping all services..."
docker-compose -f docker-compose.dev.yaml down

if [ "$CLEAN_VOLUMES" = true ]; then
    print_warning "Removing Docker volumes (all data will be lost)..."
    docker-compose -f docker-compose.dev.yaml down -v
    
    # Remove any orphaned volumes
    print_status "Cleaning up orphaned volumes..."
    docker volume prune -f
fi

if [ "$CLEAN_IMAGES" = true ]; then
    print_warning "Removing built Docker images..."
    
    # Get the project name (directory name)
    PROJECT_NAME=$(basename "$(pwd)")
    
    # Remove images built by docker-compose
    docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.ID}}" | grep "${PROJECT_NAME}" | awk '{print $3}' | xargs -r docker rmi -f
    
    # Clean up dangling images
    print_status "Cleaning up dangling images..."
    docker image prune -f
fi

# Clean up networks
print_status "Cleaning up networks..."
docker network prune -f

# Show remaining containers (if any)
REMAINING_CONTAINERS=$(docker ps -a --filter "name=medrex" --format "{{.Names}}" | wc -l)
if [ "$REMAINING_CONTAINERS" -gt 0 ]; then
    print_warning "Some containers are still running:"
    docker ps -a --filter "name=medrex" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
fi

# Show disk space usage
print_status "Docker disk usage:"
docker system df

print_header "Development Environment Stopped"

if [ "$CLEAN_VOLUMES" = true ]; then
    print_warning "All data has been removed. Next startup will initialize fresh databases."
fi

if [ "$CLEAN_IMAGES" = true ]; then
    print_warning "Docker images have been removed. Next startup will rebuild all services."
fi

print_status "To start the environment again, run: ./dev-start.sh"