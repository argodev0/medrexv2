#!/bin/bash

# Medrex DLT EMR Deployment Script with Rollback Capabilities
# Usage: ./deploy.sh [environment] [action] [options]

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
NAMESPACE_PREFIX="medrex"
SERVICES=("iam-service" "api-gateway" "clinical-notes-service" "scheduling-service" "mobile-workflow-service")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
Medrex DLT EMR Deployment Script

Usage: $0 [ENVIRONMENT] [ACTION] [OPTIONS]

ENVIRONMENTS:
    staging     Deploy to staging environment
    production  Deploy to production environment

ACTIONS:
    deploy      Deploy services
    rollback    Rollback to previous version
    status      Check deployment status
    logs        Show service logs
    health      Check service health

OPTIONS:
    --version VERSION   Specify version to deploy (default: latest)
    --service SERVICE   Deploy specific service only
    --dry-run          Show what would be deployed without executing
    --force            Force deployment without confirmation
    --help             Show this help message

EXAMPLES:
    $0 staging deploy --version v1.2.3
    $0 production rollback --service iam-service
    $0 staging status
    $0 production health --service api-gateway

EOF
}

# Parse command line arguments
parse_args() {
    ENVIRONMENT=""
    ACTION=""
    VERSION="latest"
    SERVICE=""
    DRY_RUN=false
    FORCE=false

    while [[ $# -gt 0 ]]; do
        case $1 in
            staging|production)
                ENVIRONMENT="$1"
                shift
                ;;
            deploy|rollback|status|logs|health)
                ACTION="$1"
                shift
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            --service)
                SERVICE="$2"
                shift 2
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$ENVIRONMENT" ]]; then
        log_error "Environment is required"
        show_help
        exit 1
    fi

    if [[ -z "$ACTION" ]]; then
        log_error "Action is required"
        show_help
        exit 1
    fi

    NAMESPACE="${NAMESPACE_PREFIX}-${ENVIRONMENT}"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi

    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    # Check namespace exists
    if ! kubectl get namespace "$NAMESPACE" &> /dev/null; then
        log_warning "Namespace $NAMESPACE does not exist, creating..."
        kubectl create namespace "$NAMESPACE"
    fi

    log_success "Prerequisites check passed"
}

# Backup current deployment
backup_deployment() {
    local service="$1"
    local backup_dir="$PROJECT_ROOT/backups/${ENVIRONMENT}/$(date +%Y%m%d_%H%M%S)"
    
    log_info "Creating backup for $service..."
    
    mkdir -p "$backup_dir"
    
    # Backup deployment configuration
    kubectl get deployment "$service" -n "$NAMESPACE" -o yaml > "$backup_dir/${service}-deployment.yaml" 2>/dev/null || true
    
    # Backup service configuration
    kubectl get service "$service" -n "$NAMESPACE" -o yaml > "$backup_dir/${service}-service.yaml" 2>/dev/null || true
    
    # Backup configmap if exists
    kubectl get configmap "${service}-config" -n "$NAMESPACE" -o yaml > "$backup_dir/${service}-configmap.yaml" 2>/dev/null || true
    
    echo "$backup_dir" > "/tmp/${service}-backup-path"
    log_success "Backup created at $backup_dir"
}

# Deploy service
deploy_service() {
    local service="$1"
    local version="$2"
    
    log_info "Deploying $service version $version to $ENVIRONMENT..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would deploy $service:$version"
        return 0
    fi
    
    # Backup current deployment
    backup_deployment "$service"
    
    # Update image tag in deployment file
    local deployment_file="$PROJECT_ROOT/deployments/kubernetes"
    case "$service" in
        "iam-service")
            deployment_file="$deployment_file/09-iam-service.yaml"
            ;;
        "api-gateway")
            deployment_file="$deployment_file/10-api-gateway.yaml"
            ;;
        "clinical-notes-service")
            deployment_file="$deployment_file/11-clinical-notes-service.yaml"
            ;;
        "scheduling-service")
            deployment_file="$deployment_file/12-scheduling-service.yaml"
            ;;
        "mobile-workflow-service")
            deployment_file="$deployment_file/13-mobile-workflow-service.yaml"
            ;;
        *)
            log_error "Unknown service: $service"
            return 1
            ;;
    esac
    
    # Create temporary deployment file with updated image
    local temp_file="/tmp/${service}-deployment.yaml"
    sed "s|image: .*${service}:.*|image: ghcr.io/medrex-dlt-emr/${service}:${version}|g" "$deployment_file" > "$temp_file"
    
    # Apply deployment
    kubectl apply -f "$temp_file" -n "$NAMESPACE"
    
    # Wait for rollout to complete
    log_info "Waiting for $service rollout to complete..."
    if kubectl rollout status deployment/"$service" -n "$NAMESPACE" --timeout=300s; then
        log_success "$service deployed successfully"
    else
        log_error "$service deployment failed"
        return 1
    fi
    
    # Cleanup temp file
    rm -f "$temp_file"
}

# Rollback service
rollback_service() {
    local service="$1"
    
    log_info "Rolling back $service in $ENVIRONMENT..."
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "DRY RUN: Would rollback $service"
        return 0
    fi
    
    # Perform rollback
    if kubectl rollout undo deployment/"$service" -n "$NAMESPACE"; then
        log_info "Waiting for $service rollback to complete..."
        if kubectl rollout status deployment/"$service" -n "$NAMESPACE" --timeout=300s; then
            log_success "$service rolled back successfully"
        else
            log_error "$service rollback failed"
            return 1
        fi
    else
        log_error "Failed to initiate rollback for $service"
        return 1
    fi
}

# Check service status
check_service_status() {
    local service="$1"
    
    log_info "Checking status of $service..."
    
    # Get deployment status
    local ready_replicas
    ready_replicas=$(kubectl get deployment "$service" -n "$NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
    local desired_replicas
    desired_replicas=$(kubectl get deployment "$service" -n "$NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "0")
    
    if [[ "$ready_replicas" == "$desired_replicas" ]] && [[ "$ready_replicas" != "0" ]]; then
        log_success "$service: $ready_replicas/$desired_replicas replicas ready"
    else
        log_warning "$service: $ready_replicas/$desired_replicas replicas ready"
    fi
    
    # Get pod status
    kubectl get pods -l app="$service" -n "$NAMESPACE"
}

# Check service health
check_service_health() {
    local service="$1"
    
    log_info "Checking health of $service..."
    
    # Get service port
    local port
    case "$service" in
        "iam-service") port="8080" ;;
        "api-gateway") port="8000" ;;
        "clinical-notes-service") port="8081" ;;
        "scheduling-service") port="8082" ;;
        "mobile-workflow-service") port="8083" ;;
        *) log_error "Unknown service: $service"; return 1 ;;
    esac
    
    # Check health endpoint
    local pod_name
    pod_name=$(kubectl get pods -l app="$service" -n "$NAMESPACE" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    
    if [[ -n "$pod_name" ]]; then
        if kubectl exec "$pod_name" -n "$NAMESPACE" -- wget -q --spider "http://localhost:$port/health" 2>/dev/null; then
            log_success "$service health check passed"
        else
            log_error "$service health check failed"
            return 1
        fi
    else
        log_error "No pods found for $service"
        return 1
    fi
}

# Show service logs
show_service_logs() {
    local service="$1"
    
    log_info "Showing logs for $service..."
    kubectl logs -l app="$service" -n "$NAMESPACE" --tail=100 -f
}

# Confirmation prompt
confirm_action() {
    if [[ "$FORCE" == "true" ]]; then
        return 0
    fi
    
    echo -n "Are you sure you want to $ACTION $SERVICE in $ENVIRONMENT? (y/N): "
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            log_info "Operation cancelled"
            exit 0
            ;;
    esac
}

# Main execution
main() {
    parse_args "$@"
    
    log_info "Starting $ACTION for $ENVIRONMENT environment"
    
    check_prerequisites
    
    # Determine services to process
    local services_to_process=()
    if [[ -n "$SERVICE" ]]; then
        services_to_process=("$SERVICE")
    else
        services_to_process=("${SERVICES[@]}")
    fi
    
    # Confirm action for production
    if [[ "$ENVIRONMENT" == "production" ]] && [[ "$ACTION" == "deploy" || "$ACTION" == "rollback" ]]; then
        confirm_action
    fi
    
    # Execute action
    case "$ACTION" in
        deploy)
            for service in "${services_to_process[@]}"; do
                deploy_service "$service" "$VERSION"
            done
            ;;
        rollback)
            for service in "${services_to_process[@]}"; do
                rollback_service "$service"
            done
            ;;
        status)
            for service in "${services_to_process[@]}"; do
                check_service_status "$service"
            done
            ;;
        health)
            for service in "${services_to_process[@]}"; do
                check_service_health "$service"
            done
            ;;
        logs)
            if [[ ${#services_to_process[@]} -eq 1 ]]; then
                show_service_logs "${services_to_process[0]}"
            else
                log_error "Logs can only be shown for one service at a time"
                exit 1
            fi
            ;;
    esac
    
    log_success "$ACTION completed successfully"
}

# Run main function
main "$@"