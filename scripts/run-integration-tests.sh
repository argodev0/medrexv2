#!/bin/bash

# Medrex DLT EMR Integration Test Runner
# This script sets up the test environment and runs integration tests

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_DIR="$PROJECT_ROOT/tests/integration"

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

# Cleanup function
cleanup() {
    log_info "Cleaning up test environment..."
    
    # Stop Docker containers if running
    if docker-compose -f "$PROJECT_ROOT/deployments/docker/docker-compose.yaml" ps -q > /dev/null 2>&1; then
        log_info "Stopping Docker containers..."
        docker-compose -f "$PROJECT_ROOT/deployments/docker/docker-compose.yaml" down -v > /dev/null 2>&1 || true
    fi
    
    # Remove test containers
    docker container prune -f > /dev/null 2>&1 || true
    
    log_success "Cleanup completed"
}

# Trap cleanup on exit
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Go
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed"
        exit 1
    fi
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    log_success "Prerequisites check passed"
}

# Setup test environment
setup_test_environment() {
    log_info "Setting up test environment..."
    
    # Set environment variables
    export GO_ENV=test
    export DATABASE_URL="postgres://test:testpass@localhost:5432/medrex_test?sslmode=disable"
    export FABRIC_NETWORK_PATH="$PROJECT_ROOT/deployments/docker"
    
    # Create test directories
    mkdir -p "$PROJECT_ROOT/test-results"
    mkdir -p "$PROJECT_ROOT/coverage"
    
    log_success "Test environment setup completed"
}

# Start infrastructure services
start_infrastructure() {
    log_info "Starting infrastructure services..."
    
    # Start PostgreSQL for testing (will be handled by testcontainers in tests)
    # Start minimal Fabric network for integration tests
    cd "$PROJECT_ROOT/deployments/docker"
    
    # Use development compose file for faster startup
    if [ -f "docker-compose.dev.yaml" ]; then
        log_info "Starting development infrastructure..."
        docker-compose -f docker-compose.dev.yaml up -d postgres redis > /dev/null 2>&1 || true
    fi
    
    # Wait for services to be ready
    log_info "Waiting for infrastructure services to be ready..."
    sleep 10
    
    log_success "Infrastructure services started"
}

# Run integration tests
run_integration_tests() {
    log_info "Running integration tests..."
    
    cd "$PROJECT_ROOT"
    
    # Set test build tag
    export CGO_ENABLED=1 # Required for some test dependencies
    
    # Run tests with coverage
    log_info "Executing integration test suite..."
    
    go test -v -race -tags=integration \
        -coverprofile="$PROJECT_ROOT/coverage/integration-coverage.out" \
        -covermode=atomic \
        -timeout=30m \
        ./tests/integration/... 2>&1 | tee "$PROJECT_ROOT/test-results/integration-tests.log"
    
    # Check if tests passed
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        log_success "Integration tests passed"
    else
        log_error "Integration tests failed"
        return 1
    fi
    
    # Generate coverage report
    if [ -f "$PROJECT_ROOT/coverage/integration-coverage.out" ]; then
        log_info "Generating coverage report..."
        go tool cover -html="$PROJECT_ROOT/coverage/integration-coverage.out" -o "$PROJECT_ROOT/coverage/integration-coverage.html"
        
        # Calculate coverage percentage
        COVERAGE=$(go tool cover -func="$PROJECT_ROOT/coverage/integration-coverage.out" | grep total | awk '{print $3}' | sed 's/%//')
        log_info "Integration test coverage: ${COVERAGE}%"
        
        if (( $(echo "$COVERAGE < 70" | bc -l) )); then
            log_warning "Integration test coverage is below 70%"
        else
            log_success "Integration test coverage is acceptable"
        fi
    fi
}

# Run specific test suite
run_specific_tests() {
    local test_pattern="$1"
    
    log_info "Running specific tests matching pattern: $test_pattern"
    
    cd "$PROJECT_ROOT"
    
    go test -v -race -tags=integration \
        -run "$test_pattern" \
        -timeout=15m \
        ./tests/integration/... 2>&1 | tee "$PROJECT_ROOT/test-results/specific-tests.log"
    
    if [ ${PIPESTATUS[0]} -eq 0 ]; then
        log_success "Specific tests passed"
    else
        log_error "Specific tests failed"
        return 1
    fi
}

# Generate test report
generate_test_report() {
    log_info "Generating test report..."
    
    local report_file="$PROJECT_ROOT/test-results/integration-test-report.md"
    
    cat > "$report_file" << EOF
# Medrex DLT EMR Integration Test Report

**Generated:** $(date)
**Environment:** Test
**Go Version:** $(go version)

## Test Results

EOF
    
    if [ -f "$PROJECT_ROOT/test-results/integration-tests.log" ]; then
        echo "### Integration Tests" >> "$report_file"
        echo "" >> "$report_file"
        
        # Extract test results
        local passed_tests=$(grep -c "PASS:" "$PROJECT_ROOT/test-results/integration-tests.log" || echo "0")
        local failed_tests=$(grep -c "FAIL:" "$PROJECT_ROOT/test-results/integration-tests.log" || echo "0")
        
        echo "- **Passed:** $passed_tests" >> "$report_file"
        echo "- **Failed:** $failed_tests" >> "$report_file"
        echo "" >> "$report_file"
        
        if [ "$failed_tests" -gt 0 ]; then
            echo "### Failed Tests" >> "$report_file"
            echo "" >> "$report_file"
            echo '```' >> "$report_file"
            grep "FAIL:" "$PROJECT_ROOT/test-results/integration-tests.log" >> "$report_file" || true
            echo '```' >> "$report_file"
            echo "" >> "$report_file"
        fi
    fi
    
    if [ -f "$PROJECT_ROOT/coverage/integration-coverage.out" ]; then
        echo "### Coverage Report" >> "$report_file"
        echo "" >> "$report_file"
        
        local coverage=$(go tool cover -func="$PROJECT_ROOT/coverage/integration-coverage.out" | grep total | awk '{print $3}')
        echo "**Total Coverage:** $coverage" >> "$report_file"
        echo "" >> "$report_file"
        
        echo "### Coverage by Package" >> "$report_file"
        echo "" >> "$report_file"
        echo '```' >> "$report_file"
        go tool cover -func="$PROJECT_ROOT/coverage/integration-coverage.out" | head -20 >> "$report_file"
        echo '```' >> "$report_file"
    fi
    
    log_success "Test report generated: $report_file"
}

# Main function
main() {
    local action="${1:-run}"
    local test_pattern="${2:-}"
    
    log_info "Starting Medrex DLT EMR integration tests..."
    
    case "$action" in
        "run")
            check_prerequisites
            setup_test_environment
            start_infrastructure
            run_integration_tests
            generate_test_report
            ;;
        "specific")
            if [ -z "$test_pattern" ]; then
                log_error "Test pattern is required for specific tests"
                echo "Usage: $0 specific <test_pattern>"
                exit 1
            fi
            check_prerequisites
            setup_test_environment
            start_infrastructure
            run_specific_tests "$test_pattern"
            ;;
        "setup")
            check_prerequisites
            setup_test_environment
            start_infrastructure
            log_success "Test environment setup completed"
            ;;
        "cleanup")
            cleanup
            ;;
        "help")
            cat << EOF
Medrex DLT EMR Integration Test Runner

Usage: $0 [ACTION] [OPTIONS]

ACTIONS:
    run         Run all integration tests (default)
    specific    Run specific tests matching pattern
    setup       Setup test environment only
    cleanup     Cleanup test environment
    help        Show this help message

EXAMPLES:
    $0 run
    $0 specific "TestUserWorkflow"
    $0 setup
    $0 cleanup

EOF
            ;;
        *)
            log_error "Unknown action: $action"
            echo "Use '$0 help' for usage information"
            exit 1
            ;;
    esac
    
    log_success "Integration test execution completed"
}

# Run main function
main "$@"