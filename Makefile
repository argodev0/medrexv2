# Medrex DLT EMR Makefile

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
API_GATEWAY_BINARY=api-gateway
IAM_SERVICE_BINARY=iam-service
CLINICAL_NOTES_BINARY=clinical-notes-service
SCHEDULING_BINARY=scheduling-service
MOBILE_WORKFLOW_BINARY=mobile-workflow-service

# Build directory
BUILD_DIR=build

# Docker parameters
DOCKER_REGISTRY=medrex
DOCKER_TAG=latest

.PHONY: all build clean test deps docker-build docker-push help

all: clean deps test build

# Build all services
build: build-api-gateway build-iam build-clinical build-scheduling build-mobile

build-api-gateway:
	$(GOBUILD) -o $(BUILD_DIR)/$(API_GATEWAY_BINARY) ./cmd/api-gateway

build-iam:
	$(GOBUILD) -o $(BUILD_DIR)/$(IAM_SERVICE_BINARY) ./cmd/iam-service

build-clinical:
	$(GOBUILD) -o $(BUILD_DIR)/$(CLINICAL_NOTES_BINARY) ./cmd/clinical-notes-service

build-scheduling:
	$(GOBUILD) -o $(BUILD_DIR)/$(SCHEDULING_BINARY) ./cmd/scheduling-service

build-mobile:
	$(GOBUILD) -o $(BUILD_DIR)/$(MOBILE_WORKFLOW_BINARY) ./cmd/mobile-workflow-service

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

# Run tests
test:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Download dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Docker build all services
docker-build: docker-build-api-gateway docker-build-iam docker-build-clinical docker-build-scheduling docker-build-mobile

docker-build-api-gateway:
	docker build -f deployments/docker/Dockerfile.api-gateway -t $(DOCKER_REGISTRY)/api-gateway:$(DOCKER_TAG) .

docker-build-iam:
	docker build -f deployments/docker/Dockerfile.iam-service -t $(DOCKER_REGISTRY)/iam-service:$(DOCKER_TAG) .

docker-build-clinical:
	docker build -f deployments/docker/Dockerfile.clinical-notes -t $(DOCKER_REGISTRY)/clinical-notes-service:$(DOCKER_TAG) .

docker-build-scheduling:
	docker build -f deployments/docker/Dockerfile.scheduling -t $(DOCKER_REGISTRY)/scheduling-service:$(DOCKER_TAG) .

docker-build-mobile:
	docker build -f deployments/docker/Dockerfile.mobile-workflow -t $(DOCKER_REGISTRY)/mobile-workflow-service:$(DOCKER_TAG) .

# Help
help:
	@echo "Available targets:"
	@echo "  all              - Clean, download deps, test, and build all services"
	@echo "  build            - Build all services"
	@echo "  clean            - Clean build artifacts"
	@echo "  test             - Run tests with coverage"
	@echo "  deps             - Download and tidy dependencies"
	@echo "  docker-build     - Build all Docker images"
	@echo "  help             - Show this help message"