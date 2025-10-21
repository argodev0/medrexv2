#!/bin/bash

# Medrex DLT EMR Kubernetes Deployment Script
# This script deploys the complete Medrex system to a Kubernetes cluster

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    print_error "kubectl is not installed or not in PATH"
    exit 1
fi

# Check if we can connect to the cluster
if ! kubectl cluster-info &> /dev/null; then
    print_error "Cannot connect to Kubernetes cluster"
    exit 1
fi

print_status "Starting Medrex DLT EMR deployment..."

# Create namespaces first
print_status "Creating namespaces..."
kubectl apply -f 00-namespaces.yaml

# Wait for namespaces to be ready
sleep 5

# Apply ConfigMaps and Secrets
print_status "Applying ConfigMaps and Secrets..."
kubectl apply -f 01-configmaps.yaml
kubectl apply -f 02-secrets.yaml

# Create persistent volumes
print_status "Creating persistent volumes..."
kubectl apply -f 03-persistent-volumes.yaml

# Wait for PVs to be available
print_status "Waiting for persistent volumes to be available..."
sleep 10

# Deploy PostgreSQL database
print_status "Deploying PostgreSQL database..."
kubectl apply -f 04-postgresql.yaml

# Wait for PostgreSQL to be ready
print_status "Waiting for PostgreSQL to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/postgresql -n medrex-data

# Deploy Hyperledger Fabric network components
print_status "Deploying Hyperledger Fabric orderers..."
kubectl apply -f 05-fabric-orderers.yaml

print_status "Deploying Hyperledger Fabric CAs..."
kubectl apply -f 06-fabric-cas.yaml

print_status "Deploying Hyperledger Fabric peers (Hospital)..."
kubectl apply -f 07-fabric-peers.yaml

print_status "Deploying Hyperledger Fabric peers (Pharmacy)..."
kubectl apply -f 08-fabric-pharmacy-peers.yaml

# Wait for Fabric network to be ready
print_status "Waiting for Fabric network components to be ready..."
kubectl wait --for=condition=available --timeout=600s deployment/orderer0 -n medrex-fabric
kubectl wait --for=condition=available --timeout=600s deployment/orderer1 -n medrex-fabric
kubectl wait --for=condition=available --timeout=600s deployment/orderer2 -n medrex-fabric
kubectl wait --for=condition=available --timeout=600s deployment/ca-hospital -n medrex-fabric
kubectl wait --for=condition=available --timeout=600s deployment/ca-pharmacy -n medrex-fabric

# Deploy microservices
print_status "Deploying IAM service..."
kubectl apply -f 09-iam-service.yaml

print_status "Deploying API Gateway..."
kubectl apply -f 10-api-gateway.yaml

print_status "Deploying Clinical Notes service..."
kubectl apply -f 11-clinical-notes-service.yaml

print_status "Deploying Scheduling service..."
kubectl apply -f 12-scheduling-service.yaml

print_status "Deploying Mobile Workflow service..."
kubectl apply -f 13-mobile-workflow-service.yaml

# Wait for microservices to be ready
print_status "Waiting for microservices to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/iam-service -n medrex-services
kubectl wait --for=condition=available --timeout=300s deployment/api-gateway -n medrex-services
kubectl wait --for=condition=available --timeout=300s deployment/clinical-notes-service -n medrex-services
kubectl wait --for=condition=available --timeout=300s deployment/scheduling-service -n medrex-services
kubectl wait --for=condition=available --timeout=300s deployment/mobile-workflow-service -n medrex-services

# Deploy ingress and network policies
print_status "Deploying ingress and network policies..."
kubectl apply -f 14-ingress.yaml

# Display deployment status
print_status "Deployment completed! Checking status..."

echo ""
print_status "Namespace status:"
kubectl get namespaces | grep medrex

echo ""
print_status "Persistent Volumes status:"
kubectl get pv | grep medrex

echo ""
print_status "Database status:"
kubectl get pods -n medrex-data

echo ""
print_status "Fabric network status:"
kubectl get pods -n medrex-fabric

echo ""
print_status "Microservices status:"
kubectl get pods -n medrex-services

echo ""
print_status "Services status:"
kubectl get services -n medrex-services

echo ""
print_status "Ingress status:"
kubectl get ingress -n medrex-services

echo ""
print_status "HPA status:"
kubectl get hpa -n medrex-services

print_status "Medrex DLT EMR deployment completed successfully!"
print_warning "Please ensure that:"
print_warning "1. DNS is configured to point api.medrex.com to your ingress controller"
print_warning "2. TLS certificates are properly configured"
print_warning "3. Fabric network is properly initialized with channels and chaincode"
print_warning "4. Database migrations are run"
print_warning "5. HSM service is configured and accessible"

echo ""
print_status "To check logs, use:"
echo "kubectl logs -f deployment/api-gateway -n medrex-services"
echo "kubectl logs -f deployment/iam-service -n medrex-services"
echo "kubectl logs -f deployment/clinical-notes-service -n medrex-services"

echo ""
print_status "To access the API Gateway:"
API_GATEWAY_IP=$(kubectl get service api-gateway -n medrex-services -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
if [ -n "$API_GATEWAY_IP" ]; then
    echo "API Gateway is available at: http://$API_GATEWAY_IP:8080"
else
    echo "API Gateway service is available via ingress at: https://api.medrex.com"
fi