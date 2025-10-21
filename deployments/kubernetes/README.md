# Medrex DLT EMR Kubernetes Deployment

This directory contains Kubernetes manifests for deploying the complete Medrex DLT EMR system to a Kubernetes cluster.

## Architecture Overview

The deployment consists of three main namespaces:

- **medrex-fabric**: Hyperledger Fabric network components (orderers, peers, CAs, CouchDB)
- **medrex-services**: Application microservices (IAM, API Gateway, Clinical Notes, Scheduling, Mobile Workflow)
- **medrex-data**: Data layer components (PostgreSQL database)

## Prerequisites

1. **Kubernetes Cluster**: Version 1.20 or higher
2. **kubectl**: Configured to access your cluster
3. **Storage Class**: `fast-ssd` storage class configured for high-performance storage
4. **Ingress Controller**: NGINX ingress controller installed
5. **Cert Manager**: For TLS certificate management (optional but recommended)
6. **Container Images**: All Medrex service images built and available in your registry

## Resource Requirements

### Minimum Cluster Requirements
- **Nodes**: 3 worker nodes minimum
- **CPU**: 16 cores total minimum
- **Memory**: 64 GB total minimum
- **Storage**: 1 TB high-IOPS SSD storage

### Per-Service Resource Allocation
- **PostgreSQL**: 2-4 GB RAM, 1-2 CPU cores, 100 GB storage
- **Fabric Orderers**: 1-2 GB RAM each, 0.5-1 CPU core each, 20 GB storage each
- **Fabric Peers**: 2-4 GB RAM each, 1-2 CPU cores each, 50 GB storage each
- **CouchDB**: 1-2 GB RAM each, 0.5-1 CPU core each, 30 GB storage each
- **Microservices**: 1-2 GB RAM each, 0.5-1 CPU core each

## Deployment Files

| File | Description |
|------|-------------|
| `00-namespaces.yaml` | Creates the three main namespaces |
| `01-configmaps.yaml` | Configuration data for services |
| `02-secrets.yaml` | Sensitive configuration data |
| `03-persistent-volumes.yaml` | Storage volumes for all components |
| `04-postgresql.yaml` | PostgreSQL database deployment |
| `05-fabric-orderers.yaml` | Hyperledger Fabric ordering service |
| `06-fabric-cas.yaml` | Fabric Certificate Authorities |
| `07-fabric-peers.yaml` | Hospital organization peers and CouchDB |
| `08-fabric-pharmacy-peers.yaml` | Pharmacy organization peers and CouchDB |
| `09-iam-service.yaml` | Identity and Access Management service |
| `10-api-gateway.yaml` | API Gateway service |
| `11-clinical-notes-service.yaml` | Clinical Notes management service |
| `12-scheduling-service.yaml` | Appointment scheduling service |
| `13-mobile-workflow-service.yaml` | Mobile workflow service |
| `14-ingress.yaml` | Ingress controller and network policies |

## Quick Deployment

1. **Clone the repository and navigate to the Kubernetes directory:**
   ```bash
   cd deployments/kubernetes
   ```

2. **Update configuration:**
   - Edit `01-configmaps.yaml` to match your environment
   - Update `02-secrets.yaml` with your actual secrets (base64 encoded)
   - Modify resource requests/limits in service files as needed

3. **Run the deployment script:**
   ```bash
   ./deploy.sh
   ```

4. **Monitor the deployment:**
   ```bash
   kubectl get pods --all-namespaces -w
   ```

## Manual Deployment

If you prefer to deploy manually or need to customize the deployment:

```bash
# 1. Create namespaces
kubectl apply -f 00-namespaces.yaml

# 2. Apply configuration
kubectl apply -f 01-configmaps.yaml
kubectl apply -f 02-secrets.yaml

# 3. Create storage
kubectl apply -f 03-persistent-volumes.yaml

# 4. Deploy database
kubectl apply -f 04-postgresql.yaml

# 5. Deploy Fabric network
kubectl apply -f 05-fabric-orderers.yaml
kubectl apply -f 06-fabric-cas.yaml
kubectl apply -f 07-fabric-peers.yaml
kubectl apply -f 08-fabric-pharmacy-peers.yaml

# 6. Deploy microservices
kubectl apply -f 09-iam-service.yaml
kubectl apply -f 10-api-gateway.yaml
kubectl apply -f 11-clinical-notes-service.yaml
kubectl apply -f 12-scheduling-service.yaml
kubectl apply -f 13-mobile-workflow-service.yaml

# 7. Configure networking
kubectl apply -f 14-ingress.yaml
```

## Post-Deployment Configuration

### 1. Initialize Hyperledger Fabric Network

After the Fabric components are running, you need to:

1. **Create the channel:**
   ```bash
   kubectl exec -it deployment/peer0-hospital -n medrex-fabric -- peer channel create -o orderer0-service:7050 -c healthcare -f /etc/hyperledger/fabric/channel.tx
   ```

2. **Join peers to the channel:**
   ```bash
   kubectl exec -it deployment/peer0-hospital -n medrex-fabric -- peer channel join -b healthcare.block
   kubectl exec -it deployment/peer1-hospital -n medrex-fabric -- peer channel join -b healthcare.block
   kubectl exec -it deployment/peer0-pharmacy -n medrex-fabric -- peer channel join -b healthcare.block
   kubectl exec -it deployment/peer1-pharmacy -n medrex-fabric -- peer channel join -b healthcare.block
   ```

3. **Install and instantiate chaincode:**
   ```bash
   # Install AccessPolicy chaincode
   kubectl exec -it deployment/peer0-hospital -n medrex-fabric -- peer lifecycle chaincode install accesspolicy.tar.gz
   
   # Install AuditLog chaincode
   kubectl exec -it deployment/peer0-hospital -n medrex-fabric -- peer lifecycle chaincode install auditlog.tar.gz
   ```

### 2. Database Initialization

Run database migrations:

```bash
kubectl exec -it deployment/postgresql -n medrex-data -- psql -U medrex_user -d medrex_emr -f /docker-entrypoint-initdb.d/schema.sql
```

### 3. Configure DNS and TLS

1. **Point your domain to the ingress controller:**
   ```bash
   # Get the ingress controller's external IP
   kubectl get service -n ingress-nginx ingress-nginx-controller
   ```

2. **Configure DNS:**
   - Create an A record for `api.medrex.com` pointing to the ingress IP

3. **Verify TLS certificates:**
   ```bash
   kubectl get certificate -n medrex-services
   ```

## Monitoring and Troubleshooting

### Check Pod Status
```bash
# All pods
kubectl get pods --all-namespaces

# Specific namespace
kubectl get pods -n medrex-services
kubectl get pods -n medrex-fabric
kubectl get pods -n medrex-data
```

### View Logs
```bash
# Service logs
kubectl logs -f deployment/api-gateway -n medrex-services
kubectl logs -f deployment/iam-service -n medrex-services
kubectl logs -f deployment/clinical-notes-service -n medrex-services

# Fabric logs
kubectl logs -f deployment/orderer0 -n medrex-fabric
kubectl logs -f deployment/peer0-hospital -n medrex-fabric
```

### Check Service Connectivity
```bash
# Test internal service connectivity
kubectl exec -it deployment/api-gateway -n medrex-services -- curl http://iam-service:8080/health

# Test external connectivity
curl https://api.medrex.com/health
```

### Resource Usage
```bash
# Check resource usage
kubectl top pods -n medrex-services
kubectl top nodes

# Check HPA status
kubectl get hpa -n medrex-services
```

## Scaling

The deployment includes Horizontal Pod Autoscalers (HPA) for automatic scaling:

- **API Gateway**: 3-15 replicas based on CPU/memory usage
- **IAM Service**: 3-10 replicas based on CPU/memory usage
- **Clinical Notes Service**: 3-10 replicas based on CPU/memory usage
- **Scheduling Service**: 2-8 replicas based on CPU/memory usage
- **Mobile Workflow Service**: 2-8 replicas based on CPU/memory usage

Manual scaling:
```bash
kubectl scale deployment api-gateway --replicas=5 -n medrex-services
```

## Security Considerations

1. **Network Policies**: Implemented to restrict inter-namespace communication
2. **TLS**: All external communication uses TLS
3. **Secrets Management**: Sensitive data stored in Kubernetes secrets
4. **RBAC**: Configure Kubernetes RBAC for proper access control
5. **Pod Security**: Consider implementing Pod Security Standards

## Backup and Recovery

### Database Backup
```bash
kubectl exec deployment/postgresql -n medrex-data -- pg_dump -U medrex_user medrex_emr > backup.sql
```

### Fabric State Backup
```bash
# Backup peer data
kubectl cp medrex-fabric/peer0-hospital-pod:/var/hyperledger/production ./fabric-backup/
```

## Maintenance

### Rolling Updates
```bash
# Update a service
kubectl set image deployment/api-gateway api-gateway=medrex/api-gateway:v2.0.0 -n medrex-services

# Check rollout status
kubectl rollout status deployment/api-gateway -n medrex-services

# Rollback if needed
kubectl rollout undo deployment/api-gateway -n medrex-services
```

### Certificate Renewal
Certificates managed by cert-manager will auto-renew. Manual renewal:
```bash
kubectl delete certificate medrex-api-tls -n medrex-services
kubectl apply -f 14-ingress.yaml
```

## Support

For issues with the Kubernetes deployment:

1. Check the deployment logs
2. Verify resource availability
3. Ensure all prerequisites are met
4. Check network connectivity between components
5. Validate configuration in ConfigMaps and Secrets