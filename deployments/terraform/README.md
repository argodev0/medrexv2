# Medrex DLT EMR Terraform Infrastructure

This directory contains Terraform configurations for deploying the complete Medrex DLT EMR infrastructure on AWS.

## Architecture Overview

The Terraform configuration creates:

- **VPC**: Multi-AZ VPC with public, private, and database subnets
- **EKS Cluster**: Managed Kubernetes cluster with multiple node groups
- **RDS**: PostgreSQL database with encryption and enhanced monitoring
- **KMS**: Encryption keys for all services
- **Security Groups**: Network security controls
- **IAM**: Roles and policies for service access
- **ALB**: Application Load Balancer for external access
- **EFS**: Shared file system for persistent storage
- **CloudHSM**: Hardware Security Module (optional)

## Prerequisites

1. **AWS CLI**: Configured with appropriate credentials
2. **Terraform**: Version 1.0 or higher
3. **kubectl**: For Kubernetes cluster management
4. **AWS Account**: With appropriate permissions

### Required AWS Permissions

Your AWS credentials need the following permissions:
- EC2 (VPC, Security Groups, Load Balancers)
- EKS (Cluster and Node Group management)
- RDS (Database instances)
- IAM (Roles and Policies)
- KMS (Key management)
- CloudWatch (Logging and monitoring)
- Route53 (DNS management)
- Certificate Manager (SSL certificates)

## Quick Start

1. **Clone and navigate to the directory:**
   ```bash
   cd deployments/terraform
   ```

2. **Copy and customize variables:**
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your specific values
   ```

3. **Initialize Terraform:**
   ```bash
   terraform init
   ```

4. **Plan the deployment:**
   ```bash
   terraform plan
   ```

5. **Apply the configuration:**
   ```bash
   terraform apply
   ```

6. **Configure kubectl:**
   ```bash
   aws eks update-kubeconfig --region us-west-2 --name medrex-dlt-emr-dev
   ```

## Configuration

### Essential Variables

Edit `terraform.tfvars` with your specific values:

```hcl
# Basic Configuration
aws_region   = "us-west-2"
project_name = "medrex-dlt-emr"
environment  = "production"

# Database Configuration
db_password = "your-secure-password"

# SSL Certificate (from AWS Certificate Manager)
ssl_certificate_arn = "arn:aws:acm:us-west-2:123456789012:certificate/..."

# Domain Configuration
domain_name = "yourdomain.com"
```

### Security Considerations

1. **Database Password**: Use AWS Secrets Manager in production
2. **SSL Certificate**: Obtain from AWS Certificate Manager
3. **Network Access**: Restrict `cluster_endpoint_public_access_cidrs`
4. **HSM**: Enable for production environments requiring hardware security

### Environment-Specific Configurations

#### Development
```hcl
environment = "dev"
db_instance_class = "db.t3.medium"
enable_hsm = false
enable_spot_instances = true
```

#### Production
```hcl
environment = "prod"
db_instance_class = "db.r5.2xlarge"
enable_hsm = true
enable_spot_instances = false
deletion_protection = true
```

## Modules

The infrastructure is organized into reusable modules:

| Module | Purpose |
|--------|---------|
| `vpc` | Network infrastructure |
| `eks` | Kubernetes cluster |
| `rds` | PostgreSQL database |
| `kms` | Encryption keys |
| `security-groups` | Network security |
| `iam` | Identity and access management |
| `alb` | Application load balancer |
| `efs` | Shared file system |
| `hsm` | Hardware security module |

## Deployment Process

### 1. Pre-deployment Checklist

- [ ] AWS credentials configured
- [ ] Domain name registered and DNS configured
- [ ] SSL certificate requested in AWS Certificate Manager
- [ ] Terraform variables customized
- [ ] S3 bucket created for Terraform state (optional but recommended)

### 2. State Management

For production deployments, configure remote state:

```hcl
terraform {
  backend "s3" {
    bucket = "your-terraform-state-bucket"
    key    = "medrex-dlt-emr/terraform.tfstate"
    region = "us-west-2"
  }
}
```

### 3. Deployment Steps

```bash
# Initialize with backend configuration
terraform init

# Validate configuration
terraform validate

# Plan deployment
terraform plan -out=tfplan

# Apply deployment
terraform apply tfplan
```

### 4. Post-deployment Configuration

After successful deployment:

1. **Configure kubectl:**
   ```bash
   aws eks update-kubeconfig --region $(terraform output -raw aws_region) --name $(terraform output -raw cluster_name)
   ```

2. **Verify cluster access:**
   ```bash
   kubectl get nodes
   ```

3. **Deploy Kubernetes manifests:**
   ```bash
   cd ../kubernetes
   ./deploy.sh
   ```

4. **Configure DNS:**
   - Point your domain to the ALB DNS name
   - Verify SSL certificate is working

## Monitoring and Management

### CloudWatch Integration

The infrastructure includes comprehensive CloudWatch integration:

- **EKS Cluster Logs**: Control plane logging
- **RDS Monitoring**: Enhanced monitoring and Performance Insights
- **VPC Flow Logs**: Network traffic monitoring
- **Application Logs**: Centralized logging for all services

### Cost Optimization

Built-in cost optimization features:

- **Spot Instances**: For non-critical workloads
- **Auto Scaling**: Automatic scaling based on demand
- **Storage Optimization**: GP3 volumes with optimized IOPS
- **Reserved Capacity**: Consider for production workloads

### Security Features

- **Encryption at Rest**: All data encrypted using KMS
- **Encryption in Transit**: TLS for all communications
- **Network Isolation**: Private subnets for sensitive components
- **IAM Roles**: Least privilege access
- **Security Groups**: Restrictive network rules
- **VPC Flow Logs**: Network monitoring
- **CloudTrail**: API call auditing

## Troubleshooting

### Common Issues

1. **EKS Node Group Creation Fails**
   - Check IAM permissions
   - Verify subnet configuration
   - Ensure sufficient IP addresses

2. **RDS Connection Issues**
   - Verify security group rules
   - Check subnet group configuration
   - Confirm VPC routing

3. **ALB Health Check Failures**
   - Verify target group configuration
   - Check security group rules
   - Confirm application health endpoint

### Debugging Commands

```bash
# Check Terraform state
terraform show

# Validate configuration
terraform validate

# Check AWS resources
aws eks describe-cluster --name $(terraform output -raw cluster_name)
aws rds describe-db-instances --db-instance-identifier $(terraform output -raw rds_identifier)

# Kubernetes debugging
kubectl get pods --all-namespaces
kubectl describe nodes
```

## Maintenance

### Updates and Upgrades

1. **Terraform Updates:**
   ```bash
   terraform plan
   terraform apply
   ```

2. **EKS Cluster Updates:**
   - Update cluster version in variables
   - Apply Terraform changes
   - Update node groups

3. **RDS Maintenance:**
   - Scheduled during maintenance windows
   - Automatic minor version updates enabled

### Backup and Recovery

- **RDS Backups**: Automated daily backups with 30-day retention
- **EKS Backups**: Velero for cluster backups (deploy separately)
- **Infrastructure State**: Terraform state in S3 with versioning

## Cost Estimation

Estimated monthly costs (us-west-2):

| Component | Development | Production |
|-----------|-------------|------------|
| EKS Cluster | $73 | $73 |
| Node Groups | $200-400 | $800-1200 |
| RDS Instance | $100-200 | $400-800 |
| ALB | $20 | $20 |
| NAT Gateway | $45 | $45 |
| Storage | $50-100 | $200-400 |
| Data Transfer | $20-50 | $100-300 |
| **Total** | **$500-900** | **$1600-2800** |

## Support

For issues with the Terraform deployment:

1. Check the Terraform documentation
2. Review AWS service limits
3. Verify IAM permissions
4. Check CloudWatch logs for errors
5. Use AWS Support for service-specific issues

## Cleanup

To destroy the infrastructure:

```bash
# Destroy in reverse order
terraform destroy
```

**Warning**: This will permanently delete all resources. Ensure you have backups of any important data.