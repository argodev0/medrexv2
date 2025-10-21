# Outputs for Medrex DLT EMR Infrastructure

# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "database_subnets" {
  description = "List of IDs of database subnets"
  value       = module.vpc.database_subnets
}

# EKS Cluster Outputs
output "cluster_id" {
  description = "EKS cluster ID"
  value       = module.eks.cluster_id
}

output "cluster_arn" {
  description = "EKS cluster ARN"
  value       = module.eks.cluster_arn
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
  sensitive   = true
}

output "cluster_version" {
  description = "The Kubernetes version for the EKS cluster"
  value       = module.eks.cluster_version
}

output "cluster_platform_version" {
  description = "Platform version for the EKS cluster"
  value       = module.eks.cluster_platform_version
}

output "cluster_status" {
  description = "Status of the EKS cluster"
  value       = module.eks.cluster_status
}

# Node Group Outputs
output "node_groups" {
  description = "EKS node groups"
  value       = module.eks.node_groups
  sensitive   = true
}

# RDS Outputs
output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = module.rds.db_instance_endpoint
}

output "rds_port" {
  description = "RDS instance port"
  value       = module.rds.db_instance_port
}

output "rds_identifier" {
  description = "RDS instance identifier"
  value       = module.rds.db_instance_identifier
}

output "rds_arn" {
  description = "RDS instance ARN"
  value       = module.rds.db_instance_arn
}

output "rds_status" {
  description = "RDS instance status"
  value       = module.rds.db_instance_status
}

# KMS Outputs
output "kms_cluster_key_arn" {
  description = "ARN of the KMS key for EKS cluster encryption"
  value       = module.kms.cluster_key_arn
}

output "kms_rds_key_arn" {
  description = "ARN of the KMS key for RDS encryption"
  value       = module.kms.rds_key_arn
}

output "kms_efs_key_arn" {
  description = "ARN of the KMS key for EFS encryption"
  value       = module.kms.efs_key_arn
}

# Security Group Outputs
output "alb_security_group_id" {
  description = "ID of the ALB security group"
  value       = module.security_groups.alb_security_group_id
}

output "rds_security_group_id" {
  description = "ID of the RDS security group"
  value       = module.security_groups.rds_security_group_id
}

output "efs_security_group_id" {
  description = "ID of the EFS security group"
  value       = module.security_groups.efs_security_group_id
}

# ALB Outputs
output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = module.alb.lb_arn
}

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = module.alb.lb_dns_name
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer"
  value       = module.alb.lb_zone_id
}

# EFS Outputs
output "efs_id" {
  description = "ID of the EFS file system"
  value       = module.efs.id
}

output "efs_arn" {
  description = "ARN of the EFS file system"
  value       = module.efs.arn
}

output "efs_dns_name" {
  description = "DNS name of the EFS file system"
  value       = module.efs.dns_name
}

# HSM Outputs (conditional)
output "hsm_cluster_id" {
  description = "ID of the CloudHSM cluster"
  value       = var.enable_hsm ? module.hsm[0].cluster_id : null
}

output "hsm_cluster_state" {
  description = "State of the CloudHSM cluster"
  value       = var.enable_hsm ? module.hsm[0].cluster_state : null
}

# IAM Outputs
output "cluster_service_role_arn" {
  description = "ARN of the EKS cluster service role"
  value       = module.iam.cluster_service_role_arn
}

output "node_group_role_arn" {
  description = "ARN of the EKS node group role"
  value       = module.iam.node_group_role_arn
}

# Connection Information
output "kubectl_config" {
  description = "kubectl config command to connect to the cluster"
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

output "database_connection_string" {
  description = "Database connection string (without password)"
  value       = "postgresql://${var.db_username}@${module.rds.db_instance_endpoint}:${module.rds.db_instance_port}/${var.db_name}"
  sensitive   = true
}

# Application URLs
output "api_url" {
  description = "API URL"
  value       = var.ssl_certificate_arn != "" ? "https://${var.api_subdomain}.${var.domain_name}" : "http://${module.alb.lb_dns_name}"
}

output "health_check_url" {
  description = "Health check URL"
  value       = var.ssl_certificate_arn != "" ? "https://${var.api_subdomain}.${var.domain_name}/health" : "http://${module.alb.lb_dns_name}/health"
}

# Monitoring and Logging
output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for EKS cluster"
  value       = "/aws/eks/${module.eks.cluster_name}/cluster"
}

# Cost Information
output "estimated_monthly_cost" {
  description = "Estimated monthly cost breakdown"
  value = {
    eks_cluster     = "~$73 (control plane)"
    node_groups     = "~$300-600 (depending on instance types and count)"
    rds_instance    = "~$200-400 (depending on instance class)"
    alb             = "~$20"
    nat_gateway     = "~$45"
    data_transfer   = "Variable based on usage"
    storage         = "~$50-100 (EBS volumes)"
    cloudwatch_logs = "~$10-50 (depending on log volume)"
    total_estimate  = "~$700-1300/month"
  }
}

# Security and Compliance
output "security_features_enabled" {
  description = "List of enabled security features"
  value = {
    vpc_flow_logs        = var.enable_vpc_flow_logs
    cloudtrail          = var.enable_cloudtrail
    config              = var.enable_config
    guardduty           = var.enable_guardduty
    waf                 = var.enable_waf
    shield              = var.enable_shield
    encryption_at_rest  = true
    encryption_in_transit = true
  }
}

# Backup and Recovery
output "backup_configuration" {
  description = "Backup configuration details"
  value = {
    rds_backup_retention_days = var.backup_retention_days
    rds_backup_window        = "03:00-04:00"
    rds_maintenance_window   = "sun:04:00-sun:05:00"
    cross_region_backup      = var.enable_cross_region_backup
    backup_region           = var.backup_region
  }
}

# Resource Tags
output "common_tags" {
  description = "Common tags applied to all resources"
  value = merge(
    {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
    },
    var.additional_tags
  )
}