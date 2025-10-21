# Medrex DLT EMR Infrastructure
# Main Terraform configuration for AWS deployment

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
  }

  backend "s3" {
    # Configure your S3 backend here
    # bucket = "medrex-terraform-state"
    # key    = "infrastructure/terraform.tfstate"
    # region = "us-west-2"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "Medrex-DLT-EMR"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# Local values
locals {
  cluster_name = "${var.project_name}-${var.environment}"
  
  common_tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

  # Subnet CIDR blocks
  vpc_cidr = var.vpc_cidr
  private_subnets = [
    cidrsubnet(local.vpc_cidr, 8, 1),
    cidrsubnet(local.vpc_cidr, 8, 2),
    cidrsubnet(local.vpc_cidr, 8, 3)
  ]
  public_subnets = [
    cidrsubnet(local.vpc_cidr, 8, 101),
    cidrsubnet(local.vpc_cidr, 8, 102),
    cidrsubnet(local.vpc_cidr, 8, 103)
  ]
  database_subnets = [
    cidrsubnet(local.vpc_cidr, 8, 201),
    cidrsubnet(local.vpc_cidr, 8, 202),
    cidrsubnet(local.vpc_cidr, 8, 203)
  ]
}

# VPC Module
module "vpc" {
  source = "./modules/vpc"

  name = local.cluster_name
  cidr = local.vpc_cidr

  azs              = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets  = local.private_subnets
  public_subnets   = local.public_subnets
  database_subnets = local.database_subnets

  enable_nat_gateway   = true
  enable_vpn_gateway   = false
  enable_dns_hostnames = true
  enable_dns_support   = true

  # Enable VPC Flow Logs for security monitoring
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true

  tags = local.common_tags
}

# EKS Cluster Module
module "eks" {
  source = "./modules/eks"

  cluster_name    = local.cluster_name
  cluster_version = var.kubernetes_version

  vpc_id                   = module.vpc.vpc_id
  subnet_ids              = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  # Cluster endpoint configuration
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = true
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs

  # Cluster encryption
  cluster_encryption_config = [
    {
      provider_key_arn = module.kms.cluster_key_arn
      resources        = ["secrets"]
    }
  ]

  # Node groups
  node_groups = {
    fabric_nodes = {
      name           = "fabric-nodes"
      instance_types = ["m5.2xlarge"]
      capacity_type  = "ON_DEMAND"
      
      min_size     = 3
      max_size     = 6
      desired_size = 3

      disk_size = 100
      disk_type = "gp3"

      labels = {
        role = "fabric"
      }

      taints = [
        {
          key    = "fabric"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      ]
    }

    services_nodes = {
      name           = "services-nodes"
      instance_types = ["m5.xlarge"]
      capacity_type  = "SPOT"
      
      min_size     = 2
      max_size     = 10
      desired_size = 3

      disk_size = 50
      disk_type = "gp3"

      labels = {
        role = "services"
      }
    }

    data_nodes = {
      name           = "data-nodes"
      instance_types = ["r5.xlarge"]
      capacity_type  = "ON_DEMAND"
      
      min_size     = 2
      max_size     = 4
      desired_size = 2

      disk_size = 200
      disk_type = "gp3"

      labels = {
        role = "data"
      }

      taints = [
        {
          key    = "data"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      ]
    }
  }

  tags = local.common_tags
}

# RDS Module for PostgreSQL
module "rds" {
  source = "./modules/rds"

  identifier = "${local.cluster_name}-postgres"

  engine         = "postgres"
  engine_version = "15.4"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type         = "gp3"
  storage_encrypted    = true
  kms_key_id          = module.kms.rds_key_arn

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password

  vpc_security_group_ids = [module.security_groups.rds_security_group_id]
  db_subnet_group_name   = module.vpc.database_subnet_group

  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"

  # Enhanced monitoring
  monitoring_interval = 60
  monitoring_role_arn = module.iam.rds_enhanced_monitoring_role_arn

  # Performance Insights
  performance_insights_enabled = true
  performance_insights_kms_key_id = module.kms.rds_key_arn

  deletion_protection = var.environment == "production" ? true : false

  tags = local.common_tags
}

# KMS Module for encryption keys
module "kms" {
  source = "./modules/kms"

  project_name = var.project_name
  environment  = var.environment

  tags = local.common_tags
}

# Security Groups Module
module "security_groups" {
  source = "./modules/security-groups"

  name_prefix = local.cluster_name
  vpc_id      = module.vpc.vpc_id

  tags = local.common_tags
}

# IAM Module
module "iam" {
  source = "./modules/iam"

  cluster_name = local.cluster_name
  
  tags = local.common_tags
}

# HSM Module (AWS CloudHSM)
module "hsm" {
  source = "./modules/hsm"
  
  count = var.enable_hsm ? 1 : 0

  cluster_id = "${local.cluster_name}-hsm"
  subnet_ids = module.vpc.private_subnets

  tags = local.common_tags
}

# Application Load Balancer
module "alb" {
  source = "./modules/alb"

  name = "${local.cluster_name}-alb"
  
  vpc_id          = module.vpc.vpc_id
  subnets         = module.vpc.public_subnets
  security_groups = [module.security_groups.alb_security_group_id]

  certificate_arn = var.ssl_certificate_arn

  tags = local.common_tags
}

# EFS for shared storage
module "efs" {
  source = "./modules/efs"

  name = "${local.cluster_name}-efs"
  
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  security_groups = [module.security_groups.efs_security_group_id]

  encrypted  = true
  kms_key_id = module.kms.efs_key_arn

  tags = local.common_tags
}

# Configure Kubernetes provider
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

# Configure Helm provider
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}