# RDS Module for Medrex DLT EMR

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# RDS Instance
resource "aws_db_instance" "main" {
  identifier = var.identifier

  # Engine options
  engine         = var.engine
  engine_version = var.engine_version
  instance_class = var.instance_class

  # Storage
  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type         = var.storage_type
  storage_encrypted    = var.storage_encrypted
  kms_key_id          = var.kms_key_id

  # Database configuration
  db_name  = var.db_name
  username = var.username
  password = var.password
  port     = var.port

  # Network & Security
  vpc_security_group_ids = var.vpc_security_group_ids
  db_subnet_group_name   = var.db_subnet_group_name
  publicly_accessible    = var.publicly_accessible

  # Backup & Maintenance
  backup_retention_period = var.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window
  copy_tags_to_snapshot  = true
  delete_automated_backups = false

  # Monitoring
  monitoring_interval = var.monitoring_interval
  monitoring_role_arn = var.monitoring_role_arn

  # Performance Insights
  performance_insights_enabled    = var.performance_insights_enabled
  performance_insights_kms_key_id = var.performance_insights_kms_key_id

  # Deletion protection
  deletion_protection = var.deletion_protection
  skip_final_snapshot = var.skip_final_snapshot
  final_snapshot_identifier = var.skip_final_snapshot ? null : "${var.identifier}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  # Parameter group
  parameter_group_name = aws_db_parameter_group.main.name

  # Option group
  option_group_name = aws_db_option_group.main.name

  # Enable logging
  enabled_cloudwatch_logs_exports = var.enabled_cloudwatch_logs_exports

  tags = var.tags
}

# DB Parameter Group
resource "aws_db_parameter_group" "main" {
  family = var.parameter_group_family
  name   = "${var.identifier}-params"

  # PostgreSQL specific parameters for healthcare workload
  dynamic "parameter" {
    for_each = var.engine == "postgres" ? [
      {
        name  = "shared_preload_libraries"
        value = "pg_stat_statements"
      },
      {
        name  = "log_statement"
        value = "all"
      },
      {
        name  = "log_min_duration_statement"
        value = "1000"
      },
      {
        name  = "log_connections"
        value = "1"
      },
      {
        name  = "log_disconnections"
        value = "1"
      },
      {
        name  = "log_lock_waits"
        value = "1"
      },
      {
        name  = "log_temp_files"
        value = "0"
      },
      {
        name  = "log_autovacuum_min_duration"
        value = "0"
      },
      {
        name  = "checkpoint_completion_target"
        value = "0.9"
      },
      {
        name  = "wal_buffers"
        value = "16MB"
      },
      {
        name  = "default_statistics_target"
        value = "100"
      },
      {
        name  = "random_page_cost"
        value = "1.1"
      },
      {
        name  = "effective_io_concurrency"
        value = "200"
      },
      {
        name  = "work_mem"
        value = "4MB"
      },
      {
        name  = "maintenance_work_mem"
        value = "64MB"
      }
    ] : []

    content {
      name  = parameter.value.name
      value = parameter.value.value
    }
  }

  # Custom parameters
  dynamic "parameter" {
    for_each = var.parameters
    content {
      name         = parameter.value.name
      value        = parameter.value.value
      apply_method = lookup(parameter.value, "apply_method", "immediate")
    }
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

# DB Option Group
resource "aws_db_option_group" "main" {
  name                 = "${var.identifier}-options"
  option_group_description = "Option group for ${var.identifier}"
  engine_name          = var.engine
  major_engine_version = split(".", var.engine_version)[0]

  dynamic "option" {
    for_each = var.options
    content {
      option_name = option.value.option_name

      dynamic "option_settings" {
        for_each = lookup(option.value, "option_settings", [])
        content {
          name  = option_settings.value.name
          value = option_settings.value.value
        }
      }

      dynamic "db_security_group_memberships" {
        for_each = lookup(option.value, "db_security_group_memberships", [])
        content {
          db_security_group_membership = db_security_group_memberships.value
        }
      }

      dynamic "vpc_security_group_memberships" {
        for_each = lookup(option.value, "vpc_security_group_memberships", [])
        content {
          vpc_security_group_membership = vpc_security_group_memberships.value
        }
      }
    }
  }

  tags = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

# Read Replica (optional)
resource "aws_db_instance" "read_replica" {
  count = var.create_read_replica ? 1 : 0

  identifier = "${var.identifier}-read-replica"

  replicate_source_db = aws_db_instance.main.identifier

  instance_class = var.read_replica_instance_class != "" ? var.read_replica_instance_class : var.instance_class

  # Storage
  storage_encrypted = var.storage_encrypted
  kms_key_id       = var.kms_key_id

  # Network & Security
  vpc_security_group_ids = var.vpc_security_group_ids
  publicly_accessible    = false

  # Monitoring
  monitoring_interval = var.monitoring_interval
  monitoring_role_arn = var.monitoring_role_arn

  # Performance Insights
  performance_insights_enabled    = var.performance_insights_enabled
  performance_insights_kms_key_id = var.performance_insights_kms_key_id

  # Auto minor version upgrade
  auto_minor_version_upgrade = var.auto_minor_version_upgrade

  tags = merge(
    var.tags,
    {
      Name = "${var.identifier}-read-replica"
      Type = "ReadReplica"
    }
  )
}

# CloudWatch Log Groups for RDS logs
resource "aws_cloudwatch_log_group" "postgresql" {
  count = var.engine == "postgres" && contains(var.enabled_cloudwatch_logs_exports, "postgresql") ? 1 : 0

  name              = "/aws/rds/instance/${var.identifier}/postgresql"
  retention_in_days = var.cloudwatch_log_group_retention_in_days

  tags = var.tags
}

resource "aws_cloudwatch_log_group" "upgrade" {
  count = var.engine == "postgres" && contains(var.enabled_cloudwatch_logs_exports, "upgrade") ? 1 : 0

  name              = "/aws/rds/instance/${var.identifier}/upgrade"
  retention_in_days = var.cloudwatch_log_group_retention_in_days

  tags = var.tags
}

# DB Subnet Group (if not provided)
resource "aws_db_subnet_group" "main" {
  count = var.create_db_subnet_group ? 1 : 0

  name       = "${var.identifier}-subnet-group"
  subnet_ids = var.subnet_ids

  tags = merge(
    var.tags,
    {
      Name = "${var.identifier}-subnet-group"
    }
  )
}

# Enhanced Monitoring IAM Role
resource "aws_iam_role" "enhanced_monitoring" {
  count = var.create_monitoring_role ? 1 : 0

  name = "${var.identifier}-enhanced-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "enhanced_monitoring" {
  count = var.create_monitoring_role ? 1 : 0

  role       = aws_iam_role.enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}