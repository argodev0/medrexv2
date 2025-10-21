# Outputs for RDS Module

output "db_instance_address" {
  description = "The RDS instance hostname"
  value       = aws_db_instance.main.address
}

output "db_instance_arn" {
  description = "The RDS instance ARN"
  value       = aws_db_instance.main.arn
}

output "db_instance_availability_zone" {
  description = "The availability zone of the RDS instance"
  value       = aws_db_instance.main.availability_zone
}

output "db_instance_endpoint" {
  description = "The RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
}

output "db_instance_hosted_zone_id" {
  description = "The canonical hosted zone ID of the DB instance (to be used in a Route 53 Alias record)"
  value       = aws_db_instance.main.hosted_zone_id
}

output "db_instance_id" {
  description = "The RDS instance ID"
  value       = aws_db_instance.main.id
}

output "db_instance_resource_id" {
  description = "The RDS Resource ID of this instance"
  value       = aws_db_instance.main.resource_id
}

output "db_instance_status" {
  description = "The RDS instance status"
  value       = aws_db_instance.main.status
}

output "db_instance_name" {
  description = "The database name"
  value       = aws_db_instance.main.db_name
}

output "db_instance_username" {
  description = "The master username for the database"
  value       = aws_db_instance.main.username
  sensitive   = true
}

output "db_instance_port" {
  description = "The database port"
  value       = aws_db_instance.main.port
}

output "db_instance_ca_cert_identifier" {
  description = "Specifies the identifier of the CA certificate for the DB instance"
  value       = aws_db_instance.main.ca_cert_identifier
}

output "db_instance_domain" {
  description = "The ID of the Directory Service Active Directory domain the instance is joined to"
  value       = aws_db_instance.main.domain
}

output "db_instance_domain_iam_role_name" {
  description = "The name of the IAM role to be used when making API calls to the Directory Service"
  value       = aws_db_instance.main.domain_iam_role_name
}

# DB subnet group
output "db_subnet_group_id" {
  description = "The db subnet group name"
  value       = try(aws_db_subnet_group.main[0].id, var.db_subnet_group_name)
}

output "db_subnet_group_arn" {
  description = "The ARN of the db subnet group"
  value       = try(aws_db_subnet_group.main[0].arn, "")
}

# DB parameter group
output "db_parameter_group_id" {
  description = "The db parameter group id"
  value       = aws_db_parameter_group.main.id
}

output "db_parameter_group_arn" {
  description = "The ARN of the db parameter group"
  value       = aws_db_parameter_group.main.arn
}

# DB option group
output "db_option_group_id" {
  description = "The db option group id"
  value       = aws_db_option_group.main.id
}

output "db_option_group_arn" {
  description = "The ARN of the db option group"
  value       = aws_db_option_group.main.arn
}

# Enhanced monitoring
output "enhanced_monitoring_iam_role_name" {
  description = "The name of the monitoring role"
  value       = try(aws_iam_role.enhanced_monitoring[0].name, "")
}

output "enhanced_monitoring_iam_role_arn" {
  description = "The Amazon Resource Name (ARN) specifying the monitoring role"
  value       = try(aws_iam_role.enhanced_monitoring[0].arn, "")
}

# Read replica
output "db_instance_read_replica_address" {
  description = "The RDS read replica instance hostname"
  value       = try(aws_db_instance.read_replica[0].address, "")
}

output "db_instance_read_replica_arn" {
  description = "The RDS read replica instance ARN"
  value       = try(aws_db_instance.read_replica[0].arn, "")
}

output "db_instance_read_replica_endpoint" {
  description = "The RDS read replica instance endpoint"
  value       = try(aws_db_instance.read_replica[0].endpoint, "")
}

output "db_instance_read_replica_id" {
  description = "The RDS read replica instance ID"
  value       = try(aws_db_instance.read_replica[0].id, "")
}

# CloudWatch Log Groups
output "db_instance_cloudwatch_log_groups" {
  description = "Map of CloudWatch log groups created and their attributes"
  value = {
    postgresql = try(aws_cloudwatch_log_group.postgresql[0], null)
    upgrade    = try(aws_cloudwatch_log_group.upgrade[0], null)
  }
}