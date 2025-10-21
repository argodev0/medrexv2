output "rds_enhanced_monitoring_role_arn" {
  description = "ARN of the RDS enhanced monitoring role"
  value       = aws_iam_role.rds_enhanced_monitoring.arn
}

output "cluster_service_role_arn" {
  description = "ARN of the EKS cluster service role"
  value       = ""
}

output "node_group_role_arn" {
  description = "ARN of the EKS node group role"
  value       = ""
}