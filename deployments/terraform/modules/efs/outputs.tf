output "id" {
  description = "ID of the EFS file system"
  value       = aws_efs_file_system.main.id
}

output "arn" {
  description = "ARN of the EFS file system"
  value       = aws_efs_file_system.main.arn
}

output "dns_name" {
  description = "DNS name of the EFS file system"
  value       = aws_efs_file_system.main.dns_name
}