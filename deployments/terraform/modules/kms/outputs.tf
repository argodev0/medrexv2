# Outputs for KMS Module

output "cluster_key_arn" {
  description = "The Amazon Resource Name (ARN) of the EKS cluster KMS key"
  value       = aws_kms_key.cluster.arn
}

output "cluster_key_id" {
  description = "The globally unique identifier for the EKS cluster KMS key"
  value       = aws_kms_key.cluster.key_id
}

output "rds_key_arn" {
  description = "The Amazon Resource Name (ARN) of the RDS KMS key"
  value       = aws_kms_key.rds.arn
}

output "rds_key_id" {
  description = "The globally unique identifier for the RDS KMS key"
  value       = aws_kms_key.rds.key_id
}

output "efs_key_arn" {
  description = "The Amazon Resource Name (ARN) of the EFS KMS key"
  value       = aws_kms_key.efs.arn
}

output "efs_key_id" {
  description = "The globally unique identifier for the EFS KMS key"
  value       = aws_kms_key.efs.key_id
}

output "s3_key_arn" {
  description = "The Amazon Resource Name (ARN) of the S3 KMS key"
  value       = aws_kms_key.s3.arn
}

output "s3_key_id" {
  description = "The globally unique identifier for the S3 KMS key"
  value       = aws_kms_key.s3.key_id
}