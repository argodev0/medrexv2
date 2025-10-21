# EFS Module for Medrex DLT EMR

resource "aws_efs_file_system" "main" {
  creation_token   = var.name
  performance_mode = "generalPurpose"
  throughput_mode  = "provisioned"
  provisioned_throughput_in_mibps = 100

  encrypted  = var.encrypted
  kms_key_id = var.kms_key_id

  tags = merge(var.tags, {
    Name = var.name
  })
}

resource "aws_efs_mount_target" "main" {
  count           = length(var.subnet_ids)
  file_system_id  = aws_efs_file_system.main.id
  subnet_id       = var.subnet_ids[count.index]
  security_groups = var.security_groups
}