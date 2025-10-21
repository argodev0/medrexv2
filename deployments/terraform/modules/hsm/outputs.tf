output "cluster_id" {
  description = "ID of the CloudHSM cluster"
  value       = aws_cloudhsm_v2_cluster.main.cluster_id
}

output "cluster_state" {
  description = "State of the CloudHSM cluster"
  value       = aws_cloudhsm_v2_cluster.main.cluster_state
}