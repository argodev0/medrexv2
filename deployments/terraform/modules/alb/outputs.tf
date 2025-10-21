output "lb_arn" {
  description = "ARN of the load balancer"
  value       = aws_lb.main.arn
}

output "lb_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.main.dns_name
}

output "lb_zone_id" {
  description = "Zone ID of the load balancer"
  value       = aws_lb.main.zone_id
}