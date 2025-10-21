variable "cluster_id" {
  description = "HSM cluster identifier"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for HSM"
  type        = list(string)
}

variable "tags" {
  description = "Tags to apply to resources"
  type        = map(string)
  default     = {}
}