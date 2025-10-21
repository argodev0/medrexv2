# HSM Module for Medrex DLT EMR (AWS CloudHSM)

resource "aws_cloudhsm_v2_cluster" "main" {
  hsm_type   = "hsm1.medium"
  subnet_ids = var.subnet_ids

  tags = merge(var.tags, {
    Name = var.cluster_id
  })
}

resource "aws_cloudhsm_v2_hsm" "main" {
  count      = 2
  cluster_id = aws_cloudhsm_v2_cluster.main.cluster_id
  subnet_id  = var.subnet_ids[count.index]

  tags = var.tags
}