resource "aws_ecr_repository" "sast" {
  name                 = "${var.project}-sast"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project = var.project
    Purpose = "SAST scanner Docker image"
  }
}
