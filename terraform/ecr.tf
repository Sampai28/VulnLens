resource "aws_ecr_repository" "sast" {
  name                 = "${var.project}-sast"
  image_tag_mutability = "MUTABLE"

  # Allow `terraform destroy` to delete the repo even though it holds pushed
  # images; otherwise it fails with RepositoryNotEmptyException.
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Project = var.project
    Purpose = "SAST scanner Docker image"
  }
}
