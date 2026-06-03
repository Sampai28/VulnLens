resource "aws_dynamodb_table" "scans" {
  name         = "${var.project}-scans"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scanId"

  attribute {
    name = "scanId"
    type = "S"
  }

  tags = {
    Project = var.project
    Purpose = "Scan results storage"
  }
}
