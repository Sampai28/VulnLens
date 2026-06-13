resource "aws_s3_bucket" "uploads" {
  # S3 bucket names are global across all AWS accounts. var.bucket_suffix keeps
  # the default name canonical ("vulnlens-uploads") while letting a standalone
  # stack pick a unique name (e.g. "-sagar") to avoid a global collision.
  bucket = "${var.project}-uploads${var.bucket_suffix}"

  tags = {
    Project = var.project
    Purpose = "Source code uploads"
  }
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
