output "s3_bucket" {
  description = "S3 bucket for code uploads"
  value       = aws_s3_bucket.uploads.bucket
}

output "dynamodb_table" {
  description = "DynamoDB table for scan results"
  value       = aws_dynamodb_table.scans.name
}

output "ecr_repository_url" {
  description = "ECR repository URL for SAST scanner image"
  value       = aws_ecr_repository.sast.repository_url
}

output "ecs_cluster" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "ecs_task_definition" {
  description = "ECS task definition ARN"
  value       = aws_ecs_task_definition.sast.arn
}
