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

output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "private_subnet_id" {
  description = "Private subnet ID (Fargate tasks run here)"
  value       = aws_subnet.private.id
}

output "public_subnet_id" {
  description = "Public subnet ID (NAT Gateway lives here)"
  value       = aws_subnet.public.id
}

output "fargate_security_group_id" {
  description = "Security group ID for Fargate tasks"
  value       = aws_security_group.fargate.id
}

output "sqs_queue_url" {
  description = "SQS queue URL for scan results"
  value       = aws_sqs_queue.scan_queue.url
}

output "sqs_queue_arn" {
  description = "SQS queue ARN for scan results"
  value       = aws_sqs_queue.scan_queue.arn
}

output "sqs_dlq_url" {
  description = "Dead letter queue URL"
  value       = aws_sqs_queue.scan_dlq.url
}

output "sns_alerts_topic_arn" {
  description = "SNS topic ARN for scan failure alerts"
  value       = aws_sns_topic.scan_alerts.arn
}

output "analytics_lambda_name" {
  description = "Analytics Lambda function name (SQS-triggered)"
  value       = aws_lambda_function.analytics.function_name
}

output "status_lambda_name" {
  description = "Status gate Lambda function name (posts to GitHub)"
  value       = aws_lambda_function.status.function_name
}

output "github_token_secret_name" {
  description = "Secrets Manager secret holding the GitHub token for the status gate"
  value       = aws_secretsmanager_secret.github_token.name
}
