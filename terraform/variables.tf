variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
}

variable "project" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "vulnlens"
}

variable "github_token" {
  description = "GitHub personal access token for posting PR comments and commit statuses"
  type        = string
  sensitive   = true
}
