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
