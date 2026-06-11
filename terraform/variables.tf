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

variable "lambda_role_name" {
  description = "Name of the existing IAM role Lambda functions assume. In the AWS Academy Learner Lab this is LabRole (broad permissions); set to RoleForLambdaModLabRole if your account uses a dedicated Lambda role."
  type        = string
  default     = "LabRole"
}

variable "github_token" {
  description = "GitHub token (repo:status + pull_request scope) for the status gate. Leave empty to create the Secrets Manager secret without a value and set it manually in the console."
  type        = string
  default     = ""
  sensitive   = true
}
