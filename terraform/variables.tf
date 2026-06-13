variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Project name prefix for all resources"
  type        = string
  default     = "vulnlens"
}

variable "bucket_suffix" {
  description = "Suffix appended to the S3 uploads bucket name to make it globally unique (S3 names are shared across ALL AWS accounts). Leave empty for the canonical 'vulnlens-uploads'; set e.g. '-sagar' or your account id when standing up a standalone stack."
  type        = string
  default     = ""
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
