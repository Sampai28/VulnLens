terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Auto-detect the account ID from the active credentials instead of requiring it
# as an input — the AWS Academy Learner Lab account rotates between sessions, so
# nothing should hardcode it. Referenced as data.aws_caller_identity.current.account_id.
data "aws_caller_identity" "current" {}
