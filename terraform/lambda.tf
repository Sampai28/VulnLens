# Analytics + Status Lambdas — phases 3 and 4 of the pipeline.
#
#   SQS (vulnlens-scan-queue)
#        │  {scanId, filename}
#        ▼
#   Analytics Lambda  ──► DynamoDB (write enriched `analysis`)
#        │  async invoke {scanId}
#        ▼
#   Status Lambda  ──► GitHub commit status (+ PR comment)
#                  ──► DynamoDB (write `status`)
#
# Both functions assume an existing IAM role (var.lambda_role_name) rather than
# creating one, because the AWS Academy Learner Lab forbids custom IAM. That
# role (LabRole) already grants DynamoDB, SQS, Secrets Manager, Lambda invoke,
# and CloudWatch Logs access.

locals {
  lambda_role_arn = "arn:aws:iam::${var.aws_account_id}:role/${var.lambda_role_name}"
}

# ── PACKAGING ─────────────────────────────────────────────────────────────────
# Zip each package preserving the `src/` prefix so the handler resolves as
# `src.handler.lambda_handler` and intra-package imports (`from src.engine ...`)
# keep working. Pure-Python + boto3 (provided by the runtime) means no vendored
# dependencies — just ship the source.

data "archive_file" "analytics" {
  type        = "zip"
  source_dir  = "${path.module}/../analytics"
  output_path = "${path.module}/build/analytics.zip"
  excludes = [
    "tests",
    "tests/**",
    "benchmarks",
    "benchmarks/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
    "out.json",
    "out128.json",
  ]
}

data "archive_file" "status" {
  type        = "zip"
  source_dir  = "${path.module}/../status"
  output_path = "${path.module}/build/status.zip"
  excludes = [
    "tests",
    "tests/**",
    "**/__pycache__/**",
    "**/*.pyc",
    "pyproject.toml",
    "requirements.txt",
    "requirements-dev.txt",
  ]
}

# ── SECRETS MANAGER — GITHUB TOKEN ──────────────────────────────────────────────
# The status gate reads this to authenticate the commit-status POST. Kept out of
# Lambda env vars so it never shows in the function config or logs.

resource "aws_secretsmanager_secret" "github_token" {
  name        = "${var.project}/github-token"
  description = "GitHub token used by the status Lambda to post commit statuses"

  tags = {
    Project = var.project
  }
}

# Only seed a value when one is supplied via var.github_token; otherwise the
# secret is created empty and you set it in the console (avoids the token in state).
resource "aws_secretsmanager_secret_version" "github_token" {
  count         = var.github_token == "" ? 0 : 1
  secret_id     = aws_secretsmanager_secret.github_token.id
  secret_string = jsonencode({ token = var.github_token })
}

# ── STATUS LAMBDA (phase 4 — gate) ──────────────────────────────────────────────

resource "aws_lambda_function" "status" {
  function_name = "${var.project}-status"
  role          = local.lambda_role_arn
  handler       = "src.handler.lambda_handler"
  runtime       = "python3.11"
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.status.output_path
  source_code_hash = data.archive_file.status.output_base64sha256

  environment {
    variables = {
      DYNAMO_TABLE       = aws_dynamodb_table.scans.name
      GITHUB_SECRET_ID   = aws_secretsmanager_secret.github_token.name
      GATE_FAIL_SEVERITY = "HIGH"
      STATUS_CONTEXT     = "vulnlens/security-gate"
    }
  }

  tags = {
    Project = var.project
    Purpose = "Security gate — posts pass/fail commit status to GitHub"
  }
}

# ── ANALYTICS LAMBDA (phase 3 — analytics) ──────────────────────────────────────

resource "aws_lambda_function" "analytics" {
  function_name = "${var.project}-analytics"
  role          = local.lambda_role_arn
  handler       = "src.handler.lambda_handler"
  runtime       = "python3.11"
  timeout       = 120 # must stay under the queue's 300s visibility timeout
  memory_size   = 512

  filename         = data.archive_file.analytics.output_path
  source_code_hash = data.archive_file.analytics.output_base64sha256

  environment {
    variables = {
      DYNAMO_TABLE         = aws_dynamodb_table.scans.name
      STATUS_FUNCTION_NAME = aws_lambda_function.status.function_name
    }
  }

  tags = {
    Project = var.project
    Purpose = "Analytics — enrich, score, cluster, trend; hand off to status gate"
  }
}

# Async (Event) invocation of the status Lambda from analytics: retry once, then
# give up — the enriched analysis is already persisted, so status can be re-run.
resource "aws_lambda_function_event_invoke_config" "status" {
  function_name          = aws_lambda_function.status.function_name
  maximum_retry_attempts = 1
}

# ── SQS → ANALYTICS TRIGGER ─────────────────────────────────────────────────────
# Long-poll the scan queue in batches. ReportBatchItemFailures lets a single bad
# message be redriven without re-processing the whole batch; after maxReceiveCount
# (3, set in sqs.tf) it lands in the DLQ.

resource "aws_lambda_event_source_mapping" "analytics_sqs" {
  event_source_arn                   = aws_sqs_queue.scan_queue.arn
  function_name                      = aws_lambda_function.analytics.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 5
  function_response_types            = ["ReportBatchItemFailures"]
}
