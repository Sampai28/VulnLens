# ── LAMBDA PIPELINE ───────────────────────────────────────────────────────────
#
#   S3 (vulnlens-uploads)
#        │  ObjectCreated event
#        ▼
#   Scan Trigger Lambda  ──► ECS RunTask (Fargate SAST scanner)
#
#   SQS (vulnlens-scan-queue)
#        │  {scanId, filename}
#        ▼
#   Analytics Lambda  ──► DynamoDB (write enriched analysis)
#        │  async invoke {scanId}
#        ▼
#   Status Lambda  ──► GitHub commit status + PR comment
#               ──► DynamoDB (write status decision)
#
# All functions use the existing LabRole — Learner Lab forbids custom IAM.

locals {
  lambda_role_arn = "arn:aws:iam::${var.aws_account_id}:role/${var.lambda_role_name}"
}

# ── PACKAGING ─────────────────────────────────────────────────────────────────

data "archive_file" "scan_trigger" {
  type        = "zip"
  source_file = "${path.module}/../lambda/scan_trigger.py"
  output_path = "${path.module}/build/scan_trigger.zip"
}

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

# ── SECRETS MANAGER — GITHUB TOKEN ────────────────────────────────────────────
# Status Lambda reads this to authenticate GitHub API calls. Kept out of
# Lambda env vars so it never appears in function config or logs.

resource "aws_secretsmanager_secret" "github_token" {
  name        = "${var.project}/github-token"
  description = "GitHub token used by the status Lambda to post commit statuses"

  tags = {
    Project = var.project
  }
}

resource "aws_secretsmanager_secret_version" "github_token" {
  count         = var.github_token == "" ? 0 : 1
  secret_id     = aws_secretsmanager_secret.github_token.id
  secret_string = jsonencode({ token = var.github_token })
}

# ── SCAN TRIGGER LAMBDA ───────────────────────────────────────────────────────
# Receives S3 ObjectCreated events, reads PR metadata from S3 object metadata,
# and calls ecs:RunTask to start the Fargate SAST scanner.

resource "aws_lambda_function" "scan_trigger" {
  function_name    = "${var.project}-scan-trigger"
  runtime          = "python3.11"
  handler          = "scan_trigger.handler"
  role             = local.lambda_role_arn
  filename         = data.archive_file.scan_trigger.output_path
  source_code_hash = data.archive_file.scan_trigger.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      ECS_CLUSTER         = aws_ecs_cluster.main.name
      ECS_TASK_DEFINITION = aws_ecs_task_definition.sast.arn
      SUBNET_ID           = aws_subnet.private.id
      SECURITY_GROUP_ID   = aws_security_group.fargate.id
    }
  }

  tags = {
    Project = var.project
    Purpose = "Scan trigger - starts Fargate SAST scanner on S3 upload"
  }
}

resource "aws_lambda_permission" "s3_invoke_scan_trigger" {
  statement_id  = "AllowS3Invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scan_trigger.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.uploads.arn
}

resource "aws_s3_bucket_notification" "upload_trigger" {
  bucket = aws_s3_bucket.uploads.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.scan_trigger.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.s3_invoke_scan_trigger]
}

# ── STATUS LAMBDA ─────────────────────────────────────────────────────────────
# Final pipeline phase: evaluates the security gate and posts commit status
# + PR comment to GitHub. Invoked asynchronously by the analytics Lambda.

resource "aws_lambda_function" "status" {
  function_name    = "${var.project}-status"
  role             = local.lambda_role_arn
  handler          = "src.handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 256
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
    Purpose = "Security gate - posts pass/fail commit status to GitHub"
  }
}

# ── ANALYTICS LAMBDA ──────────────────────────────────────────────────────────
# Reads scanId from SQS, runs the analytics pipeline, persists enriched results
# to DynamoDB, then asynchronously invokes the status Lambda.

resource "aws_lambda_function" "analytics" {
  function_name    = "${var.project}-analytics"
  role             = local.lambda_role_arn
  handler          = "src.handler.lambda_handler"
  runtime          = "python3.11"
  timeout          = 120
  memory_size      = 512
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
    Purpose = "Analytics - enrich score cluster trend and hand off to status gate"
  }
}

resource "aws_lambda_function_event_invoke_config" "status" {
  function_name          = aws_lambda_function.status.function_name
  maximum_retry_attempts = 1
}

# ── SQS → ANALYTICS TRIGGER ───────────────────────────────────────────────────
# ReportBatchItemFailures lets a single bad message be redriven without
# reprocessing the whole batch; after maxReceiveCount (3) it lands in the DLQ.

resource "aws_lambda_event_source_mapping" "analytics_sqs" {
  event_source_arn                   = aws_sqs_queue.scan_queue.arn
  function_name                      = aws_lambda_function.analytics.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 5
  function_response_types            = ["ReportBatchItemFailures"]
}
