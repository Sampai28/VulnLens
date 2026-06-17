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
  lambda_role_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.lambda_role_name}"
}

# ── SCAN TRIGGER LAMBDA (phase 2 — kick off the scan) ───────────────────────────
# Receives S3 ObjectCreated events from the uploads bucket and calls ecs:RunTask
# to start the Fargate SAST scanner. Reads PR metadata off the S3 object and
# passes it as container env-var overrides so the scanner can write the github
# context block to DynamoDB. Restored after it was dropped from lambda.tf in a
# merge — without it, S3 uploads fire no event and the pipeline never starts.

data "archive_file" "scan_trigger" {
  type        = "zip"
  source_file = "${path.module}/../lambda/scan_trigger.py"
  output_path = "${path.module}/build/scan_trigger.zip"
}

resource "aws_lambda_function" "scan_trigger" {
  function_name    = "${var.project}-scan-trigger"
  role             = local.lambda_role_arn
  handler          = "scan_trigger.handler"
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 128
  filename         = data.archive_file.scan_trigger.output_path
  source_code_hash = data.archive_file.scan_trigger.output_base64sha256

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
    Purpose = "Scan trigger - S3 event to ECS RunTask"
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

  # Delete immediately on destroy instead of the default 30-day recovery window,
  # so a re-apply after a destroy doesn't hit "scheduled for deletion".
  recovery_window_in_days = 0

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
    Purpose = "Security gate - posts pass/fail commit status to GitHub"
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
    Purpose = "Analytics - enrich score cluster trend then hand off to status gate"
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
