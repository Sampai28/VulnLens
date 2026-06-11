# ── SCAN TRIGGER LAMBDA ───────────────────────────────────────────────────────
# Receives S3 ObjectCreated events and calls ecs:RunTask to start the Fargate
# SAST scanner. Reads PR metadata from S3 object metadata and passes it as
# container env var overrides so the scanner can write github context to DynamoDB.

data "archive_file" "scan_trigger" {
  type        = "zip"
  source_file = "${path.module}/../lambda/scan_trigger.py"
  output_path = "${path.module}/scan_trigger.zip"
}

resource "aws_lambda_function" "scan_trigger" {
  function_name    = "${var.project}-scan-trigger"
  runtime          = "python3.11"
  handler          = "scan_trigger.handler"
  role             = "arn:aws:iam::${var.aws_account_id}:role/LabRole"
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

# ── ANALYTICS LAMBDA ──────────────────────────────────────────────────────────
# Reads scanId from SQS, fetches scan from DynamoDB, runs analytics pipeline,
# writes enriched results back to DynamoDB, posts GitHub PR comment + commit status.

data "archive_file" "analytics" {
  type        = "zip"
  source_dir  = "${path.module}/../analytics/src"
  output_path = "${path.module}/analytics.zip"
}

resource "aws_lambda_function" "analytics" {
  function_name    = "${var.project}-analytics"
  runtime          = "python3.11"
  handler          = "handler.lambda_handler"
  role             = "arn:aws:iam::${var.aws_account_id}:role/LabRole"
  filename         = data.archive_file.analytics.output_path
  source_code_hash = data.archive_file.analytics.output_base64sha256
  timeout          = 300

  environment {
    variables = {
      DYNAMO_TABLE = aws_dynamodb_table.scans.name
      GITHUB_TOKEN = var.github_token
    }
  }

  tags = {
    Project = var.project
  }
}

resource "aws_lambda_event_source_mapping" "sqs_to_analytics" {
  event_source_arn = aws_sqs_queue.scan_queue.arn
  function_name    = aws_lambda_function.analytics.arn
  batch_size       = 1
  enabled          = true
}
