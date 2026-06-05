# SQS queue between SAST scanner and analytics Lambda.
# Decouples the two services — if analytics fails, the message stays in the
# queue and retries automatically instead of being lost.
#
# Why SQS over direct Lambda invocation:
# - Retry on failure: message stays in queue if Lambda errors, retried up to maxReceiveCount
# - Dead letter queue: after 3 failures, message moves to DLQ for investigation
# - Decoupled scaling: scanner and analytics scale independently
# - No data loss: even if analytics Lambda is down, messages wait in queue

# ── MAIN QUEUE ────────────────────────────────────────────────────────────────

resource "aws_sqs_queue" "scan_queue" {
  name                       = "${var.project}-scan-queue"
  visibility_timeout_seconds = 300  # 5 min — enough time for analytics Lambda to process
  message_retention_seconds  = 86400 # 1 day
  receive_wait_time_seconds  = 20   # long polling — reduces empty receives

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.scan_dlq.arn
    maxReceiveCount     = 3  # after 3 failures, move to DLQ
  })

  tags = {
    Project = var.project
    Purpose = "SAST scan results → analytics pipeline"
  }
}

# ── DEAD LETTER QUEUE ─────────────────────────────────────────────────────────
# Messages that fail 3 times land here for investigation.
# A CloudWatch alarm fires when DLQ depth > 0.

resource "aws_sqs_queue" "scan_dlq" {
  name                      = "${var.project}-scan-dlq"
  message_retention_seconds = 1209600 # 14 days — keep failed messages for debugging

  tags = {
    Project = var.project
    Purpose = "Dead letter queue for failed scan messages"
  }
}

# ── CLOUDWATCH ALARM ──────────────────────────────────────────────────────────
# Fires when any message lands in the DLQ (i.e. failed after 3 retries).

resource "aws_cloudwatch_metric_alarm" "dlq_depth" {
  alarm_name          = "${var.project}-dlq-messages"
  alarm_description   = "Messages in DLQ — scan or analytics failed after 3 retries"
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions = {
    QueueName = aws_sqs_queue.scan_dlq.name
  }
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  tags = {
    Project = var.project
  }
}
