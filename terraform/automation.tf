# Notifications (SNS) and the near-real-time drift path:
#   AWS Config / CloudTrail -> EventBridge -> Lambda (drift_trigger) -> SQS -> core engine

resource "aws_sns_topic" "alerts" {
  name = "${var.project}-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sqs_queue" "drift" {
  name                      = "${var.project}-drift-events"
  message_retention_seconds = 86400
}

data "archive_file" "drift_trigger" {
  type        = "zip"
  source_file = "${path.module}/../lambda/drift_trigger.py"
  output_path = "${path.module}/.build/drift_trigger.zip"
}

resource "aws_iam_role" "drift_trigger" {
  name = "${var.project}-drift-trigger"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "lambda.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy" "drift_trigger" {
  role = aws_iam_role.drift_trigger.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "sqs:SendMessage", Resource = aws_sqs_queue.drift.arn },
      { Effect = "Allow", Action = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], Resource = "*" }
    ]
  })
}

resource "aws_lambda_function" "drift_trigger" {
  function_name    = "${var.project}-drift-trigger"
  role             = aws_iam_role.drift_trigger.arn
  runtime          = "python3.12"
  handler          = "drift_trigger.handler"
  filename         = data.archive_file.drift_trigger.output_path
  source_code_hash = data.archive_file.drift_trigger.output_base64sha256
  timeout          = 10
  environment {
    variables = { QUEUE_URL = aws_sqs_queue.drift.url }
  }
}

# Configuration changes recorded by AWS Config.
resource "aws_cloudwatch_event_rule" "config_change" {
  name = "${var.project}-config-change"
  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Configuration Item Change Notification"]
  })
}

# The API calls that can break an MBSS control (the cloudtrail_events lists in config/mbss.json).
# IAM is a global service: its events are delivered in us-east-1 only, so IAM drift
# is picked up by the periodic scan unless this rule is also created there.
resource "aws_cloudwatch_event_rule" "api_call" {
  name = "${var.project}-watched-api-calls"
  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules",
        "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock", "PutBucketPolicy", "DeleteBucketPolicy",
        "PutBucketAcl", "PutBucketVersioning", "PutBucketLogging",
        "DisableEbsEncryptionByDefault", "ModifyInstanceMetadataOptions",
        "UpdateTrail", "StopLogging", "DeleteFlowLogs",
        "StopConfigurationRecorder", "DeleteConfigurationRecorder"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "config_change" {
  rule = aws_cloudwatch_event_rule.config_change.name
  arn  = aws_lambda_function.drift_trigger.arn
}

resource "aws_cloudwatch_event_target" "api_call" {
  rule = aws_cloudwatch_event_rule.api_call.name
  arn  = aws_lambda_function.drift_trigger.arn
}

resource "aws_lambda_permission" "config_change" {
  statement_id  = "AllowConfigChangeRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.config_change.arn
}

resource "aws_lambda_permission" "api_call" {
  statement_id  = "AllowApiCallRule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.drift_trigger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.api_call.arn
}

# ---------------------------------------------------------------------------
# Outputs: copy these into the "aws" block of config/settings.json
# ---------------------------------------------------------------------------
output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "drift_queue_url" {
  value = aws_sqs_queue.drift.url
}

output "log_bucket" {
  value = aws_s3_bucket.logs.id
}

output "servers" {
  value = { for name, s in aws_instance.server : name => s.id }
}
