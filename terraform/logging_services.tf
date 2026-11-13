# ---------------------------------------------------------------------------
# CloudTrail: needed to say who made each change.
# PLANTED (LOG.1, LOG.2): single-region trail, log file validation off.
# ---------------------------------------------------------------------------
resource "aws_cloudtrail" "main" {
  name                          = "stride-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  is_multi_region_trail         = !local.planted
  include_global_service_events = true
  enable_log_file_validation    = !local.planted
  depends_on                    = [aws_s3_bucket_policy.logs]
  lifecycle { ignore_changes = [is_multi_region_trail, enable_log_file_validation] }
}

# ---------------------------------------------------------------------------
# AWS Config: records configuration changes (the drift signal).
# ---------------------------------------------------------------------------
resource "aws_iam_role" "config" {
  count = var.enable_security_services ? 1 : 0
  name  = "${var.project}-config"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "config.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_security_services ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_security_services ? 1 : 0
  name     = "default"
  role_arn = aws_iam_role.config[0].arn
  # AWS Config bills per configuration item recorded. Recording only the resource
  # types the MBSS watches keeps that to a handful of items instead of hundreds.
  recording_group {
    all_supported = false
    resource_types = [
      "AWS::EC2::SecurityGroup", "AWS::EC2::Instance", "AWS::EC2::Volume", "AWS::EC2::VPC",
      "AWS::EC2::FlowLog", "AWS::S3::Bucket", "AWS::CloudTrail::Trail", "AWS::IAM::User",
    ]
  }
}

resource "aws_config_delivery_channel" "main" {
  count          = var.enable_security_services ? 1 : 0
  name           = "default"
  s3_bucket_name = aws_s3_bucket.logs.id
  s3_key_prefix  = "config"
  depends_on     = [aws_config_configuration_recorder.main, aws_s3_bucket_policy.logs]
}

resource "aws_config_configuration_recorder_status" "main" {
  count      = var.enable_security_services ? 1 : 0
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

# ---------------------------------------------------------------------------
# Security Hub with the CIS AWS Foundations Benchmark, and Amazon Inspector.
# ---------------------------------------------------------------------------
resource "aws_securityhub_account" "main" {
  count                    = var.enable_security_hub ? 1 : 0
  enable_default_standards = false
}

resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_security_hub ? 1 : 0
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_inspector2_enabler" "ec2" {
  count          = var.enable_inspector ? 1 : 0
  account_ids    = [local.account_id]
  resource_types = ["EC2"]
}
