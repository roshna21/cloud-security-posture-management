# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

# Central log bucket: CloudTrail, AWS Config, S3 access logs and VPC flow logs.
resource "aws_s3_bucket" "logs" {
  bucket        = "stride-logs-${local.suffix}"
  force_destroy = true
  tags          = { BusinessUnit = "platform" }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ServiceAclCheck"
        Effect    = "Allow"
        Principal = { Service = ["cloudtrail.amazonaws.com", "config.amazonaws.com", "delivery.logs.amazonaws.com"] }
        Action    = ["s3:GetBucketAcl", "s3:ListBucket"]
        Resource  = aws_s3_bucket.logs.arn
      },
      {
        Sid       = "ServiceWrite"
        Effect    = "Allow"
        Principal = { Service = ["cloudtrail.amazonaws.com", "config.amazonaws.com", "delivery.logs.amazonaws.com", "logging.s3.amazonaws.com"] }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/*"
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# Online Store: product images.
# PLANTED (DP.1, DP.2): Block Public Access off, and no HTTPS-only policy.
resource "aws_s3_bucket" "product_images" {
  bucket        = "stride-product-images-${local.suffix}"
  force_destroy = true
  tags          = { BusinessUnit = "online-store" }
}

resource "aws_s3_bucket_public_access_block" "product_images" {
  bucket                  = aws_s3_bucket.product_images.id
  block_public_acls       = !local.planted
  ignore_public_acls      = !local.planted
  block_public_policy     = !local.planted
  restrict_public_buckets = !local.planted
  lifecycle { ignore_changes = all }
}

resource "aws_s3_bucket_versioning" "product_images" {
  bucket = aws_s3_bucket.product_images.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "product_images" {
  bucket        = aws_s3_bucket.product_images.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/product-images/"
}

resource "aws_s3_bucket_policy" "product_images_ssl" {
  count  = local.planted ? 0 : 1
  bucket = aws_s3_bucket.product_images.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.product_images.arn, "${aws_s3_bucket.product_images.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# Finance and HR: reports.
# PLANTED (DP.3, LOG.5): versioning off, access logging off.
resource "aws_s3_bucket" "finance_reports" {
  bucket        = "stride-finance-reports-${local.suffix}"
  force_destroy = true
  tags          = { BusinessUnit = "finance-hr" }
}

resource "aws_s3_bucket_public_access_block" "finance_reports" {
  bucket                  = aws_s3_bucket.finance_reports.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "finance_reports" {
  count  = local.planted ? 0 : 1
  bucket = aws_s3_bucket.finance_reports.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "finance_reports" {
  count         = local.planted ? 0 : 1
  bucket        = aws_s3_bucket.finance_reports.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/finance-reports/"
}

resource "aws_s3_bucket_policy" "finance_reports_ssl" {
  bucket = aws_s3_bucket.finance_reports.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.finance_reports.arn, "${aws_s3_bucket.finance_reports.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  lifecycle { ignore_changes = [policy] }
}

# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------

# PLANTED (IAM.2): weak password policy. Compliant form: length 14, reuse 24.
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length   = local.planted ? 8 : 14
  password_reuse_prevention = 24
  lifecycle { ignore_changes = all }
}

# Safety net: the planted users below look dangerous to the checks (which is the
# point) but this permissions boundary denies every action, so the credentials
# cannot actually be used for anything if they leak.
resource "aws_iam_policy" "deny_all_boundary" {
  name = "${var.project}-deny-all-boundary"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}

# PLANTED (IAM.4, IAM.6): console user without MFA and with AdministratorAccess.
resource "aws_iam_user" "ops_admin" {
  name                 = "ops-admin"
  permissions_boundary = aws_iam_policy.deny_all_boundary.arn
  force_destroy        = true
  tags                 = { BusinessUnit = "platform" }
}

# The Free plan blocks iam:CreateLoginProfile, so the "console user without MFA" issue (IAM.4)
# cannot be planted on this account. Set var.allow_login_profile=true on a paid-plan account.
variable "allow_login_profile" {
  type    = bool
  default = false
}

resource "aws_iam_user_login_profile" "ops_admin" {
  count                   = local.planted && var.allow_login_profile ? 1 : 0
  user                    = aws_iam_user.ops_admin.name
  password_length         = 24
  password_reset_required = true
}

resource "aws_iam_user_policy_attachment" "ops_admin" {
  count      = local.planted ? 1 : 0
  user       = aws_iam_user.ops_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# A service user that follows the rules. (IAM.5, an access key older than 90 days,
# cannot be planted at creation time; it exists only in the local simulation.)
resource "aws_iam_user" "finance_app" {
  name                 = "finance-app-svc"
  permissions_boundary = aws_iam_policy.deny_all_boundary.arn
  force_destroy        = true
  tags                 = { BusinessUnit = "finance-hr" }
}
