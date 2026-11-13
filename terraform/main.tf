# Simulated company ("Stride Sports Goods") on AWS, with planted security issues.
#
#   terraform init
#   terraform apply   -var alert_email=you@example.com
#   terraform destroy                      # run this when you finish working
#
# Set plant_issues=false to build the same company in its MBSS-compliant form.
# NOTE: these files have not been applied to a live account. Run `terraform validate`
# and `terraform plan` first and expect small corrections.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws     = { source = "hashicorp/aws", version = "~> 5.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.4" }
    random  = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = var.project }
  }
}

variable "region" {
  type    = string
  default = "ap-southeast-2" # Sydney: the only region this Free-plan account may use
}

variable "project" {
  type    = string
  default = "cspm-demo"
}

variable "plant_issues" {
  description = "Build the environment with the known security issues used as ground truth."
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Security Hub with the CIS standard. Blocked on this account's Free plan, so off by default."
  type        = bool
  default     = false
}

variable "enable_inspector" {
  description = "Amazon Inspector. Blocked on this account's Free plan, so off by default; the engine reads CVEs from the servers' package manager instead."
  type        = bool
  default     = false
}

variable "enable_security_services" {
  description = "Turn on AWS Config recording (the drift signal)."
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "Address subscribed to the SNS topic. All notifications for the simulated company arrive here."
  type        = string
  default     = ""
}

variable "outdated_ami_name" {
  description = "Name filter for the deliberately old Amazon Linux 2 image (it must still be listed in your region)."
  type        = string
  default     = "amzn2-ami-hvm-2.0.2022*-x86_64-gp2"
}

variable "budget_limit_usd" {
  description = "Monthly spend (before credits) at which the budget emails you. AWS budgets warn; they do not stop spending."
  type        = number
  default     = 20
}

# ---------------------------------------------------------------------------
# Cost guardrail. Created first so alerts exist before anything billable does.
# It measures usage BEFORE credits are applied, so you see how fast credits burn.
# ---------------------------------------------------------------------------
resource "aws_budgets_budget" "guardrail" {
  count        = var.alert_email == "" ? 0 : 1
  name         = "${var.project}-monthly-guardrail"
  budget_type  = "COST"
  limit_amount = tostring(var.budget_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_types {
    include_credit = false
    include_refund = false
  }

  dynamic "notification" {
    for_each = [25, 50, 80, 100]
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = notification.value
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = [var.alert_email]
    }
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}

data "aws_caller_identity" "current" {}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  planted    = var.plant_issues
  account_id = data.aws_caller_identity.current.account_id
  suffix     = random_id.suffix.hex

  servers = {
    "store-web-01" = {
      bu = "online-store", owner = "Karthik Menon", owner_email = "karthik.menon@stride.example",
      criticality = "high", internet_facing = true, sg = "web", services = "nginx",
      imdsv1 = true, unencrypted = true, root_login = true, password_auth = false
    }
    "store-db-01" = {
      bu = "online-store", owner = "Karthik Menon", owner_email = "karthik.menon@stride.example",
      criticality = "high", internet_facing = false, sg = "db", services = "postgresql",
      imdsv1 = false, unencrypted = false, root_login = false, password_auth = false
    }
    "mfg-erp-01" = {
      bu = "manufacturing", owner = "Divya Pillai", owner_email = "divya.pillai@stride.example",
      criticality = "medium", internet_facing = false, sg = "mfg", services = "mariadb",
      imdsv1 = false, unencrypted = false, root_login = false, password_auth = true
    }
    "fin-payroll-01" = {
      bu = "finance-hr", owner = "Suresh Kumar", owner_email = "suresh.kumar@stride.example",
      criticality = "high", internet_facing = false, sg = "fin", services = "mariadb",
      imdsv1 = true, unencrypted = false, root_login = false, password_auth = false
    }
  }
}
