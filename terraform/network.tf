# One VPC with a single public subnet. Every server gets a public IP so that the
# SSM agent can reach AWS without a NAT gateway (which would be the main cost).
# Whether a server counts as internet-facing for risk scoring comes from its
# InternetFacing tag, not from the subnet.

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "stride-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  tags                    = { Name = "stride-public" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# PLANTED (NET.3): the default security group keeps a rule. Compliant form: no rules.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "default", BusinessUnit = "platform" }

  dynamic "ingress" {
    for_each = local.planted ? [1] : []
    content {
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      cidr_blocks = ["10.0.0.0/16"]
    }
  }
}

locals {
  egress_all = { protocol = "-1", from_port = 0, to_port = 0, cidr_blocks = ["0.0.0.0/0"] }
}

resource "aws_security_group" "web" {
  name   = "store-web-sg"
  vpc_id = aws_vpc.main.id
  tags   = { Name = "store-web-sg", BusinessUnit = "online-store" }

  ingress {
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
  # PLANTED (NET.1): SSH open to the internet
  dynamic "ingress" {
    for_each = local.planted ? [1] : []
    content {
      protocol    = "tcp"
      from_port   = 22
      to_port     = 22
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  egress {
    protocol    = local.egress_all.protocol
    from_port   = local.egress_all.from_port
    to_port     = local.egress_all.to_port
    cidr_blocks = local.egress_all.cidr_blocks
  }
  lifecycle { ignore_changes = [ingress] } # the CSPM engine edits rules; do not fight it
}

resource "aws_security_group" "db" {
  name   = "store-db-sg"
  vpc_id = aws_vpc.main.id
  tags   = { Name = "store-db-sg", BusinessUnit = "online-store" }

  ingress {
    protocol    = "tcp"
    from_port   = 5432
    to_port     = 5432
    cidr_blocks = ["10.0.0.0/16"]
  }
  egress {
    protocol    = local.egress_all.protocol
    from_port   = local.egress_all.from_port
    to_port     = local.egress_all.to_port
    cidr_blocks = local.egress_all.cidr_blocks
  }
  lifecycle { ignore_changes = [ingress] }
}

resource "aws_security_group" "mfg" {
  name   = "mfg-erp-sg"
  vpc_id = aws_vpc.main.id
  tags   = { Name = "mfg-erp-sg", BusinessUnit = "manufacturing" }

  ingress {
    protocol    = "tcp"
    from_port   = 8443
    to_port     = 8443
    cidr_blocks = ["10.0.0.0/16"]
  }
  # PLANTED (NET.2): RDP open to the internet
  dynamic "ingress" {
    for_each = local.planted ? [1] : []
    content {
      protocol    = "tcp"
      from_port   = 3389
      to_port     = 3389
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  egress {
    protocol    = local.egress_all.protocol
    from_port   = local.egress_all.from_port
    to_port     = local.egress_all.to_port
    cidr_blocks = local.egress_all.cidr_blocks
  }
  lifecycle { ignore_changes = [ingress] }
}

resource "aws_security_group" "fin" {
  name   = "fin-payroll-sg"
  vpc_id = aws_vpc.main.id
  tags   = { Name = "fin-payroll-sg", BusinessUnit = "finance-hr" }

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["10.0.0.0/16"]
  }
  # PLANTED (NET.4): MySQL open to the internet
  dynamic "ingress" {
    for_each = local.planted ? [1] : []
    content {
      protocol    = "tcp"
      from_port   = 3306
      to_port     = 3306
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  egress {
    protocol    = local.egress_all.protocol
    from_port   = local.egress_all.from_port
    to_port     = local.egress_all.to_port
    cidr_blocks = local.egress_all.cidr_blocks
  }
  lifecycle { ignore_changes = [ingress] }
}

locals {
  sg_ids = {
    web = aws_security_group.web.id
    db  = aws_security_group.db.id
    mfg = aws_security_group.mfg.id
    fin = aws_security_group.fin.id
  }
}

# PLANTED (LOG.4): no VPC flow log. Compliant form creates one.
resource "aws_flow_log" "vpc" {
  count                = local.planted ? 0 : 1
  vpc_id               = aws_vpc.main.id
  traffic_type         = "REJECT"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.logs.arn}/vpc-flow-logs/"
}
