# Servers of the three business units. With plant_issues=true they launch from an
# old Amazon Linux 2 image with boot-time security updates switched off, so
# Amazon Inspector reports real CVEs on them.

data "aws_ami" "outdated" {
  owners             = ["amazon"]
  most_recent        = true
  include_deprecated = true
  filter {
    name   = "name"
    values = [var.outdated_ami_name]
  }
}

data "aws_ami" "current" {
  owners      = ["amazon"]
  most_recent = true
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-2.0.*-x86_64-gp2"]
  }
}

resource "aws_iam_role" "server" {
  name = "${var.project}-server"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" } }]
  })
}

resource "aws_iam_role_policy_attachment" "server_ssm" {
  role       = aws_iam_role.server.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "server" {
  name = "${var.project}-server"
  role = aws_iam_role.server.name
}

# PLANTED (DP.4): EBS encryption by default is off.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = !local.planted
}

resource "aws_instance" "server" {
  for_each = local.servers

  ami                    = local.planted ? data.aws_ami.outdated.id : data.aws_ami.current.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [local.sg_ids[each.value.sg]]
  iam_instance_profile   = aws_iam_instance_profile.server.name

  # PLANTED (SRV.1): IMDSv1 allowed on some servers
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = local.planted && each.value.imdsv1 ? "optional" : "required"
  }

  # PLANTED (DP.5): unencrypted root volume on store-web-01
  root_block_device {
    volume_size = 8
    encrypted   = !(local.planted && each.value.unencrypted)
  }

  # repo_upgrade: none stops cloud-init from installing security updates at first
  # boot, which would otherwise remove the planted CVEs.
  # PLANTED (SRV.3, SRV.4): weak sshd settings on some servers
  user_data = <<-EOT
    #cloud-config
    repo_upgrade: ${local.planted ? "none" : "security"}
    runcmd:
      - sed -i -E '/^[#[:space:]]*(PermitRootLogin|PasswordAuthentication)[[:space:]]/d' /etc/ssh/sshd_config
      - echo 'PermitRootLogin ${local.planted && each.value.root_login ? "yes" : "no"}' >> /etc/ssh/sshd_config
      - echo 'PasswordAuthentication ${local.planted && each.value.password_auth ? "yes" : "no"}' >> /etc/ssh/sshd_config
      - systemctl reload sshd
      - amazon-linux-extras install -y nginx1 || true
      - yum install -y mariadb-server postgresql-server || true
      - postgresql-setup initdb || true
      - systemctl enable --now ${each.value.services} || true
  EOT

  tags = {
    Name           = each.key
    BusinessUnit   = each.value.bu
    Owner          = each.value.owner
    OwnerEmail     = each.value.owner_email
    Criticality    = each.value.criticality
    InternetFacing = tostring(each.value.internet_facing)
    Services       = each.value.services
    PatchGroup     = each.value.bu
  }

  lifecycle {
    ignore_changes = [ami, user_data, metadata_options, root_block_device]
  }
}

# Patch baseline: approve every security update immediately, whatever its severity.
# The AWS default baseline for Amazon Linux 2 only installs Critical and Important
# ones, which leaves medium and low CVEs on the server after "patching".
resource "aws_ssm_patch_baseline" "all_security" {
  name             = "${var.project}-all-security"
  operating_system = "AMAZON_LINUX_2"
  approval_rule {
    approve_after_days = 0
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security"]
    }
  }
}

resource "aws_ssm_default_patch_baseline" "al2" {
  baseline_id      = aws_ssm_patch_baseline.all_security.id
  operating_system = aws_ssm_patch_baseline.all_security.operating_system
}
