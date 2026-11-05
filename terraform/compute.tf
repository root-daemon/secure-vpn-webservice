# Internal web server: private subnet, no public IP, IMDSv2 only, encrypted
# root volume, administered through SSM Session Manager (port 22 is closed).

data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

resource "aws_security_group" "app" {
  name        = "${local.name}-app"
  description = "Internal web service: HTTPS only from Client VPN and synthetic check"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-app" }
}

resource "aws_vpc_security_group_ingress_rule" "app_https_from_vpn" {
  security_group_id            = aws_security_group.app.id
  description                  = "HTTPS from Client VPN"
  referenced_security_group_id = aws_security_group.vpn.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_ingress_rule" "app_http_from_vpn" {
  security_group_id            = aws_security_group.app.id
  description                  = "HTTP from Client VPN (301 redirect to HTTPS)"
  referenced_security_group_id = aws_security_group.vpn.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
}

resource "aws_vpc_security_group_ingress_rule" "app_https_from_synthetic" {
  security_group_id            = aws_security_group.app.id
  description                  = "HTTPS from synthetic health check Lambda"
  referenced_security_group_id = aws_security_group.synthetic.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "app_to_endpoints" {
  security_group_id            = aws_security_group.app.id
  description                  = "HTTPS to interface VPC endpoints"
  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "app_to_s3" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS to S3 through the gateway endpoint"
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# ---------------------------------------------------------------------------
# IAM: least privilege instance role
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "app" {
  name               = "${local.name}-app-instance"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
}

resource "aws_iam_role_policy_attachment" "app_ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "app_cwagent" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/CloudWatchAgentServerPolicy"
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ListVault"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.data.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["vault/*", "vault/"]
    }
  }

  statement {
    sid       = "ReadWriteVaultObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.data.arn}/vault/*"]
  }

  statement {
    sid       = "ReadDeploymentArtifacts"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.data.arn}/artifacts/*"]
  }

  statement {
    sid = "ReadBucketSecurityPosture"
    actions = [
      "s3:GetEncryptionConfiguration",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketVersioning",
    ]
    resources = [aws_s3_bucket.data.arn]
  }

  statement {
    sid       = "UseProjectKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
    resources = [aws_kms_key.main.arn]
  }

  statement {
    sid       = "ReadTlsMaterial"
    actions   = ["ssm:GetParameter", "ssm:GetParameters"]
    resources = ["arn:${local.partition}:ssm:${local.region}:${local.account_id}:parameter/${local.name}/*"]
  }
}

resource "aws_iam_role_policy" "app" {
  name   = "app-least-privilege"
  role   = aws_iam_role.app.id
  policy = data.aws_iam_policy_document.app.json
}

resource "aws_iam_instance_profile" "app" {
  name = "${local.name}-app"
  role = aws_iam_role.app.name
}

# ---------------------------------------------------------------------------
# Configuration delivered through SSM Parameter Store (KMS encrypted)
# ---------------------------------------------------------------------------

resource "aws_ssm_parameter" "web_tls_cert" {
  name        = "/${local.name}/tls/fullchain"
  description = "TLS certificate chain for ${local.app_fqdn}"
  type        = "SecureString"
  key_id      = aws_kms_key.main.arn
  value       = "${file("${local.pki_dir}/issued/web.crt")}${file("${local.pki_dir}/ca/ca.crt")}"
}

resource "aws_ssm_parameter" "web_tls_key" {
  name        = "/${local.name}/tls/privkey"
  description = "TLS private key for ${local.app_fqdn}"
  type        = "SecureString"
  key_id      = aws_kms_key.main.arn
  value       = file("${local.pki_dir}/issued/web.key")
}

resource "aws_cloudwatch_log_group" "app" {
  for_each = {
    nginx_access = "/${local.name}/app/nginx-access"
    nginx_error  = "/${local.name}/app/nginx-error"
    application  = "/${local.name}/app/application"
    bootstrap    = "/${local.name}/app/bootstrap"
  }

  name              = each.value
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.main.arn
}

# The CloudWatch agent reads its config from SSM (the managed
# CloudWatchAgentServerPolicy allows parameters named AmazonCloudWatch-*).
resource "aws_ssm_parameter" "cwagent_config" {
  name = "AmazonCloudWatch-${local.name}"
  type = "String"
  value = templatefile("${path.module}/templates/cwagent.json.tftpl", {
    namespace        = "${var.project}/WebServer"
    log_nginx_access = aws_cloudwatch_log_group.app["nginx_access"].name
    log_nginx_error  = aws_cloudwatch_log_group.app["nginx_error"].name
    log_application  = aws_cloudwatch_log_group.app["application"].name
    log_bootstrap    = aws_cloudwatch_log_group.app["bootstrap"].name
  })
}

# ---------------------------------------------------------------------------
# Instance
# ---------------------------------------------------------------------------

resource "aws_instance" "app" {
  ami                         = nonsensitive(data.aws_ssm_parameter.al2023_ami.value)
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.private[0].id
  vpc_security_group_ids      = [aws_security_group.app.id]
  iam_instance_profile        = aws_iam_instance_profile.app.name
  associate_public_ip_address = false
  ebs_optimized               = true
  monitoring                  = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 10
    encrypted             = true
    kms_key_id            = aws_kms_key.main.arn
    delete_on_termination = true
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/templates/user_data.sh.tftpl", {
    region          = local.region
    bucket          = aws_s3_bucket.data.id
    bundle_key      = aws_s3_object.app_bundle.key
    kms_key_arn     = aws_kms_key.main.arn
    tls_cert_param  = aws_ssm_parameter.web_tls_cert.name
    tls_key_param   = aws_ssm_parameter.web_tls_key.name
    cwagent_param   = aws_ssm_parameter.cwagent_config.name
    app_fqdn        = local.app_fqdn
    environment     = var.environment
    project         = local.name
    allowed_origins = join(",", var.cors_allowed_origins)
  })

  tags = { Name = "${local.name}-web" }

  # The instance needs private paths to S3/SSM/CloudWatch before it boots.
  depends_on = [
    aws_vpc_endpoint.s3,
    aws_vpc_endpoint.interface,
    aws_route_table_association.private,
    aws_iam_role_policy.app,
    aws_iam_role_policy_attachment.app_ssm,
  ]
}

# ---------------------------------------------------------------------------
# Private DNS: app.<internal_domain> resolves only inside the VPC / VPN
# ---------------------------------------------------------------------------

resource "aws_route53_zone" "internal" {
  name    = var.internal_domain
  comment = "${local.name} private zone"

  vpc {
    vpc_id = aws_vpc.main.id
  }
}

resource "aws_route53_record" "app" {
  zone_id = aws_route53_zone.internal.zone_id
  name    = local.app_fqdn
  type    = "A"
  ttl     = 60
  records = [aws_instance.app.private_ip]
}
