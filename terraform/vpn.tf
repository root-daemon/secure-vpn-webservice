# AWS Client VPN with mutual TLS (certificate) authentication.
# Certificates come from the private CA created by scripts/gen-certs.sh.
# Clients get a split tunnel: only VPC traffic goes through the VPN.

resource "aws_acm_certificate" "vpn_server" {
  private_key       = file("${local.pki_dir}/issued/vpn-server.key")
  certificate_body  = file("${local.pki_dir}/issued/vpn-server.crt")
  certificate_chain = file("${local.pki_dir}/ca/ca.crt")

  tags = { Name = "${local.name}-vpn-server" }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_cloudwatch_log_group" "vpn" {
  name              = "/${local.name}/client-vpn/connections"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_cloudwatch_log_stream" "vpn" {
  name           = "connections"
  log_group_name = aws_cloudwatch_log_group.vpn.name
}

# The Client VPN ENIs use this group. It has no inbound rules and can only
# talk HTTPS to the web server, so a VPN user cannot reach anything else.
resource "aws_security_group" "vpn" {
  name        = "${local.name}-client-vpn"
  description = "Client VPN endpoint: egress to the internal web service only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-client-vpn" }
}

resource "aws_vpc_security_group_egress_rule" "vpn_to_app_https" {
  security_group_id            = aws_security_group.vpn.id
  description                  = "HTTPS to internal web service"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "vpn_to_app_http" {
  security_group_id            = aws_security_group.vpn.id
  description                  = "HTTP to internal web service (redirects to HTTPS)"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 80
  to_port                      = 80
}

resource "aws_ec2_client_vpn_endpoint" "main" {
  description            = "${local.name} client VPN"
  server_certificate_arn = aws_acm_certificate.vpn_server.arn
  client_cidr_block      = var.client_vpn_cidr
  vpc_id                 = aws_vpc.main.id
  security_group_ids     = [aws_security_group.vpn.id]
  dns_servers            = [cidrhost(var.vpc_cidr, 2)]
  split_tunnel           = true
  transport_protocol     = "udp"
  vpn_port               = 443
  session_timeout_hours  = var.vpn_session_timeout_hours
  self_service_portal    = "disabled"

  # Server and client certificates are issued by the same private CA, so the
  # server certificate's chain is used to validate client certificates.
  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.vpn_server.arn
  }

  connection_log_options {
    enabled               = true
    cloudwatch_log_group  = aws_cloudwatch_log_group.vpn.name
    cloudwatch_log_stream = aws_cloudwatch_log_stream.vpn.name
  }

  client_login_banner_options {
    enabled     = true
    banner_text = "Authorized use only. All connections to ${local.name} are logged and monitored."
  }

  tags = { Name = "${local.name}-client-vpn" }
}

# One subnet association keeps cost down (billed per associated subnet-hour).
# Associating a subnet also adds the route to the VPC CIDR automatically.
resource "aws_ec2_client_vpn_network_association" "main" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  subnet_id              = aws_subnet.private[0].id
}

resource "aws_ec2_client_vpn_authorization_rule" "vpc" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.main.id
  target_network_cidr    = var.vpc_cidr
  authorize_all_groups   = true
  description            = "Certificate-authenticated clients may reach the VPC"
}
