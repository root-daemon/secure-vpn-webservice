output "app_url" {
  description = "Internal URL (resolvable and reachable only while connected to the VPN)."
  value       = "https://${local.app_fqdn}"
}

output "client_vpn_endpoint_id" {
  description = "Client VPN endpoint ID (used by scripts/make-ovpn.sh)."
  value       = aws_ec2_client_vpn_endpoint.main.id
}

output "instance_id" {
  description = "Web server instance ID (connect with: aws ssm start-session --target <id>)."
  value       = aws_instance.app.id
}

output "instance_private_ip" {
  description = "Private IP of the web server (it has no public IP)."
  value       = aws_instance.app.private_ip
}

output "data_bucket" {
  description = "Encrypted S3 bucket holding vault files."
  value       = aws_s3_bucket.data.id
}

output "kms_key_arn" {
  description = "Customer-managed KMS key protecting all data at rest."
  value       = aws_kms_key.main.arn
}

output "sns_topic_arn" {
  description = "Alert topic (confirm the subscription email)."
  value       = aws_sns_topic.alerts.arn
}

output "dashboard_url" {
  description = "CloudWatch dashboard."
  value       = "https://${local.region}.console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards:name=${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "synthetic_function" {
  description = "Synthetic check Lambda name (invoke manually to test)."
  value       = aws_lambda_function.synthetic.function_name
}

output "app_security_group_id" {
  description = "Web server security group (used by the sg-guard demo)."
  value       = aws_security_group.app.id
}

output "region" {
  value = local.region
}

output "project_name" {
  value = local.name
}
