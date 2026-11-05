# Two automation functions:
#   synthetic_check - runs inside the VPC every N minutes, calls the app over
#                     HTTPS (verifying our private CA) and publishes
#                     availability/latency metrics.
#   sg_guard        - auto-remediation: revokes any 0.0.0.0/0 or ::/0 ingress
#                     rule added to a project security group and alerts.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# ---------------------------------------------------------------------------
# Synthetic availability check
# ---------------------------------------------------------------------------

data "archive_file" "synthetic" {
  type        = "zip"
  output_path = "${path.module}/../build/synthetic_check.zip"

  source {
    content  = file("${path.module}/../lambdas/synthetic_check/handler.py")
    filename = "handler.py"
  }

  source {
    content  = file("${local.pki_dir}/ca/ca.crt")
    filename = "ca.crt"
  }
}

resource "aws_security_group" "synthetic" {
  name        = "${local.name}-synthetic"
  description = "Synthetic check Lambda: HTTPS to app and CloudWatch endpoint only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name}-synthetic" }
}

resource "aws_vpc_security_group_egress_rule" "synthetic_to_app" {
  security_group_id            = aws_security_group.synthetic.id
  description                  = "HTTPS to internal web service"
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_vpc_security_group_egress_rule" "synthetic_to_endpoints" {
  security_group_id            = aws_security_group.synthetic.id
  description                  = "HTTPS to CloudWatch interface endpoint"
  referenced_security_group_id = aws_security_group.endpoints.id
  ip_protocol                  = "tcp"
  from_port                    = 443
  to_port                      = 443
}

resource "aws_iam_role" "synthetic" {
  name               = "${local.name}-synthetic-check"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "synthetic_vpc" {
  role       = aws_iam_role.synthetic.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy_attachment" "synthetic_xray" {
  role       = aws_iam_role.synthetic.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

data "aws_iam_policy_document" "synthetic" {
  statement {
    sid       = "PublishSyntheticMetrics"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["${var.project}/Synthetics"]
    }
  }

  statement {
    sid       = "DecryptEnvironment"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "synthetic" {
  name   = "publish-metrics"
  role   = aws_iam_role.synthetic.id
  policy = data.aws_iam_policy_document.synthetic.json
}

resource "aws_cloudwatch_log_group" "synthetic" {
  name              = "/aws/lambda/${local.name}-synthetic-check"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_lambda_function" "synthetic" {
  function_name    = "${local.name}-synthetic-check"
  description      = "Probes https://${local.app_fqdn}/health from inside the VPC"
  role             = aws_iam_role.synthetic.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.synthetic.output_path
  source_code_hash = data.archive_file.synthetic.output_base64sha256
  timeout          = 20
  memory_size      = 128
  kms_key_arn      = aws_kms_key.main.arn

  vpc_config {
    subnet_ids         = aws_subnet.private[*].id
    security_group_ids = [aws_security_group.synthetic.id]
  }

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      TARGET_URL       = "https://${local.app_fqdn}/health"
      METRIC_NAMESPACE = "${var.project}/Synthetics"
      TIMEOUT_SECONDS  = "8"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.synthetic,
    aws_iam_role_policy_attachment.synthetic_vpc,
  ]
}

resource "aws_cloudwatch_event_rule" "synthetic_schedule" {
  name                = "${local.name}-synthetic-schedule"
  description         = "Run the synthetic availability check"
  schedule_expression = "rate(${var.synthetic_check_rate_minutes} minutes)"
}

resource "aws_cloudwatch_event_target" "synthetic_schedule" {
  rule = aws_cloudwatch_event_rule.synthetic_schedule.name
  arn  = aws_lambda_function.synthetic.arn
}

resource "aws_lambda_permission" "synthetic_schedule" {
  statement_id  = "AllowEventBridgeSchedule"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.synthetic.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.synthetic_schedule.arn
}

# ---------------------------------------------------------------------------
# Security group guard (auto-remediation)
# ---------------------------------------------------------------------------

data "archive_file" "sg_guard" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/sg_guard/handler.py"
  output_path = "${path.module}/../build/sg_guard.zip"
}

resource "aws_iam_role" "sg_guard" {
  name               = "${local.name}-sg-guard"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_iam_role_policy_attachment" "sg_guard_xray" {
  role       = aws_iam_role.sg_guard.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AWSXRayDaemonWriteAccess"
}

data "aws_iam_policy_document" "sg_guard" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.sg_guard.arn}:*"]
  }

  statement {
    sid       = "InspectSecurityGroups"
    actions   = ["ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules"]
    resources = ["*"]
  }

  # Can only modify security groups that belong to this project.
  statement {
    sid       = "RevokeOnProjectGroupsOnly"
    actions   = ["ec2:RevokeSecurityGroupIngress"]
    resources = ["arn:${local.partition}:ec2:${local.region}:${local.account_id}:security-group/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = [var.project]
    }
  }

  statement {
    sid       = "Notify"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid       = "UseKeyForSnsAndEnv"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.main.arn]
  }
}

resource "aws_iam_role_policy" "sg_guard" {
  name   = "remediate-open-ingress"
  role   = aws_iam_role.sg_guard.id
  policy = data.aws_iam_policy_document.sg_guard.json
}

resource "aws_cloudwatch_log_group" "sg_guard" {
  name              = "/aws/lambda/${local.name}-sg-guard"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_lambda_function" "sg_guard" {
  function_name    = "${local.name}-sg-guard"
  description      = "Revokes world-open ingress rules on project security groups"
  role             = aws_iam_role.sg_guard.arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.sg_guard.output_path
  source_code_hash = data.archive_file.sg_guard.output_base64sha256
  timeout          = 30
  memory_size      = 128
  kms_key_arn      = aws_kms_key.main.arn

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      PROJECT_TAG   = var.project
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }

  depends_on = [aws_cloudwatch_log_group.sg_guard]
}

resource "aws_cloudwatch_event_rule" "sg_ingress_change" {
  name        = "${local.name}-sg-ingress-change"
  description = "Security group ingress rule added (CloudTrail)"

  event_pattern = jsonencode({
    source        = ["aws.ec2"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress", "ModifySecurityGroupRules"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_guard" {
  rule = aws_cloudwatch_event_rule.sg_ingress_change.name
  arn  = aws_lambda_function.sg_guard.arn
}

resource "aws_lambda_permission" "sg_guard" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sg_guard.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_ingress_change.arn
}
