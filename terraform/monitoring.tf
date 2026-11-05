# Automated monitoring: SNS alerting, CloudWatch alarms (with self-healing
# actions), log metric filters, security event rules, dashboard and budget.

# ---------------------------------------------------------------------------
# Alert topic (KMS encrypted)
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name              = "${local.name}-alerts"
  kms_master_key_id = aws_kms_key.main.arn
}

data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "AllowAccountOwner"
    actions   = ["sns:Publish", "sns:Subscribe", "sns:GetTopicAttributes", "sns:SetTopicAttributes"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowAlarmsAndEvents"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "events.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

locals {
  alarm_actions      = [aws_sns_topic.alerts.arn]
  instance_dims      = { InstanceId = aws_instance.app.id }
  webserver_ns       = "${var.project}/WebServer"
  synthetics_ns      = "${var.project}/Synthetics"
  logs_ns            = "${var.project}/Logs"
  synthetic_period_s = var.synthetic_check_rate_minutes * 60
}

# ---------------------------------------------------------------------------
# Instance health, with self-healing actions
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "system_status" {
  alarm_name          = "${local.name}-ec2-system-status-failed"
  alarm_description   = "Underlying host failed. Action: EC2 auto-recover to healthy hardware."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_System"
  dimensions          = local.instance_dims
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = concat(local.alarm_actions, ["arn:${local.partition}:automate:${local.region}:ec2:recover"])
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "instance_status" {
  alarm_name          = "${local.name}-ec2-instance-status-failed"
  alarm_description   = "Guest OS unhealthy. Action: automatic reboot."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed_Instance"
  dimensions          = local.instance_dims
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = concat(local.alarm_actions, ["arn:${local.partition}:automate:${local.region}:ec2:reboot"])
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${local.name}-cpu-high"
  alarm_description   = "Web server CPU above 80% for 10 minutes."
  namespace           = "AWS/EC2"
  metric_name         = "CPUUtilization"
  dimensions          = local.instance_dims
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "memory_high" {
  alarm_name          = "${local.name}-memory-high"
  alarm_description   = "Web server memory above 85% (CloudWatch agent)."
  namespace           = local.webserver_ns
  metric_name         = "mem_used_percent"
  dimensions          = local.instance_dims
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  threshold           = 85
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "disk_high" {
  alarm_name          = "${local.name}-disk-high"
  alarm_description   = "Root volume above 80% used (CloudWatch agent)."
  namespace           = local.webserver_ns
  metric_name         = "disk_used_percent"
  dimensions          = local.instance_dims
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "missing"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

# ---------------------------------------------------------------------------
# Application health (synthetic check + logs)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "app_unavailable" {
  alarm_name          = "${local.name}-app-unavailable"
  alarm_description   = "Synthetic check from inside the VPC failed twice in a row (or stopped reporting)."
  namespace           = local.synthetics_ns
  metric_name         = "Availability"
  dimensions          = { Endpoint = local.app_fqdn }
  statistic           = "Minimum"
  period              = local.synthetic_period_s
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "app_latency" {
  alarm_name          = "${local.name}-app-latency-high"
  alarm_description   = "Health endpoint latency above 2 seconds."
  namespace           = local.synthetics_ns
  metric_name         = "LatencyMs"
  dimensions          = { Endpoint = local.app_fqdn }
  statistic           = "Average"
  period              = local.synthetic_period_s
  evaluation_periods  = 3
  threshold           = 2000
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions
}

locals {
  # name => [log group, filter pattern, metric name]
  metric_filters = {
    nginx_5xx = {
      log_group = aws_cloudwatch_log_group.app["nginx_access"].name
      pattern   = "{ $.status >= 500 }"
      metric    = "Nginx5xx"
    }
    app_errors = {
      log_group = aws_cloudwatch_log_group.app["application"].name
      pattern   = "{ $.level = \"ERROR\" }"
      metric    = "AppErrors"
    }
    bootstrap_failed = {
      log_group = aws_cloudwatch_log_group.app["bootstrap"].name
      pattern   = "\"failed after\""
      metric    = "BootstrapFailures"
    }
    vpn_failed_connections = {
      log_group = aws_cloudwatch_log_group.vpn.name
      pattern   = "\"failed\""
      metric    = "VpnFailedConnections"
    }
    vpc_rejected_packets = {
      log_group = aws_cloudwatch_log_group.flow_logs.name
      pattern   = "[version, account, eni, source, destination, srcport, destport, protocol, packets, bytes, windowstart, windowend, action=\"REJECT\", flowlogstatus]"
      metric    = "RejectedFlows"
    }
  }

  # name => [threshold, period seconds, description]
  log_alarms = {
    nginx_5xx              = { threshold = 5, period = 300, description = "5 or more HTTP 5xx responses in 5 minutes." }
    app_errors             = { threshold = 5, period = 300, description = "5 or more application errors in 5 minutes." }
    bootstrap_failed       = { threshold = 1, period = 300, description = "Instance bootstrap (user data) failed." }
    vpn_failed_connections = { threshold = 3, period = 300, description = "3 or more failed VPN connection attempts in 5 minutes (bad or revoked certificate?)." }
    vpc_rejected_packets   = { threshold = 200, period = 300, description = "Spike in traffic rejected by security groups (possible scan)." }
  }
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each = local.metric_filters

  name           = "${local.name}-${replace(each.key, "_", "-")}"
  log_group_name = each.value.log_group
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.value.metric
    namespace     = local.logs_ns
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "logs" {
  for_each = local.log_alarms

  alarm_name          = "${local.name}-${replace(each.key, "_", "-")}"
  alarm_description   = each.value.description
  namespace           = local.logs_ns
  metric_name         = local.metric_filters[each.key].metric
  statistic           = "Sum"
  period              = each.value.period
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.alarm_actions
  ok_actions          = local.alarm_actions

  depends_on = [aws_cloudwatch_log_metric_filter.this]
}

# ---------------------------------------------------------------------------
# Security change notifications (CloudTrail -> EventBridge -> SNS)
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "security_changes" {
  name        = "${local.name}-security-changes"
  description = "Changes to security groups, VPN, KMS, S3 policies or CloudTrail"

  event_pattern = jsonencode({
    source        = ["aws.ec2", "aws.kms", "aws.s3", "aws.cloudtrail"]
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "ModifySecurityGroupRules",
        "DeleteSecurityGroup",
        "ModifyClientVpnEndpoint",
        "DeleteClientVpnEndpoint",
        "AuthorizeClientVpnIngress",
        "DisableKey",
        "ScheduleKeyDeletion",
        "PutKeyPolicy",
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketEncryption",
        "DeleteBucketEncryption",
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "security_changes" {
  rule = aws_cloudwatch_event_rule.security_changes.name
  arn  = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      event  = "$.detail.eventName"
      source = "$.detail.eventSource"
      user   = "$.detail.userIdentity.arn"
      ip     = "$.detail.sourceIPAddress"
      time   = "$.time"
      region = "$.region"
    }
    input_template = "\"[SECURITY] <event> on <source> by <user> from <ip> at <time> (<region>). Review in CloudTrail.\""
  }
}

resource "aws_cloudwatch_event_rule" "guardduty" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "${local.name}-guardduty-findings"
  description = "GuardDuty findings with severity medium or higher"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", 4] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty" {
  count = var.enable_guardduty ? 1 : 0
  rule  = aws_cloudwatch_event_rule.guardduty[0].name
  arn   = aws_sns_topic.alerts.arn
}

# ---------------------------------------------------------------------------
# Cost guardrail
# ---------------------------------------------------------------------------

resource "aws_budgets_budget" "monthly" {
  name         = "${local.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.alert_email]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.alert_email]
  }
}

# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${local.name}-overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type = "text", x = 0, y = 0, width = 24, height = 2
        properties = {
          markdown = "# ${local.name}: secure internal web service\nApp: `https://${local.app_fqdn}` (VPN only) | Instance `${aws_instance.app.id}` | VPN `${aws_ec2_client_vpn_endpoint.main.id}`"
        }
      },
      {
        type = "alarm", x = 0, y = 2, width = 24, height = 4
        properties = {
          title = "Alarm status"
          alarms = concat(
            [
              aws_cloudwatch_metric_alarm.app_unavailable.arn,
              aws_cloudwatch_metric_alarm.app_latency.arn,
              aws_cloudwatch_metric_alarm.system_status.arn,
              aws_cloudwatch_metric_alarm.instance_status.arn,
              aws_cloudwatch_metric_alarm.cpu_high.arn,
              aws_cloudwatch_metric_alarm.memory_high.arn,
              aws_cloudwatch_metric_alarm.disk_high.arn,
            ],
            [for a in aws_cloudwatch_metric_alarm.logs : a.arn],
          )
        }
      },
      {
        type = "metric", x = 0, y = 6, width = 8, height = 6
        properties = {
          title   = "App availability (synthetic, in-VPC)"
          region  = local.region
          stat    = "Minimum"
          period  = local.synthetic_period_s
          metrics = [[local.synthetics_ns, "Availability", "Endpoint", local.app_fqdn]]
          yAxis   = { left = { min = 0, max = 1 } }
        }
      },
      {
        type = "metric", x = 8, y = 6, width = 8, height = 6
        properties = {
          title   = "App latency (ms)"
          region  = local.region
          stat    = "Average"
          period  = local.synthetic_period_s
          metrics = [[local.synthetics_ns, "LatencyMs", "Endpoint", local.app_fqdn]]
        }
      },
      {
        type = "metric", x = 16, y = 6, width = 8, height = 6
        properties = {
          title  = "Client VPN"
          region = local.region
          stat   = "Maximum"
          period = 300
          metrics = [
            ["AWS/ClientVPN", "ActiveConnectionsCount", "Endpoint", aws_ec2_client_vpn_endpoint.main.id],
            [local.logs_ns, "VpnFailedConnections", { stat = "Sum" }],
          ]
        }
      },
      {
        type = "metric", x = 0, y = 12, width = 8, height = 6
        properties = {
          title  = "Web server resources (%)"
          region = local.region
          stat   = "Average"
          period = 300
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", aws_instance.app.id],
            [local.webserver_ns, "mem_used_percent", "InstanceId", aws_instance.app.id],
            [local.webserver_ns, "disk_used_percent", "InstanceId", aws_instance.app.id],
          ]
          yAxis = { left = { min = 0, max = 100 } }
        }
      },
      {
        type = "metric", x = 8, y = 12, width = 8, height = 6
        properties = {
          title  = "Errors"
          region = local.region
          stat   = "Sum"
          period = 300
          metrics = [
            [local.logs_ns, "Nginx5xx"],
            [local.logs_ns, "AppErrors"],
          ]
        }
      },
      {
        type = "metric", x = 16, y = 12, width = 8, height = 6
        properties = {
          title   = "Rejected network flows (VPC Flow Logs)"
          region  = local.region
          stat    = "Sum"
          period  = 300
          metrics = [[local.logs_ns, "RejectedFlows"]]
        }
      },
      {
        type = "log", x = 0, y = 18, width = 24, height = 6
        properties = {
          title  = "Recent requests (nginx)"
          region = local.region
          query  = "SOURCE '${aws_cloudwatch_log_group.app["nginx_access"].name}' | fields @timestamp, status, request_method, uri, request_time | sort @timestamp desc | limit 50"
          view   = "table"
        }
      },
    ]
  })
}
