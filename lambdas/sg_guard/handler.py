"""Auto-remediation: revoke world-open ingress on project security groups.

Triggered by EventBridge when CloudTrail records AuthorizeSecurityGroupIngress
or ModifySecurityGroupRules. If the affected group is tagged
Project=<PROJECT_TAG> and now has an ingress rule open to 0.0.0.0/0 or ::/0,
the rule is revoked and an alert is published to SNS.
"""

import json
import logging
import os

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

PROJECT_TAG = os.environ.get("PROJECT_TAG", "securevpn")
SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
OPEN_CIDRS = {"0.0.0.0/0", "::/0"}

ec2 = boto3.client("ec2")
sns = boto3.client("sns")


def extract_group_id(detail: dict) -> str | None:
    params = detail.get("requestParameters") or {}
    if params.get("groupId"):
        return params["groupId"]
    modify = params.get("ModifySecurityGroupRulesRequest") or {}
    return modify.get("GroupId")


def find_open_ingress_rules(rules: list[dict]) -> list[dict]:
    return [
        rule
        for rule in rules
        if not rule.get("IsEgress")
        and (rule.get("CidrIpv4") in OPEN_CIDRS or rule.get("CidrIpv6") in OPEN_CIDRS)
    ]


def is_project_group(group: dict) -> bool:
    tags = {tag["Key"]: tag["Value"] for tag in group.get("Tags", [])}
    return tags.get("Project") == PROJECT_TAG


def handler(event, context):
    detail = event.get("detail", {})
    group_id = extract_group_id(detail)
    if not group_id:
        logger.info("No security group id in event; ignoring")
        return {"action": "ignored", "reason": "no-group-id"}

    groups = ec2.describe_security_groups(GroupIds=[group_id])["SecurityGroups"]
    if not groups or not is_project_group(groups[0]):
        logger.info("Group %s is not tagged Project=%s; ignoring", group_id, PROJECT_TAG)
        return {"action": "ignored", "reason": "not-project-group", "group_id": group_id}

    rules = ec2.describe_security_group_rules(
        Filters=[{"Name": "group-id", "Values": [group_id]}]
    )["SecurityGroupRules"]
    open_rules = find_open_ingress_rules(rules)
    if not open_rules:
        return {"action": "none", "group_id": group_id}

    rule_ids = [rule["SecurityGroupRuleId"] for rule in open_rules]
    ec2.revoke_security_group_ingress(GroupId=group_id, SecurityGroupRuleIds=rule_ids)

    actor = (detail.get("userIdentity") or {}).get("arn", "unknown")
    summary = {
        "action": "revoked",
        "group_id": group_id,
        "rule_ids": rule_ids,
        "rules": [
            {
                "protocol": r.get("IpProtocol"),
                "from_port": r.get("FromPort"),
                "to_port": r.get("ToPort"),
                "cidr": r.get("CidrIpv4") or r.get("CidrIpv6"),
            }
            for r in open_rules
        ],
        "actor": actor,
        "source_ip": detail.get("sourceIPAddress"),
    }
    logger.warning(json.dumps(summary))

    if SNS_TOPIC_ARN:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"[AUTO-REMEDIATED] Public ingress revoked on {group_id}",
            Message=json.dumps(summary, indent=2),
        )
    return summary
