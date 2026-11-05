import importlib.util
import ssl
from pathlib import Path
from unittest import mock

import boto3
from moto import mock_aws

LAMBDAS = Path(__file__).resolve().parents[1] / "lambdas"


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"{name}_handler", LAMBDAS / name / "handler.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------- sg_guard


def test_find_open_ingress_rules_only_flags_world_open_ingress():
    sg_guard = load("sg_guard")
    rules = [
        {"SecurityGroupRuleId": "a", "IsEgress": False, "CidrIpv4": "0.0.0.0/0"},
        {"SecurityGroupRuleId": "b", "IsEgress": False, "CidrIpv6": "::/0"},
        {"SecurityGroupRuleId": "c", "IsEgress": False, "CidrIpv4": "10.0.0.0/16"},
        {"SecurityGroupRuleId": "d", "IsEgress": True, "CidrIpv4": "0.0.0.0/0"},
        {"SecurityGroupRuleId": "e", "IsEgress": False, "ReferencedGroupInfo": {"GroupId": "sg-1"}},
    ]
    assert [r["SecurityGroupRuleId"] for r in sg_guard.find_open_ingress_rules(rules)] == ["a", "b"]


def test_extract_group_id_handles_both_api_shapes():
    sg_guard = load("sg_guard")
    assert sg_guard.extract_group_id({"requestParameters": {"groupId": "sg-1"}}) == "sg-1"
    assert (
        sg_guard.extract_group_id({"requestParameters": {"ModifySecurityGroupRulesRequest": {"GroupId": "sg-2"}}})
        == "sg-2"
    )
    assert sg_guard.extract_group_id({}) is None


@mock_aws
def test_sg_guard_revokes_public_rule_on_project_group_only():
    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

    def make_group(name, project):
        group_id = ec2.create_security_group(GroupName=name, Description=name, VpcId=vpc_id)["GroupId"]
        ec2.create_tags(Resources=[group_id], Tags=[{"Key": "Project", "Value": project}])
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
        )
        return group_id

    ours = make_group("ours", "securevpn")
    theirs = make_group("theirs", "someone-else")

    sg_guard = load("sg_guard")
    sg_guard.SNS_TOPIC_ARN = ""

    result = sg_guard.handler({"detail": {"requestParameters": {"groupId": ours}}}, None)
    assert result["action"] == "revoked"

    ignored = sg_guard.handler({"detail": {"requestParameters": {"groupId": theirs}}}, None)
    assert ignored["action"] == "ignored"

    def open_rules(group_id):
        rules = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [group_id]}])
        return sg_guard.find_open_ingress_rules(rules["SecurityGroupRules"])

    assert open_rules(ours) == []
    assert len(open_rules(theirs)) == 1


# --------------------------------------------------------- synthetic_check


def test_probe_reports_failure_for_unreachable_target():
    synthetic = load("synthetic_check")
    result = synthetic.probe("https://127.0.0.1:9/health", ssl.create_default_context(), timeout=1)
    assert result["ok"] is False
    assert result["error"]


def test_probe_reports_success_for_healthy_response():
    synthetic = load("synthetic_check")

    class FakeResponse:
        status = 200

        def read(self):
            return b'{"status": "ok"}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    with mock.patch.object(synthetic.urllib.request, "urlopen", return_value=FakeResponse()):
        result = synthetic.probe("https://app.example/health", ssl.create_default_context(), timeout=1)
    assert result == {"ok": True, "latency_ms": result["latency_ms"], "status": 200, "error": None}
