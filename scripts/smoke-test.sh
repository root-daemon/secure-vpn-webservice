#!/usr/bin/env bash
# End-to-end verification of the security requirements. Run it while
# connected to the VPN (network tests) or with --no-vpn (AWS posture only).
# Prints a PASS/FAIL report you can screenshot for the project report.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CA="${PKI_DIR:-$ROOT/pki}/ca/ca.crt"
TF="terraform -chdir=$ROOT/terraform"
WITH_VPN=1
[[ "${1:-}" == "--no-vpn" ]] && WITH_VPN=0

REGION="$($TF output -raw region)"
APP_URL="$($TF output -raw app_url)"
APP_HOST="${APP_URL#https://}"
INSTANCE_ID="$($TF output -raw instance_id)"
BUCKET="$($TF output -raw data_bucket)"
KMS_ARN="$($TF output -raw kms_key_arn)"
VPN_ID="$($TF output -raw client_vpn_endpoint_id)"
export AWS_REGION="$REGION"

pass=0; fail=0
check() {
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    printf '  \033[32mPASS\033[0m  %s\n' "$name"; pass=$((pass + 1))
  else
    printf '  \033[31mFAIL\033[0m  %s\n' "$name"; fail=$((fail + 1))
  fi
}
not() { ! "$@"; }

echo "== Network isolation =="
check "Instance has no public IP" \
  test "$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)" = "None"
check "VPC has no internet gateway" \
  test "$(aws ec2 describe-internet-gateways --filters "Name=attachment.vpc-id,Values=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].VpcId' --output text)" --query 'length(InternetGateways)')" = "0"
check "App security group has no 0.0.0.0/0 ingress" \
  test "$(aws ec2 describe-security-group-rules --filters "Name=group-id,Values=$($TF output -raw app_security_group_id)" --query "length(SecurityGroupRules[?IsEgress==\`false\` && CidrIpv4=='0.0.0.0/0'])")" = "0"
check "IMDSv2 enforced" \
  test "$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" --query 'Reservations[0].Instances[0].MetadataOptions.HttpTokens' --output text)" = "required"

echo "== VPN =="
check "Client VPN endpoint is available" \
  test "$(aws ec2 describe-client-vpn-endpoints --client-vpn-endpoint-ids "$VPN_ID" --query 'ClientVpnEndpoints[0].Status.Code' --output text)" = "available"
check "VPN uses certificate (mutual TLS) authentication" \
  test "$(aws ec2 describe-client-vpn-endpoints --client-vpn-endpoint-ids "$VPN_ID" --query 'ClientVpnEndpoints[0].AuthenticationOptions[0].Type' --output text)" = "certificate-authentication"
check "VPN connection logging enabled" \
  test "$(aws ec2 describe-client-vpn-endpoints --client-vpn-endpoint-ids "$VPN_ID" --query 'ClientVpnEndpoints[0].ConnectionLogOptions.Enabled' --output text)" = "True"

echo "== Encryption at rest =="
check "Root EBS volume encrypted with project CMK" \
  test "$(aws ec2 describe-volumes --filters "Name=attachment.instance-id,Values=$INSTANCE_ID" --query 'Volumes[0].KmsKeyId' --output text)" = "$KMS_ARN"
check "S3 default encryption is SSE-KMS" \
  test "$(aws s3api get-bucket-encryption --bucket "$BUCKET" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text)" = "aws:kms"
check "S3 Block Public Access fully enabled" \
  test "$(aws s3api get-public-access-block --bucket "$BUCKET" --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text)" = "True	True	True	True"
check "S3 versioning enabled" \
  test "$(aws s3api get-bucket-versioning --bucket "$BUCKET" --query Status --output text)" = "Enabled"
check "KMS key rotation enabled" \
  test "$(aws kms get-key-rotation-status --key-id "$KMS_ARN" --query KeyRotationEnabled --output text)" = "True"
check "Plain-HTTP S3 access denied by bucket policy" \
  not aws s3api list-objects-v2 --bucket "$BUCKET" --endpoint-url "http://s3.$REGION.amazonaws.com" --max-items 1

echo "== Monitoring =="
check "CloudTrail is logging" \
  test "$(aws cloudtrail get-trail-status --name "$($TF output -raw project_name)-trail" --query IsLogging --output text)" = "True"
check "Alarm topic has a confirmed subscription" \
  test "$(aws sns get-topic-attributes --topic-arn "$($TF output -raw sns_topic_arn)" --query 'Attributes.SubscriptionsConfirmed' --output text)" -ge 1
SYNTHETIC_OUT="$(mktemp)"
trap 'rm -f "$SYNTHETIC_OUT"' EXIT
check "Synthetic check (in-VPC Lambda) reports the app healthy" \
  sh -c "aws lambda invoke --function-name '$($TF output -raw synthetic_function)' '$SYNTHETIC_OUT' && grep -q '\"ok\": true' '$SYNTHETIC_OUT'"

if [[ "$WITH_VPN" == 1 ]]; then
  echo "== Through the VPN =="
  check "Private DNS resolves $APP_HOST" \
    sh -c "getent hosts $APP_HOST || dig +short $APP_HOST | grep -q . || nslookup $APP_HOST"
  check "HTTPS health check passes (cert verified by private CA)" \
    sh -c "curl -fsS --max-time 10 --cacert '$CA' '$APP_URL/health' | grep -q '\"status\":\"ok\"'"
  check "HTTP redirects to HTTPS (301)" \
    test "$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://$APP_HOST/")" = "301"
  check "TLS 1.1 is refused" \
    not curl -fsS --max-time 10 --cacert "$CA" --tlsv1.1 --tls-max 1.1 "$APP_URL/health"
  check "HSTS header present" \
    sh -c "curl -sI --max-time 10 --cacert '$CA' '$APP_URL/' | grep -qi strict-transport-security"
  check "App reports SSE-KMS + public access blocked" \
    sh -c "curl -fsS --max-time 10 --cacert '$CA' '$APP_URL/api/security' | grep -q '\"all_public_access_blocked\":true'"
else
  echo "== Without VPN =="
  check "App is NOT reachable without the VPN" \
    not curl -fsS --max-time 5 --cacert "$CA" "$APP_URL/health"
fi

echo
echo "Result: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
