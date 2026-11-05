#!/usr/bin/env bash
# Live demonstrations of the automated monitoring and self-healing.
#
#   scripts/demo.sh alert           # fire a test alarm -> email within ~1 min
#   scripts/demo.sh outage          # stop the app -> synthetic check alarm (~10 min)
#   scripts/demo.sh restore         # start the app again -> alarm returns to OK
#   scripts/demo.sh sg-guard        # open port 22 to the world -> auto-revoked
#   scripts/demo.sh cpu             # burn CPU for 15 min -> cpu-high alarm
#   scripts/demo.sh shell           # SSM shell on the server (no SSH, no bastion)
#   scripts/demo.sh logs            # tail VPN connection + nginx logs
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF="terraform -chdir=$ROOT/terraform"
REGION="$($TF output -raw region)"
NAME="$($TF output -raw project_name)"
INSTANCE_ID="$($TF output -raw instance_id)"
export AWS_REGION="$REGION"

log() { printf '\033[1;35m[demo]\033[0m %s\n' "$*"; }

ssm_run() {
  local cmd_id
  cmd_id="$(aws ssm send-command --instance-ids "$INSTANCE_ID" \
    --document-name AWS-RunShellScript --comment "demo: ${1:0:90}" \
    --parameters "{\"commands\":[\"$1\"]}" --query Command.CommandId --output text)"
  aws ssm wait command-executed --command-id "$cmd_id" --instance-id "$INSTANCE_ID" || true
  aws ssm get-command-invocation --command-id "$cmd_id" --instance-id "$INSTANCE_ID" \
    --query '[Status, StandardOutputContent]' --output text
}

case "${1:-}" in
  alert)
    alarm="$NAME-cpu-high"
    log "Forcing $alarm into ALARM to prove SNS email delivery"
    aws cloudwatch set-alarm-state --alarm-name "$alarm" --state-value ALARM \
      --state-reason "Manual notification test from scripts/demo.sh"
    log "Check your inbox. The alarm re-evaluates to OK on its own within ~5 minutes."
    ;;
  outage)
    log "Stopping the vault service on $INSTANCE_ID (nginx will return 502)"
    ssm_run "systemctl stop vault && systemctl is-active vault || true"
    log "The in-VPC synthetic check now fails; '$NAME-app-unavailable' fires after 2 failed runs (~10 min)."
    log "Speed it up: aws lambda invoke --function-name $NAME-synthetic-check /dev/stdout"
    ;;
  restore)
    ssm_run "systemctl start vault && systemctl is-active vault"
    log "Service restored. The alarm returns to OK after the next successful check."
    ;;
  sg-guard)
    sg="$($TF output -raw app_security_group_id)"
    log "Simulating a mistake: opening SSH (22/tcp) on $sg to 0.0.0.0/0"
    aws ec2 authorize-security-group-ingress --group-id "$sg" \
      --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0,Description=demo-mistake}]' >/dev/null
    log "Rule added. Waiting for CloudTrail -> EventBridge -> sg-guard Lambda (usually 1-3 minutes)..."
    for i in $(seq 1 36); do
      open="$(aws ec2 describe-security-group-rules --filters "Name=group-id,Values=$sg" \
        --query "length(SecurityGroupRules[?IsEgress==\`false\` && CidrIpv4=='0.0.0.0/0'])" --output text)"
      if [[ "$open" == "0" ]]; then
        log "Auto-remediated after ~$((i * 10))s: the public rule was revoked. Check your email for the alert."
        exit 0
      fi
      sleep 10
    done
    log "Still open after 6 minutes. Check /aws/lambda/$NAME-sg-guard logs."
    exit 1
    ;;
  cpu)
    log "Burning CPU on $INSTANCE_ID for 15 minutes (cpu-high fires after 10 min > 80%)"
    ssm_run "nohup timeout 900 sh -c 'yes >/dev/null & yes >/dev/null & wait' >/dev/null 2>&1 &"
    ;;
  shell)
    exec aws ssm start-session --target "$INSTANCE_ID"
    ;;
  logs)
    aws logs tail "/$NAME/client-vpn/connections" --since 1h --format short || true
    aws logs tail "/$NAME/app/nginx-access" --since 15m --format short --follow
    ;;
  *)
    sed -n '2,11p' "$0"
    exit 1
    ;;
esac
