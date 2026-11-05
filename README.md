# Secure AWS VPN-Based Internal Web Service

An internal web application (a document vault) that is reachable **only through AWS Client VPN**. All data at rest is encrypted with a customer-managed KMS key. Monitoring, alerting and self-healing are fully automated. Everything is defined in Terraform.

See [docs/architecture.md](docs/architecture.md) for the diagram, the security controls matrix, design decisions and the cost breakdown.

## Highlights

- **Zero internet exposure:** private subnets only, no internet gateway, no NAT, no public IPs, no SSH. AWS APIs are reached through VPC endpoints.
- **VPN with mutual TLS:** a private CA issues per-user client certificates. Revocation is enforced through a CRL, and every connection is logged.
- **Encryption everywhere:** a KMS CMK covers EBS, S3, CloudWatch Logs, CloudTrail, SNS and SSM parameters. HTTPS uses TLS 1.2+, and the S3 bucket is TLS-only.
- **Data can't be exfiltrated with leaked keys:** S3 object access is allowed only through the VPC endpoint.
- **Automated monitoring:** 12 CloudWatch alarms, an in-VPC synthetic check, log metric filters, VPC Flow Logs, CloudTrail, a dashboard and a budget.
- **Self-healing:** EC2 auto-recover and auto-reboot, plus a Lambda that **automatically revokes** any security group rule opened to the world.
- **DevOps practices:** immutable deployments, an offline reproducible artifact, CI (fmt/validate, Checkov, ruff, pytest, shellcheck) and unit tests with mocked AWS.

## Repository layout

```
terraform/            Infrastructure as code (one file per concern)
  vpc.tf              VPC, private subnets, flow logs, VPC endpoints
  kms.tf              Customer-managed key + key policy
  vpn.tf              Client VPN endpoint, ACM cert, auth rules, logging
  compute.tf          EC2, security groups, IAM role, SSM params, private DNS
  storage.tf          Encrypted S3 bucket, bucket policy, app artifact
  security.tf         CloudTrail, GuardDuty (optional)
  monitoring.tf       SNS, alarms, metric filters, EventBridge, dashboard, budget
  lambdas.tf          Synthetic check + security-group guard
  templates/          user_data bootstrap, CloudWatch agent config
app/                  Flask JSON API, nginx + systemd config, pinned dependencies
fe/                   Browser UI (React + Vite), served as static files by nginx
lambdas/              Lambda function code
scripts/              PKI, bundle build, VPN profile, smoke tests, demos
tests/                pytest unit tests (moto-mocked AWS)
.github/workflows/    CI pipeline
```

## Prerequisites

- An AWS account and an admin IAM user/role with MFA (`aws sts get-caller-identity` works)
- Terraform >= 1.6, AWS CLI v2, OpenSSL, Python 3 with pip, Node.js 20+ with npm, make
- [AWS VPN Client](https://aws.amazon.com/vpn/client-vpn-download/) or any OpenVPN client

## Deploy

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# edit alert_email (and region if not us-east-1)

make deploy          # certs -> app bundle -> terraform init -> terraform apply (~10-15 min)
```

Then:

1. **Confirm the SNS subscription** email sent to `alert_email`.
2. Build your VPN profile: `make vpn-config` creates `vpn-clients/client1.ovpn`.
3. Import the profile into the AWS VPN Client and connect.
4. Trust the private CA: import `pki/ca/ca.crt` into your OS/browser trust store. This gives a valid padlock.
5. Open **https://app.securevpn.internal**.

> If `python3` has no pip, run `PYTHON=/path/to/python3 make deploy`.

## Run the UI locally (no AWS account needed)

The Flask API runs against moto-mocked S3 and KMS with sample documents:

```bash
python3 fe/dev/mock_api.py          # API on 127.0.0.1:8000 (needs requirements-dev.txt)
cd fe && npm install && npm run dev # UI on http://localhost:5173, proxies /api to :8000
```

## Verify (evidence for the report)

```bash
make smoke           # while connected to the VPN: ~20 PASS/FAIL checks
make smoke-novpn     # disconnected: proves the app is unreachable
make test            # unit tests
```

## Demo script (for the presentation)

| Step | Command | What the audience sees |
|---|---|---|
| 1 | Disconnect the VPN, open the URL | Name doesn't resolve / times out |
| 2 | Connect the VPN, open the URL | App loads with a valid TLS padlock |
| 3 | Upload a file, click **SSE-KMS** | Object metadata shows `aws:kms` + the CMK ARN |
| 4 | Open `/api/security` | Live bucket encryption, public-access block, IMDSv2, no public IP |
| 5 | `make demo-alert` | Alarm email arrives in about 1 minute |
| 6 | `make demo-sg-guard` | Port 22 opened to the world is **revoked automatically**, then an email arrives |
| 7 | `make demo-outage`, later `make demo-restore` | Synthetic check alarm fires, then recovers |
| 8 | `make client NAME=alice`, then `make revoke NAME=alice` | Alice's VPN connection is rejected and appears in the connection logs |
| 9 | Open the CloudWatch dashboard (`make outputs`) | All metrics and alarm states on one screen |
| 10 | `make shell` | Root shell over SSM with no SSH key and no open port |

## Operations

| Task | Command |
|---|---|
| Add a VPN user | `make client NAME=alice` (sends them `vpn-clients/alice.ovpn`) |
| Remove a VPN user | `make revoke NAME=alice` |
| Ship a new app version | edit `app/`, then `make plan apply` (instance is replaced immutably) |
| Admin shell | `make shell` |
| Tail logs | `scripts/demo.sh logs` |
| Tear down (stop all charges) | `make destroy` |

## Cost

About **$4.35/day while deployed**, driven mostly by the Client VPN association and the interface endpoints. Destroy the stack when you're not using it. An AWS Budget emails you at 80% of `monthly_budget_usd`. Full breakdown: [docs/architecture.md](docs/architecture.md#cost-estimate-us-east-1-while-deployed).

## Notes and limitations

- **Terraform state contains the imported private keys** (ACM, SSM). For anything beyond a single operator, use the encrypted S3 backend in `terraform/backend.tf.example`.
- `pki/` holds your CA private key. It is git-ignored; keep it safe.
- Destroying takes a few extra minutes because Lambda VPC network interfaces are released asynchronously.
- `enable_ebs_encryption_by_default` turns on account-wide default EBS encryption in the region. It is reverted on destroy.
- The deploying IAM principal is exempt from the VPC-endpoint-only S3 rule, so Terraform can upload the app bundle and destroy the bucket.
