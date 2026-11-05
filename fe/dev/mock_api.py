"""Run the real Flask API locally against moto-mocked S3 and KMS.

For UI development and documentation screenshots only. Nothing here touches
a real AWS account: credentials are fake and every call is served by moto.

usage: python fe/dev/mock_api.py   (then: cd fe && npm run dev)
"""

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "app"))

for var, value in {
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
    "AWS_SESSION_TOKEN": "testing",
    "AWS_DEFAULT_REGION": "us-east-1",
}.items():
    os.environ[var] = value

import boto3  # noqa: E402
from moto import mock_aws  # noqa: E402

from vault import create_app  # noqa: E402

BUCKET = "securevpn-dev-vault-local"
SAMPLES = {
    "vpn-access-policy.pdf": 186_412,
    "incident-runbook.md": 9_217,
    "client-cert-rotation.txt": 2_304,
    "q3-cloud-costs.csv": 41_870,
    "network-diagram.png": 412_995,
}


def main() -> None:
    with mock_aws():
        kms = boto3.client("kms")
        key_arn = kms.create_key(Description="securevpn-dev (local mock)")["KeyMetadata"]["Arn"]
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket=BUCKET)
        s3.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
        s3.put_bucket_encryption(
            Bucket=BUCKET,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": key_arn},
                        "BucketKeyEnabled": True,
                    }
                ]
            },
        )
        s3.put_public_access_block(
            Bucket=BUCKET,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        if os.environ.get("MOCK_EMPTY") != "1":
            for name, size in SAMPLES.items():
                s3.put_object(
                    Bucket=BUCKET,
                    Key=f"vault/{name}",
                    Body=b"sample document for local UI testing\n" * (size // 37 + 1),
                    ServerSideEncryption="aws:kms",
                    SSEKMSKeyId=key_arn,
                    BucketKeyEnabled=True,
                )

        app = create_app(
            s3_client=s3,
            config={
                "BUCKET": BUCKET,
                "KMS_KEY_ARN": key_arn,
                "ENVIRONMENT": "dev (local mock)",
                "FQDN": "app.securevpn.internal",
                "SESSION_COOKIE_SECURE": False,
            },
        )
        app.run(host="127.0.0.1", port=int(os.environ.get("MOCK_PORT", "8000")), debug=False)


if __name__ == "__main__":
    main()
