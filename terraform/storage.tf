# Encrypted object storage for the internal web service.
#
# Defence in depth on the bucket:
#   1. SSE-KMS with the project CMK (bucket key enabled to cut KMS cost)
#   2. Block Public Access + BucketOwnerEnforced (ACLs disabled)
#   3. Bucket policy: TLS only, no downgrade to SSE-S3, and object access only
#      through the VPC endpoint (except the deploying principal, so Terraform
#      can upload the app bundle and destroy the bucket)
#   4. Versioning + lifecycle for recovery from accidental deletes
#   5. CloudTrail data events record every object read/write (see security.tf)

resource "aws_s3_bucket" "data" {
  bucket        = "${local.name}-data-${local.account_id}-${local.region}"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  depends_on = [aws_s3_bucket_versioning.data]
}

data "aws_iam_policy_document" "data_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.data.arn,
      "${aws_s3_bucket.data.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Rejects uploads that explicitly ask for weaker encryption (e.g. AES256).
  # Uploads with no header still get SSE-KMS from the bucket default.
  statement {
    sid       = "DenyNonKmsEncryption"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
  }

  # Object data is only readable/writable from inside the VPC. Leaked
  # credentials used from the internet cannot touch the files.
  statement {
    sid    = "DenyObjectAccessOutsideVpc"
    effect = "Deny"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = ["${aws_s3_bucket.data.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpce"
      values   = [aws_vpc_endpoint.s3.id]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [local.deployer_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = data.aws_iam_policy_document.data_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.data]
}

# ---------------------------------------------------------------------------
# Application bundle (app code + offline Python wheels), built by
# scripts/build-bundle.sh. The instance is replaced whenever the bundle
# changes (immutable deployments).
# ---------------------------------------------------------------------------

data "archive_file" "app_bundle" {
  type        = "zip"
  source_dir  = "${path.module}/../build/bundle"
  output_path = "${path.module}/../build/app-bundle.zip"
}

resource "aws_s3_object" "app_bundle" {
  bucket                 = aws_s3_bucket.data.id
  key                    = "artifacts/app-bundle-${data.archive_file.app_bundle.output_sha256}.zip"
  source                 = data.archive_file.app_bundle.output_path
  source_hash            = data.archive_file.app_bundle.output_sha256
  server_side_encryption = "aws:kms"
  kms_key_id             = aws_kms_key.main.arn

  depends_on = [
    aws_s3_bucket_policy.data,
    aws_s3_bucket_server_side_encryption_configuration.data,
  ]
}
