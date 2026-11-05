terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.70"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.6"
    }
  }

  # For team use, copy backend.tf.example to backend.tf (S3 backend with
  # encryption + native lockfile). Local state is fine for a single operator,
  # but note that the state contains the imported certificate private keys.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = var.owner
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# Resolves the IAM role behind an assumed-role/SSO session so the bucket
# policy can exempt the deploying principal from the VPC-endpoint-only rule.
data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

locals {
  name       = "${var.project}-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
  azs        = slice(data.aws_availability_zones.available.names, 0, 2)

  deployer_arn = data.aws_iam_session_context.current.issuer_arn
  app_fqdn     = "app.${var.internal_domain}"
  pki_dir      = abspath("${path.module}/../pki")
}
