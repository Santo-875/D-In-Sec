# ================================================================
# D-In-Sec M3 Sidecar — AWS Infrastructure
# Terraform >= 1.5  |  Provider: hashicorp/aws >= 5.0
#
# Resources (all cheap/ephemeral, no EC2/NAT):
#   - S3 bucket (Object Lock, versioning, SSE-KMS, lifecycle)
#   - KMS key for signing (RSASSA_PSS_SHA_256 SIGN_VERIFY)
#   - KMS key for data encryption (Encrypt/Decrypt)
#   - IAM user + policy (least-privilege sidecar access)
#   - IAM role (for EC2/ECS workloads)
#
# Variables: see variables.tf and terraform.tfvars.example
# ================================================================

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Local helpers ───────────────────────────────────────────────
locals {
  name_prefix = "dinsec-m3"
  tags = {
    Project     = "D-In-Sec"
    Module      = "M3-Sidecar"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

# ── KMS — Signing key (RSASSA_PSS_SHA_256) ──────────────────────
resource "aws_kms_key" "sign_key" {
  description              = "${local.name_prefix} Merkle root signing key"
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "RSA_2048"
  multi_region             = false
  deletion_window_in_days  = 7
  enable_key_rotation      = false  # Not supported for asymmetric keys

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "KeyAdminAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "SidecarSignAccess"
        Effect = "Allow"
        Principal = { AWS = aws_iam_user.sidecar.arn }
        Action   = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.tags, { Name = "${local.name_prefix}-sign-key" })
}

resource "aws_kms_alias" "sign_key" {
  name          = "alias/${local.name_prefix}-sign"
  target_key_id = aws_kms_key.sign_key.key_id
}

# ── KMS — Data encryption key (Encrypt/Decrypt/GenerateDataKey) ─
resource "aws_kms_key" "data_key" {
  description             = "${local.name_prefix} S3 data encryption key"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "KeyAdminAccess"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "SidecarDataAccess"
        Effect = "Allow"
        Principal = { AWS = aws_iam_user.sidecar.arn }
        Action   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.tags, { Name = "${local.name_prefix}-data-key" })
}

resource "aws_kms_alias" "data_key" {
  name          = "alias/${local.name_prefix}-data"
  target_key_id = aws_kms_key.data_key.key_id
}

# ── S3 bucket ───────────────────────────────────────────────────
resource "aws_s3_bucket" "audit" {
  bucket        = var.s3_bucket_name
  force_destroy = var.environment != "prod"  # Safety: never destroy prod bucket automatically

  tags = merge(local.tags, { Name = var.s3_bucket_name })
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "audit" {
  bucket                  = aws_s3_bucket.audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning
resource "aws_s3_bucket_versioning" "audit" {
  bucket = aws_s3_bucket.audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Object Lock (GOVERNANCE for demo, COMPLIANCE for prod)
resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.object_lock_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.audit]
}

# SSE-KMS encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data_key.arn
    }
    bucket_key_enabled = true
  }
}

# Lifecycle: delete logs/ objects after 180 days; roots/ kept forever
resource "aws_s3_bucket_lifecycle_configuration" "audit" {
  bucket = aws_s3_bucket.audit.id

  rule {
    id     = "logs-retention-180d"
    status = "Enabled"
    filter { prefix = "logs/" }
    expiration { days = 180 }
  }

  rule {
    id     = "summaries-retention-365d"
    status = "Enabled"
    filter { prefix = "summaries/" }
    expiration { days = 365 }
  }
  # roots/ and models/ have no expiration rule — kept forever
}

# ── IAM — Least-privilege sidecar user ─────────────────────────
resource "aws_iam_user" "sidecar" {
  name = "${local.name_prefix}-sidecar"
  tags = local.tags
}

# IAM access key is optional (default off). Recommended: use an AWS profile or IAM role.
resource "aws_iam_access_key" "sidecar" {
  count = var.create_iam_access_key ? 1 : 0
  user  = aws_iam_user.sidecar.name
}

resource "aws_iam_user_policy" "sidecar" {
  name = "${local.name_prefix}-sidecar-policy"
  user = aws_iam_user.sidecar.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3AuditReadWrite"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.audit.arn,
          "${aws_s3_bucket.audit.arn}/logs/*",
          "${aws_s3_bucket.audit.arn}/roots/*",
          "${aws_s3_bucket.audit.arn}/summaries/*",
          "${aws_s3_bucket.audit.arn}/models/*"
        ]
      },
      {
        Sid    = "KMSSign"
        Effect = "Allow"
        Action = ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"]
        Resource = [aws_kms_key.sign_key.arn]
      },
      {
        Sid    = "KMSData"
        Effect = "Allow"
        Action = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"]
        Resource = [aws_kms_key.data_key.arn]
      }
    ]
  })
}

# ── IAM — Role for ECS/EC2 workloads ────────────────────────────
resource "aws_iam_role" "sidecar_role" {
  name = "${local.name_prefix}-role"
  tags = local.tags

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = ["ec2.amazonaws.com", "ecs-tasks.amazonaws.com"] }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "sidecar_role" {
  name   = "${local.name_prefix}-role-policy"
  role   = aws_iam_role.sidecar_role.id
  policy = aws_iam_user_policy.sidecar.policy
}

# ── Data sources ────────────────────────────────────────────────
data "aws_caller_identity" "current" {}
