# ================================================================
# D-In-Sec M3 Sidecar — Terraform Variables
# ================================================================

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Environment identifier (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "s3_bucket_name" {
  description = "Globally unique name for the S3 audit bucket"
  type        = string
  default     = "dinsec-m3-audit-bucket"
}

variable "object_lock_mode" {
  description = "S3 Object Lock retention mode (GOVERNANCE or COMPLIANCE)"
  type        = string
  default     = "GOVERNANCE"
}

variable "object_lock_days" {
  description = "Number of days for S3 Object Lock retention"
  type        = number
  default     = 180
}

variable "create_iam_access_key" {
  description = "Whether to create static IAM access key credentials. Default is false (Recommended: use AWS_PROFILE or IAM roles)."
  type        = bool
  default     = false
}
