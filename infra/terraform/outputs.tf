# ================================================================
# D-In-Sec M3 Sidecar — Terraform Outputs
# ================================================================

output "bucket" {
  description = "Name of the S3 audit bucket"
  value       = aws_s3_bucket.audit.id
}

output "bucket_arn" {
  description = "ARN of the S3 audit bucket"
  value       = aws_s3_bucket.audit.arn
}

output "sign_key_id" {
  description = "KMS Asymmetric Key ID for digital signatures"
  value       = aws_kms_key.sign_key.key_id
}

output "sign_key_arn" {
  description = "KMS Asymmetric Key ARN for digital signatures"
  value       = aws_kms_key.sign_key.arn
}

output "data_key_id" {
  description = "KMS Symmetric Key ID for S3 SSE data encryption"
  value       = aws_kms_key.data_key.key_id
}

output "data_key_arn" {
  description = "KMS Symmetric Key ARN for S3 SSE data encryption"
  value       = aws_kms_key.data_key.arn
}

output "aws_region" {
  description = "Configured AWS region"
  value       = var.aws_region
}

output "iam_access_key_id" {
  description = "IAM Access Key ID (only present if create_iam_access_key is true)"
  value       = try(aws_iam_access_key.sidecar[0].id, "")
  sensitive   = true
}

output "iam_secret_access_key" {
  description = "IAM Secret Access Key (only present if create_iam_access_key is true)"
  value       = try(aws_iam_access_key.sidecar[0].secret, "")
  sensitive   = true
}
