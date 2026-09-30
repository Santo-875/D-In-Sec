#!/usr/bin/env bash
# scripts/tf_to_env.sh — Extracts Terraform outputs and prints .env configuration lines
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "${SCRIPT_DIR}/../infra/terraform" && pwd)"

if ! command -v terraform &>/dev/null; then
    echo "# Warning: terraform command not found in PATH" >&2
    exit 1
fi

if [ ! -d "$TF_DIR" ]; then
    echo "# Error: Terraform directory not found: $TF_DIR" >&2
    exit 1
fi

pushd "$TF_DIR" >/dev/null

BUCKET=$(terraform output -raw bucket 2>/dev/null || echo "")
SIGN_KEY_ID=$(terraform output -raw sign_key_id 2>/dev/null || echo "")
DATA_KEY_ID=$(terraform output -raw data_key_id 2>/dev/null || echo "")
AWS_REGION=$(terraform output -raw aws_region 2>/dev/null || echo "ap-south-1")

popd >/dev/null

cat <<EOF
# ── Generated from Terraform Outputs ───────────────────────────────────────────
STORAGE_BACKEND=s3
SIGNER_BACKEND=kms
S3_BUCKET=${BUCKET}
AWS_REGION=${AWS_REGION}
KMS_KEY_ID=${SIGN_KEY_ID}
KMS_DATA_KEY_ID=${DATA_KEY_ID}
EOF
