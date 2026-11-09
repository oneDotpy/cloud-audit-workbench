# WARNING: INTENTIONALLY INSECURE. Synthetic sample for Cloud Audit Workbench.
# These resources are misconfigured on purpose to produce scanner findings.
# NEVER deploy this file to a real AWS account.

# v2 changes: customer documents bucket is now private.
# Still open: no KMS encryption, versioning, or access logging on either bucket.
resource "aws_s3_bucket" "customer_documents" {
  bucket = "acme-customer-documents-example"
}

resource "aws_s3_bucket_acl" "customer_documents" {
  bucket = aws_s3_bucket.customer_documents.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "customer_documents" {
  bucket                  = aws_s3_bucket.customer_documents.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "finance_exports" {
  bucket = "acme-finance-exports-example"
}

resource "aws_s3_bucket_public_access_block" "finance_exports" {
  bucket                  = aws_s3_bucket.finance_exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# v2 change: data volume is now encrypted with a customer managed key.
resource "aws_ebs_volume" "app_data" {
  availability_zone = "ap-southeast-1a"
  size              = 50
  encrypted         = true
  kms_key_id        = aws_kms_key.audit_logs.arn

  tags = {
    Name = "app-data"
  }
}
