# WARNING: INTENTIONALLY INSECURE. Synthetic sample for Cloud Audit Workbench.
# These resources are misconfigured on purpose to produce scanner findings.
# NEVER deploy this file to a real AWS account.

# Customer document store: public read access, no encryption, no versioning, no logging.
resource "aws_s3_bucket" "customer_documents" {
  bucket = "acme-customer-documents-example"
}

resource "aws_s3_bucket_acl" "customer_documents" {
  bucket = aws_s3_bucket.customer_documents.id
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "customer_documents" {
  bucket                  = aws_s3_bucket.customer_documents.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Finance exports bucket: private, but no server-side encryption, versioning, or access logging.
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

# Application server data volume, not encrypted at rest.
resource "aws_ebs_volume" "app_data" {
  availability_zone = "ap-southeast-1a"
  size              = 50
  encrypted         = false

  tags = {
    Name = "app-data"
  }
}
