# WARNING: INTENTIONALLY INSECURE. Synthetic sample for Cloud Audit Workbench.
# These resources are misconfigured on purpose to produce scanner findings.
# NEVER deploy this file to a real AWS account.

# v2 changes: trail is multi-region, validates log files, and is encrypted with a CMK.
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = "acme-cloudtrail-logs-example"
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.audit_logs.arn
}

# NEW ISSUE introduced in v2: the key created to remediate CloudTrail encryption
# has automatic rotation disabled.
resource "aws_kms_key" "audit_logs" {
  description             = "CMK for audit log and data volume encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = false
}
