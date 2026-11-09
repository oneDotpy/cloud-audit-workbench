# WARNING: INTENTIONALLY INSECURE. Synthetic sample for Cloud Audit Workbench.
# These resources are misconfigured on purpose to produce scanner findings.
# NEVER deploy this file to a real AWS account.

# Audit trail: single-region only, no log file validation, no KMS encryption.
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = "acme-cloudtrail-logs-example"
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_log_file_validation    = false
}
