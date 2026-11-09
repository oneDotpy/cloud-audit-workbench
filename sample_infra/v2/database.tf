# WARNING: INTENTIONALLY INSECURE. Synthetic sample for Cloud Audit Workbench.
# These resources are misconfigured on purpose to produce scanner findings.
# NEVER deploy this file to a real AWS account.

# v2 changes: public access removed and automated backups enabled.
# Still open: storage encryption at rest.
resource "aws_db_instance" "customer_db" {
  identifier                  = "customer-db"
  engine                      = "mysql"
  engine_version              = "8.0"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "dbadmin"
  manage_master_user_password = true
  storage_encrypted           = false
  publicly_accessible         = false
  backup_retention_period     = 7
  skip_final_snapshot         = true
}
