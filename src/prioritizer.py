"""Audit priority (High / Medium / Low).

All rules live in this file and are applied in this order:

  1. Baseline from scanner severity:
       CRITICAL, HIGH -> High;  MEDIUM -> Medium;  LOW, INFO -> Low.
     If the scanner gives no severity, use `default_severity` from control_mapping.yaml.
     If that is also missing (unmapped check), start at Low.
  2. Data store: findings on a resource that holds data (buckets, databases, volumes)
     are raised one level (Low -> Medium, Medium -> High).
  3. Public exposure: findings showing the resource is reachable from the internet are
     raised to High. Detected from the check title / status text ("public", "0.0.0.0",
     "::/0", "internet"); egress rules are excluded because they do not expose inbound.
  4. Logging gap: findings in the Logging & Monitoring domain are at least Medium.

Every rule that changes the result is recorded in `priority_rationale`, so the
reasoning for each priority is visible in the report.
"""
from __future__ import annotations

from src.mapper import ControlMapping, load_mapping
from src.schema import Finding

LEVELS = ["Low", "Medium", "High"]

SEVERITY_TO_PRIORITY = {
    "CRITICAL": "High",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Low",
    "INFORMATIONAL": "Low",
}

# Resource types (Checkov Terraform types and Prowler/ASFF types) that hold data.
DATA_STORE_TYPES = {
    "aws_s3_bucket", "aws_s3_bucket_public_access_block", "aws_s3_bucket_acl",
    "aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table", "aws_ebs_volume",
    "aws_efs_file_system", "aws_redshift_cluster", "aws_elasticache_cluster",
    "AwsS3Bucket", "AwsRdsDbInstance", "AwsRdsDbCluster", "AwsDynamoDbTable",
    "AwsEc2Volume", "AwsEfsFileSystem", "AwsRedshiftCluster",
}

# Phrases in a check title that indicate internet exposure.
PUBLIC_EXPOSURE_KEYWORDS = ("public", "0.0.0.0", "::/0", "internet", "open to everyone")

LOGGING_DOMAIN = "Logging & Monitoring"


def _raise_one(level: str) -> str:
    return LEVELS[min(LEVELS.index(level) + 1, len(LEVELS) - 1)]


def is_data_store(f: Finding) -> bool:
    return (f.resource_type or "") in DATA_STORE_TYPES


def is_public_exposure(f: Finding) -> bool:
    """Inbound exposure only: outbound (egress) rules mention 0.0.0.0 but do not
    make the resource reachable from the internet."""
    text = f"{f.check_title} {f.status_detail or ''}".lower()
    if "egress" in text:
        return False
    return any(k in text for k in PUBLIC_EXPOSURE_KEYWORDS)


def prioritize(f: Finding, mapping: ControlMapping | None) -> Finding:
    reasons: list[str] = []

    # Rule 1: baseline
    if f.raw_severity and f.raw_severity.upper() in SEVERITY_TO_PRIORITY:
        level = SEVERITY_TO_PRIORITY[f.raw_severity.upper()]
        reasons.append(f"Baseline {level} from scanner severity {f.raw_severity.upper()}.")
    elif mapping and mapping.default_severity:
        level = SEVERITY_TO_PRIORITY[mapping.default_severity]
        reasons.append(f"Scanner gave no severity; baseline {level} from control mapping.")
    else:
        level = "Low"
        reasons.append("No scanner severity and no mapping default; baseline Low.")

    # Rule 2: data store
    if is_data_store(f):
        new = _raise_one(level)
        if new != level:
            reasons.append(f"Raised to {new}: resource is a data store.")
        level = new

    # Rule 3: public exposure
    if is_public_exposure(f) and level != "High":
        level = "High"
        reasons.append("Raised to High: indicates public or internet exposure.")

    # Rule 4: logging floor
    if f.control_domain == LOGGING_DOMAIN and level == "Low":
        level = "Medium"
        reasons.append("Raised to Medium: logging gaps are at least Medium.")

    f.priority = level
    f.priority_rationale = reasons
    return f


def prioritize_findings(findings: list[Finding], index: dict[str, ControlMapping] | None = None) -> list[Finding]:
    if index is None:
        _, index = load_mapping()
    for f in findings:
        prioritize(f, index.get(f.check_id))
    return findings
