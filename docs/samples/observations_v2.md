# Cloud Configuration Review: Summary of Observations

**Environment:** sample-aws-environment  
**Scope:** sample_infra/v2, assessed with checkov 3.4.3  
**Run:** 20261109T165259Z (09 Nov 2026 16:52 UTC)  
**Workpaper reference:** CAW-20261109T165259Z

## Overall summary

We reviewed the configuration of the in-scope infrastructure and identified 40 exceptions (15 High, 22 Medium, 3 Low) across 6 control domains, grouped below into 19 observations. 3 exceptions could not be mapped to a control domain and require reviewer assessment.

Compared with the previous review (20261109T165257Z), 13 exceptions have been remediated, 38 remain open and 2 are new.

New exceptions relate to: Encryption key access not explicitly defined; Encryption key rotation disabled.

## High-priority observations

### 1. IAM policy permits privilege escalation or data exfiltration (High)

*Control domain:* Logical Access & Identity

- **Criteria:** Users cannot grant themselves additional access or move data outside approved boundaries.
- **Condition:** 5 checks failed on 1 resource: `aws_iam_policy.ops_full_access`.
- **Risk:** Users could raise their own access level or copy data out of the environment without approval, bypassing the access request and review process.
- **Recommendation:** Remove permissions that allow modifying IAM, exposing credentials or unconstrained writes, and require approved change requests for any exception.
- **Status:** Open since 09 Nov 2026 16:52 UTC (2 reviews).
- **Evidence:** checks CKV_AWS_286, CKV_AWS_287, CKV_AWS_288, CKV_AWS_289, CKV_AWS_290; see Findings sheet.

### 2. Access and activity logging not enabled (High)

*Control domain:* Logging & Monitoring

- **Criteria:** Access to data and network activity is logged and retained for investigation.
- **Condition:** 4 checks failed on 4 resources: `aws_db_instance.customer_db`, `aws_s3_bucket.customer_documents`, `aws_s3_bucket.finance_exports`, `aws_vpc.main`.
- **Risk:** There is no record of who accessed stored files, the database, or network traffic, so a data breach could not be scoped or investigated.
- **Recommendation:** Enable S3 server access logging, VPC flow logs and RDS log exports to a central, access-restricted log store.
- **Status:** Open since 09 Nov 2026 16:52 UTC (2 reviews).
- **Evidence:** checks CKV2_AWS_11, CKV_AWS_129, CKV_AWS_18; see Findings sheet.

### 3. Unrestricted administrative permissions (High)

*Control domain:* Logical Access & Identity

- **Criteria:** Access rights are granted on a least-privilege basis and administrative privileges are restricted to authorized roles.
- **Condition:** 4 checks failed on 1 resource: `aws_iam_policy.ops_full_access`.
- **Risk:** Anyone holding this policy can do anything in the cloud account, including reading customer data, deleting systems, or creating new users. A single compromised account would give an attacker full control.
- **Recommendation:** Replace wildcard actions and resources with the specific permissions each role needs, and route administrative access through a separately approved, monitored role.
- **Status:** Open since 09 Nov 2026 16:52 UTC (2 reviews).
- **Evidence:** checks CKV2_AWS_40, CKV_AWS_355, CKV_AWS_62, CKV_AWS_63; see Findings sheet.

### 4. Administrative ports open to the internet (High)

*Control domain:* Network Security

- **Criteria:** Remote administrative access is restricted to approved networks and users.
- **Condition:** 2 checks failed on 1 resource: `aws_security_group.admin_access`.
- **Risk:** Remote login services (SSH and RDP) can be reached by anyone on the internet, which invites automated password-guessing and exploitation attempts against servers.
- **Recommendation:** Restrict SSH and RDP to a corporate IP range or bastion host, or replace direct access with AWS Systems Manager Session Manager.
- **Status:** Open since 09 Nov 2026 16:52 UTC (2 reviews).
- **Evidence:** checks CKV_AWS_24, CKV_AWS_25; see Findings sheet.

### 5. Data not encrypted at rest (High)

*Control domain:* Data Protection & Encryption

- **Criteria:** Sensitive data is encrypted at rest.
- **Condition:** 1 check failed on 1 resource: `aws_db_instance.customer_db`.
- **Risk:** If storage media, snapshots or backups are accessed without authorization, the data can be read directly because it is not encrypted.
- **Recommendation:** Enable storage encryption on the database and data volumes. For existing RDS instances this requires restoring from an encrypted snapshot, so plan a change window.
- **Status:** Open since 09 Nov 2026 16:52 UTC (2 reviews).
- **Evidence:** checks CKV_AWS_16; see Findings sheet.

## Medium and Low priority observations

Full criteria, risk and recommendation for each item are in the Findings sheet of the workpaper.

| Observation | Priority | Control domain | Resources | Status |
|---|---|---|---|---|
| No redundancy across locations | Medium | Backup & Resilience | 3 | Persisting |
| Object versioning disabled | Medium | Backup & Resilience | 2 | Persisting |
| Data retention configuration not defined | Medium | Change & Configuration Management | 2 | Persisting |
| Encryption not using customer-managed keys | Medium | Data Protection & Encryption | 2 | Persisting |
| Audit events not monitored or alerted | Medium | Logging & Monitoring | 1 | Persisting |
| Database deletion protection disabled | Medium | Backup & Resilience | 1 | Persisting |
| Database patching not automated | Medium | Change & Configuration Management | 1 | Persisting |
| Encryption key rotation disabled | Medium | Data Protection & Encryption | 1 | New |
| Database health monitoring not enabled | Medium | Logging & Monitoring | 1 | Persisting |
| Database authentication not integrated with central identity | Medium | Logical Access & Identity | 1 | Persisting |
| Default security group not locked down | Medium | Network Security | 1 | Persisting |
| Unrestricted outbound network traffic | Medium | Network Security | 1 | Persisting |
| Network configuration undocumented or unused | Low | Change & Configuration Management | 1 | Persisting |
| Encryption key access not explicitly defined | Low | Logical Access & Identity | 1 | New |

## Remediated since previous review

- Publicly accessible storage (Data Protection & Encryption): `aws_s3_bucket.customer_documents`, `aws_s3_bucket_public_access_block.customer_documents`
- Automated database backups disabled (Backup & Resilience): `aws_db_instance.customer_db`
- Data not encrypted at rest (Data Protection & Encryption): `aws_ebs_volume.app_data`
- Audit trail does not cover all regions (Logging & Monitoring): `aws_cloudtrail.main`
- Database reachable from the internet (Network Security): `aws_db_instance.customer_db`
- Audit log integrity not protected (Logging & Monitoring): `aws_cloudtrail.main`
- Encryption not using customer-managed keys (Data Protection & Encryption): `aws_ebs_volume.app_data`

## Items requiring review

The following 3 exceptions relate to checks not yet in the control mapping. They have not been assigned a control domain and should be assessed by the reviewer:

- CKV2_AWS_60: Ensure RDS instance with copy tags to snapshots is enabled (`aws_db_instance.customer_db`)
- CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled (`aws_s3_bucket.customer_documents`)
- CKV2_AWS_62: Ensure S3 buckets should have event notifications enabled (`aws_s3_bucket.finance_exports`)

## Basis of preparation

Exceptions are taken from automated scanner output and were not re-performed. Infrastructure-as-code was assessed as written; no deployed cloud resources were accessed. Framework references, where shown in the workpaper, are those supplied by the scanner only.
