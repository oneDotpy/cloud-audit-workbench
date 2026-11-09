"""Parsers handle real Checkov output, the sample Prowler file, and missing fields."""
import copy

import pytest

from src.parsers import detect_and_parse, parse_checkov, parse_prowler
from tests.conftest import ROOT

# ----------------------------------------------------------------- Checkov


def test_checkov_real_output_v1(checkov_v1):
    findings, meta = parse_checkov(checkov_v1)
    assert len(findings) == 51
    assert meta["tool_version"] == "3.4.3"
    assert meta["passed"] == 22 and meta["failed"] == 51
    assert meta["duplicates_removed"] == 0

    sg = next(f for f in findings if f.check_id == "CKV_AWS_24")
    assert sg.source_tool == "checkov"
    assert sg.resource == "aws_security_group.admin_access"
    assert sg.resource_type == "aws_security_group"
    assert sg.file_path == "/network.tf"
    assert (sg.line_start, sg.line_end) == (10, 34)
    assert sg.guideline_url.startswith("https://")
    assert "0.0.0.0" in sg.check_title


def test_checkov_oss_leaves_severity_and_benchmarks_empty(checkov_v1):
    """Checkov OSS without an API key returns null severity/benchmarks; we must not invent them."""
    findings, _ = parse_checkov(checkov_v1)
    assert all(f.raw_severity is None for f in findings)
    assert all(f.framework_refs == {} for f in findings)


def test_checkov_uses_scanner_severity_and_benchmarks_when_present(checkov_v1):
    data = copy.deepcopy(checkov_v1)
    check = data["results"]["failed_checks"][0]
    check["severity"] = "high"
    check["benchmarks"] = {"CIS AWS V1.3": ["2.3.1"]}
    findings, _ = parse_checkov(data)
    f = next(x for x in findings if x.check_id == check["check_id"])
    assert f.raw_severity == "HIGH"
    assert f.framework_refs == {"CIS AWS V1.3": ["2.3.1"]}


def test_checkov_list_of_frameworks_and_duplicates(checkov_v1):
    """Multi-framework output is a list; the same check/resource twice is deduplicated."""
    findings, meta = parse_checkov([checkov_v1, checkov_v1])
    assert len(findings) == 51
    assert meta["duplicates_removed"] == 51


def test_checkov_missing_fields_tolerated():
    data = {"check_type": "terraform", "results": {"failed_checks": [
        {"check_id": "CKV_AWS_99", "resource": "aws_x.y"},                     # minimal record
        {"check_id": "CKV_AWS_98", "resource": "aws_x.z", "file_line_range": None,
         "severity": None, "guideline": None, "benchmarks": "unexpected"},     # odd values
        {"check_name": "no id or resource"},                                    # unusable: skipped
    ]}}
    findings, meta = parse_checkov(data)
    assert {f.check_id for f in findings} == {"CKV_AWS_99", "CKV_AWS_98"}
    f = next(x for x in findings if x.check_id == "CKV_AWS_99")
    assert f.check_title == "CKV_AWS_99" and f.line_start is None and f.framework_refs == {}
    assert meta["tool_version"] is None


def test_checkov_no_failures():
    findings, meta = parse_checkov({"check_type": "terraform", "results": {},
                                    "summary": {"passed": 5, "failed": 0, "checkov_version": "3.4.3"}})
    assert findings == [] and meta["passed"] == 5


def test_fixture_matches_live_checkov_run():
    """The committed fixture should still match what the pinned Checkov produces."""
    pytest.importorskip("checkov")
    from src.pipeline import run_checkov
    live, _ = parse_checkov(run_checkov(ROOT / "sample_infra" / "v1"))
    from tests.conftest import load
    fixture, _ = parse_checkov(load("checkov_v1.json"))
    assert {f.finding_id for f in live} == {f.finding_id for f in fixture}

# ----------------------------------------------------------------- Prowler


def test_prowler_sample(prowler_sample):
    findings, meta = parse_prowler(prowler_sample)
    # 13 records: 1 PASS, 1 duplicate FAIL, 1 malformed FAIL -> 10 unique findings
    assert len(findings) == 10
    assert meta["passed"] == 1
    assert meta["duplicates_removed"] == 1
    assert meta["records_skipped"] == 1
    assert meta["tool_version"] == "4.5.0"

    s3 = next(f for f in findings if f.check_id == "s3_bucket_public_access")
    assert s3.resource == "arn:aws:s3:::acme-customer-documents-example"
    assert s3.raw_severity == "CRITICAL"
    assert s3.framework_refs == {"CIS-1.4": ["2.1.5"]}
    assert s3.region == "ap-southeast-1" and s3.account_id == "111122223333"
    assert "public access" in s3.condition


def test_prowler_missing_fields(prowler_sample):
    findings, _ = parse_prowler(prowler_sample)
    ebs = next(f for f in findings if f.check_id == "ec2_ebs_default_encryption")
    assert ebs.raw_severity is None
    assert ebs.resource_type is None
    assert ebs.guideline_url is None
    assert ebs.framework_refs == {}


def test_prowler_legacy_v3_format():
    data = [
        {"CheckID": "iam_root_mfa_enabled", "CheckTitle": "Ensure MFA is enabled for the root account",
         "Status": "FAIL", "StatusExtended": "MFA is not enabled for root account.", "Severity": "critical",
         "ResourceArn": "arn:aws:iam::111122223333:root", "Region": "us-east-1",
         "Compliance": {"CIS-1.4": ["1.5"]},
         "Remediation": {"Recommendation": {"Url": "https://example.com/fix"}}},
        {"CheckID": "x", "Status": "PASS", "ResourceId": "r"},
        {"CheckID": "y", "Status": "FAIL"},
    ]
    findings, meta = parse_prowler(data)
    assert len(findings) == 1
    f = findings[0]
    assert f.raw_severity == "CRITICAL" and f.guideline_url == "https://example.com/fix"
    assert f.framework_refs == {"CIS-1.4": ["1.5"]}
    assert meta["passed"] == 1 and meta["records_skipped"] == 1


def test_detect_and_parse(checkov_v1, prowler_sample):
    assert detect_and_parse(checkov_v1)[0] == "checkov"
    assert detect_and_parse([checkov_v1])[0] == "checkov"
    assert detect_and_parse(prowler_sample)[0] == "prowler"
    with pytest.raises(ValueError):
        detect_and_parse({"unexpected": True})
