"""Prioritization rules behave as documented in prioritizer.py and the README."""
import pytest

from src.mapper import ControlMapping, load_mapping, map_findings
from src.parsers import parse_checkov
from src.prioritizer import prioritize, prioritize_findings
from src.schema import Finding, make_finding_id


def mk(check_title="Ensure something", severity=None, resource_type="aws_iam_role",
       domain="Logical Access & Identity", detail=None):
    return Finding(finding_id=make_finding_id("t", check_title, "r"), source_tool="t", check_id="T_1",
                   check_title=check_title, resource=f"{resource_type}.r", resource_type=resource_type,
                   raw_severity=severity, control_domain=domain, status_detail=detail)


def mapping(default):
    return ControlMapping("i", "Logical Access & Identity", "o", "r", "rec", default)


@pytest.mark.parametrize("sev,expected", [("CRITICAL", "High"), ("HIGH", "High"), ("MEDIUM", "Medium"),
                                          ("LOW", "Low"), ("INFO", "Low")])
def test_rule1_scanner_severity_baseline(sev, expected):
    assert prioritize(mk(severity=sev), mapping("HIGH")).priority == expected


def test_rule1_scanner_severity_wins_over_mapping_default():
    f = prioritize(mk(severity="LOW"), mapping("HIGH"))
    assert f.priority == "Low"
    assert "scanner severity LOW" in f.priority_rationale[0]


def test_rule1_fallback_to_mapping_default_when_severity_empty():
    f = prioritize(mk(severity=None), mapping("MEDIUM"))
    assert f.priority == "Medium"
    assert "no severity" in f.priority_rationale[0]


def test_rule1_fallback_to_low_when_nothing_known():
    assert prioritize(mk(severity=None), None).priority == "Low"


@pytest.mark.parametrize("base,expected", [("LOW", "Medium"), ("MEDIUM", "High"), ("HIGH", "High")])
def test_rule2_data_store_raises_one_level(base, expected):
    f = prioritize(mk(severity=base, resource_type="aws_s3_bucket"), None)
    assert f.priority == expected


def test_rule2_prowler_data_store_type():
    assert prioritize(mk(severity="LOW", resource_type="AwsRdsDbInstance"), None).priority == "Medium"


@pytest.mark.parametrize("title", ["Ensure all data stored in RDS is not publicly accessible",
                                   "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22",
                                   "Ensure no security groups allow ingress from ::/0 to port 3389"])
def test_rule3_public_exposure_is_high(title):
    f = prioritize(mk(check_title=title, severity="LOW"), None)
    assert f.priority == "High"
    assert any("public" in r for r in f.priority_rationale)


def test_rule3_uses_status_detail_too():
    f = prioritize(mk(severity="LOW", detail="Bucket has public access through its ACL."), None)
    assert f.priority == "High"


def test_rule3_egress_is_not_public_exposure():
    f = prioritize(mk(check_title="Ensure no security groups allow egress from 0.0.0.0:0 to port -1",
                      severity="LOW", domain="Network Security"), None)
    assert f.priority == "Low"


def test_rule4_logging_gap_at_least_medium():
    f = prioritize(mk(severity="LOW", domain="Logging & Monitoring"), None)
    assert f.priority == "Medium"
    assert prioritize(mk(severity="HIGH", domain="Logging & Monitoring"), None).priority == "High"


def test_rule4_does_not_apply_to_other_domains():
    assert prioritize(mk(severity="LOW", domain="Backup & Resilience"), None).priority == "Low"


def test_every_real_finding_gets_priority_and_rationale(checkov_v1):
    findings, _ = parse_checkov(checkov_v1)
    _, index = load_mapping()
    map_findings(findings, index)
    prioritize_findings(findings, index)
    assert all(f.priority in {"High", "Medium", "Low"} for f in findings)
    assert all(f.priority_rationale for f in findings)
    by_check = {f.check_id: f.priority for f in findings}
    assert by_check["CKV_AWS_24"] == "High"     # SSH open to internet
    assert by_check["CKV_AWS_62"] == "High"     # wildcard admin policy (mapping default HIGH)
    assert by_check["CKV_AWS_67"] == "High"     # CloudTrail not multi-region
    assert by_check["CKV_AWS_23"] == "Low"      # missing SG description
