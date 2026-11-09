"""Control mapping rules and report output."""
import io
import re

import pytest
import yaml
from openpyxl import load_workbook

from src import report, tracker
from src.mapper import MAPPING_PATH, UNMAPPED_DOMAIN, load_mapping, map_findings
from src.parsers import parse_checkov, parse_prowler
from src.prioritizer import prioritize_findings

SIX_DOMAINS = ["Logical Access & Identity", "Network Security", "Data Protection & Encryption",
               "Logging & Monitoring", "Backup & Resilience", "Change & Configuration Management"]


def test_mapping_uses_exactly_the_six_domains():
    domains, index = load_mapping()
    assert domains == SIX_DOMAINS
    assert {m.control_domain for m in index.values()} == set(SIX_DOMAINS)


def test_mapping_does_not_invent_framework_references():
    """Framework refs must only come from scanner output, never from our YAML."""
    doc = yaml.safe_load(MAPPING_PATH.read_text(encoding="utf-8"))
    text = yaml.safe_dump(doc["mappings"])
    for name in ["COBIT", "ISO 27001", "ISO/IEC", "NIST", "MAS TRM", "SOC 2", "PCI", "CIS "]:
        assert name not in text, f"{name} found in control_mapping.yaml"


def test_every_entry_has_objective_risk_recommendation():
    _, index = load_mapping()
    for m in index.values():
        assert m.control_objective.endswith(".") and m.business_risk and m.recommendation


def test_unmapped_checks_are_not_guessed(checkov_v1):
    findings, _ = parse_checkov(checkov_v1)
    map_findings(findings)
    unmapped = sorted({f.check_id for f in findings if f.control_domain == UNMAPPED_DOMAIN})
    assert unmapped == ["CKV2_AWS_60", "CKV2_AWS_62"]
    assert all(not f.is_mapped for f in findings if f.check_id in unmapped)


def test_prowler_unmapped_check(prowler_sample):
    findings, _ = parse_prowler(prowler_sample)
    map_findings(findings)
    unmapped = {f.check_id for f in findings if not f.is_mapped}
    assert unmapped == {"account_security_contact_information_is_registered"}


def test_duplicate_check_in_mapping_rejected(tmp_path):
    bad = tmp_path / "m.yaml"
    entry = {"issue": "x", "control_domain": "Network Security", "control_objective": "o.",
             "business_risk": "r", "recommendation": "c", "checks": ["A"]}
    bad.write_text(yaml.safe_dump({"domains": SIX_DOMAINS, "mappings": [entry, dict(entry, issue="y")]}))
    with pytest.raises(ValueError, match="more than once"):
        load_mapping(bad)


def test_unknown_domain_rejected(tmp_path):
    bad = tmp_path / "m.yaml"
    bad.write_text(yaml.safe_dump({"domains": SIX_DOMAINS, "mappings": [
        {"issue": "x", "control_domain": "Physical Security", "control_objective": "o.",
         "business_risk": "r", "recommendation": "c", "checks": ["A"]}]}))
    with pytest.raises(ValueError, match="Unknown control domain"):
        load_mapping(bad)


@pytest.fixture
def comparison(tmp_path, checkov_v1, checkov_v2):
    runs = []
    for data, target in ((checkov_v1, "sample_infra/v1"), (checkov_v2, "sample_infra/v2")):
        findings, meta = parse_checkov(data)
        map_findings(findings)
        prioritize_findings(findings)
        runs.append(tracker.save_run(findings, meta, target, "env", tmp_path))
    return runs[0], runs[1], tracker.compare(runs[0], runs[1], tracker.list_runs(tmp_path))


def test_workbook_structure(comparison):
    prev, cur, cmp = comparison
    wb = load_workbook(io.BytesIO(report.build_workbook(cur, cmp, prev)))
    assert wb.sheetnames == ["Summary", "Findings", "Resolved"]
    findings = wb["Findings"]
    headers = [c.value for c in findings[1]]
    for col in ["Control domain", "Control objective", "Condition (what was found)", "Business risk",
                "Priority", "Recommendation", "Resource", "File", "Lines", "Check ID", "Status"]:
        assert col in headers
    assert findings.max_row - 1 == 40
    assert wb["Resolved"].max_row - 1 == 13
    summary_text = " ".join(str(c.value) for row in wb["Summary"].iter_rows() for c in row if c.value)
    assert "checkov 3.4.3" in summary_text and UNMAPPED_DOMAIN in summary_text


def test_markdown_observations(comparison):
    prev, cur, cmp = comparison
    md = report.build_markdown(cur, cmp, prev)
    assert "13 exceptions have been remediated, 38 remain open and 2 are new" in md
    assert "**Criteria:**" in md and "**Condition:**" in md and "**Risk:**" in md
    assert "Administrative ports open to the internet (High)" in md
    assert "## Items requiring review" in md
    assert not re.search(r"[\U0001F300-\U0001FAFF]", md)  # no emojis
