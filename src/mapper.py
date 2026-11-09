"""Attach control domain, objective, business risk and recommendation to each finding."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from src.schema import Finding

MAPPING_PATH = Path(__file__).with_name("control_mapping.yaml")
UNMAPPED_DOMAIN = "Unmapped – requires review"
REQUIRED_FIELDS = ("issue", "control_domain", "control_objective", "business_risk",
                   "recommendation", "checks")
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


@dataclass(frozen=True)
class ControlMapping:
    issue: str
    control_domain: str
    control_objective: str
    business_risk: str
    recommendation: str
    default_severity: str | None


def load_mapping(path: Path | str = MAPPING_PATH) -> tuple[list[str], dict[str, ControlMapping]]:
    """Load and validate the YAML. Returns (domains, {check_id: mapping})."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)

    domains = doc["domains"]
    index: dict[str, ControlMapping] = {}
    for i, entry in enumerate(doc["mappings"]):
        missing = [f for f in REQUIRED_FIELDS if not entry.get(f)]
        if missing:
            raise ValueError(f"Mapping entry {i} ({entry.get('issue')}) missing: {missing}")
        if entry["control_domain"] not in domains:
            raise ValueError(f"Unknown control domain '{entry['control_domain']}' in {entry['issue']}")
        sev = entry.get("default_severity")
        if sev and str(sev).upper() not in SEVERITIES:
            raise ValueError(f"Invalid default_severity '{sev}' in {entry['issue']}")
        mapping = ControlMapping(
            issue=entry["issue"],
            control_domain=entry["control_domain"],
            control_objective=entry["control_objective"].strip(),
            business_risk=entry["business_risk"].strip(),
            recommendation=entry["recommendation"].strip(),
            default_severity=str(sev).upper() if sev else None,
        )
        for check_id in entry["checks"]:
            if check_id in index:
                raise ValueError(f"Check {check_id} is mapped more than once")
            index[check_id] = mapping
    return domains, index


def map_findings(findings: list[Finding], index: dict[str, ControlMapping] | None = None) -> list[Finding]:
    """Annotate findings in place. Unknown checks go to the unmapped bucket, never guessed."""
    if index is None:
        _, index = load_mapping()
    for f in findings:
        m = index.get(f.check_id)
        if m is None:
            f.control_domain = UNMAPPED_DOMAIN
            f.issue = f.check_title
            f.control_objective = "Not yet mapped. Reviewer to assess and add to control_mapping.yaml."
            f.business_risk = "Not yet assessed."
            f.recommendation = "Review this check and assign it to a control domain."
            continue
        f.control_domain = m.control_domain
        f.issue = m.issue
        f.control_objective = m.control_objective
        f.business_risk = m.business_risk
        f.recommendation = m.recommendation
    return findings
