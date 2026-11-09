"""Parser for Prowler JSON output.

Two layouts are accepted, both as a top-level JSON list of finding objects:

1. Prowler 4.x `json-ocsf` (default JSON output in v4). Key fields:
   metadata.event_code (check id), finding_info.title, status_code (PASS/FAIL),
   status_detail, severity, resources[].uid/name/type/region, cloud.account.uid,
   remediation.references, unmapped.compliance.
2. Prowler 3.x native JSON (`-M json`): CheckID, CheckTitle, Status, StatusExtended,
   Severity, ResourceArn/ResourceId, Region, AccountId, Compliance, RelatedUrl,
   Remediation.Recommendation.Url.

The sample file in tests/fixtures was written by hand to match these layouts; it was
not produced by a live Prowler run. Field names have not been checked against every
Prowler release, so every lookup below is defensive and missing fields are allowed.
"""
from __future__ import annotations

from typing import Any

from src.schema import Finding, deduplicate, make_finding_id

TOOL = "prowler"


def _get(obj: Any, *path: str, default=None):
    for key in path:
        if not isinstance(obj, dict):
            return default
        obj = obj.get(key)
    return default if obj is None else obj


def _compliance(raw: Any) -> dict[str, list[str]]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[str]] = {}
    for framework, ids in raw.items():
        if isinstance(ids, (list, tuple)):
            out[str(framework)] = [str(i) for i in ids]
        elif ids:
            out[str(framework)] = [str(ids)]
    return out


def _first_url(*candidates: Any) -> str | None:
    for c in candidates:
        if isinstance(c, str) and c.startswith("http"):
            return c
        if isinstance(c, list):
            for item in c:
                if isinstance(item, str) and item.startswith("http"):
                    return item
    return None


def _is_ocsf(item: dict) -> bool:
    return "finding_info" in item or "status_code" in item or "metadata" in item


def _parse_ocsf(item: dict) -> Finding | None:
    if str(item.get("status_code", "")).upper() != "FAIL":
        return None
    check_id = _get(item, "metadata", "event_code") or _get(item, "finding_info", "uid")
    resources = item.get("resources") or [{}]
    res = resources[0] if isinstance(resources[0], dict) else {}
    resource = res.get("uid") or res.get("name")
    if not check_id or not resource:
        return None
    return Finding(
        finding_id=make_finding_id(TOOL, check_id, resource),
        source_tool=TOOL,
        check_id=check_id,
        check_title=_get(item, "finding_info", "title") or check_id,
        resource=resource,
        resource_type=res.get("type"),
        raw_severity=str(item["severity"]).upper() if item.get("severity") else None,
        framework_refs=_compliance(_get(item, "unmapped", "compliance")),
        guideline_url=_first_url(_get(item, "remediation", "references"),
                                 _get(item, "unmapped", "related_url")),
        status_detail=item.get("status_detail") or item.get("message"),
        region=res.get("region") or _get(item, "cloud", "region"),
        account_id=_get(item, "cloud", "account", "uid"),
    )


def _parse_legacy(item: dict) -> Finding | None:
    if str(item.get("Status", "")).upper() != "FAIL":
        return None
    check_id = item.get("CheckID")
    resource = item.get("ResourceArn") or item.get("ResourceId")
    if not check_id or not resource:
        return None
    return Finding(
        finding_id=make_finding_id(TOOL, check_id, resource),
        source_tool=TOOL,
        check_id=check_id,
        check_title=item.get("CheckTitle") or check_id,
        resource=resource,
        resource_type=item.get("ResourceType"),
        raw_severity=str(item["Severity"]).upper() if item.get("Severity") else None,
        framework_refs=_compliance(item.get("Compliance")),
        guideline_url=_first_url(_get(item, "Remediation", "Recommendation", "Url"),
                                 item.get("RelatedUrl")),
        status_detail=item.get("StatusExtended"),
        region=item.get("Region"),
        account_id=item.get("AccountId"),
    )


def parse_prowler(data: list | dict) -> tuple[list[Finding], dict]:
    """Return (findings, metadata). Only FAIL results become findings."""
    items = data if isinstance(data, list) else data.get("findings", [])
    findings: list[Finding] = []
    version = None
    passed = 0
    skipped = 0
    for item in items:
        if not isinstance(item, dict):
            skipped += 1
            continue
        ocsf = _is_ocsf(item)
        version = version or _get(item, "metadata", "product", "version")
        status = item.get("status_code") if ocsf else item.get("Status")
        if str(status).upper() == "PASS":
            passed += 1
            continue
        finding = _parse_ocsf(item) if ocsf else _parse_legacy(item)
        if finding:
            findings.append(finding)
        elif str(status).upper() == "FAIL":
            skipped += 1

    deduped = deduplicate(findings)
    meta = {"tool": TOOL, "tool_version": version, "passed": passed,
            "failed": len(findings), "duplicates_removed": len(findings) - len(deduped),
            "records_skipped": skipped, "frameworks": ["aws"]}
    return deduped, meta
