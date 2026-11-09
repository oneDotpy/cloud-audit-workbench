"""Parser for Checkov JSON output (`checkov -o json`).

Structure verified against Checkov 3.4.3 output for sample_infra/v1:
- A single framework produces one dict: {"check_type", "results": {"failed_checks": [...]}, "summary"}.
  Several frameworks produce a list of those dicts.
- Each failed check has check_id, check_name, resource, file_path (relative to the scan
  root), file_line_range, guideline, severity, benchmarks.
- Open-source Checkov without a Prisma Cloud API key leaves severity, benchmarks and
  bc_category as null. The parser reads them when present and never fills them in.
"""
from __future__ import annotations

from typing import Any

from src.schema import Finding, deduplicate, make_finding_id

TOOL = "checkov"


def _framework_refs(raw: Any) -> dict[str, list[str]]:
    """Checkov `benchmarks` is a dict of {benchmark name: [control ids]} when populated."""
    if not isinstance(raw, dict):
        return {}
    refs: dict[str, list[str]] = {}
    for name, ids in raw.items():
        if isinstance(ids, (list, tuple)):
            refs[str(name)] = [str(i) for i in ids]
        elif ids is not None:
            refs[str(name)] = [str(ids)]
    return refs


def _parse_check(check: dict) -> Finding | None:
    check_id = check.get("check_id")
    resource = check.get("resource")
    if not check_id or not resource:
        return None
    line_range = check.get("file_line_range") or []
    severity = check.get("severity")
    return Finding(
        finding_id=make_finding_id(TOOL, check_id, resource),
        source_tool=TOOL,
        check_id=check_id,
        check_title=check.get("check_name") or check_id,
        resource=resource,
        resource_type=resource.split(".")[0] if "." in resource else None,
        file_path=check.get("file_path") or check.get("repo_file_path"),
        line_start=line_range[0] if len(line_range) > 0 else None,
        line_end=line_range[1] if len(line_range) > 1 else None,
        raw_severity=str(severity).upper() if severity else None,
        framework_refs=_framework_refs(check.get("benchmarks")),
        guideline_url=check.get("guideline"),
    )


def parse_checkov(data: dict | list) -> tuple[list[Finding], dict]:
    """Return (findings, metadata). Only failed checks become findings."""
    reports = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    meta = {"tool": TOOL, "tool_version": None, "passed": 0, "failed": 0,
            "resource_count": 0, "frameworks": []}

    for report in reports:
        if not isinstance(report, dict):
            continue
        summary = report.get("summary") or {}
        meta["tool_version"] = meta["tool_version"] or summary.get("checkov_version")
        meta["passed"] += summary.get("passed", 0) or 0
        meta["failed"] += summary.get("failed", 0) or 0
        meta["resource_count"] += summary.get("resource_count", 0) or 0
        if report.get("check_type"):
            meta["frameworks"].append(report["check_type"])
        for check in (report.get("results") or {}).get("failed_checks") or []:
            finding = _parse_check(check)
            if finding:
                findings.append(finding)

    deduped = deduplicate(findings)
    meta["duplicates_removed"] = len(findings) - len(deduped)
    return deduped, meta
