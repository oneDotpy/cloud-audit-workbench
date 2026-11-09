"""Normalized finding model shared by every parser.

Each scanner has its own output format. Parsers convert them into Finding objects
so that mapping, prioritization, tracking and reporting work the same way
regardless of which tool produced the result.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from pydantic import BaseModel, Field


def make_finding_id(source_tool: str, check_id: str, resource: str) -> str:
    """Stable identifier for "this check failed on this resource".

    File paths, line numbers and timestamps are deliberately excluded so the same
    issue keeps the same ID when files move or lines shift between scans.
    """
    key = f"{source_tool.lower()}|{check_id.strip()}|{resource.strip()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    # Fields required by the normalized schema
    finding_id: str
    source_tool: str
    check_id: str
    check_title: str
    resource: str
    file_path: Optional[str] = None
    raw_severity: Optional[str] = None
    framework_refs: dict[str, list[str]] = Field(default_factory=dict)
    guideline_url: Optional[str] = None

    # Extra evidence the scanners provide when available
    resource_type: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    status_detail: Optional[str] = None
    region: Optional[str] = None
    account_id: Optional[str] = None

    # Populated by mapper.py
    control_domain: Optional[str] = None
    control_objective: Optional[str] = None
    business_risk: Optional[str] = None
    recommendation: Optional[str] = None
    issue: Optional[str] = None

    # Populated by prioritizer.py
    priority: Optional[str] = None
    priority_rationale: list[str] = Field(default_factory=list)

    # Populated by tracker.py
    status: Optional[str] = None
    first_seen: Optional[str] = None
    runs_open: Optional[int] = None
    days_open: Optional[int] = None

    @property
    def is_mapped(self) -> bool:
        from src.mapper import UNMAPPED_DOMAIN

        return bool(self.control_domain) and self.control_domain != UNMAPPED_DOMAIN

    @property
    def evidence(self) -> str:
        parts = [f"Resource: {self.resource}"]
        if self.file_path:
            loc = self.file_path
            if self.line_start:
                loc += f" (lines {self.line_start}-{self.line_end or self.line_start})"
            parts.append(f"File: {loc}")
        if self.region:
            parts.append(f"Region: {self.region}")
        parts.append(f"Check: {self.check_id} ({self.source_tool})")
        return "; ".join(parts)

    @property
    def condition(self) -> str:
        """What was found, stated as a fact rather than as a scanner rule."""
        if self.status_detail:
            return self.status_detail
        return f'{self.resource} does not meet the requirement "{self.check_title}".'


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that refer to the same check on the same resource.

    Checkov can report the same failure more than once (for example when a module is
    referenced twice or several frameworks are scanned together). Framework
    references from duplicates are merged so nothing is lost.
    """
    by_id: dict[str, Finding] = {}
    for f in findings:
        existing = by_id.get(f.finding_id)
        if existing is None:
            by_id[f.finding_id] = f
            continue
        for framework, refs in f.framework_refs.items():
            merged = set(existing.framework_refs.get(framework, [])) | set(refs)
            existing.framework_refs[framework] = sorted(merged)
    return list(by_id.values())
