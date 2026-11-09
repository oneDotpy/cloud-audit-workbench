"""Workpaper-style Excel export and markdown summary of observations."""
from __future__ import annotations

import io
from collections import defaultdict
from datetime import datetime

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.worksheet import Worksheet

from src.mapper import UNMAPPED_DOMAIN, load_mapping
from src.schema import Finding
from src.tracker import Comparison

PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}
STATUS_ORDER = {"New": 0, "Persisting": 1, "Resolved": 2}

NAVY = "1F3864"
FILL_HEADER = PatternFill("solid", fgColor=NAVY)
FILL_SECTION = PatternFill("solid", fgColor="D9E1F2")
FILL_PRIORITY = {
    "High": PatternFill("solid", fgColor="F4CCCC"),
    "Medium": PatternFill("solid", fgColor="FCE5CD"),
    "Low": PatternFill("solid", fgColor="D9EAD3"),
}
FONT_HEADER = Font(bold=True, color="FFFFFF")
FONT_TITLE = Font(bold=True, size=14, color=NAVY)
FONT_BOLD = Font(bold=True)
FONT_NOTE = Font(italic=True, size=9, color="595959")
THIN = Side(style="thin", color="BFBFBF")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
WRAP_TOP = Alignment(wrap_text=True, vertical="top")


def _fmt_date(iso: str | None) -> str:
    if not iso:
        return ""
    return datetime.fromisoformat(iso).strftime("%d %b %Y %H:%M UTC")


def _sort_key(f: Finding):
    return (PRIORITY_ORDER.get(f.priority, 9), f.control_domain == UNMAPPED_DOMAIN,
            f.control_domain or "", f.issue or "", f.resource)


def _refs(f: Finding) -> str:
    return "; ".join(f"{k}: {', '.join(v)}" for k, v in f.framework_refs.items())


def _domains() -> list[str]:
    domains, _ = load_mapping()
    return domains + [UNMAPPED_DOMAIN]


def _write_table(ws: Worksheet, start_row: int, headers: list[str], rows: list[list],
                 widths: list[int] | None = None, priority_col: int | None = None) -> int:
    for c, h in enumerate(headers, start=1):
        cell = ws.cell(row=start_row, column=c, value=h)
        cell.fill, cell.font, cell.border = FILL_HEADER, FONT_HEADER, BORDER
        cell.alignment = Alignment(wrap_text=True, vertical="center")
    for r, row in enumerate(rows, start=start_row + 1):
        for c, val in enumerate(row, start=1):
            cell = ws.cell(row=r, column=c, value=val)
            cell.border, cell.alignment = BORDER, WRAP_TOP
        if priority_col is not None:
            p = ws.cell(row=r, column=priority_col)
            if p.value in FILL_PRIORITY:
                p.fill = FILL_PRIORITY[p.value]
    if widths:
        for c, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(c)].width = w
    return start_row + len(rows) + 1


def _section(ws: Worksheet, row: int, title: str, ncols: int = 5) -> int:
    for c in range(1, ncols + 1):
        ws.cell(row=row, column=c).fill = FILL_SECTION
    ws.cell(row=row, column=1, value=title).font = FONT_BOLD
    return row + 1


def _kv(ws: Worksheet, row: int, pairs: list[tuple[str, object]]) -> int:
    for k, v in pairs:
        ws.cell(row=row, column=1, value=k).font = FONT_BOLD
        cell = ws.cell(row=row, column=2, value=v)
        cell.alignment = Alignment(wrap_text=True, vertical="top")
        ws.merge_cells(start_row=row, start_column=2, end_row=row, end_column=5)
        row += 1
    return row


def _summary_sheet(ws: Worksheet, run: dict, cmp: Comparison, previous: dict | None) -> None:
    meta = run.get("scan_summary", {})
    current = cmp.current_findings
    ws.title = "Summary"
    ws.sheet_view.showGridLines = False
    ws["A1"] = "Cloud Configuration Review - Workpaper"
    ws["A1"].font = FONT_TITLE
    ws["A2"] = "Automated review of infrastructure configuration against scanner checks, mapped to IT control domains."
    ws["A2"].font = FONT_NOTE

    row = _section(ws, 4, "Workpaper details")
    row = _kv(ws, row, [
        ("W/P reference", f"CAW-{run['run_id']}"),
        ("Environment", run.get("environment")),
        ("Prepared by", "Cloud Audit Workbench (automated)"),
        ("Prepared on", _fmt_date(run["timestamp"])),
        ("Reviewed by", ""),
        ("Reviewed on", ""),
    ])

    row = _section(ws, row + 1, "Scope")
    tool = f"{run.get('tool', '')} {run.get('tool_version') or '(version not reported)'}"
    row = _kv(ws, row, [
        ("Target scanned", run.get("target")),
        ("Scanner and version", tool),
        ("Frameworks scanned", ", ".join(meta.get("frameworks", [])) or "n/a"),
        ("Resources evaluated", meta.get("resource_count", "n/a")),
        ("Checks passed / failed", f"{meta.get('passed', 0)} / {meta.get('failed', 0)}"),
        ("Duplicate results removed", meta.get("duplicates_removed", 0)),
        ("Run date", _fmt_date(run["timestamp"])),
        ("Run ID", run["run_id"]),
    ])

    row = _section(ws, row + 1, "Findings by control domain and priority")
    table = []
    for d in _domains():
        in_d = [f for f in current if f.control_domain == d]
        table.append([d] + [sum(f.priority == p for f in in_d) for p in ("High", "Medium", "Low")] + [len(in_d)])
    table.append(["Total"] + [sum(f.priority == p for f in current) for p in ("High", "Medium", "Low")] + [len(current)])
    end = _write_table(ws, row, ["Control domain", "High", "Medium", "Low", "Total"], table)
    for c in range(1, 6):
        ws.cell(row=end - 1, column=c).font = FONT_BOLD
    for r in range(row + 1, end):
        for c in range(2, 6):
            ws.cell(row=r, column=c).alignment = Alignment(horizontal="center", vertical="top")

    row = _section(ws, end + 1, "Comparison to previous run")
    if previous:
        c = cmp.counts
        row = _kv(ws, row, [
            ("Previous run", f"{previous['run_id']} ({_fmt_date(previous['timestamp'])}), target {previous.get('target')}"),
            ("Findings in previous run", len(previous.get("findings", []))),
            ("Findings in this run", len(current)),
            ("New", c["New"]),
            ("Resolved", c["Resolved"]),
            ("Persisting", c["Persisting"]),
        ])
    else:
        row = _kv(ws, row, [("Previous run", "None for this environment. All findings are classified as New.")])

    row = _section(ws, row + 1, "Unmapped checks")
    unmapped = [f for f in current if not f.is_mapped]
    row = _kv(ws, row, [
        (UNMAPPED_DOMAIN, len(unmapped)),
        ("Checks", ", ".join(sorted({f.check_id for f in unmapped})) or "None"),
    ])

    row = _section(ws, row + 1, "Basis of preparation")
    notes = [
        "Findings are taken from the scanner output listed in Scope. This workpaper does not re-perform the scanner's tests.",
        "Infrastructure-as-code was assessed as written; deployed cloud resources were not inspected.",
        "Priority uses scanner severity where provided, otherwise the default recorded in control_mapping.yaml, adjusted by the rules in prioritizer.py (see Priority rationale column).",
        "Framework references shown are only those supplied by the scanner. No other framework mapping is asserted.",
        "Checks not present in control_mapping.yaml are reported as 'Unmapped – requires review' rather than assigned to a domain.",
    ]
    for n in notes:
        ws.cell(row=row, column=1, value=f"- {n}").alignment = Alignment(wrap_text=True, vertical="top")
        ws.merge_cells(start_row=row, start_column=1, end_row=row, end_column=5)
        ws.row_dimensions[row].height = 30
        row += 1

    ws.column_dimensions["A"].width = 34
    for col in "BCDE":
        ws.column_dimensions[col].width = 18


FINDING_HEADERS = [
    "Ref", "Status", "Priority", "Control domain", "Issue", "Control objective",
    "Condition (what was found)", "Business risk", "Recommendation", "Priority rationale",
    "Resource", "File", "Lines", "Check ID", "Check title", "Scanner severity",
    "Framework refs (from scanner)", "Guideline", "First seen", "Runs open", "Days open",
    "Finding ID", "Management response", "Reviewer notes",
]
FINDING_WIDTHS = [7, 11, 9, 22, 28, 34, 40, 44, 44, 40, 34, 16, 8, 14, 40, 10, 18, 30, 18, 7, 7, 18, 30, 24]


def _finding_row(ref: str, f: Finding) -> list:
    lines = f"{f.line_start}-{f.line_end}" if f.line_start else ""
    return [ref, f.status, f.priority, f.control_domain, f.issue, f.control_objective,
            f.condition, f.business_risk, f.recommendation, " ".join(f.priority_rationale),
            f.resource, f.file_path, lines, f.check_id, f.check_title, f.raw_severity or "Not provided",
            _refs(f) or "None provided", f.guideline_url, _fmt_date(f.first_seen), f.runs_open,
            f.days_open, f.finding_id, "", ""]


def _findings_sheet(ws: Worksheet, findings: list[Finding]) -> None:
    ws.title = "Findings"
    ordered = sorted(findings, key=_sort_key)
    rows = [_finding_row(f"F-{i:03d}", f) for i, f in enumerate(ordered, start=1)]
    _write_table(ws, 1, FINDING_HEADERS, rows, FINDING_WIDTHS, priority_col=3)
    ws.freeze_panes = "D2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(FINDING_HEADERS))}{len(rows) + 1}"


def _resolved_sheet(ws: Worksheet, resolved: list[Finding], cmp: Comparison) -> None:
    ws.title = "Resolved"
    headers = ["Ref", "Control domain", "Issue", "Resource", "Check ID", "Check title",
               "Priority when last open", "First seen", "Runs open", "Last seen in run",
               "Not present in run", "Validation note"]
    widths = [7, 24, 30, 36, 14, 44, 12, 18, 8, 20, 20, 36]
    rows = [[f"R-{i:03d}", f.control_domain, f.issue, f.resource, f.check_id, f.check_title,
             f.priority, _fmt_date(f.first_seen), f.runs_open, cmp.previous_run_id,
             cmp.current_run_id, "Check passed or resource absent in current scan."]
            for i, f in enumerate(sorted(resolved, key=_sort_key), start=1)]
    if not rows:
        rows = [["", "No findings resolved since the previous run.", *[""] * 10]]
    _write_table(ws, 1, headers, rows, widths, priority_col=7)
    ws.freeze_panes = "B2"


def build_workbook(run: dict, cmp: Comparison, previous: dict | None) -> bytes:
    wb = Workbook()
    _summary_sheet(wb.active, run, cmp, previous)
    _findings_sheet(wb.create_sheet(), cmp.current_findings)
    _resolved_sheet(wb.create_sheet(), cmp.resolved, cmp)
    for ws in wb.worksheets:
        ws.page_setup.orientation = "landscape"
        ws.page_setup.fitToWidth = 1
        ws.sheet_properties.pageSetUpPr.fitToPage = True
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ------------------------------------------------------------------ markdown

def _group_by_issue(findings: list[Finding]) -> list[dict]:
    groups: dict[tuple, list[Finding]] = defaultdict(list)
    for f in findings:
        groups[(f.control_domain, f.issue)].append(f)
    out = []
    for (domain, issue), fs in groups.items():
        priority = min((f.priority for f in fs), key=lambda p: PRIORITY_ORDER.get(p, 9))
        persisting = [f for f in fs if f.status == "Persisting"]
        out.append({
            "domain": domain, "issue": issue, "findings": fs, "priority": priority,
            "resources": sorted({f.resource for f in fs}),
            "status": "Persisting" if persisting else "New",
            "first_seen": min((f.first_seen for f in fs if f.first_seen), default=None),
            "runs_open": max((f.runs_open or 1 for f in fs), default=1),
        })
    return sorted(out, key=lambda g: (PRIORITY_ORDER.get(g["priority"], 9), g["domain"] == UNMAPPED_DOMAIN,
                                      -len(g["findings"]), g["domain"], g["issue"]))


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def build_markdown(run: dict, cmp: Comparison, previous: dict | None) -> str:
    current = cmp.current_findings
    mapped = [f for f in current if f.is_mapped]
    unmapped = [f for f in current if not f.is_mapped]
    groups = _group_by_issue(mapped)
    domains_hit = sorted({f.control_domain for f in mapped})
    by_p = {p: sum(f.priority == p for f in current) for p in ("High", "Medium", "Low")}

    lines = [
        "# Cloud Configuration Review: Summary of Observations",
        "",
        f"**Environment:** {run.get('environment')}  ",
        f"**Scope:** {run.get('target')}, assessed with {run.get('tool')} {run.get('tool_version') or ''}  ",
        f"**Run:** {run['run_id']} ({_fmt_date(run['timestamp'])})  ",
        f"**Workpaper reference:** CAW-{run['run_id']}",
        "",
        "## Overall summary",
        "",
        f"We reviewed the configuration of the in-scope infrastructure and identified "
        f"{_plural(len(current), 'exception')} ({by_p['High']} High, {by_p['Medium']} Medium, {by_p['Low']} Low) "
        f"across {_plural(len(domains_hit), 'control domain')}, grouped below into {_plural(len(groups), 'observation')}."
        + (f" {_plural(len(unmapped), 'exception')} could not be mapped to a control domain and require reviewer assessment."
           if unmapped else ""),
        "",
    ]
    if previous:
        c = cmp.counts
        lines += [
            f"Compared with the previous review ({previous['run_id']}), {_plural(c['Resolved'], 'exception')} "
            f"{'has' if c['Resolved'] == 1 else 'have'} been remediated, {c['Persisting']} remain open and "
            f"{c['New']} {'is' if c['New'] == 1 else 'are'} new.",
            "",
        ]
        if cmp.new:
            new_issues = sorted({f.issue for f in cmp.new})
            lines += [f"New exceptions relate to: {'; '.join(new_issues)}.", ""]

    def status_text(g: dict) -> str:
        if g["status"] == "New":
            return "New in this review."
        return f"Open since {_fmt_date(g['first_seen'])} ({_plural(g['runs_open'], 'review')})."

    key = [g for g in groups if g["priority"] == "High"]
    lines += ["## High-priority observations", ""]
    if not key:
        lines += ["None.", ""]
    for i, g in enumerate(key, start=1):
        fs = g["findings"]
        f0 = fs[0]
        details = sorted({f.status_detail for f in fs if f.status_detail})
        condition = (f"{_plural(len(fs), 'check')} failed on {_plural(len(g['resources']), 'resource')}: "
                     + ", ".join(f"`{r}`" for r in g["resources"]) + ".")
        if details:
            condition += " " + " ".join(details)
        lines += [
            f"### {i}. {g['issue']} ({g['priority']})",
            "",
            f"*Control domain:* {g['domain']}",
            "",
            f"- **Criteria:** {f0.control_objective}",
            f"- **Condition:** {condition}",
            f"- **Risk:** {f0.business_risk}",
            f"- **Recommendation:** {f0.recommendation}",
            f"- **Status:** {status_text(g)}",
            f"- **Evidence:** checks {', '.join(sorted({f.check_id for f in fs}))}; see Findings sheet.",
            "",
        ]

    other = [g for g in groups if g["priority"] != "High"]
    if other:
        lines += ["## Medium and Low priority observations", "",
                  "Full criteria, risk and recommendation for each item are in the Findings sheet of the workpaper.", "",
                  "| Observation | Priority | Control domain | Resources | Status |", "|---|---|---|---|---|"]
        lines += [f"| {g['issue']} | {g['priority']} | {g['domain']} | {len(g['resources'])} | {g['status']} |"
                  for g in other]
        lines.append("")

    if previous:
        lines += ["## Remediated since previous review", ""]
        if cmp.resolved:
            for g in _group_by_issue(cmp.resolved):
                lines.append(f"- {g['issue']} ({g['domain']}): {', '.join(f'`{r}`' for r in g['resources'])}")
        else:
            lines.append("- None.")
        lines.append("")

    lines += ["## Items requiring review", ""]
    if unmapped:
        lines += [f"The following {_plural(len(unmapped), 'exception')} relate to checks not yet in the control mapping. "
                  "They have not been assigned a control domain and should be assessed by the reviewer:", ""]
        lines += [f"- {f.check_id}: {f.check_title} (`{f.resource}`)" for f in sorted(unmapped, key=lambda x: x.check_id)]
    else:
        lines.append("- None.")
    lines += [
        "",
        "## Basis of preparation",
        "",
        "Exceptions are taken from automated scanner output and were not re-performed. Infrastructure-as-code was "
        "assessed as written; no deployed cloud resources were accessed. Framework references, where shown in the "
        "workpaper, are those supplied by the scanner only.",
        "",
    ]
    return "\n".join(lines)
