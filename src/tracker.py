"""Scan history and remediation tracking.

Each run is saved as runs/<timestamp>.json. Runs are grouped by `environment`
(for example v1 and v2 of the sample infrastructure are two points in time of the
same environment), and any two runs can be compared.

Classification, using the stable finding_id:
  New        - in the current run, not in the previous run
  Resolved   - in the previous run, not in the current run
  Persisting - in both runs
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from src.schema import Finding

RUNS_DIR = Path(__file__).resolve().parent.parent / "runs"
NEW, RESOLVED, PERSISTING = "New", "Resolved", "Persisting"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def save_run(findings: list[Finding], meta: dict, target: str, environment: str,
             runs_dir: Path = RUNS_DIR, timestamp: datetime | None = None) -> dict:
    """Write the run to disk and return it as a dict."""
    runs_dir = Path(runs_dir)
    runs_dir.mkdir(parents=True, exist_ok=True)
    ts = timestamp or _now()
    run_id = ts.strftime("%Y%m%dT%H%M%SZ")
    path = runs_dir / f"{run_id}.json"
    n = 2
    while path.exists():
        path = runs_dir / f"{run_id}-{n}.json"
        n += 1
    run = {
        "run_id": path.stem,
        "timestamp": ts.isoformat(),
        "environment": environment,
        "target": target,
        "tool": meta.get("tool"),
        "tool_version": meta.get("tool_version"),
        "scan_summary": meta,
        "findings": [f.model_dump() for f in findings],
    }
    path.write_text(json.dumps(run, indent=2), encoding="utf-8")
    run["_path"] = str(path)
    return run


def load_run(path: Path | str) -> dict:
    run = json.loads(Path(path).read_text(encoding="utf-8"))
    run["_path"] = str(path)
    return run


def list_runs(runs_dir: Path = RUNS_DIR, environment: str | None = None) -> list[dict]:
    """All saved runs, oldest first, optionally limited to one environment."""
    runs_dir = Path(runs_dir)
    if not runs_dir.exists():
        return []
    runs = [load_run(p) for p in runs_dir.glob("*.json")]
    if environment:
        runs = [r for r in runs if r.get("environment") == environment]
    return sorted(runs, key=lambda r: (r["timestamp"], r["run_id"]))


def findings_of(run: dict) -> list[Finding]:
    return [Finding(**f) for f in run.get("findings", [])]


def previous_run(current: dict, history: list[dict]) -> dict | None:
    """Most recent run in the same environment before `current`."""
    earlier = [r for r in history
               if r.get("environment") == current.get("environment")
               and (r["timestamp"], r["run_id"]) < (current["timestamp"], current["run_id"])]
    return earlier[-1] if earlier else None


def _age(finding_id: str, upto: dict, history: list[dict]) -> tuple[str, int]:
    """Walk back from `upto` through consecutive runs that contain the finding.
    Returns (first_seen timestamp, number of runs open)."""
    chain = [r for r in history
             if r.get("environment") == upto.get("environment")
             and (r["timestamp"], r["run_id"]) <= (upto["timestamp"], upto["run_id"])]
    first_seen, count = upto["timestamp"], 0
    for run in reversed(chain):
        if any(f["finding_id"] == finding_id for f in run.get("findings", [])):
            first_seen, count = run["timestamp"], count + 1
        else:
            break
    return first_seen, max(count, 1)


def _days_between(start_iso: str, end_iso: str) -> int:
    start = datetime.fromisoformat(start_iso)
    end = datetime.fromisoformat(end_iso)
    return max((end - start).days, 0)


@dataclass
class Comparison:
    previous_run_id: str | None
    current_run_id: str
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    persisting: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {NEW: len(self.new), RESOLVED: len(self.resolved), PERSISTING: len(self.persisting)}

    @property
    def current_findings(self) -> list[Finding]:
        return self.new + self.persisting


def compare(previous: dict | None, current: dict, history: list[dict] | None = None) -> Comparison:
    """Classify every finding in two runs as New, Resolved or Persisting."""
    history = history if history is not None else [r for r in (previous, current) if r]
    if current not in history:
        history = sorted(history + [current], key=lambda r: (r["timestamp"], r["run_id"]))
    cur = {f.finding_id: f for f in findings_of(current)}
    prev = {f.finding_id: f for f in findings_of(previous)} if previous else {}
    result = Comparison(previous_run_id=previous["run_id"] if previous else None,
                        current_run_id=current["run_id"])

    for fid, f in cur.items():
        if fid in prev:
            f.status = PERSISTING
            f.first_seen, f.runs_open = _age(fid, current, history)
            f.days_open = _days_between(f.first_seen, current["timestamp"])
            result.persisting.append(f)
        else:
            f.status = NEW
            f.first_seen, f.runs_open, f.days_open = current["timestamp"], 1, 0
            result.new.append(f)

    for fid, f in prev.items():
        if fid not in cur:
            f.status = RESOLVED
            f.first_seen, f.runs_open = _age(fid, previous, history)
            f.days_open = _days_between(f.first_seen, current["timestamp"])
            result.resolved.append(f)
    return result
