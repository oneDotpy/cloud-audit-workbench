"""End-to-end pipeline: scan -> parse -> map -> prioritize -> save run -> compare -> report.

Command line usage (from the project root):

  python -m src.pipeline scan sample_infra/v1
  python -m src.pipeline scan sample_infra/v2
  python -m src.pipeline import tests/fixtures/prowler_sample.json --environment prowler-sample
  python -m src.pipeline compare runs/<older>.json runs/<newer>.json
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from src import report, tracker
from src.mapper import load_mapping, map_findings
from src.parsers import detect_and_parse
from src.prioritizer import prioritize_findings

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"
DEFAULT_ENVIRONMENT = "sample-aws-environment"


def run_checkov(target: Path | str) -> dict | list:
    """Run Checkov locally against a Terraform directory. Never touches a cloud account."""
    cmd = [sys.executable, "-m", "checkov.main", "-d", str(target), "--framework", "terraform",
           "-o", "json", "--quiet", "--compact"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    # Checkov exits 1 when checks fail; that is the expected case.
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"Checkov failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return json.loads(proc.stdout)


def process(data: dict | list, target: str, environment: str,
            runs_dir: Path = tracker.RUNS_DIR) -> tuple[dict, tracker.Comparison, dict | None]:
    """Normalize, map, prioritize and save one scan. Returns (run, comparison, previous_run)."""
    _, findings, meta = detect_and_parse(data)
    _, index = load_mapping()
    map_findings(findings, index)
    prioritize_findings(findings, index)
    run = tracker.save_run(findings, meta, target=target, environment=environment, runs_dir=runs_dir)
    history = tracker.list_runs(runs_dir, environment=environment)
    previous = tracker.previous_run(run, history)
    comparison = tracker.compare(previous, run, history)
    return run, comparison, previous


def write_outputs(run: dict, comparison: tracker.Comparison, previous: dict | None,
                  out_dir: Path = REPORTS_DIR) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    xlsx = out_dir / f"workpaper_{run['run_id']}.xlsx"
    md = out_dir / f"observations_{run['run_id']}.md"
    xlsx.write_bytes(report.build_workbook(run, comparison, previous))
    md.write_text(report.build_markdown(run, comparison, previous), encoding="utf-8")
    return xlsx, md


def print_summary(run: dict, comparison: tracker.Comparison) -> None:
    current = comparison.current_findings
    print(f"\nRun {run['run_id']}  |  {run['tool']} {run['tool_version']}  |  target: {run['target']}")
    print(f"  Findings in scope: {len(current)}")
    for level in ("High", "Medium", "Low"):
        print(f"    {level:<7}{sum(f.priority == level for f in current)}")
    unmapped = sum(not f.is_mapped for f in current)
    print(f"  Unmapped – requires review: {unmapped}")
    if comparison.previous_run_id:
        c = comparison.counts
        print(f"  Compared with {comparison.previous_run_id}: "
              f"New {c['New']}, Resolved {c['Resolved']}, Persisting {c['Persisting']}")
    else:
        print("  No previous run for this environment: all findings classified as New.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Cloud Audit Workbench")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Run Checkov on a Terraform directory")
    p_scan.add_argument("target")
    p_scan.add_argument("--environment", default=DEFAULT_ENVIRONMENT)

    p_imp = sub.add_parser("import", help="Import an existing Checkov or Prowler JSON file")
    p_imp.add_argument("file")
    p_imp.add_argument("--environment", default=None)

    p_cmp = sub.add_parser("compare", help="Compare two saved runs")
    p_cmp.add_argument("previous")
    p_cmp.add_argument("current")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        target = Path(args.target)
        rel = str(target.resolve().relative_to(ROOT)) if target.resolve().is_relative_to(ROOT) else str(target)
        run, comparison, previous = process(run_checkov(target), rel, args.environment)
    elif args.cmd == "import":
        data = json.loads(Path(args.file).read_text(encoding="utf-8"))
        tool, _, _ = detect_and_parse(data)
        env = args.environment or f"{tool}-import"
        run, comparison, previous = process(data, Path(args.file).name, env)
    else:
        previous = tracker.load_run(args.previous)
        run = tracker.load_run(args.current)
        history = tracker.list_runs(environment=run.get("environment"))
        comparison = tracker.compare(previous, run, history)

    print_summary(run, comparison)
    xlsx, md = write_outputs(run, comparison, previous)
    print(f"  Workpaper: {xlsx.relative_to(ROOT)}")
    print(f"  Observations: {md.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
