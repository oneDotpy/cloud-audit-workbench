"""The v1 -> v2 comparison classifies New, Resolved and Persisting correctly."""
from datetime import datetime, timezone

import pytest

from src import tracker
from src.mapper import map_findings
from src.parsers import parse_checkov
from src.prioritizer import prioritize_findings
from src.schema import make_finding_id

ENV = "test-env"
T1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
T2 = datetime(2026, 1, 31, tzinfo=timezone.utc)
T3 = datetime(2026, 3, 2, tzinfo=timezone.utc)


def _save(data, runs_dir, ts, target):
    findings, meta = parse_checkov(data)
    map_findings(findings)
    prioritize_findings(findings)
    return tracker.save_run(findings, meta, target=target, environment=ENV, runs_dir=runs_dir, timestamp=ts)


@pytest.fixture
def two_runs(tmp_path, checkov_v1, checkov_v2):
    r1 = _save(checkov_v1, tmp_path, T1, "sample_infra/v1")
    r2 = _save(checkov_v2, tmp_path, T2, "sample_infra/v2")
    return tmp_path, r1, r2


def cid(check, resource):
    return make_finding_id("checkov", check, resource)


def test_counts(two_runs):
    runs_dir, r1, r2 = two_runs
    cmp = tracker.compare(r1, r2, tracker.list_runs(runs_dir))
    assert cmp.counts == {"New": 2, "Resolved": 13, "Persisting": 38}
    assert len(cmp.current_findings) == len(r2["findings"])


def test_specific_classifications(two_runs):
    runs_dir, r1, r2 = two_runs
    cmp = tracker.compare(r1, r2, tracker.list_runs(runs_dir))
    new = {f.finding_id for f in cmp.new}
    resolved = {f.finding_id for f in cmp.resolved}
    persisting = {f.finding_id for f in cmp.persisting}

    # New issue introduced in v2: KMS key without rotation
    assert cid("CKV_AWS_7", "aws_kms_key.audit_logs") in new
    # Fixed in v2: public bucket, public RDS, RDS backups, CloudTrail multi-region, EBS encryption
    for check, res in [("CKV_AWS_20", "aws_s3_bucket.customer_documents"),
                       ("CKV_AWS_17", "aws_db_instance.customer_db"),
                       ("CKV_AWS_133", "aws_db_instance.customer_db"),
                       ("CKV_AWS_67", "aws_cloudtrail.main"),
                       ("CKV_AWS_3", "aws_ebs_volume.app_data")]:
        assert cid(check, res) in resolved
    # Not fixed: SSH/RDP open, wildcard IAM, unencrypted RDS
    for check, res in [("CKV_AWS_24", "aws_security_group.admin_access"),
                       ("CKV_AWS_25", "aws_security_group.admin_access"),
                       ("CKV_AWS_62", "aws_iam_policy.ops_full_access"),
                       ("CKV_AWS_16", "aws_db_instance.customer_db")]:
        assert cid(check, res) in persisting
    assert not (new & resolved) and not (new & persisting) and not (resolved & persisting)
    assert all(f.status == "Resolved" for f in cmp.resolved)


def test_age_of_persisting_findings(two_runs):
    runs_dir, r1, r2 = two_runs
    cmp = tracker.compare(r1, r2, tracker.list_runs(runs_dir))
    for f in cmp.persisting:
        assert f.runs_open == 2
        assert f.days_open == 30
        assert f.first_seen == T1.isoformat()
    for f in cmp.new:
        assert f.runs_open == 1 and f.days_open == 0


def test_age_across_three_runs(two_runs, checkov_v2):
    runs_dir, r1, r2 = two_runs
    r3 = _save(checkov_v2, runs_dir, T3, "sample_infra/v2")
    history = tracker.list_runs(runs_dir)
    assert tracker.previous_run(r3, history)["run_id"] == r2["run_id"]
    cmp = tracker.compare(r2, r3, history)
    ssh = next(f for f in cmp.persisting if f.check_id == "CKV_AWS_24")
    kms = next(f for f in cmp.persisting if f.check_id == "CKV_AWS_7")
    assert (ssh.runs_open, ssh.days_open) == (3, 60)   # open since run 1
    assert (kms.runs_open, kms.days_open) == (2, 30)   # introduced in run 2


def test_first_run_has_no_previous(tmp_path, checkov_v1):
    r1 = _save(checkov_v1, tmp_path, T1, "v1")
    assert tracker.previous_run(r1, tracker.list_runs(tmp_path)) is None
    cmp = tracker.compare(None, r1)
    assert cmp.counts == {"New": 51, "Resolved": 0, "Persisting": 0}


def test_runs_saved_as_timestamped_json(two_runs):
    runs_dir, r1, _ = two_runs
    files = sorted(p.name for p in runs_dir.glob("*.json"))
    assert files == ["20260101T000000Z.json", "20260131T000000Z.json"]
    loaded = tracker.load_run(runs_dir / files[0])
    assert loaded["environment"] == ENV and len(loaded["findings"]) == 51


def test_environments_are_kept_separate(two_runs, checkov_v1):
    runs_dir, _, r2 = two_runs
    findings, meta = parse_checkov(checkov_v1)
    other = tracker.save_run(findings, meta, "x", "other-env", runs_dir, timestamp=T3)
    assert tracker.previous_run(other, tracker.list_runs(runs_dir)) is None
