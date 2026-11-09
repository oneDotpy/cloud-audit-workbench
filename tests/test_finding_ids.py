"""Finding IDs must stay stable across runs for the same issue."""
from src.parsers import parse_checkov
from src.schema import make_finding_id


def test_id_is_deterministic():
    assert make_finding_id("checkov", "CKV_AWS_24", "aws_security_group.admin_access") == \
        make_finding_id("checkov", "CKV_AWS_24", "aws_security_group.admin_access")


def test_id_differs_by_check_resource_and_tool():
    base = make_finding_id("checkov", "CKV_AWS_21", "aws_s3_bucket.a")
    assert base != make_finding_id("checkov", "CKV_AWS_21", "aws_s3_bucket.b")
    assert base != make_finding_id("checkov", "CKV_AWS_18", "aws_s3_bucket.a")
    assert base != make_finding_id("prowler", "CKV_AWS_21", "aws_s3_bucket.a")


def test_id_ignores_whitespace_and_tool_case():
    assert make_finding_id("Checkov", " CKV_AWS_21", "aws_s3_bucket.a ") == \
        make_finding_id("checkov", "CKV_AWS_21", "aws_s3_bucket.a")


def test_same_issue_same_id_across_v1_and_v2_even_when_lines_move(checkov_v1, checkov_v2):
    v1, _ = parse_checkov(checkov_v1)
    v2, _ = parse_checkov(checkov_v2)
    rds_v1 = next(f for f in v1 if f.check_id == "CKV_AWS_16")
    rds_v2 = next(f for f in v2 if f.check_id == "CKV_AWS_16")
    # A comment line was added in v2, so the resource moved down one line...
    assert rds_v1.line_start != rds_v2.line_start
    # ...but it is still the same finding.
    assert rds_v1.finding_id == rds_v2.finding_id


def test_parsing_twice_gives_identical_ids(checkov_v1):
    a, _ = parse_checkov(checkov_v1)
    b, _ = parse_checkov(checkov_v1)
    assert [f.finding_id for f in a] == [f.finding_id for f in b]
    assert len({f.finding_id for f in a}) == len(a)
