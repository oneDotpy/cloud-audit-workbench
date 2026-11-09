from src.parsers.checkov_parser import parse_checkov
from src.parsers.prowler_parser import parse_prowler

__all__ = ["parse_checkov", "parse_prowler", "detect_and_parse"]


def detect_and_parse(data):
    """Pick the right parser for an uploaded JSON document.

    Checkov output is a dict (or list of dicts) with a "results" key.
    Prowler output is a list of finding objects.
    Returns (tool_name, findings, metadata).
    """
    if isinstance(data, dict) and "results" in data:
        return "checkov", *parse_checkov(data)
    if isinstance(data, list) and data and isinstance(data[0], dict) and "results" in data[0]:
        return "checkov", *parse_checkov(data)
    if isinstance(data, list):
        return "prowler", *parse_prowler(data)
    raise ValueError("Unrecognised file: expected Checkov JSON or Prowler JSON output.")
