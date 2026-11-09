import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture
def checkov_v1():
    return load("checkov_v1.json")


@pytest.fixture
def checkov_v2():
    return load("checkov_v2.json")


@pytest.fixture
def prowler_sample():
    return load("prowler_sample.json")
