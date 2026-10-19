"""Unit tests for the YAML case loader and its schema validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from doipbench.testing import CaseSchemaError, load_cases

pytestmark = pytest.mark.unit

DATA = Path(__file__).resolve().parents[1] / "data" / "uds_cases.yaml"


def write_case(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "cases.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_real_suite_loads_with_unique_ids() -> None:
    cases = load_cases(DATA)
    assert len(cases) >= 30
    ids = [case.id for case in cases]
    assert len(ids) == len(set(ids))


def test_case_fields_are_parsed() -> None:
    cases = {case.id: case for case in load_cases(DATA)}
    case = cases["UDS-SES-001"]
    assert case.request == bytes.fromhex("1003")
    assert case.expected is not None and case.expected.startswith(bytes.fromhex("5003"))
    assert case.precondition.session is None
    assert "smoke" in case.tags


def test_hex_string_accepts_spaces() -> None:
    cases = {case.id: case for case in load_cases(DATA)}
    assert cases["UDS-RDBI-001"].request == bytes.fromhex("22F190")


def test_duplicate_id_is_rejected(tmp_path: Path) -> None:
    path = write_case(
        tmp_path,
        """
cases:
  - id: DUP-1
    title: first
    request: "10 03"
    expected: "50 03"
  - id: DUP-1
    title: second
    request: "10 01"
    expected: "50 01"
""",
    )
    with pytest.raises(CaseSchemaError, match="duplicate"):
        load_cases(path)


def test_missing_expectation_is_rejected(tmp_path: Path) -> None:
    path = write_case(
        tmp_path,
        """
cases:
  - id: BAD-1
    title: no expectation
    request: "10 03"
""",
    )
    with pytest.raises(CaseSchemaError, match="exactly one"):
        load_cases(path)


def test_invalid_hex_is_rejected(tmp_path: Path) -> None:
    path = write_case(
        tmp_path,
        """
cases:
  - id: BAD-2
    title: bad hex
    request: "10 0G"
    expected: "50 03"
""",
    )
    with pytest.raises(CaseSchemaError, match="invalid hex"):
        load_cases(path)


def test_missing_title_is_rejected(tmp_path: Path) -> None:
    path = write_case(
        tmp_path,
        """
cases:
  - id: BAD-3
    request: "10 03"
    expected: "50 03"
""",
    )
    with pytest.raises(CaseSchemaError, match="title"):
        load_cases(path)


def test_unknown_severity_is_rejected(tmp_path: Path) -> None:
    path = write_case(
        tmp_path,
        """
cases:
  - id: BAD-4
    title: severity
    request: "10 03"
    expected: "50 03"
    severity: urgent
""",
    )
    with pytest.raises(CaseSchemaError, match="severity"):
        load_cases(path)
