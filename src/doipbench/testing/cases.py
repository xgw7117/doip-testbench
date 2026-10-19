"""YAML test-case model and loader.

Keeping the cases in YAML has two benefits that matter in an interview:

* the test logic stays in ``test_*.py`` while the data lives in ``data/*.yaml``,
  so a test engineer can add coverage without touching Python;
* the loader validates the schema up front, which turns a typo into a clear
  error message instead of a mysterious failure forty lines later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_SEVERITIES = {"blocker", "critical", "normal", "minor", "trivial"}


class CaseSchemaError(ValueError):
    """Raised when a YAML case does not follow the schema."""


@dataclass(frozen=True, slots=True)
class Precondition:
    """State that must be established before the request is sent."""

    session: int | None = None
    unlock: bool = False
    seed: bool = False


@dataclass(frozen=True, slots=True)
class Case:
    """One data-driven diagnostic test case."""

    id: str
    title: str
    request: bytes
    expected: bytes | None = None
    expected_nrc: int | None = None
    expect_no_response: bool = False
    precondition: Precondition = field(default_factory=Precondition)
    tags: tuple[str, ...] = ()
    severity: str = "normal"
    description: str = ""

    @property
    def service_id(self) -> int:
        return self.request[0]


def _hex(value: Any, field_name: str, case_id: str) -> bytes:
    if not isinstance(value, str):
        raise CaseSchemaError(f"{case_id}: '{field_name}' must be a hex string")
    cleaned = value.replace("0x", "").replace(",", " ").strip()
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise CaseSchemaError(f"{case_id}: invalid hex in '{field_name}': {value!r}") from exc


def _parse_case(raw: dict[str, Any], seen: set[str]) -> Case:
    case_id = str(raw.get("id", "")).strip()
    if not case_id:
        raise CaseSchemaError("every case needs a non-empty 'id'")
    if case_id in seen:
        raise CaseSchemaError(f"duplicate case id: {case_id}")
    seen.add(case_id)

    title = str(raw.get("title", "")).strip()
    if not title:
        raise CaseSchemaError(f"{case_id}: 'title' is required")
    if "request" not in raw:
        raise CaseSchemaError(f"{case_id}: 'request' is required")

    expected = _hex(raw["expected"], "expected", case_id) if "expected" in raw else None
    expected_nrc = raw.get("expected_nrc")
    if expected_nrc is not None:
        expected_nrc = int(str(expected_nrc), 0)
        if not 0 <= expected_nrc <= 0xFF:
            raise CaseSchemaError(f"{case_id}: NRC out of range")
    expect_no_response = bool(raw.get("expect_no_response", False))

    modes = sum(x is not None for x in (expected, expected_nrc)) + int(expect_no_response)
    if modes != 1:
        raise CaseSchemaError(
            f"{case_id}: exactly one of 'expected', 'expected_nrc' or "
            f"'expect_no_response' must be given"
        )

    pre_raw = raw.get("precondition") or {}
    if not isinstance(pre_raw, dict):
        raise CaseSchemaError(f"{case_id}: 'precondition' must be a mapping")
    precondition = Precondition(
        session=int(str(pre_raw["session"]), 0) if "session" in pre_raw else None,
        unlock=bool(pre_raw.get("unlock", False)),
        seed=bool(pre_raw.get("seed", False)),
    )

    severity = str(raw.get("severity", "normal"))
    if severity not in VALID_SEVERITIES:
        raise CaseSchemaError(f"{case_id}: unknown severity {severity!r}")

    return Case(
        id=case_id,
        title=title,
        request=_hex(raw["request"], "request", case_id),
        expected=expected,
        expected_nrc=expected_nrc,
        expect_no_response=expect_no_response,
        precondition=precondition,
        tags=tuple(str(tag) for tag in raw.get("tags", [])),
        severity=severity,
        description=str(raw.get("description", "")).strip(),
    )


def load_cases(path: str | Path) -> list[Case]:
    """Load and validate a YAML case file."""
    file_path = Path(path)
    with file_path.open(encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, dict) or "cases" not in document:
        raise CaseSchemaError(f"{file_path}: expected a mapping with a 'cases' list")

    raw_cases = document["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise CaseSchemaError(f"{file_path}: 'cases' must be a non-empty list")

    seen: set[str] = set()
    return [_parse_case(raw, seen) for raw in raw_cases]


def load_suite(directory: str | Path) -> list[Case]:
    """Load every ``*.yaml`` file in ``directory``, sorted by file name."""
    cases: list[Case] = []
    seen: set[str] = set()
    for path in sorted(Path(directory).glob("*.yaml")):
        for case in load_cases(path):
            if case.id in seen:
                raise CaseSchemaError(f"duplicate case id across files: {case.id}")
            seen.add(case.id)
            cases.append(case)
    return cases
