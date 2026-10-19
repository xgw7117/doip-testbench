"""Smoke tests for the command line interface."""

from __future__ import annotations

from pathlib import Path

import pytest

from doipbench.cli import main
from doipbench.doip import DoIPServer

pytestmark = pytest.mark.unit

CASES = Path(__file__).resolve().parents[1] / "data" / "uds_cases.yaml"


def test_frame_command_decodes_a_diagnostic_message(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["frame", "02 FD 80 01 00 00 00 06 0E 00 10 01 10 03"])
    output = capsys.readouterr().out
    assert code == 0
    assert "0x8001" in output
    assert "0x0E00" in output
    assert "10 03" in output


def test_frame_command_rejects_invalid_hex() -> None:
    assert main(["frame", "not-hex"]) == 2


def test_run_command_executes_the_yaml_suite(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", str(CASES), "--start-ecu", "--port", "0", "--timeout", "1"])
    output = capsys.readouterr().out
    assert code == 0, output
    assert "0 failed" in output


def test_identify_command(ecu_server: DoIPServer, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["identify", "--port", str(ecu_server.port)])
    output = capsys.readouterr().out
    assert code == 0
    assert "LSVAA2BM5N2123456" in output
    assert "0x1001" in output
