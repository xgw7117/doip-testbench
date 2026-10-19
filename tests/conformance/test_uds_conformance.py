"""Data-driven UDS conformance suite.

Every case in ``tests/data/*.yaml`` becomes exactly one pytest item, so the
console output, the Allure report and the CI log all use the same case ids.
"""

from __future__ import annotations

from pathlib import Path

import allure
import pytest

from doipbench.config import EcuConfig
from doipbench.doip import DoIPClient, DoIPTimeout
from doipbench.testing.cases import Case, load_cases
from doipbench.uds import compute_key

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
CASES = load_cases(DATA_DIR / "uds_cases.yaml")
CASE_IDS = [case.id for case in CASES]


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrise every test that asks for a ``case`` argument."""
    if "case" in metafunc.fixturenames:
        metafunc.parametrize("case", CASES, ids=CASE_IDS)


def _apply_precondition(case: Case, client: DoIPClient, config: EcuConfig) -> None:
    precondition = case.precondition
    if precondition.session is not None:
        response = client.change_session(precondition.session)
        assert response[:1] == b"\x50", f"could not enter session: {response.hex()}"
    if precondition.unlock or precondition.seed:
        response = client.request_uds(b"\x27\x01")
        assert response[0] == 0x67, f"seed request failed: {response.hex()}"
        if precondition.unlock:
            key = compute_key(response[2:], config.security.secret)
            unlocked = client.request_uds(b"\x27\x02" + key)
            assert unlocked[:2] == b"\x67\x02", f"unlock failed: {unlocked.hex()}"


@pytest.mark.conformance
@allure.feature("UDS conformance")
@allure.story("ISO 14229-1 services")
def test_uds_case(case: Case, client: DoIPClient, ecu_config: EcuConfig) -> None:
    allure.dynamic.title(f"{case.id} · {case.title}")
    allure.dynamic.severity(case.severity)
    allure.dynamic.tag(*case.tags)
    if case.description:
        allure.dynamic.description(case.description)

    with allure.step("Arrange: routing activation"):
        result = client.routing_activation()
        assert result.accepted

    with allure.step("Arrange: preconditions"):
        _apply_precondition(case, client, ecu_config)

    with allure.step(f"Act: send {case.request.hex(' ').upper()}"):
        if case.expect_no_response:
            with pytest.raises(DoIPTimeout):
                client.request_uds(case.request, timeout=0.3)
            return
        response = client.request_uds(case.request)

    with allure.step("Assert: response"):
        allure.attach(
            response.hex(" ").upper(),
            name="response",
            attachment_type=allure.attachment_type.TEXT,
        )
        if case.expected_nrc is not None:
            expected = bytes([0x7F, case.service_id, case.expected_nrc])
            assert response == expected, (
                f"expected NRC response {expected.hex(' ')}, got {response.hex(' ')}"
            )
        else:
            assert case.expected is not None
            assert response.startswith(case.expected), (
                f"expected prefix {case.expected.hex(' ')}, got {response.hex(' ')}"
            )
