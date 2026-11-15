"""0x8002 diagnostic message acknowledgement (ISO 13400-2 9.5.2)."""

from __future__ import annotations

import allure
import pytest

from doipbench.config import EcuConfig, default_config
from doipbench.doip import DoIPClient, DoIPServer, PayloadType
from doipbench.doip.constants import DiagnosticAckCode


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic acknowledgement")
def test_diagnostic_message_is_acknowledged_before_the_response(
    routed_client: DoIPClient, ecu_config: EcuConfig
) -> None:
    routed_client.send_diagnostic(b"\x22\xf1\x90")

    ack = routed_client.receive_frame()
    assert ack.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_ACK
    assert ack.payload == (
        ecu_config.logical_address.to_bytes(2, "big")
        + routed_client.client_address.to_bytes(2, "big")
        + bytes([DiagnosticAckCode.ACCEPTED])
    )

    response = routed_client.receive_frame()
    assert response.payload_type == PayloadType.DIAGNOSTIC_MESSAGE
    assert response.payload[4:].startswith(b"\x62\xf1\x90")


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic acknowledgement")
def test_acknowledgement_can_be_disabled_for_internal_nodes() -> None:
    config = default_config(ack_diagnostic_messages=False)
    with DoIPServer(config) as server:
        with DoIPClient(port=server.port, timeout=2.0).connect() as client:
            assert client.routing_activation().accepted
            client.send_diagnostic(b"\x22\xf1\x90")
            frame = client.receive_frame()
            assert frame.payload_type == PayloadType.DIAGNOSTIC_MESSAGE
            assert frame.payload[4:].startswith(b"\x62\xf1\x90")
