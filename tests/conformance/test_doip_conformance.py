"""DoIP conformance tests (ISO 13400-2).

The cases here focus on the parts that are easy to get wrong in a student
project and expensive to debug on a real bench: framing over a byte stream,
routing activation state, and the difference between a generic NACK and a
diagnostic NACK.
"""

from __future__ import annotations

import struct
import time

import allure
import pytest

from doipbench.config import EcuConfig, default_config
from doipbench.doip import (
    DiagnosticRejected,
    DoIPClient,
    DoIPConnectionClosed,
    DoIPFrame,
    DoIPServer,
    DoIPTimeout,
    EntityStatus,
)
from doipbench.doip.constants import (
    DiagnosticNackCode,
    GenericNackCode,
    PayloadType,
    RoutingActivationResponseCode,
)


def _routing_payload(client_address: int, activation_type: int = 0x00) -> bytes:
    return client_address.to_bytes(2, "big") + bytes([activation_type]) + bytes(4)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_vehicle_identification_response(client: DoIPClient, ecu_config: EcuConfig) -> None:
    announcement = client.read_vehicle_identification()
    assert announcement.vin == ecu_config.vin
    assert announcement.logical_address == ecu_config.logical_address
    assert announcement.eid == ecu_config.eid
    assert announcement.gid == ecu_config.gid
    assert announcement.further_action == 0x10


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_by_eid_matches(client: DoIPClient, ecu_config: EcuConfig) -> None:
    client.send_frame(DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID, ecu_config.eid))
    announcement = client.wait_announcement()
    assert announcement.vin == ecu_config.vin


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_by_eid_ignores_other_entity(client: DoIPClient) -> None:
    client.send_frame(
        DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID, bytes.fromhex("FFFFFFFFFFFF"))
    )
    with pytest.raises(DoIPTimeout):
        client.wait_announcement(timeout=0.3)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_by_vin_matches(client: DoIPClient, ecu_config: EcuConfig) -> None:
    client.send_frame(
        DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN, ecu_config.vin.encode("ascii"))
    )
    announcement = client.wait_announcement()
    assert announcement.logical_address == ecu_config.logical_address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_by_vin_ignores_other_vehicle(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN, b"X" * 17))
    with pytest.raises(DoIPTimeout):
        client.wait_announcement(timeout=0.3)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Vehicle identification")
def test_identification_with_wrong_vin_length_is_nacked(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN, b"SHORT"))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert (
        int.from_bytes(frame.payload[:2], "big") == PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN
    )
    assert frame.payload[2] == GenericNackCode.INVALID_PAYLOAD_LENGTH


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_routing_activation_is_accepted(client: DoIPClient, ecu_config: EcuConfig) -> None:
    result = client.routing_activation()
    assert result.response_code == RoutingActivationResponseCode.ACCEPTED
    assert result.client_address == client.client_address
    assert result.entity_address == ecu_config.entity_address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_routing_activation_with_oem_specific_data(client: DoIPClient) -> None:
    result = client.routing_activation(oem=b"\x01\x02\x03\x04")
    assert result.accepted


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_duplicate_routing_activation_is_denied(client: DoIPClient) -> None:
    assert client.routing_activation().accepted
    second = client.routing_activation()
    assert second.response_code == RoutingActivationResponseCode.DENIED_SA_ALREADY_REGISTERED


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_second_source_address_on_same_socket_is_denied(client: DoIPClient) -> None:
    assert client.routing_activation().accepted
    client.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, _routing_payload(0x0E01)))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.ROUTING_ACTIVATION_RESPONSE
    assert (
        frame.payload[4] == RoutingActivationResponseCode.DENIED_SA_DIFFERENT_FROM_ALREADY_ACTIVATED
    )


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_zero_source_address_is_denied(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, _routing_payload(0x0000)))
    frame = client.receive_frame()
    assert frame.payload[4] == RoutingActivationResponseCode.DENIED_UNKNOWN_SOURCE_ADDRESS


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_unsupported_activation_type_is_denied(client: DoIPClient) -> None:
    payload = _routing_payload(client.client_address, activation_type=0x07)
    client.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, payload))
    frame = client.receive_frame()
    assert (
        frame.payload[4] == RoutingActivationResponseCode.DENIED_UNSUPPORTED_ROUTING_ACTIVATION_TYPE
    )


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Routing activation")
def test_routing_activation_with_bad_length_is_nacked(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, bytes(6)))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert frame.payload[2] == GenericNackCode.INVALID_PAYLOAD_LENGTH


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic messages")
def test_diagnostic_before_routing_activation_is_nacked(client: DoIPClient) -> None:
    client.send_diagnostic(b"\x10\x03")
    with pytest.raises(DiagnosticRejected) as error:
        client.wait_diagnostic()
    assert error.value.code == DiagnosticNackCode.INVALID_SOURCE_ADDRESS


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic messages")
def test_diagnostic_to_unknown_target_is_nacked(routed_client: DoIPClient) -> None:
    routed_client.send_diagnostic(b"\x10\x03", target=0x1234)
    with pytest.raises(DiagnosticRejected) as error:
        routed_client.wait_diagnostic()
    assert error.value.code == DiagnosticNackCode.UNKNOWN_TARGET_ADDRESS


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic messages")
def test_truncated_diagnostic_message_is_nacked(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, b"\x0e\x00"))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_NACK
    assert frame.payload[4] == DiagnosticNackCode.TRANSPORT_PROTOCOL_ERROR


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Generic NACK")
def test_unknown_payload_type_is_nacked(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(0x1234, b""))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert int.from_bytes(frame.payload[:2], "big") == 0x1234
    assert frame.payload[2] == GenericNackCode.UNKNOWN_PAYLOAD_TYPE


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Generic NACK")
def test_oversized_payload_is_nacked_and_connection_closed(client: DoIPClient) -> None:
    header = struct.pack(">BBHI", 0x02, 0xFD, PayloadType.DIAGNOSTIC_MESSAGE, 0x00FFFFFF)
    client.send_raw(header)
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert frame.payload[2] == GenericNackCode.MESSAGE_TOO_LARGE
    with pytest.raises((DoIPConnectionClosed, DoIPTimeout)):
        client.receive_frame(timeout=0.5)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Header validation")
def test_unsupported_protocol_version_closes_connection(client: DoIPClient) -> None:
    client.send_raw(struct.pack(">BBHI", 0x01, 0xFE, PayloadType.VEHICLE_IDENTIFICATION_REQUEST, 0))
    with pytest.raises((DoIPConnectionClosed, DoIPTimeout)):
        client.receive_frame(timeout=0.5)


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Header validation")
def test_inverse_version_mismatch_gets_nack(client: DoIPClient) -> None:
    client.send_raw(struct.pack(">BBHI", 0x02, 0x00, PayloadType.VEHICLE_IDENTIFICATION_REQUEST, 0))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    assert frame.payload[2] == GenericNackCode.INCORRECT_PATTERN_FORMAT


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Alive check")
def test_alive_check_echoes_source_address(routed_client: DoIPClient) -> None:
    assert routed_client.alive_check() == routed_client.client_address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Entity status")
def test_entity_status_reports_capabilities(client: DoIPClient, ecu_config: EcuConfig) -> None:
    status: EntityStatus = client.entity_status()
    assert status.node_type == 0x01
    assert status.max_concurrent_sockets == ecu_config.max_concurrent_sockets
    assert status.max_data_size == ecu_config.max_data_size
    assert status.open_sockets >= 1


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Power mode")
def test_power_mode_is_ready(client: DoIPClient) -> None:
    client.send_frame(DoIPFrame(PayloadType.POWER_MODE_INFORMATION_REQUEST))
    frame = client.receive_frame()
    assert frame.payload_type == PayloadType.POWER_MODE_INFORMATION_RESPONSE
    assert frame.payload == b"\x01"


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Framing")
def test_two_frames_in_one_tcp_segment(routed_client: DoIPClient) -> None:
    """Sticky packets: two alive checks coalesced into one send()."""
    request = DoIPFrame(PayloadType.ALIVE_CHECK_REQUEST).encode()
    routed_client.send_raw(request + request)
    first = routed_client.receive_frame()
    second = routed_client.receive_frame()
    for frame in (first, second):
        assert frame.payload_type == PayloadType.ALIVE_CHECK_RESPONSE
        assert int.from_bytes(frame.payload, "big") == routed_client.client_address


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Framing")
def test_split_frame_reassembled_from_three_segments(routed_client: DoIPClient) -> None:
    """Split frames: header, partial payload, remainder."""
    frame = DoIPFrame(PayloadType.ENTITY_STATUS_REQUEST).encode()
    for chunk in (frame[:3], frame[3:7], frame[7:]):
        routed_client.send_raw(chunk)
        time.sleep(0.01)
    response = routed_client.receive_frame(timeout=1.0)
    assert response.payload_type == PayloadType.ENTITY_STATUS_RESPONSE


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Framing")
def test_byte_by_byte_transmission(routed_client: DoIPClient) -> None:
    frame = DoIPFrame(PayloadType.POWER_MODE_INFORMATION_REQUEST).encode()
    for byte in frame:
        routed_client.send_raw(bytes([byte]))
    response = routed_client.receive_frame(timeout=1.0)
    assert response.payload_type == PayloadType.POWER_MODE_INFORMATION_RESPONSE


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Resource limits")
def test_fourth_socket_is_denied_when_three_are_active() -> None:
    """A separate ECU instance keeps the assertion independent of other tests."""
    config = default_config(max_concurrent_sockets=3)
    with DoIPServer(config) as server:
        clients = [DoIPClient(port=server.port).connect() for _ in range(4)]
        try:
            for client in clients[:3]:
                assert client.routing_activation().accepted
            denied = clients[3].routing_activation()
            assert (
                denied.response_code == RoutingActivationResponseCode.DENIED_ALL_SOCKETS_REGISTERED
            )
        finally:
            for client in clients:
                client.close()
