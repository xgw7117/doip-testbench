"""DoIP over UDP 13400 (ISO 13400-2 §7.2).

Only a handful of payload types belong on UDP: the three vehicle
identification requests, entity status and power mode. They exist on UDP
because the tester sends them before it knows the ECU's IP address, so they
have to survive a broadcast.

Everything else - routing activation, diagnostic messages, alive check - is
bound to a TCP connection. Sending those on UDP has to be refused with a
generic NACK, and that distinction is what most of these tests are about.
"""

from __future__ import annotations

import socket

import allure
import pytest

from doipbench.config import EcuConfig, default_config
from doipbench.doip import DoIPFrame, DoIPServer
from doipbench.doip.constants import GenericNackCode, PayloadType
from doipbench.doip.frame import decode_frame

UDP_PORT = 13400  # only used as documentation; the fixture binds an ephemeral port

pytestmark = pytest.mark.conformance


def exchange(port: int, data: bytes, timeout: float = 1.0) -> bytes | None:
    """Send one datagram and return the reply, or ``None`` when nothing came back."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(data, ("127.0.0.1", port))
        try:
            return sock.recvfrom(65535)[0]
        except TimeoutError:
            return None


def nack_code(reply: bytes) -> tuple[int, int]:
    """Return ``(quoted payload type, NACK code)`` of a 0x0000 frame."""
    frame = decode_frame(reply)
    assert frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK
    return int.from_bytes(frame.payload[0:2], "big"), frame.payload[2]


@allure.feature("DoIP over UDP")
def test_vehicle_identification_over_udp_returns_announcement(
    ecu_server: DoIPServer, ecu_config: EcuConfig
) -> None:
    reply = exchange(
        ecu_server.port, DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST).encode()
    )
    assert reply is not None, "ECU did not answer the identification request on UDP"

    frame = decode_frame(reply)
    assert frame.payload_type == PayloadType.VEHICLE_ANNOUNCEMENT
    assert len(frame.payload) == 32
    assert frame.payload[:17].decode("ascii") == ecu_config.vin
    assert int.from_bytes(frame.payload[17:19], "big") == ecu_config.logical_address
    assert frame.payload[19:25] == ecu_config.eid
    assert frame.payload[25:31] == ecu_config.gid
    assert frame.payload[31] == 0x10  # further action: routing activation required


@allure.feature("DoIP over UDP")
def test_identification_by_vin_only_answers_its_own_vin(
    ecu_server: DoIPServer, ecu_config: EcuConfig
) -> None:
    wrong = DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN, b"WVWZZZ1JZXW000001").encode()
    assert exchange(ecu_server.port, wrong, timeout=0.3) is None

    right = DoIPFrame(
        PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN, ecu_config.vin.encode("ascii")
    ).encode()
    reply = exchange(ecu_server.port, right)
    assert reply is not None
    assert decode_frame(reply).payload_type == PayloadType.VEHICLE_ANNOUNCEMENT


@allure.feature("DoIP over UDP")
def test_identification_by_eid_only_answers_its_own_eid(
    ecu_server: DoIPServer, ecu_config: EcuConfig
) -> None:
    assert (
        exchange(
            ecu_server.port,
            DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID, bytes(6)).encode(),
            timeout=0.3,
        )
        is None
    )

    reply = exchange(
        ecu_server.port,
        DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID, ecu_config.eid).encode(),
    )
    assert reply is not None
    assert decode_frame(reply).payload_type == PayloadType.VEHICLE_ANNOUNCEMENT


@allure.feature("DoIP over UDP")
def test_entity_status_over_udp(ecu_server: DoIPServer, ecu_config: EcuConfig) -> None:
    reply = exchange(ecu_server.port, DoIPFrame(PayloadType.ENTITY_STATUS_REQUEST).encode())
    assert reply is not None

    frame = decode_frame(reply)
    assert frame.payload_type == PayloadType.ENTITY_STATUS_RESPONSE
    assert len(frame.payload) == 7
    assert frame.payload[0] == 0x01  # node type: not a gateway
    assert frame.payload[1] == ecu_config.max_concurrent_sockets
    assert int.from_bytes(frame.payload[3:7], "big") == ecu_config.max_data_size


@allure.feature("DoIP over UDP")
def test_power_mode_over_udp(ecu_server: DoIPServer) -> None:
    reply = exchange(
        ecu_server.port, DoIPFrame(PayloadType.POWER_MODE_INFORMATION_REQUEST).encode()
    )
    assert reply is not None

    frame = decode_frame(reply)
    assert frame.payload_type == PayloadType.POWER_MODE_INFORMATION_RESPONSE
    assert frame.payload == b"\x01"  # ready


@allure.feature("DoIP over UDP")
@pytest.mark.parametrize(
    "payload_type",
    [
        PayloadType.ROUTING_ACTIVATION_REQUEST,
        PayloadType.DIAGNOSTIC_MESSAGE,
        PayloadType.ALIVE_CHECK_REQUEST,
    ],
)
def test_connection_bound_payload_types_are_refused_on_udp(
    ecu_server: DoIPServer, payload_type: int
) -> None:
    """Routing activation, diagnostics and alive check need a socket, not a datagram."""
    reply = exchange(ecu_server.port, DoIPFrame(payload_type, bytes(6)).encode())
    assert reply is not None, "expected a generic NACK instead of silence"

    quoted, code = nack_code(reply)
    assert quoted == payload_type, "the NACK must quote the offending payload type"
    assert code == GenericNackCode.UNKNOWN_PAYLOAD_TYPE


@allure.feature("DoIP over UDP")
def test_truncated_datagram_is_dropped_without_nack(ecu_server: DoIPServer) -> None:
    """A datagram shorter than the header announces has no payload type to quote."""
    header_only = bytes.fromhex("02 FD 00 01 00 00 00 10")  # announces 16 bytes, sends none
    assert exchange(ecu_server.port, header_only, timeout=0.3) is None


@allure.feature("DoIP over UDP")
def test_identification_with_extra_payload_is_rejected(ecu_server: DoIPServer) -> None:
    reply = exchange(
        ecu_server.port,
        DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST, b"\x00\x01").encode(),
    )
    assert reply is not None

    quoted, code = nack_code(reply)
    assert quoted == PayloadType.VEHICLE_IDENTIFICATION_REQUEST
    assert code == GenericNackCode.INVALID_PAYLOAD_LENGTH


def test_udp_endpoint_works_when_bound_to_wildcard_address() -> None:
    """绑 0.0.0.0 时 UDP 端点仍要能收发。

    生产环境必须绑通配地址才收得到广播，而绑 127.0.0.1 的 socket 一个广播包
    都收不到。这里用回环地址发包，验证的是"通配绑定不影响收发"。
    """
    with DoIPServer(default_config(), host="0.0.0.0") as srv:
        assert srv.host == "0.0.0.0"
        reply = exchange(srv.port, DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST).encode())
        assert reply is not None, "wildcard-bound UDP endpoint did not answer"
        assert decode_frame(reply).payload_type == PayloadType.VEHICLE_ANNOUNCEMENT
