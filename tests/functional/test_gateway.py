"""Gateway routing behaviour."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from doipbench.config import default_config
from doipbench.doip import DiagnosticRejected, DoIPClient, DoIPFrame, DoIPServer
from doipbench.doip.constants import PayloadType

pytestmark = pytest.mark.functional

GATEWAY = 0x1001
ECU_A = 0x1010
UNKNOWN = 0x9999

VIN_REQUEST = b"\x22\xf1\x90"
VIN_PREFIX = b"\x62\xf1\x90"


@pytest.fixture
def gateway() -> Iterator[DoIPServer]:
    config = default_config(routing_table={GATEWAY: "gateway", ECU_A: "ecu_a"})
    server = DoIPServer(config, port=0).start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def gateway_client(gateway: DoIPServer) -> Iterator[DoIPClient]:
    client = DoIPClient(port=gateway.port, timeout=2.0).connect()
    try:
        assert client.routing_activation().accepted
        yield client
    finally:
        client.close()


def test_gateway_answers_its_own_address(gateway_client: DoIPClient) -> None:
    """TA equals the gateway address: the gateway handles it itself."""
    gateway_client.send_diagnostic(VIN_REQUEST, target=GATEWAY)
    assert gateway_client.wait_diagnostic().startswith(VIN_PREFIX)


def test_gateway_routes_to_attached_ecu(gateway_client: DoIPClient) -> None:
    """TA equals an attached ECU: the response must come back from that ECU."""
    payload = (
        gateway_client.client_address.to_bytes(2, "big") + ECU_A.to_bytes(2, "big") + VIN_REQUEST
    )
    gateway_client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, payload))

    ack = gateway_client.receive_frame()
    assert ack.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_ACK
    assert int.from_bytes(ack.payload[0:2], "big") == GATEWAY

    frame = gateway_client.receive_frame()

    assert int.from_bytes(frame.payload[0:2], "big") == ECU_A
    assert int.from_bytes(frame.payload[2:4], "big") == gateway_client.client_address
    assert frame.payload[4:].startswith(VIN_PREFIX)


def test_gateway_rejects_unknown_target(gateway_client: DoIPClient) -> None:
    """TA is not in the routing table: the request never reaches UDS."""
    gateway_client.send_diagnostic(VIN_REQUEST, target=UNKNOWN)
    with pytest.raises(DiagnosticRejected) as excinfo:
        gateway_client.wait_diagnostic()
    assert excinfo.value.code == 0x03  # ISO Table 26: unknown target address


def test_one_activation_covers_every_address(gateway_client: DoIPClient) -> None:
    """Routing activation is per connection, not per target address."""
    for target in (GATEWAY, ECU_A):
        gateway_client.send_diagnostic(VIN_REQUEST, target=target)
        assert gateway_client.wait_diagnostic().startswith(VIN_PREFIX)


def test_functional_request_switches_every_ecu(gateway_client: DoIPClient) -> None:
    """A functional ``10 03`` must move *every* ECU into the extended session.

    Only one response comes back -- two ECUs answering into the same socket
    would collide -- so the state change can only be observed by unicasting to
    each address afterwards.  This is exactly what a ``break`` placed inside
    the dispatch loop breaks: the first ECU switches, the rest stay in the
    default session, and the tester still sees a positive ``50 03``.
    """
    gateway_client.send_diagnostic(b"\x10\x03", target=0xE400)
    functional_response = gateway_client.wait_diagnostic()
    assert functional_response[:2] == b"\x50\x03"

    for target in (GATEWAY, ECU_A):
        gateway_client.send_diagnostic(b"\x27\x01", target=target)
        seed = gateway_client.wait_diagnostic()
        # 默认会话里 27 01 是 7F 27 7F；只有真的进了扩展会话才会给种子。
        assert seed[0] == 0x67, f"0x{target:04X} 仍在默认会话: {seed.hex(' ')}"
