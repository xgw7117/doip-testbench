"""End-to-end diagnostic flows.

These tests exercise the bench the way a real tester would: routing activation,
session handling, security access, a write/read closed loop, DTC retrieval and
an interoperability check with ``udsoncan``.
"""

from __future__ import annotations

import time

import pytest
from udsoncan import AsciiCodec, configs
from udsoncan.client import Client
from udsoncan.exceptions import NegativeResponseException

from doipbench.config import EcuConfig
from doipbench.doip import DoIPClient, DoIPServer, DoIPTimeout
from doipbench.uds import Session, compute_key
from doipbench.uds.udsoncan_connector import DoIPConnection

pytestmark = pytest.mark.functional

VIN_DID = 0xF190
CONFIG_DID = 0x0100
VALUE = bytes.fromhex("11 22 33 44 55 66 77 88")


def test_write_then_read_back_then_read_dtcs(unlocked_client: DoIPClient) -> None:
    assert unlocked_client.request_uds(b"\x2e\x01\x00" + VALUE) == b"\x6e\x01\x00"
    assert unlocked_client.request_uds(b"\x22\x01\x00") == b"\x62\x01\x00" + VALUE

    dtcs = unlocked_client.request_uds(b"\x19\x02\xff")
    assert dtcs.startswith(b"\x59\x02\xff")
    assert len(dtcs[3:]) % 4 == 0


def test_vin_is_stable_across_sessions(extended_client: DoIPClient, ecu_config: EcuConfig) -> None:
    response = extended_client.request_uds(bytes([0x22, VIN_DID >> 8, VIN_DID & 0xFF]))
    assert response[3:] == ecu_config.vin.encode("ascii")


def test_session_change_locks_security_again(unlocked_client: DoIPClient) -> None:
    assert unlocked_client.request_uds(b"\x2e\x01\x00" + VALUE)[0] == 0x6E

    unlocked_client.change_session(Session.DEFAULT)
    unlocked_client.change_session(Session.EXTENDED)

    rejected = unlocked_client.request_uds(b"\x2e\x01\x00" + VALUE)
    assert rejected == bytes.fromhex("7F 2E 33")


def test_s3_timeout_drops_back_to_default_session() -> None:
    from doipbench.config import default_config

    with DoIPServer(default_config(s3_ms=300)) as server:
        client = DoIPClient(port=server.port, timeout=2.0).connect()
        try:
            assert client.routing_activation().accepted
            assert client.change_session(Session.EXTENDED)[:2] == b"\x50\x03"
            time.sleep(0.45)  # longer than the 300 ms S3 timer
            assert client.request_uds(b"\x22\xf1\x86") == b"\x62\xf1\x86\x01"
        finally:
            client.close()


def test_security_lockout_expires(ecu_server: DoIPServer) -> None:
    client = DoIPClient(port=ecu_server.port, timeout=2.0).connect()
    try:
        client.routing_activation()
        client.change_session(Session.EXTENDED)

        for _ in range(3):
            client.request_uds(b"\x27\x01")
            client.request_uds(b"\x27\x02\xde\xad\xbe\xef")

        assert client.request_uds(b"\x27\x01") == bytes.fromhex("7F 27 37")
        time.sleep(0.6)
        assert client.request_uds(b"\x27\x01")[0] == 0x67
    finally:
        client.close()


def test_two_testers_keep_independent_sessions() -> None:
    from doipbench.config import default_config

    with DoIPServer(default_config()) as server:
        first = DoIPClient(port=server.port, client_address=0x0E00).connect()
        second = DoIPClient(port=server.port, client_address=0x0E01).connect()
        try:
            assert first.routing_activation().accepted
            assert second.routing_activation().accepted

            first.change_session(Session.EXTENDED)
            assert first.request_uds(b"\x22\xf1\x86") == b"\x62\xf1\x86\x03"
            assert second.request_uds(b"\x22\xf1\x86") == b"\x62\xf1\x86\x01"
        finally:
            first.close()
            second.close()


def test_suppressed_response_does_not_desynchronise_the_stream(
    extended_client: DoIPClient,
) -> None:
    with pytest.raises(DoIPTimeout):
        extended_client.request_uds(b"\x3e\x80", timeout=0.25)
    assert extended_client.request_uds(b"\x3e\x00") == b"\x7e\x00"


def test_p2_response_time_is_within_budget(routed_client: DoIPClient) -> None:
    started = time.perf_counter()
    response = routed_client.change_session(Session.EXTENDED)
    elapsed = time.perf_counter() - started

    assert response[2:4] == (50).to_bytes(2, "big")
    assert response[4:6] == (500).to_bytes(2, "big")
    assert elapsed < 0.5, f"session change took {elapsed * 1000:.0f} ms"


def test_udsoncan_client_interoperability(ecu_server: DoIPServer, ecu_config: EcuConfig) -> None:
    transport = DoIPClient(port=ecu_server.port, timeout=2.0).connect()
    assert transport.routing_activation().accepted

    client_config = dict(configs.default_client_config)
    client_config["p2_timeout"] = 2.0
    client_config["p2_star_timeout"] = 5.0
    client_config["data_identifiers"] = {VIN_DID: AsciiCodec(17)}

    with Client(DoIPConnection(transport), config=client_config) as client:
        session = client.change_session(Session.EXTENDED)
        assert session.positive

        vin = client.read_data_by_identifier(VIN_DID)
        assert vin.service_data.values[VIN_DID] == ecu_config.vin

        with pytest.raises(NegativeResponseException) as error:
            client.change_session(0x05)
        assert error.value.response.code == 0x12


def test_unlock_requires_a_fresh_seed_per_attempt(
    extended_client: DoIPClient, ecu_config: EcuConfig
) -> None:
    first_seed = extended_client.request_uds(b"\x27\x01")[2:]
    second_seed = extended_client.request_uds(b"\x27\x01")[2:]
    assert first_seed != second_seed

    key = compute_key(second_seed, ecu_config.security.secret)
    assert extended_client.request_uds(b"\x27\x02" + key) == b"\x67\x02"
    assert extended_client.request_uds(b"\x27\x01") == b"\x67\x01" + bytes(4)
