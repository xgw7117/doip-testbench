"""Unit tests for the UDS server, driven without any socket.

These tests are the fastest way to pin down NRC behaviour: no TCP, no timing,
just request bytes in and response bytes out.
"""

from __future__ import annotations

import pytest

from doipbench.config import SecurityConfig, default_config
from doipbench.uds import NegativeResponseCode as NRC
from doipbench.uds import Session, UdsServer, compute_key


class FakeClock:
    """Controllable monotonic clock."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def server(clock: FakeClock) -> UdsServer:
    config = default_config(s3_ms=1000, security=SecurityConfig(delay_seconds=0.5))
    return UdsServer(config, clock=clock)


def nrc(response: bytes) -> int:
    assert response[0] == 0x7F, response.hex()
    return response[2]


pytestmark = pytest.mark.unit


def test_session_control_encodes_p2_timings(server: UdsServer) -> None:
    response = server.handle(b"\x10\x03")
    assert response[:2] == b"\x50\x03"
    assert int.from_bytes(response[2:4], "big") == server.config.p2_ms
    assert int.from_bytes(response[4:6], "big") == server.config.p2_star_ms // 10


def test_unknown_session_is_rejected(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x10\x09")) == NRC.SUB_FUNCTION_NOT_SUPPORTED


def test_security_access_requires_extended_session(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x27\x01")) == NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION


def test_seed_key_flow_unlocks_the_ecu(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed_response = server.handle(b"\x27\x01")
    assert seed_response[0] == 0x67
    assert len(seed_response) == 2 + server.config.security.seed_length

    key = compute_key(seed_response[2:], server.config.security.secret)
    assert server.handle(b"\x27\x02" + key) == b"\x67\x02"
    assert server.security_level == 1


def test_wrong_key_counts_attempts(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    server.handle(b"\x27\x01")
    assert nrc(server.handle(b"\x27\x02\xde\xad\xbe\xef")) == NRC.INVALID_KEY
    assert server.failed_attempts == 1


def test_three_wrong_keys_lock_the_ecu(server: UdsServer, clock: FakeClock) -> None:
    server.handle(b"\x10\x03")
    for _ in range(3):
        server.handle(b"\x27\x01")
        assert nrc(server.handle(b"\x27\x02\xde\xad\xbe\xef")) == (
            NRC.INVALID_KEY if server.failed_attempts < 3 else NRC.EXCEED_NUMBER_OF_ATTEMPTS
        )
    assert nrc(server.handle(b"\x27\x01")) == NRC.REQUIRED_TIME_DELAY_NOT_EXPIRED

    clock.advance(server.config.security.delay_seconds + 0.1)
    assert server.handle(b"\x27\x01")[0] == 0x67


def test_send_key_without_seed_is_a_sequence_error(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    assert nrc(server.handle(b"\x27\x02\x00\x00\x00\x00")) == NRC.REQUEST_SEQUENCE_ERROR


def test_s3_timeout_returns_to_default_session(server: UdsServer, clock: FakeClock) -> None:
    server.handle(b"\x10\x03")
    assert server.session is Session.EXTENDED
    clock.advance(1.5)
    response = server.handle(b"\x22\xf1\x86")
    assert response == b"\x62\xf1\x86\x01"
    assert server.session is Session.DEFAULT


def test_tester_present_keeps_the_session_alive(server: UdsServer, clock: FakeClock) -> None:
    server.handle(b"\x10\x03")
    clock.advance(0.6)
    assert server.handle(b"\x3e\x00") == b"\x7e\x00"
    clock.advance(0.6)
    assert server.handle(b"\x22\xf1\x86") == b"\x62\xf1\x86\x03"


def test_read_multiple_dids_are_concatenated(server: UdsServer) -> None:
    response = server.handle(b"\x22\xf1\x90\xf1\x87")
    assert response[:3] == b"\x62\xf1\x90"
    assert b"8R0 907 115 A" in response


def test_read_unknown_did_is_rejected(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x22\x12\x34")) == NRC.REQUEST_OUT_OF_RANGE


def test_write_is_rejected_in_default_session(server: UdsServer) -> None:
    response = server.handle(b"\x2e\x01\x00" + bytes(8))
    assert nrc(response) == NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION


def test_write_requires_unlock(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    assert nrc(server.handle(b"\x2e\x01\x00" + bytes(8))) == NRC.SECURITY_ACCESS_DENIED


def test_write_read_closed_loop(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))

    value = bytes.fromhex("11 22 33 44 55 66 77 88")
    assert server.handle(b"\x2e\x01\x00" + value) == b"\x6e\x01\x00"
    assert server.handle(b"\x22\x01\x00") == b"\x62\x01\x00" + value


def test_write_with_wrong_length_is_rejected(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))
    assert nrc(server.handle(b"\x2e\x01\x00\x00")) == NRC.INCORRECT_MESSAGE_LENGTH


def test_write_to_read_only_did_is_rejected(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))
    assert nrc(server.handle(b"\x2e\xf1\x90" + b"X" * 17)) == NRC.REQUEST_OUT_OF_RANGE


def test_dtc_count_and_listing(server: UdsServer) -> None:
    assert server.handle(b"\x19\x01\xff") == b"\x59\x01\xff\x01\x00\x03"
    listing = server.handle(b"\x19\x02\xff")
    assert listing[:4] == b"\x59\x02\xff\xc1"


def test_dtc_mask_filters_pending_only(server: UdsServer) -> None:
    listing = server.handle(b"\x19\x02\x04")
    assert listing == b"\x59\x02\x04\xc1\x23\x87\x04"


def test_dtc_snapshot_contains_vin(server: UdsServer) -> None:
    response = server.handle(b"\x19\x04\xc1\x23\x45\x01")
    assert response[:6] == b"\x59\x04\xc1\x23\x45\x09"
    assert server.config.vin.encode("ascii") in response


def test_dtc_unknown_record_is_out_of_range(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x19\x04\xc1\x23\x45\x09")) == NRC.REQUEST_OUT_OF_RANGE


def test_unsupported_service(server: UdsServer) -> None:
    assert nrc(server.handle(b"\x31\x01\x02\x03")) == NRC.SERVICE_NOT_SUPPORTED


def test_suppress_positive_response(server: UdsServer) -> None:
    assert server.handle(b"\x10\x83") == b""
    assert server.session is Session.EXTENDED


def test_reset_restores_factory_state(server: UdsServer) -> None:
    server.handle(b"\x10\x03")
    seed = server.handle(b"\x27\x01")[2:]
    server.handle(b"\x27\x02" + compute_key(seed, server.config.security.secret))
    server.handle(b"\x2e\x01\x00" + bytes(8))

    server.reset()
    assert server.session is Session.DEFAULT
    assert server.security_level == 0
    assert server.handle(b"\x22\x01\x00") == b"\x62\x01\x00" + bytes(8)
