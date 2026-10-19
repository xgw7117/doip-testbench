"""Unit tests for the SOME/IP header and service discovery codec."""

from __future__ import annotations

import pytest

from doipbench.someip import (
    MessageType,
    ReturnCode,
    SdEntryType,
    SdError,
    SdOptionType,
    SomeIpError,
    SomeIpMessage,
    build_offer,
    decode,
    decode_sd,
    error_for,
    response_for,
)

pytestmark = pytest.mark.unit


def test_header_roundtrip() -> None:
    message = SomeIpMessage(
        service_id=0x1234,
        method_id=0x0001,
        client_id=0x0001,
        session_id=0x0002,
        payload=b"\xde\xad\xbe\xef",
        interface_version=0x02,
    )
    decoded = decode(message.encode())
    assert decoded == message


def test_header_layout_matches_autosar() -> None:
    message = SomeIpMessage(0x1234, 0x5678, 0x0001, 0x0002, b"\xaa")
    encoded = message.encode()
    assert encoded[:4] == bytes.fromhex("12 34 56 78")
    assert int.from_bytes(encoded[4:8], "big") == 9  # 8 + 1 payload byte
    assert encoded[8:12] == bytes.fromhex("00 01 00 02")
    assert encoded[12:16] == bytes.fromhex("01 01 00 00")


def test_length_field_excludes_header_prefix() -> None:
    message = SomeIpMessage(0x0001, 0x0001, 1, 1, bytes(100))
    assert int.from_bytes(message.encode()[4:8], "big") == 108


def test_truncated_message_is_rejected() -> None:
    with pytest.raises(SomeIpError):
        decode(b"\x00" * 12)


def test_payload_shorter_than_length_is_rejected() -> None:
    encoded = SomeIpMessage(0x0001, 0x0001, 1, 1, bytes(10)).encode()
    with pytest.raises(SomeIpError):
        decode(encoded[:-2])


def test_response_echoes_request_id() -> None:
    request = SomeIpMessage(0x1234, 0x0001, 0x00AA, 0x0007, b"\x01")
    response = response_for(request, b"\x02\x03")
    assert response.message_type == MessageType.RESPONSE
    assert response.client_id == 0x00AA
    assert response.session_id == 0x0007
    assert response.payload == b"\x02\x03"


def test_error_carries_return_code() -> None:
    request = SomeIpMessage(0x1234, 0x0001, 1, 1)
    error = error_for(request, ReturnCode.E_UNKNOWN_METHOD)
    assert error.message_type == MessageType.ERROR
    assert error.return_code == ReturnCode.E_UNKNOWN_METHOD


def test_encode_rejects_oversized_ids() -> None:
    with pytest.raises(ValueError):
        SomeIpMessage(0x1FFFF, 0, 0, 0).encode()


def test_offer_service_roundtrip() -> None:
    offer = build_offer(0x1234, 0x0001, "192.168.1.10", 30509, ttl=5)
    encoded = offer.encode()
    decoded = decode(encoded)

    assert decoded.service_id == 0xFFFF
    assert decoded.method_id == 0x8001
    assert decoded.message_type == MessageType.NOTIFICATION

    sd = decode_sd(decoded.payload)
    assert len(sd.entries) == 1
    entry = sd.entries[0]
    assert entry.entry_type == SdEntryType.OFFER_SERVICE
    assert entry.service_id == 0x1234
    assert entry.instance_id == 0x0001
    assert entry.ttl == 5
    assert entry.options[0].option_type == SdOptionType.IPV4_ENDPOINT
    assert entry.options[0].ipv4_endpoint == ("192.168.1.10", 0x11, 30509)


def test_sd_rejects_truncated_option() -> None:
    payload = bytes([0xC0, 0, 0, 0]) + bytes(16) + bytes.fromhex("00 20 04") + b"\x00"
    with pytest.raises(SdError):
        decode_sd(payload)


def test_sd_empty_payload_is_rejected() -> None:
    with pytest.raises(SdError):
        decode_sd(b"\xc0")
