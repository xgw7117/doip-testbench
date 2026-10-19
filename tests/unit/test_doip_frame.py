"""Unit tests for the DoIP frame codec and stream parser."""

from __future__ import annotations

import struct

import pytest

from doipbench.doip.constants import GenericNackCode, PayloadType
from doipbench.doip.frame import (
    DoIPFrame,
    DoIPFrameParser,
    IncompleteFrame,
    IncorrectPatternFormat,
    InvalidProtocolVersion,
    MessageTooLarge,
    decode_frame,
)

pytestmark = pytest.mark.unit


def test_encode_produces_the_standard_header() -> None:
    frame = DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST)
    assert frame.encode() == bytes.fromhex("02 FD 00 01 00 00 00 00")


def test_encode_includes_payload_length() -> None:
    frame = DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, b"\x0e\x00\x10\x01\x10\x03")
    encoded = frame.encode()
    assert encoded[:8] == bytes.fromhex("02 FD 80 01 00 00 00 06")
    assert encoded[8:] == b"\x0e\x00\x10\x01\x10\x03"


def test_roundtrip_preserves_fields() -> None:
    original = DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, bytes.fromhex("0E0000000000"))
    decoded = decode_frame(original.encode())
    assert decoded == original


def test_decode_rejects_truncated_header() -> None:
    with pytest.raises(IncompleteFrame):
        decode_frame(b"\x02\xfd\x00")


def test_decode_rejects_truncated_payload() -> None:
    data = DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, bytes(10)).encode()[:-3]
    with pytest.raises(IncompleteFrame):
        decode_frame(data)


def test_decode_rejects_unsupported_version() -> None:
    data = struct.pack(">BBHI", 0x01, 0xFE, 0x0001, 0)
    with pytest.raises(InvalidProtocolVersion):
        decode_frame(data)


def test_decode_rejects_bad_inverse_version() -> None:
    data = struct.pack(">BBHI", 0x02, 0x00, 0x0001, 0)
    with pytest.raises(IncorrectPatternFormat) as error:
        decode_frame(data)
    assert error.value.nack_code == GenericNackCode.INCORRECT_PATTERN_FORMAT
    assert error.value.send_nack is True


def test_decode_rejects_oversized_payload() -> None:
    data = struct.pack(">BBHI", 0x02, 0xFD, 0x8001, 0x00FFFFFF)
    with pytest.raises(MessageTooLarge) as error:
        decode_frame(data, max_payload_size=4096)
    assert error.value.payload_type == 0x8001
    assert error.value.nack_code == GenericNackCode.MESSAGE_TOO_LARGE


def test_parser_returns_two_frames_from_one_chunk() -> None:
    parser = DoIPFrameParser()
    chunk = DoIPFrame(0x0007).encode() + DoIPFrame(0x4003).encode()
    frames = parser.feed(chunk)
    assert [frame.payload_type for frame in frames] == [0x0007, 0x4003]
    assert parser.buffered_bytes == 0


def test_parser_waits_for_split_frame() -> None:
    parser = DoIPFrameParser()
    encoded = DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, bytes(range(20))).encode()

    assert parser.feed(encoded[:5]) == []
    assert parser.buffered_bytes == 5
    assert parser.feed(encoded[5:15]) == []
    frames = parser.feed(encoded[15:])
    assert len(frames) == 1
    assert frames[0].payload == bytes(range(20))


def test_parser_handles_byte_by_byte_input() -> None:
    parser = DoIPFrameParser()
    encoded = DoIPFrame(PayloadType.ALIVE_CHECK_REQUEST).encode()
    frames = []
    for byte in encoded:
        frames.extend(parser.feed(bytes([byte])))
    assert len(frames) == 1
    assert frames[0].payload_type == PayloadType.ALIVE_CHECK_REQUEST


def test_parser_reset_drops_partial_frame() -> None:
    parser = DoIPFrameParser()
    parser.feed(DoIPFrame(PayloadType.ALIVE_CHECK_REQUEST).encode()[:4])
    assert parser.buffered_bytes == 4
    parser.reset()
    assert parser.buffered_bytes == 0


def test_frame_rejects_out_of_range_payload_type() -> None:
    with pytest.raises(ValueError):
        DoIPFrame(0x1FFFF).encode()
