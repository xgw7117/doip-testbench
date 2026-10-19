"""Unit tests for VLAN tagging and gPTP header parsing."""

from __future__ import annotations

import pytest

from doipbench.net import (
    ETHERTYPE_GPTP,
    EthernetError,
    GptpError,
    GptpMessageType,
    VlanTag,
    build_frame,
    build_sync,
    decode_gptp,
    parse_ethernet,
)

pytestmark = pytest.mark.unit


def test_vlan_tag_encoding() -> None:
    tag = VlanTag(vid=100, pcp=5, dei=True)
    assert tag.encode() == bytes.fromhex("81 00 B0 64")
    assert tag.tci == 0xB064


def test_vlan_tag_roundtrip_from_tci() -> None:
    tag = VlanTag.from_tci(0xB064)
    assert (tag.vid, tag.pcp, tag.dei) == (100, 5, True)


def test_vlan_id_bounds() -> None:
    with pytest.raises(ValueError):
        VlanTag(vid=4095)


def test_parse_untagged_frame() -> None:
    raw = build_frame(
        destination=bytes.fromhex("001122334455"),
        source=bytes.fromhex("66778899AABB"),
        ethertype=0x0800,
        payload=b"\x45\x00",
    )
    frame = parse_ethernet(raw)
    assert frame.vlan is None
    assert frame.ethertype == 0x0800
    assert frame.payload == b"\x45\x00"


def test_parse_tagged_frame() -> None:
    raw = build_frame(
        destination=bytes.fromhex("0180C200000E"),
        source=bytes.fromhex("001122334455"),
        ethertype=ETHERTYPE_GPTP,
        payload=b"\x00" * 44,
        vlan=VlanTag(vid=20, pcp=6),
    )
    frame = parse_ethernet(raw)
    assert frame.vlan is not None
    assert frame.vlan.vid == 20
    assert frame.vlan.pcp == 6
    assert frame.ethertype == ETHERTYPE_GPTP
    assert len(frame.payload) == 44


def test_truncated_frame_is_rejected() -> None:
    with pytest.raises(EthernetError):
        parse_ethernet(b"\x00" * 10)


def test_truncated_vlan_tag_is_rejected() -> None:
    raw = bytes.fromhex("00112233445566778899AABB8100") + b"\x00"
    with pytest.raises(EthernetError):
        parse_ethernet(raw)


def test_gptp_sync_roundtrip() -> None:
    encoded = build_sync(42, domain=3, seconds=1234, nanoseconds=500)
    message = decode_gptp(encoded)
    assert message.header.message_type == GptpMessageType.SYNC
    assert message.header.domain == 3
    assert message.header.sequence_id == 42
    assert message.header.version == 2
    assert message.header.correction_ns == 0.0
    assert message.body == (1234).to_bytes(6, "big") + (500).to_bytes(4, "big")


def test_gptp_rejects_short_buffer() -> None:
    with pytest.raises(GptpError):
        decode_gptp(b"\x00" * 10)


def test_gptp_rejects_invalid_message_length() -> None:
    encoded = bytearray(build_sync(1))
    encoded[2:4] = (100).to_bytes(2, "big")
    with pytest.raises(GptpError):
        decode_gptp(bytes(encoded))


def test_gptp_over_vlan_end_to_end() -> None:
    frame = build_frame(
        destination=bytes.fromhex("0180C200000E"),
        source=bytes.fromhex("001122334455"),
        ethertype=ETHERTYPE_GPTP,
        payload=build_sync(7, domain=1),
        vlan=VlanTag(vid=30, pcp=7),
    )
    parsed = parse_ethernet(frame)
    message = decode_gptp(parsed.payload)
    assert message.header.sequence_id == 7
    assert message.header.domain == 1
    assert parsed.vlan is not None and parsed.vlan.vid == 30
