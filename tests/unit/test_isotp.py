"""Unit tests for ISO-TP segmentation and reassembly."""

from __future__ import annotations

import pytest

from doipbench.transport import (
    FlowStatus,
    IsoTpError,
    IsoTpReassembler,
    IsoTpSegmenter,
    PciType,
    flow_control,
    pci_type,
)

pytestmark = pytest.mark.unit


def test_single_frame() -> None:
    frames = IsoTpSegmenter().segment(b"\x10\x03")
    assert frames == [bytes.fromhex("02 10 03")]
    assert pci_type(frames[0]) == PciType.SINGLE_FRAME
    assert IsoTpReassembler().feed(frames[0]) == b"\x10\x03"


def test_multi_frame_roundtrip() -> None:
    payload = bytes(range(30))
    frames = IsoTpSegmenter().segment(payload)
    assert len(frames) == 5
    assert pci_type(frames[0]) == PciType.FIRST_FRAME
    assert int.from_bytes(frames[0][:2], "big") & 0x0FFF == 30

    reassembler = IsoTpReassembler()
    result = None
    for frame in frames:
        result = reassembler.feed(frame)
    assert result == payload
    assert not reassembler.in_progress


def test_sequence_number_wraps_after_fifteen_frames() -> None:
    payload = bytes(range(0, 200))
    frames = IsoTpSegmenter().segment(payload)
    assert len(frames) > 16

    reassembler = IsoTpReassembler()
    result = None
    for frame in frames:
        result = reassembler.feed(frame)
    assert result == payload
    assert frames[16][0] & 0x0F == 0  # sequence wrapped 15 -> 0


def test_sequence_error_is_detected() -> None:
    payload = bytes(20)
    frames = IsoTpSegmenter().segment(payload)
    reassembler = IsoTpReassembler()
    assert reassembler.feed(frames[0]) is None
    broken = bytes([0x25]) + frames[1][1:]
    with pytest.raises(IsoTpError):
        reassembler.feed(broken)


def test_consecutive_frame_without_first_frame() -> None:
    with pytest.raises(IsoTpError):
        IsoTpReassembler().feed(bytes.fromhex("21 00 00"))


def test_flow_control_frame() -> None:
    frame = flow_control(FlowStatus.WAIT, block_size=8, st_min=0x0A)
    assert frame == bytes.fromhex("31 08 0A")
    assert pci_type(frame) == PciType.FLOW_CONTROL


def test_empty_payload_is_rejected() -> None:
    with pytest.raises(IsoTpError):
        IsoTpSegmenter().segment(b"")
