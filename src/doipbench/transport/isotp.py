"""ISO-TP (ISO 15765-2) segmentation and reassembly.

Although the project focuses on Ethernet, most vehicles still route diagnostics
through a CAN gateway.  Being able to explain why ISO-TP exists next to DoIP -
and to implement the four PCI types - is a frequent interview question.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_CLASSIC_FRAME = 8
MAX_CLASSIC_PAYLOAD = 4095


class IsoTpError(ValueError):
    """Raised on malformed or out-of-sequence frames."""


class PciType:
    """Protocol control information types."""

    SINGLE_FRAME = 0x00
    FIRST_FRAME = 0x01
    CONSECUTIVE_FRAME = 0x02
    FLOW_CONTROL = 0x03


class FlowStatus:
    """Flow control status values."""

    CONTINUE_TO_SEND = 0x00
    WAIT = 0x01
    OVERFLOW = 0x02


def pci_type(frame: bytes) -> int:
    """Return the PCI type nibble of a CAN frame."""
    if not frame:
        raise IsoTpError("empty CAN frame")
    return frame[0] >> 4


@dataclass
class IsoTpSegmenter:
    """Split a UDS payload into ISO-TP frames."""

    max_frame_size: int = MAX_CLASSIC_FRAME

    def segment(self, data: bytes) -> list[bytes]:
        """Return the frames needed to transmit ``data``."""
        if not data:
            raise IsoTpError("cannot segment an empty payload")
        if len(data) <= self.max_frame_size - 1:
            return [bytes([len(data)]) + data]
        if len(data) > MAX_CLASSIC_PAYLOAD:
            raise IsoTpError(f"payload of {len(data)} bytes exceeds the 12 bit length field")

        first_chunk = self.max_frame_size - 2
        frames = [
            bytes([0x10 | (len(data) >> 8), len(data) & 0xFF]) + data[:first_chunk],
        ]
        offset = first_chunk
        sequence = 1
        while offset < len(data):
            chunk = data[offset : offset + self.max_frame_size - 1]
            frames.append(bytes([0x20 | (sequence & 0x0F)]) + chunk)
            offset += len(chunk)
            sequence += 1
        return frames


@dataclass
class IsoTpReassembler:
    """Reassemble ISO-TP frames into one UDS payload."""

    max_message_size: int = MAX_CLASSIC_PAYLOAD
    _buffer: bytearray = field(default_factory=bytearray, repr=False)
    _expected_length: int = 0
    _next_sequence: int = 1
    _active: bool = False

    @property
    def in_progress(self) -> bool:
        return self._active

    def reset(self) -> None:
        self._buffer.clear()
        self._expected_length = 0
        self._next_sequence = 1
        self._active = False

    def feed(self, frame: bytes) -> bytes | None:
        """Feed one CAN frame; return the complete payload when it is finished."""
        if not frame:
            raise IsoTpError("empty CAN frame")

        kind = pci_type(frame)
        if kind == PciType.SINGLE_FRAME:
            length = frame[0] & 0x0F
            if length == 0 or len(frame) < 1 + length:
                raise IsoTpError("invalid single frame length")
            return bytes(frame[1 : 1 + length])

        if kind == PciType.FIRST_FRAME:
            if len(frame) < 3:
                raise IsoTpError("first frame is too short")
            length = ((frame[0] & 0x0F) << 8) | frame[1]
            if length < 8 or length > self.max_message_size:
                raise IsoTpError(f"invalid first frame length {length}")
            self.reset()
            self._expected_length = length
            self._buffer.extend(frame[2:])
            self._active = True
            self._next_sequence = 1
            return self._finish_if_complete()

        if kind == PciType.CONSECUTIVE_FRAME:
            if not self._active:
                raise IsoTpError("consecutive frame without a first frame")
            sequence = frame[0] & 0x0F
            if sequence != self._next_sequence:
                raise IsoTpError(f"sequence error: expected {self._next_sequence}, got {sequence}")
            self._next_sequence = (self._next_sequence + 1) & 0x0F
            self._buffer.extend(frame[1:])
            return self._finish_if_complete()

        if kind == PciType.FLOW_CONTROL:
            raise IsoTpError("flow control frames are handled by the sender, not the reassembler")

        raise IsoTpError(f"unknown PCI type 0x{kind:X}")

    def _finish_if_complete(self) -> bytes | None:
        if len(self._buffer) < self._expected_length:
            return None
        payload = bytes(self._buffer[: self._expected_length])
        self.reset()
        return payload


def flow_control(
    status: int = FlowStatus.CONTINUE_TO_SEND, block_size: int = 0, st_min: int = 0
) -> bytes:
    """Build a flow control frame (classic CAN)."""
    return bytes([0x30 | (status & 0x0F), block_size & 0xFF, st_min & 0xFF])
