"""DoIP frame codec (ISO 13400-2, section 7).

The encoder is deliberately strict: a frame that cannot be represented on the
wire raises instead of silently producing a malformed packet.  The decoder is
split in two layers:

``decode_frame``
    Decodes exactly one complete frame.  Used by unit tests and by tools that
    already own the framing.

``DoIPFrameParser``
    Incremental parser for TCP streams.  It tolerates arbitrary segmentation
    ("split frames") and coalescing ("sticky packets"), which is the number one
    source of flakiness in DoIP test benches.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .constants import DEFAULT_MAX_PAYLOAD_SIZE, DOIP_HEADER_SIZE, PROTOCOL_VERSION

_HEADER = struct.Struct(">BBHI")


class ProtocolError(Exception):
    """Base class for framing errors.

    ``payload_type`` is set when the header was decoded far enough to know which
    payload the entity should nack.  ``send_nack`` tells the server whether a
    generic negative acknowledgement is meaningful before closing the socket.
    """

    def __init__(
        self,
        message: str,
        *,
        payload_type: int | None = None,
        nack_code: int | None = None,
        send_nack: bool = False,
    ) -> None:
        super().__init__(message)
        self.payload_type = payload_type
        self.nack_code = nack_code
        self.send_nack = send_nack


class InvalidProtocolVersion(ProtocolError):
    """The protocol version is not supported by the entity (socket is closed)."""


class IncorrectPatternFormat(ProtocolError):
    """Version and inverse version do not complement each other."""


class MessageTooLarge(ProtocolError):
    """The announced payload length exceeds the configured limit."""


class IncompleteFrame(ProtocolError):
    """Not enough bytes for a complete frame (raised by ``decode_frame`` only)."""


@dataclass(frozen=True, slots=True)
class DoIPFrame:
    """A single DoIP frame."""

    payload_type: int
    payload: bytes = b""
    protocol_version: int = PROTOCOL_VERSION

    def encode(self) -> bytes:
        """Serialise the frame including the 8 byte header."""
        if not 0 <= self.payload_type <= 0xFFFF:
            raise ValueError(f"payload type out of range: {self.payload_type!r}")
        if len(self.payload) > 0xFFFFFFFF:
            raise ValueError("payload exceeds the 32 bit length field")
        header = _HEADER.pack(
            self.protocol_version,
            (~self.protocol_version) & 0xFF,
            self.payload_type,
            len(self.payload),
        )
        return header + self.payload

    def to_hex(self) -> str:
        """Return the frame as space separated upper-case hex (for logs)."""
        return self.encode().hex(" ").upper()


def _read_header(data: bytes | bytearray, offset: int = 0) -> tuple[int, int, int]:
    version, inverse, payload_type, length = _HEADER.unpack_from(data, offset)
    if version != PROTOCOL_VERSION:
        raise InvalidProtocolVersion(
            f"unsupported DoIP protocol version 0x{version:02X}",
            payload_type=payload_type,
        )
    if (version ^ inverse) != 0xFF:
        raise IncorrectPatternFormat(
            f"version 0x{version:02X} / inverse 0x{inverse:02X} do not complement",
            payload_type=payload_type,
            nack_code=0x00,
            send_nack=True,
        )
    return payload_type, length, version


def decode_frame(
    data: bytes | bytearray,
    *,
    max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE,
) -> DoIPFrame:
    """Decode exactly one frame from ``data``.

    Raises :class:`IncompleteFrame` when the buffer is shorter than the header
    announces, and :class:`MessageTooLarge` when the announced length exceeds
    ``max_payload_size``.
    """
    if len(data) < DOIP_HEADER_SIZE:
        raise IncompleteFrame(f"need {DOIP_HEADER_SIZE} header bytes, got {len(data)}")

    payload_type, length, version = _read_header(data)
    if length > max_payload_size:
        raise MessageTooLarge(
            f"payload length {length} exceeds limit {max_payload_size}",
            payload_type=payload_type,
            nack_code=0x02,
            send_nack=True,
        )
    end = DOIP_HEADER_SIZE + length
    if len(data) < end:
        raise IncompleteFrame(f"need {end} bytes, got {len(data)}")
    return DoIPFrame(payload_type, bytes(data[DOIP_HEADER_SIZE:end]), version)


@dataclass
class DoIPFrameParser:
    """Incremental DoIP frame parser for a byte stream.

    Feed every ``recv()`` chunk into :meth:`feed`; complete frames are returned
    in order.  Partial frames stay in the buffer until the rest arrives, so the
    parser is agnostic to TCP segmentation.
    """

    max_payload_size: int = DEFAULT_MAX_PAYLOAD_SIZE
    _buffer: bytearray = field(default_factory=bytearray, repr=False)

    @property
    def buffered_bytes(self) -> int:
        """Number of bytes waiting for the remainder of their frame."""
        return len(self._buffer)

    def reset(self) -> None:
        """Drop any partial frame (used when a socket is reused)."""
        self._buffer.clear()

    def feed(self, data: bytes | bytearray) -> list[DoIPFrame]:
        """Consume ``data`` and return all frames that became complete."""
        if data:
            self._buffer.extend(data)

        frames: list[DoIPFrame] = []
        while len(self._buffer) >= DOIP_HEADER_SIZE:
            payload_type, length, version = _read_header(self._buffer)

            if length > self.max_payload_size:
                raise MessageTooLarge(
                    f"payload length {length} exceeds limit {self.max_payload_size}",
                    payload_type=payload_type,
                    nack_code=0x02,
                    send_nack=True,
                )

            end = DOIP_HEADER_SIZE + length
            if len(self._buffer) < end:
                break

            payload = bytes(self._buffer[DOIP_HEADER_SIZE:end])
            del self._buffer[:end]
            frames.append(DoIPFrame(payload_type, payload, version))

        return frames
