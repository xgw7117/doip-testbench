"""IEEE 802.1AS (gPTP) message header codec.

gPTP is the clock synchronisation profile used by TSN.  A test bench needs to
recognise at least Sync, Follow_Up, Announce and the peer delay messages, and to
read the domain and sequence id so that a capture can be correlated with a test
step.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

GPTP_ETHERTYPE = 0x88F7
GPTP_MULTICAST = bytes.fromhex("0180C200000E")
GPTP_HEADER_SIZE = 34

_HEADER = struct.Struct(">BBHBBHqI10sHBB")


class GptpMessageType(IntEnum):
    """Message types of IEEE 1588 / 802.1AS."""

    SYNC = 0x00
    DELAY_REQ = 0x01
    PDELAY_REQ = 0x02
    PDELAY_RESP = 0x03
    FOLLOW_UP = 0x08
    PDELAY_RESP_FOLLOW_UP = 0x0A
    ANNOUNCE = 0x0B


class GptpError(ValueError):
    """Raised when a gPTP frame is malformed."""


@dataclass(frozen=True, slots=True)
class GptpHeader:
    """34 byte common PTP header."""

    message_type: int
    version: int = 2
    domain: int = 0
    flags: int = 0
    correction_field: int = 0
    source_port_identity: bytes = bytes(10)
    sequence_id: int = 0
    control_field: int = 0
    log_message_interval: int = 0
    transport_specific: int = 0

    @property
    def correction_ns(self) -> float:
        """Correction field converted to nanoseconds (unit is 2^-16 ns)."""
        return self.correction_field / 65536.0


@dataclass(frozen=True, slots=True)
class GptpMessage:
    """Decoded gPTP message."""

    header: GptpHeader
    body: bytes = b""

    def encode(self) -> bytes:
        total = GPTP_HEADER_SIZE + len(self.body)
        type_byte = ((self.header.transport_specific & 0x0F) << 4) | (
            self.header.message_type & 0x0F
        )
        return (
            _HEADER.pack(
                type_byte,
                self.header.version,
                total,
                self.header.domain,
                0,
                self.header.flags,
                self.header.correction_field,
                0,
                self.header.source_port_identity,
                self.header.sequence_id,
                self.header.control_field,
                self.header.log_message_interval,
            )
            + self.body
        )


def decode_gptp(data: bytes) -> GptpMessage:
    """Decode a gPTP message (Ethernet payload, without the Ethernet header)."""
    if len(data) < GPTP_HEADER_SIZE:
        raise GptpError(f"gPTP header needs {GPTP_HEADER_SIZE} bytes, got {len(data)}")

    (
        type_byte,
        version,
        message_length,
        domain,
        _reserved,
        flags,
        correction,
        _reserved2,
        port_identity,
        sequence_id,
        control,
        log_interval,
    ) = _HEADER.unpack_from(data)

    if message_length < GPTP_HEADER_SIZE or message_length > len(data):
        raise GptpError(f"invalid messageLength {message_length} for {len(data)} bytes")

    header = GptpHeader(
        message_type=type_byte & 0x0F,
        transport_specific=(type_byte >> 4) & 0x0F,
        version=version,
        domain=domain,
        flags=flags,
        correction_field=correction,
        source_port_identity=port_identity,
        sequence_id=sequence_id,
        control_field=control,
        log_message_interval=log_interval,
    )
    return GptpMessage(header=header, body=data[GPTP_HEADER_SIZE:message_length])


def build_sync(
    sequence_id: int, *, domain: int = 0, seconds: int = 0, nanoseconds: int = 0
) -> bytes:
    """Build a Sync message with a 10 byte origin timestamp body."""
    header = GptpHeader(message_type=GptpMessageType.SYNC, domain=domain, sequence_id=sequence_id)
    body = seconds.to_bytes(6, "big") + nanoseconds.to_bytes(4, "big")
    return GptpMessage(header=header, body=body).encode()
