"""SOME/IP message header codec (AUTOSAR PRS SOME/IP).

Wire format (16 bytes)::

    Message ID   (4)  service id (2) + method id (2)
    Length       (4)  bytes from Request ID to the end of the payload
    Request ID   (4)  client id (2) + session id (2)
    Protocol Ver (1)
    Interface Ver(1)
    Message Type (1)
    Return Code  (1)
    Payload      (n)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

HEADER_SIZE = 16
_LENGTH_BASE = 8  # request id + protocol/interface version + type + return code


class MessageType(IntEnum):
    """SOME/IP message types."""

    REQUEST = 0x00
    REQUEST_NO_RETURN = 0x01
    NOTIFICATION = 0x02
    RESPONSE = 0x80
    ERROR = 0x81


class ReturnCode(IntEnum):
    """SOME/IP return codes."""

    E_OK = 0x00
    E_NOT_OK = 0x01
    E_UNKNOWN_SERVICE = 0x02
    E_UNKNOWN_METHOD = 0x03
    E_NOT_READY = 0x04
    E_NOT_REACHABLE = 0x05
    E_TIMEOUT = 0x06
    E_WRONG_PROTOCOL_VERSION = 0x07
    E_WRONG_INTERFACE_VERSION = 0x08
    E_MALFORMED_MESSAGE = 0x09
    E_WRONG_MESSAGE_TYPE = 0x0A


class SomeIpError(ValueError):
    """Raised when a buffer is not a valid SOME/IP message."""


@dataclass(frozen=True, slots=True)
class SomeIpMessage:
    """Decoded SOME/IP message."""

    service_id: int
    method_id: int
    client_id: int
    session_id: int
    payload: bytes = b""
    protocol_version: int = 0x01
    interface_version: int = 0x01
    message_type: int = MessageType.REQUEST
    return_code: int = ReturnCode.E_OK

    @property
    def message_id(self) -> int:
        return (self.service_id << 16) | self.method_id

    @property
    def request_id(self) -> int:
        return (self.client_id << 16) | self.session_id

    def encode(self) -> bytes:
        """Serialise the message including the 16 byte header."""
        if not 0 <= self.service_id <= 0xFFFF or not 0 <= self.method_id <= 0xFFFF:
            raise ValueError("service and method id must fit in 16 bits")
        length = _LENGTH_BASE + len(self.payload)
        return (
            struct.pack(
                ">HHIHHBBBB",
                self.service_id,
                self.method_id,
                length,
                self.client_id,
                self.session_id,
                self.protocol_version,
                self.interface_version,
                self.message_type,
                self.return_code,
            )
            + self.payload
        )


def decode(data: bytes) -> SomeIpMessage:
    """Decode one complete SOME/IP message."""
    if len(data) < HEADER_SIZE:
        raise SomeIpError(f"need at least {HEADER_SIZE} bytes, got {len(data)}")

    service_id, method_id, length, client_id, session_id, proto, iface, msg_type, ret = (
        struct.unpack_from(">HHIHHBBBB", data)
    )
    if length < _LENGTH_BASE:
        raise SomeIpError(f"invalid length field {length}")
    total = 8 + length  # length counts from the request id to the end
    if len(data) < total:
        raise SomeIpError(f"truncated message: need {total} bytes, got {len(data)}")

    return SomeIpMessage(
        service_id=service_id,
        method_id=method_id,
        client_id=client_id,
        session_id=session_id,
        payload=data[HEADER_SIZE:total],
        protocol_version=proto,
        interface_version=iface,
        message_type=msg_type,
        return_code=ret,
    )


def response_for(
    request: SomeIpMessage, payload: bytes = b"", return_code: int = ReturnCode.E_OK
) -> SomeIpMessage:
    """Build a RESPONSE that echoes the request id of ``request``."""
    return SomeIpMessage(
        service_id=request.service_id,
        method_id=request.method_id,
        client_id=request.client_id,
        session_id=request.session_id,
        payload=payload,
        protocol_version=request.protocol_version,
        interface_version=request.interface_version,
        message_type=MessageType.RESPONSE,
        return_code=return_code,
    )


def error_for(request: SomeIpMessage, return_code: int) -> SomeIpMessage:
    """Build an ERROR message for ``request``."""
    return SomeIpMessage(
        service_id=request.service_id,
        method_id=request.method_id,
        client_id=request.client_id,
        session_id=request.session_id,
        payload=b"",
        protocol_version=request.protocol_version,
        interface_version=request.interface_version,
        message_type=MessageType.ERROR,
        return_code=return_code,
    )
