"""Constants defined by ISO 13400-2 (DoIP).

Everything in this module is taken from the wire format tables of the standard;
keeping them in one place makes the conformance tests readable and keeps magic
numbers out of the codec.
"""

from __future__ import annotations

from enum import IntEnum


class PayloadType(IntEnum):
    """DoIP payload types (ISO 13400-2, table 3)."""

    GENERIC_NEGATIVE_ACK = 0x0000
    VEHICLE_IDENTIFICATION_REQUEST = 0x0001
    VEHICLE_IDENTIFICATION_REQUEST_EID = 0x0002
    VEHICLE_IDENTIFICATION_REQUEST_VIN = 0x0003
    VEHICLE_ANNOUNCEMENT = 0x0004
    ROUTING_ACTIVATION_REQUEST = 0x0005
    ROUTING_ACTIVATION_RESPONSE = 0x0006
    ALIVE_CHECK_REQUEST = 0x0007
    ALIVE_CHECK_RESPONSE = 0x0008
    ENTITY_STATUS_REQUEST = 0x4001
    ENTITY_STATUS_RESPONSE = 0x4002
    POWER_MODE_INFORMATION_REQUEST = 0x4003
    POWER_MODE_INFORMATION_RESPONSE = 0x4004
    DIAGNOSTIC_MESSAGE = 0x8001
    DIAGNOSTIC_MESSAGE_ACK = 0x8002
    DIAGNOSTIC_MESSAGE_NACK = 0x8003


class GenericNackCode(IntEnum):
    """NACK codes carried by payload type 0x0000."""

    INCORRECT_PATTERN_FORMAT = 0x00
    UNKNOWN_PAYLOAD_TYPE = 0x01
    MESSAGE_TOO_LARGE = 0x02
    OUT_OF_MEMORY = 0x03
    INVALID_PAYLOAD_LENGTH = 0x04


class RoutingActivationResponseCode(IntEnum):
    """Response codes of the routing activation response (0x0006)."""

    DENIED_UNKNOWN_SOURCE_ADDRESS = 0x00
    DENIED_ALL_SOCKETS_REGISTERED = 0x01
    DENIED_SA_DIFFERENT_FROM_ALREADY_ACTIVATED = 0x02
    DENIED_SA_ALREADY_REGISTERED = 0x03
    DENIED_MISSING_AUTHENTICATION = 0x04
    DENIED_REJECTED_CONFIRMATION = 0x05
    DENIED_UNSUPPORTED_ROUTING_ACTIVATION_TYPE = 0x06
    ACCEPTED = 0x10
    ACCEPTED_CONFIRMATION_REQUIRED = 0x11


class DiagnosticNackCode(IntEnum):
    """NACK codes carried by payload type 0x8003."""

    INVALID_SOURCE_ADDRESS = 0x02
    UNKNOWN_TARGET_ADDRESS = 0x03
    DIAGNOSTIC_MESSAGE_TOO_LARGE = 0x04
    OUT_OF_MEMORY = 0x05
    TARGET_UNREACHABLE = 0x06
    UNKNOWN_NETWORK = 0x07
    TRANSPORT_PROTOCOL_ERROR = 0x08


class PowerMode(IntEnum):
    """Diagnostic power mode information (0x4004)."""

    NOT_READY = 0x00
    READY = 0x01
    NOT_SUPPORTED = 0x02


class NodeType(IntEnum):
    """DoIP node type reported in the entity status response."""

    GATEWAY = 0x00
    NODE = 0x01


class FurtherAction(IntEnum):
    """Further action byte of the vehicle announcement (0x0004)."""

    NO_FURTHER_ACTION = 0x00
    ROUTING_ACTIVATION_REQUIRED = 0x10


class ActivationType(IntEnum):
    """Routing activation types understood by the test bench."""

    DEFAULT = 0x00
    WWH_OBD = 0x01
    CENTRAL_SECURITY = 0xE0


#: Number of header bytes in front of every DoIP payload.
DOIP_HEADER_SIZE = 8

#: Protocol version implemented by this test bench (ISO 13400-2:2012).
PROTOCOL_VERSION = 0x02

#: Protocol version of ISO 13400-2:2019.  Accepted on decode for reference only.
PROTOCOL_VERSION_2019 = 0x03

#: Upper bound used by the decoder to protect a test bench from absurd lengths.
DEFAULT_MAX_PAYLOAD_SIZE = 64 * 1024
