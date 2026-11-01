"""Wire-format constants pinned to literal values from the standard.

The rest of the suite refers to ``DiagnosticNackCode`` by symbol, so it can
only prove that the implementation agrees with itself.  These assertions are
deliberately written against the numbers from ISO 13400-2: if someone ever
renumbers the enum, the whole test suite stays green while the bytes on the
wire become wrong.  **Do not refactor these to symbols** -- the duplication is
the point.
"""

from __future__ import annotations

import pytest

from doipbench.doip.constants import (
    DiagnosticNackCode,
    GenericNackCode,
    PayloadType,
    RoutingActivationResponseCode,
)


def test_payload_type_values() -> None:
    """Payload types are 16-bit values, not SIDs."""
    assert PayloadType.GENERIC_NEGATIVE_ACK == 0x0000
    assert PayloadType.VEHICLE_IDENTIFICATION_REQUEST == 0x0001
    assert PayloadType.VEHICLE_ANNOUNCEMENT == 0x0004
    assert PayloadType.ROUTING_ACTIVATION_REQUEST == 0x0005
    assert PayloadType.ROUTING_ACTIVATION_RESPONSE == 0x0006
    assert PayloadType.DIAGNOSTIC_MESSAGE == 0x8001
    assert PayloadType.DIAGNOSTIC_MESSAGE_ACK == 0x8002
    assert PayloadType.DIAGNOSTIC_MESSAGE_NACK == 0x8003


@pytest.mark.parametrize(
    ("code", "value"),
    [
        (DiagnosticNackCode.INVALID_SOURCE_ADDRESS, 0x01),
        (DiagnosticNackCode.UNKNOWN_TARGET_ADDRESS, 0x02),
        (DiagnosticNackCode.DIAGNOSTIC_MESSAGE_TOO_LARGE, 0x03),
        (DiagnosticNackCode.OUT_OF_MEMORY, 0x04),
        (DiagnosticNackCode.TARGET_UNREACHABLE, 0x05),
        (DiagnosticNackCode.UNKNOWN_NETWORK, 0x06),
        (DiagnosticNackCode.TRANSPORT_PROTOCOL_ERROR, 0x07),
    ],
)
def test_nack_code_matches_iso_13400_2(code: DiagnosticNackCode, value: int) -> None:
    """0x8003 carries these seven codes, numbered from 0x01.

    A previous revision started the table at 0x02, shifting every entry by
    one; 159 tests stayed green because their assertions used the same enum.
    """
    assert int(code) == value


def test_generic_nack_code_values() -> None:
    """0x0000 uses its own numbering, starting at 0x00."""
    assert GenericNackCode.INCORRECT_PATTERN_FORMAT == 0x00
    assert GenericNackCode.UNKNOWN_PAYLOAD_TYPE == 0x01
    assert GenericNackCode.MESSAGE_TOO_LARGE == 0x02
    assert GenericNackCode.OUT_OF_MEMORY == 0x03
    assert GenericNackCode.INVALID_PAYLOAD_LENGTH == 0x04


def test_routing_activation_response_values() -> None:
    """Accepted codes are 0x10/0x11, denials start at 0x00."""
    assert RoutingActivationResponseCode.DENIED_UNKNOWN_SOURCE_ADDRESS == 0x00
    assert RoutingActivationResponseCode.DENIED_ALL_SOCKETS_REGISTERED == 0x01
    assert RoutingActivationResponseCode.ACCEPTED == 0x10
    assert RoutingActivationResponseCode.ACCEPTED_CONFIRMATION_REQUIRED == 0x11
