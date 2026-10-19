"""ECU configuration objects shared by the UDS and DoIP layers.

The defaults describe a small but realistic body-control ECU: VIN readable,
a couple of writable identification DIDs that require an unlocked extended
session, and three stored DTCs with different status bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

#: Default VIN of the virtual ECU (17 ASCII characters).
DEFAULT_VIN = "LSVAA2BM5N2123456"


@dataclass(frozen=True, slots=True)
class SecurityConfig:
    """Seed/key configuration for service 0x27, level 1."""

    level: int = 0x01
    seed_length: int = 4
    max_attempts: int = 3
    delay_seconds: float = 5.0
    #: Demo secret.  A production ECU keeps this in HSMs, never in source code.
    secret: bytes = b"doip-testbench-demo"

    def __post_init__(self) -> None:
        if self.seed_length not in (4, 8, 16):
            raise ValueError("seed length must be 4, 8 or 16 bytes")


@dataclass(slots=True)
class DidDefinition:
    """One entry of the DID table."""

    did: int
    name: str
    value: bytes
    readable: bool = True
    writable: bool = False
    sessions: frozenset[int] = frozenset({0x01, 0x02, 0x03, 0x04})
    security_level: int = 0
    write_length: int | None = None
    #: 0x03 = extended session.  Kept as a plain int so that ``config`` does not
    #: import the UDS package (which would create an import cycle).
    write_session: frozenset[int] = frozenset({0x03})


@dataclass(slots=True)
class DtcDefinition:
    """One stored diagnostic trouble code."""

    code: int
    status: int
    description: str = ""
    #: Snapshot record: record number -> {DID: value}
    snapshot: dict[int, dict[int, bytes]] = field(default_factory=dict)
    #: Extended data record number -> raw bytes
    extended: dict[int, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not 0 <= self.code <= 0xFFFFFF:
            raise ValueError(f"DTC out of 3 byte range: {self.code!r}")


@dataclass(slots=True)
class EcuConfig:
    """Static description of the virtual ECU."""

    vin: str = DEFAULT_VIN
    logical_address: int = 0x1001
    entity_address: int = 0x1001
    entity_name: str = "doip-testbench-virtual-ecu"
    eid: bytes = bytes.fromhex("001122334455")
    gid: bytes = bytes.fromhex("AABBCCDDEEFF")
    max_concurrent_sockets: int = 3
    max_data_size: int = 4096
    p2_ms: int = 50
    p2_star_ms: int = 5000
    s3_ms: int = 5000
    #: ``None`` accepts any tester address except 0x0000.
    allowed_testers: frozenset[int] | None = None
    security: SecurityConfig = field(default_factory=SecurityConfig)
    dids: dict[int, DidDefinition] = field(default_factory=dict)
    dtcs: list[DtcDefinition] = field(default_factory=list)
    dtc_status_availability_mask: int = 0xFF

    def __post_init__(self) -> None:
        if len(self.vin) != 17:
            raise ValueError("VIN must be exactly 17 characters")
        if not 0 <= self.logical_address <= 0xFFFF:
            raise ValueError("logical address must fit in 16 bits")
        if len(self.eid) != 6 or len(self.gid) != 6:
            raise ValueError("EID and GID must be 6 bytes")

    def get_did(self, did: int) -> DidDefinition | None:
        """Return the DID definition or ``None`` when it is not supported."""
        return self.dids.get(did)


def _default_dids(vin: str) -> dict[int, DidDefinition]:
    return {
        0xF190: DidDefinition(0xF190, "VIN", vin.encode("ascii"), writable=False),
        0xF187: DidDefinition(0xF187, "Spare part number", b"8R0 907 115 A"),
        0xF18C: DidDefinition(0xF18C, "ECU serial number", b"ECU-2026-0001"),
        0xF186: DidDefinition(0xF186, "Active diagnostic session", b"\x01"),
        0xF195: DidDefinition(0xF195, "Software version", b"SW 01.04.02"),
        0x0100: DidDefinition(
            0x0100,
            "Config block A",
            bytes.fromhex("00 00 00 00 00 00 00 00"),
            writable=True,
            security_level=1,
            write_length=8,
        ),
        0x0101: DidDefinition(
            0x0101,
            "Config block B",
            bytes.fromhex("01 02 03 04"),
            writable=True,
            security_level=1,
            write_length=4,
        ),
        0x0200: DidDefinition(0x0200, "Production date", b"20260101"),
    }


def _default_dtcs() -> list[DtcDefinition]:
    return [
        DtcDefinition(
            code=0xC12345,
            status=0x09,  # testFailed | confirmedDTC
            description="Vehicle speed sensor A circuit",
            snapshot={0x01: {0xF190: b"LSVAA2BM5N2123456", 0x0100: bytes(8)}},
            extended={0x01: bytes.fromhex("01 2C 00 64")},
        ),
        DtcDefinition(
            code=0xC12387,
            status=0x04,  # pendingDTC
            description="Lost communication with BCM",
            extended={0x01: bytes.fromhex("00 0A 00 00")},
        ),
        DtcDefinition(
            code=0x012345,
            status=0x08,  # confirmedDTC only
            description="Control module internal failure",
        ),
    ]


def default_config(**overrides: Any) -> EcuConfig:
    """Build the default ECU configuration, with optional field overrides."""
    vin = str(overrides.get("vin", DEFAULT_VIN))
    values: dict[str, Any] = {
        "vin": vin,
        "dids": _default_dids(vin),
        "dtcs": _default_dtcs(),
    }
    values.update(overrides)
    return EcuConfig(**values)
