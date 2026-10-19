"""IEEE 802.1Q VLAN tagging and Ethernet II framing.

Automotive Ethernet ECUs usually sit on a VLAN (diagnostics on one VID, SOME/IP
on another).  Being able to build and parse tagged frames is a prerequisite for
any switch or TC8 style test, and it costs only a few dozen lines.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

VLAN_TPID = 0x8100
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_GPTP = 0x88F7

_HEADER = struct.Struct(">6s6sH")


class EthernetError(ValueError):
    """Raised when a frame cannot be parsed."""


@dataclass(frozen=True, slots=True)
class VlanTag:
    """802.1Q tag control information."""

    vid: int
    pcp: int = 0
    dei: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.vid <= 4094:
            raise ValueError("VLAN id must be in 0..4094")
        if not 0 <= self.pcp <= 7:
            raise ValueError("PCP must be in 0..7")

    @property
    def tci(self) -> int:
        return (self.pcp << 13) | (int(self.dei) << 12) | self.vid

    def encode(self) -> bytes:
        """Return TPID + TCI (4 bytes)."""
        return struct.pack(">HH", VLAN_TPID, self.tci)

    @classmethod
    def from_tci(cls, tci: int) -> VlanTag:
        return cls(vid=tci & 0x0FFF, pcp=(tci >> 13) & 0x07, dei=bool(tci & 0x1000))


@dataclass(frozen=True, slots=True)
class EthernetFrame:
    """Decoded Ethernet II frame, optionally VLAN tagged."""

    destination: bytes
    source: bytes
    ethertype: int
    payload: bytes
    vlan: VlanTag | None = None

    def encode(self) -> bytes:
        if self.vlan is not None:
            header = (
                _HEADER.pack(self.destination, self.source, VLAN_TPID)
                + struct.pack(">H", self.vlan.tci)
                + struct.pack(">H", self.ethertype)
            )
        else:
            header = _HEADER.pack(self.destination, self.source, self.ethertype)
        return header + self.payload

    @property
    def tci(self) -> int | None:
        return self.vlan.tci if self.vlan else None


def parse_ethernet(data: bytes) -> EthernetFrame:
    """Parse an Ethernet II frame, transparently handling one 802.1Q tag."""
    if len(data) < 14:
        raise EthernetError(f"frame too short: {len(data)} bytes")

    destination, source, ethertype = _HEADER.unpack_from(data)
    offset = 14
    vlan: VlanTag | None = None
    if ethertype == VLAN_TPID:
        if len(data) < 18:
            raise EthernetError("truncated VLAN tag")
        _, tci = struct.unpack_from(">HH", data, 12)
        vlan = VlanTag.from_tci(tci)
        ethertype = struct.unpack_from(">H", data, 16)[0]
        offset = 18

    return EthernetFrame(
        destination=destination,
        source=source,
        ethertype=ethertype,
        payload=data[offset:],
        vlan=vlan,
    )


def build_frame(
    *,
    destination: bytes,
    source: bytes,
    ethertype: int,
    payload: bytes,
    vlan: VlanTag | None = None,
) -> bytes:
    """Build an Ethernet II frame with an optional VLAN tag."""
    if len(destination) != 6 or len(source) != 6:
        raise EthernetError("MAC addresses must be 6 bytes")
    return EthernetFrame(destination, source, ethertype, payload, vlan).encode()
