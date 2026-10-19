"""Automotive Ethernet link-layer helpers (VLAN, gPTP)."""

from __future__ import annotations

from .gptp import (
    GPTP_ETHERTYPE,
    GptpError,
    GptpHeader,
    GptpMessage,
    GptpMessageType,
    build_sync,
    decode_gptp,
)
from .vlan import (
    ETHERTYPE_GPTP,
    ETHERTYPE_IPV4,
    VLAN_TPID,
    EthernetError,
    EthernetFrame,
    VlanTag,
    build_frame,
    parse_ethernet,
)

__all__ = [
    "ETHERTYPE_GPTP",
    "ETHERTYPE_IPV4",
    "GPTP_ETHERTYPE",
    "VLAN_TPID",
    "EthernetError",
    "EthernetFrame",
    "GptpError",
    "GptpHeader",
    "GptpMessage",
    "GptpMessageType",
    "VlanTag",
    "build_frame",
    "build_sync",
    "decode_gptp",
    "parse_ethernet",
]
