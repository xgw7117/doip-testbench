"""SOME/IP-SD (Service Discovery) message codec.

Only the subset needed by the test bench is implemented: FindService,
OfferService, StopOfferService, SubscribeEventgroup and the IPv4 endpoint
option.  That is enough to decode a real Wireshark capture of an ECU booting
up, which is exactly what the unit tests do.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

SD_SERVICE_ID = 0xFFFF
SD_METHOD_ID = 0x8001
SD_MESSAGE_ID = 0xFFFF8001
SD_PORT = 30490

SD_HEADER_SIZE = 4  # flags(1) + reserved(3)


class SdEntryType:
    """Service discovery entry types."""

    FIND_SERVICE = 0x00
    OFFER_SERVICE = 0x01
    STOP_OFFER_SERVICE = 0x02
    SUBSCRIBE_EVENTGROUP = 0x06
    SUBSCRIBE_EVENTGROUP_ACK = 0x07


class SdOptionType:
    """Service discovery option types."""

    CONFIGURATION = 0x01
    IPV4_ENDPOINT = 0x04
    IPV6_ENDPOINT = 0x06
    IPV4_MULTICAST = 0x14
    IPV6_MULTICAST = 0x16


class SdError(ValueError):
    """Raised when a service discovery payload is malformed."""


@dataclass(frozen=True, slots=True)
class SdOption:
    """One SD option (length is implicit in ``value``)."""

    option_type: int
    value: bytes

    def encode(self) -> bytes:
        return struct.pack(">HB", len(self.value), self.option_type) + self.value

    @property
    def ipv4_endpoint(self) -> tuple[str, int, int] | None:
        """Return ``(address, l4_protocol, port)`` for an IPv4 endpoint option."""
        if self.option_type != SdOptionType.IPV4_ENDPOINT or len(self.value) < 7:
            return None
        address = ".".join(str(byte) for byte in self.value[:4])
        protocol = self.value[4]
        port = int.from_bytes(self.value[5:7], "big")
        return address, protocol, port


@dataclass(frozen=True, slots=True)
class SdEntry:
    """One 16 byte SD entry."""

    entry_type: int
    service_id: int
    instance_id: int
    major_version: int
    ttl: int
    minor_version: int
    index_first_option: int = 0
    index_second_option: int = 0
    num_options: int = 0
    options: tuple[SdOption, ...] = field(default=())

    def encode(self) -> bytes:
        return struct.pack(
            ">BBBBHHB3sI",
            self.entry_type,
            self.index_first_option,
            self.index_second_option,
            self.num_options,
            self.service_id,
            self.instance_id,
            self.major_version,
            self.ttl.to_bytes(3, "big"),
            self.minor_version,
        )


@dataclass(frozen=True, slots=True)
class SdMessage:
    """Decoded SD message."""

    entries: tuple[SdEntry, ...]
    flags: int = 0xC0
    options: tuple[SdOption, ...] = field(default=())

    def encode(self) -> bytes:
        payload = bytes([self.flags, 0, 0, 0])
        payload += b"".join(entry.encode() for entry in self.entries)
        payload += b"".join(option.encode() for option in self.options)
        header = struct.pack(
            ">HHIHHBBBB", SD_SERVICE_ID, SD_METHOD_ID, 8 + len(payload), 0, 1, 1, 1, 0x02, 0
        )
        return header + payload


def decode_sd(payload: bytes) -> SdMessage:
    """Decode the payload of an SD message (without the SOME/IP header)."""
    if len(payload) < SD_HEADER_SIZE:
        raise SdError("SD payload is shorter than its header")

    flags = payload[0]
    offset = SD_HEADER_SIZE
    entries: list[SdEntry] = []
    while offset + 16 <= len(payload):
        entry_type, first, second, count, service, instance, major, ttl_raw, minor = (
            struct.unpack_from(">BBBBHHB3sI", payload, offset)
        )
        offset += 16
        entries.append(
            SdEntry(
                entry_type=entry_type,
                service_id=service,
                instance_id=instance,
                major_version=major,
                ttl=int.from_bytes(ttl_raw, "big"),
                minor_version=minor,
                index_first_option=first,
                index_second_option=second,
                num_options=count,
            )
        )

    options: list[SdOption] = []
    while offset + 3 <= len(payload):
        length, option_type = struct.unpack_from(">HB", payload, offset)
        start = offset + 3
        end = start + length
        if end > len(payload):
            raise SdError("truncated SD option")
        options.append(SdOption(option_type, payload[start:end]))
        offset = end

    # Attach the options referenced by each entry (first option run).
    resolved: list[SdEntry] = []
    for entry in entries:
        selected = tuple(
            options[entry.index_first_option : entry.index_first_option + entry.num_options]
        )
        resolved.append(
            SdEntry(
                entry_type=entry.entry_type,
                service_id=entry.service_id,
                instance_id=entry.instance_id,
                major_version=entry.major_version,
                ttl=entry.ttl,
                minor_version=entry.minor_version,
                index_first_option=entry.index_first_option,
                index_second_option=entry.index_second_option,
                num_options=entry.num_options,
                options=selected,
            )
        )

    return SdMessage(entries=tuple(resolved), flags=flags, options=tuple(options))


def build_offer(
    service_id: int, instance_id: int, address: str, port: int, ttl: int = 3
) -> SdMessage:
    """Build an OfferService with one IPv4 endpoint option."""
    octets = bytes(int(part) for part in address.split("."))
    option = SdOption(SdOptionType.IPV4_ENDPOINT, octets + b"\x11" + port.to_bytes(2, "big"))
    entry = SdEntry(
        entry_type=SdEntryType.OFFER_SERVICE,
        service_id=service_id,
        instance_id=instance_id,
        major_version=1,
        ttl=ttl,
        minor_version=0,
        num_options=1,
        options=(option,),
    )
    return SdMessage(entries=(entry,), options=(option,))
