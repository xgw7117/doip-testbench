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
    #: 密钥版本号，经 DID 0xF1A0 对外公布。tester 先读它，再选对应的 secret；
    #: 版本对不上时报"版本不匹配"，而不是让 0x27 回一个看不出原因的 0x35。
    key_version: int = 1

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
    #: 同时存在的 TCP 连接硬上限（含尚未路由激活的）。``max_concurrent_sockets``
    #: 只管"已激活"的连接，空连接不受它约束，所以另设一个防耗尽的上限。
    max_open_sockets: int = 16
    #: 单条连接的空闲上限（秒）。超时后服务端主动关闭连接。``None`` 关闭该机制。
    #: 没有它，拔网线/掉电的 tester 只能等内核重传耗尽（十几分钟）才被清理，
    #: 期间一直占着 ``max_concurrent_sockets`` 的名额。
    inactivity_timeout: float | None = 300.0
    max_data_size: int = 4096
    #: 收到 0x8001 后是否先回一帧 0x8002（诊断消息正向确认）。
    #: tester 发完诊断请求会等这一帧，再等着收诊断响应；不回的实现在
    #: ``python-doipclient`` 这类客户端下表现为"ECU 没有响应"然后超时。
    #: 直连的边缘节点应当开启；网关后面的内部节点应当关闭，否则 tester
    #: 会收到两份确认，P6Client 计时被搅乱。
    ack_diagnostic_messages: bool = True
    p2_ms: int = 50
    p2_star_ms: int = 5000
    s3_ms: int = 5000
    #: ``None`` accepts any tester address except 0x0000.
    allowed_testers: frozenset[int] | None = None
    #: Gateway mode: logical address -> ECU name.  Empty means direct connection
    #: (the ECU answers on ``logical_address`` only).
    routing_table: dict[int, str] = field(default_factory=dict)
    #: 可以一次性寻址到多台 ECU 的逻辑地址。Table 13 里只有两段合法来源：
    #: 0xE000 是 ISO 27145 WWH-OBD 的功能组地址，0xE400–0xEFFF 是厂商定义的
    #: 功能组区间。0xE001–0xE3FF 虽然也画在功能组里，但标注为 ISO/SAE 保留，
    #: 不开放。0xE400 是最通行的 OBD 功能地址；0xE000 与
    #: ActivationType.WWH_OBD 是配套的两半，接受 0x01 激活却不认这个地址，
    #: 会让 WWH-OBD tester 在第一帧 10 03 上就拿到 0x8003。
    #: 这里曾经写过 0xDFFF（SAE Truck & Bus 保留段），凭记忆抄的。
    functional_addresses: frozenset[int] = frozenset({0xE000, 0xE400})
    security: SecurityConfig = field(default_factory=SecurityConfig)
    dids: dict[int, DidDefinition] = field(default_factory=dict)
    dtcs: list[DtcDefinition] = field(default_factory=list)
    dtc_status_availability_mask: int = 0xFF
    #: 刷写区大小（字节）。0x34 的「地址 + 长度」不能越过它。
    flash_size: int = 0x10000
    #: 0x36 单块上限，含 SID 与 blockSequenceCounter 两字节。这就是 ISO 14229-1
    #: 里 0x34 正响应回给 tester 的 maxNumberOfBlockLength。
    max_block_length: int = 0x0102

    def __post_init__(self) -> None:
        if len(self.vin) != 17:
            raise ValueError("VIN must be exactly 17 characters")
        if not 0 <= self.logical_address <= 0xFFFF:
            raise ValueError("logical address must fit in 16 bits")
        if len(self.eid) != 6 or len(self.gid) != 6:
            raise ValueError("EID and GID must be 6 bytes")
        for address in sorted(self.functional_addresses):
            if address != 0xE000 and not 0xE400 <= address <= 0xEFFF:
                raise ValueError(
                    "functional address must be 0xE000 (WWH-OBD, ISO 27145) or "
                    "inside 0xE400-0xEFFF (ISO 13400-2 Table 13); "
                    f"got {hex(address)}"
                )

    def get_did(self, did: int) -> DidDefinition | None:
        """Return the DID definition or ``None`` when it is not supported."""
        return self.dids.get(did)


def _default_dids(vin: str, key_version: int = 1) -> dict[int, DidDefinition]:
    return {
        0xF190: DidDefinition(0xF190, "VIN", vin.encode("ascii"), writable=False),
        0xF187: DidDefinition(0xF187, "Spare part number", b"8R0 907 115 A"),
        0xF18C: DidDefinition(0xF18C, "ECU serial number", b"ECU-2026-0001"),
        0xF186: DidDefinition(0xF186, "Active diagnostic session", b"\x01"),
        0xF195: DidDefinition(0xF195, "Software version", b"SW 01.04.02"),
        #: 密钥版本。0xF1A0 是 OEM 自定义区（ISO 14229-1 把 0xF180-0xF1FF 留给
        #: 车厂），真车上叫什么各厂不一，作用都一样：让 tester 知道自己该用哪套密钥。
        0xF1A0: DidDefinition(0xF1A0, "Security key version", bytes([key_version & 0xFF])),
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
    security = overrides.get("security") or SecurityConfig()
    values: dict[str, Any] = {
        "vin": vin,
        "dids": _default_dids(vin, security.key_version),
        "dtcs": _default_dtcs(),
    }
    values.update(overrides)
    return EcuConfig(**values)
