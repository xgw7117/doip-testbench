"""A small but faithful UDS server (ISO 14229-1).

Implemented services: 0x10, 0x27, 0x22, 0x2E, 0x19 plus 0x3E for session
keep-alive.  The server is transport agnostic: it takes a raw UDS request and
returns a raw UDS response, so it can be driven from DoIP, ISO-TP or a unit
test without any socket.
"""

from __future__ import annotations

import logging
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import DidDefinition, DtcDefinition, EcuConfig
from .constants import (
    POSITIVE_RESPONSE_OFFSET,
    SUB_FUNCTION_MASK,
    SUPPRESS_POSITIVE_RESPONSE,
    DtcReportType,
    ServiceId,
    Session,
)
from .constants import (
    NegativeResponseCode as NRC,
)
from .security import SeedGenerator, compute_key
from .state import EcuState

logger = logging.getLogger(__name__)

Handler = Callable[[bytes], bytes]


@dataclass
class _Download:
    """一次 0x34 → 0x36* → 0x37 刷写事务的连接级状态。

    next_counter 不是"已收到几块"，而是要 tester 下一块用的
    blockSequenceCounter：从 0x01 开始，0xFF 之后回 0x00，0x00 之后回 0x01。
    拿"块数"去比对是这块最常见的实现错误。
    """

    address: int
    size: int
    data: bytearray = field(default_factory=bytearray)
    next_counter: int = 0x01


class UdsNegativeResponse(Exception):
    """Raised by a service handler to produce a 0x7F response."""

    def __init__(self, code: int) -> None:
        super().__init__(f"NRC 0x{code:02X}")
        self.code = code


def negative_response(sid: int, nrc: int) -> bytes:
    """Build a negative response for ``sid``."""
    return bytes([0x7F, sid, nrc])


class UdsServer:
    """Stateful UDS request handler for one diagnostic connection."""

    def __init__(
        self,
        config: EcuConfig,
        state: EcuState | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = config
        self.state = state or EcuState(config)
        self._clock = clock
        self.session = Session.DEFAULT
        self.security_level = 0
        self.failed_attempts = 0
        self.lockout_until = 0.0
        self.pending_seed: bytes | None = None
        self.last_activity = clock()
        self._seeds = SeedGenerator(config.security)
        self._download: _Download | None = None
        #: 懒分配：只有真发起 0x34 才占这块内存。
        self._flash: bytearray | None = None
        self._handlers: dict[int, Handler] = {
            ServiceId.DIAGNOSTIC_SESSION_CONTROL: self._diagnostic_session_control,
            ServiceId.SECURITY_ACCESS: self._security_access,
            ServiceId.READ_DATA_BY_IDENTIFIER: self._read_data_by_identifier,
            ServiceId.WRITE_DATA_BY_IDENTIFIER: self._write_data_by_identifier,
            ServiceId.READ_DTC_INFORMATION: self._read_dtc_information,
            ServiceId.TESTER_PRESENT: self._tester_present,
            ServiceId.REQUEST_DOWNLOAD: self._request_download,
            ServiceId.TRANSFER_DATA: self._transfer_data,
            ServiceId.REQUEST_TRANSFER_EXIT: self._request_transfer_exit,
            ServiceId.ECU_RESET: self._ecu_reset,
            ServiceId.ROUTINE_CONTROL: self._routine_control,
        }

    # ------------------------------------------------------------- public API
    def handle(self, request: bytes) -> bytes:
        """Process one UDS request and return the response (empty if suppressed)."""
        if not request:
            return b""

        now = self._clock()
        self._expire_session(now)
        self.last_activity = now

        sid = request[0]
        handler = self._handlers.get(sid)
        if handler is None:
            return negative_response(sid, NRC.SERVICE_NOT_SUPPORTED)

        try:
            return handler(request)
        except UdsNegativeResponse as exc:
            return negative_response(sid, exc.code)
        except Exception:  # pragma: no cover - defensive guard
            logger.exception("unhandled error while processing service 0x%02X", sid)
            return negative_response(sid, NRC.GENERAL_REJECT)

    def reset(self) -> None:
        """Return to the default session and lock security access."""
        self._reset_to_default()
        self.last_activity = self._clock()
        self._seeds.reset()

    # ------------------------------------------------------------- internals
    def _reset_to_default(self) -> None:
        # 故意不重置 failed_attempts / lockout_until：切会话不能解除安全锁定。
        self.session = Session.DEFAULT
        self.security_level = 0
        self.pending_seed = None
        # 切会话等于中断刷写：留下半截事务会让下一块数据拼到旧地址上。
        self._download = None

    def _expire_session(self, now: float) -> None:
        if self.session is Session.DEFAULT:
            return
        elapsed_ms = (now - self.last_activity) * 1000.0
        if elapsed_ms > self.config.s3_ms:
            logger.debug("S3 timer expired after %.0f ms, back to default session", elapsed_ms)
            self._reset_to_default()

    def _suppress(self, sub_function_byte: int) -> bool:
        return bool(sub_function_byte & SUPPRESS_POSITIVE_RESPONSE)

    def _positive(self, sid: int, sub: int | None = None, data: bytes = b"") -> bytes:
        response = bytearray([sid + POSITIVE_RESPONSE_OFFSET])
        if sub is not None:
            response.append(sub)
        response.extend(data)
        return bytes(response)

    # ---------------------------------------------------------------- 0x10
    def _diagnostic_session_control(self, request: bytes) -> bytes:
        if len(request) != 2:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        raw = request[1]
        target = raw & SUB_FUNCTION_MASK
        try:
            session = Session(target)
        except ValueError as exc:
            raise UdsNegativeResponse(NRC.SUB_FUNCTION_NOT_SUPPORTED) from exc

        self._reset_to_default()
        self.session = session
        logger.debug("session changed to 0x%02X", target)

        if self._suppress(raw):
            return b""
        p2 = self.config.p2_ms.to_bytes(2, "big")
        p2_star = max(1, self.config.p2_star_ms // 10).to_bytes(2, "big")
        return self._positive(ServiceId.DIAGNOSTIC_SESSION_CONTROL, target, p2 + p2_star)

    # ---------------------------------------------------------------- 0x27
    def _security_access(self, request: bytes) -> bytes:
        if len(request) < 2:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        raw = request[1]
        sub = raw & SUB_FUNCTION_MASK
        if self.session is Session.DEFAULT:
            raise UdsNegativeResponse(NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION)
        if sub not in (0x01, 0x02):
            raise UdsNegativeResponse(NRC.SUB_FUNCTION_NOT_SUPPORTED)
        suppress = self._suppress(raw)
        if self._is_locked_out():
            raise UdsNegativeResponse(NRC.REQUIRED_TIME_DELAY_NOT_EXPIRED)

        if sub == 0x01:
            if len(request) != 2:
                raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
            # Already unlocked: a zero seed tells the tester to skip the key.
            seed = (
                bytes(self.config.security.seed_length)
                if self.security_level
                else self._seeds.next_seed()
            )
            self.pending_seed = seed
            return b"" if suppress else self._positive(ServiceId.SECURITY_ACCESS, sub, seed)

        if self.pending_seed is None:
            raise UdsNegativeResponse(NRC.REQUEST_SEQUENCE_ERROR)
        if len(request) != 2 + len(self.pending_seed):
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        expected = compute_key(self.pending_seed, self.config.security.secret)
        if request[2:] != expected:
            self.failed_attempts += 1
            self.pending_seed = None
            if self.failed_attempts >= self.config.security.max_attempts:
                self.lockout_until = self._clock() + self.config.security.delay_seconds
                logger.info("security access locked for %.1fs", self.config.security.delay_seconds)
                raise UdsNegativeResponse(NRC.EXCEED_NUMBER_OF_ATTEMPTS)
            raise UdsNegativeResponse(NRC.INVALID_KEY)

        self.security_level = 1
        self.failed_attempts = 0
        self.pending_seed = None
        return b"" if suppress else self._positive(ServiceId.SECURITY_ACCESS, sub)

    def _is_locked_out(self) -> bool:
        now = self._clock()
        if now < self.lockout_until:
            return True
        if self.lockout_until:
            # 窗口已过：重新给满 max_attempts，否则错一次就再锁一轮。
            self.failed_attempts = 0
            self.lockout_until = 0.0
        return False

    # ---------------------------------------------------------------- 0x22
    def _read_data_by_identifier(self, request: bytes) -> bytes:
        if len(request) < 3 or (len(request) - 1) % 2 != 0:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        response = bytearray(self._positive(ServiceId.READ_DATA_BY_IDENTIFIER))
        for offset in range(1, len(request), 2):
            raw_did = request[offset : offset + 2]
            did = int.from_bytes(raw_did, "big")
            definition = self.config.get_did(did)
            if definition is None or not definition.readable:
                raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)
            if self.session not in definition.sessions:
                raise UdsNegativeResponse(NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION)
            response.extend(raw_did)
            response.extend(self._did_value(definition))
        return bytes(response)

    def _did_value(self, definition: DidDefinition) -> bytes:
        if definition.did == 0xF186:
            return bytes([int(self.session)])
        return self.state.read_did(definition.did)

    # ---------------------------------------------------------------- 0x2E
    def _write_data_by_identifier(self, request: bytes) -> bytes:
        if len(request) < 4:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        did = int.from_bytes(request[1:3], "big")
        definition = self.config.get_did(did)
        if definition is None or not definition.writable:
            raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)
        if self.session not in definition.write_session:
            raise UdsNegativeResponse(NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION)
        if self.security_level < definition.security_level:
            raise UdsNegativeResponse(NRC.SECURITY_ACCESS_DENIED)

        value = request[3:]
        if definition.write_length is not None and len(value) != definition.write_length:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        self.state.write_did(did, value)
        logger.debug("DID 0x%04X written (%d bytes)", did, len(value))
        return self._positive(ServiceId.WRITE_DATA_BY_IDENTIFIER, data=bytes(request[1:3]))

    # ---------------------------------------------------------------- 0x19
    def _read_dtc_information(self, request: bytes) -> bytes:
        if len(request) < 2:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        raw = request[1]
        sub = raw & SUB_FUNCTION_MASK
        handlers: dict[int, Handler] = {
            DtcReportType.REPORT_NUMBER_OF_DTC_BY_STATUS_MASK: self._report_dtc_count,
            DtcReportType.REPORT_DTC_BY_STATUS_MASK: self._report_dtc_by_status,
            DtcReportType.REPORT_DTC_SNAPSHOT_RECORD_BY_DTC_NUMBER: self._report_dtc_snapshot,
            DtcReportType.REPORT_DTC_EXT_DATA_RECORD_BY_DTC_NUMBER: self._report_dtc_extended,
            DtcReportType.REPORT_SUPPORTED_DTC: self._report_supported_dtc,
        }
        handler = handlers.get(sub)
        if handler is None:
            raise UdsNegativeResponse(NRC.SUB_FUNCTION_NOT_SUPPORTED)

        body = handler(request)
        return (
            b""
            if self._suppress(raw)
            else self._positive(ServiceId.READ_DTC_INFORMATION, sub, body)
        )

    def _dtc_records(self, dtcs: list[DtcDefinition]) -> bytes:
        payload = bytearray()
        for dtc in dtcs:
            payload.extend(dtc.code.to_bytes(3, "big"))
            payload.append(dtc.status)
        return bytes(payload)

    def _report_dtc_count(self, request: bytes) -> bytes:
        if len(request) != 3:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        # 响应首字节是服务端支持哪些 status bit，跟请求 mask 无关。
        available = self.config.dtc_status_availability_mask
        count = len(self.state.dtcs(request[2]))
        return bytes([available, 0x01]) + count.to_bytes(2, "big")

    def _report_dtc_by_status(self, request: bytes) -> bytes:
        if len(request) != 3:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        available = self.config.dtc_status_availability_mask
        return bytes([available]) + self._dtc_records(self.state.dtcs(request[2]))

    def _report_supported_dtc(self, request: bytes) -> bytes:
        if len(request) != 2:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        mask = self.config.dtc_status_availability_mask
        return bytes([mask]) + self._dtc_records(self.state.all_dtcs())

    def _parse_dtc_selector(self, request: bytes) -> tuple[int, int]:
        if len(request) != 6:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        code = int.from_bytes(request[2:5], "big")
        if self.state.find_dtc(code) is None:
            raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)
        return code, request[5]

    def _report_dtc_snapshot(self, request: bytes) -> bytes:
        code, record_number = self._parse_dtc_selector(request)
        dtc = self.state.find_dtc(code)
        assert dtc is not None
        if record_number not in dtc.snapshot:
            raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)

        identifiers = dtc.snapshot[record_number]
        body = bytearray(code.to_bytes(3, "big"))
        body.append(dtc.status)
        body.append(record_number)
        body.append(len(identifiers))
        for did, value in identifiers.items():
            body.extend(did.to_bytes(2, "big"))
            body.append(len(value))
            body.extend(value)
        return bytes(body)

    def _report_dtc_extended(self, request: bytes) -> bytes:
        code, record_number = self._parse_dtc_selector(request)
        dtc = self.state.find_dtc(code)
        assert dtc is not None
        if record_number not in dtc.extended:
            raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)

        body = bytearray(code.to_bytes(3, "big"))
        body.append(dtc.status)
        body.append(record_number)
        body.extend(dtc.extended[record_number])
        return bytes(body)

    # ---------------------------------------------------------------- 0x3E
    def _tester_present(self, request: bytes) -> bytes:
        if len(request) != 2:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        raw = request[1]
        sub = raw & SUB_FUNCTION_MASK
        if sub != 0x00:
            raise UdsNegativeResponse(NRC.SUB_FUNCTION_NOT_SUPPORTED)
        if self._suppress(raw):
            return b""
        return self._positive(ServiceId.TESTER_PRESENT, 0x00)

    # ---------------------------------------------------------------- 0x34
    def _request_download(self, request: bytes) -> bytes:
        """RequestDownload：告诉 tester「往哪写、写多少、一块最大多少」。

        真实刷写序列比这里长（写指纹、31 01 FF00 擦除、37 之后还要 31 01
        FF01 校验、11 01 复位）。这里只做数据传输这一段，擦除和校验当作
        外部已经完成——边界写在 README 里，不假装全做了。
        """
        self._require_programming()
        if len(request) < 3:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        if self._download is not None:
            # 上一个事务没 37 就再来一次 34：先 37 或切会话。
            raise UdsNegativeResponse(NRC.REQUEST_SEQUENCE_ERROR)

        if request[1] != 0x00:
            # dataFormatIdentifier 非 0 表示压缩或加密，本实现都不支持。
            raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)

        alfid = request[2]
        address_length = alfid & 0x0F
        size_length = alfid >> 4
        if address_length == 0 or size_length == 0:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        if len(request) != 3 + address_length + size_length:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        address = int.from_bytes(request[3 : 3 + address_length], "big")
        size = int.from_bytes(request[3 + address_length :], "big")
        if size == 0 or address + size > self.config.flash_size:
            raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)

        self._download = _Download(address=address, size=size)
        logger.debug("download 0x%X..0x%X", address, address + size)
        return self._positive(
            ServiceId.REQUEST_DOWNLOAD,
            0x20,  # lengthFormatIdentifier：后面 2 字节是 maxNumberOfBlockLength
            self.config.max_block_length.to_bytes(2, "big"),
        )

    # ---------------------------------------------------------------- 0x36
    def _transfer_data(self, request: bytes) -> bytes:
        self._require_programming()
        if self._download is None:
            raise UdsNegativeResponse(NRC.REQUEST_SEQUENCE_ERROR)
        if len(request) < 3:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        if len(request) > self.config.max_block_length:
            raise UdsNegativeResponse(NRC.TRANSFER_DATA_SUSPENDED)

        counter = request[1]
        if counter != self._download.next_counter:
            # 丢块 / 重发 / 乱序都落到这里。tester 见到 0x73 要从该块重发。
            raise UdsNegativeResponse(NRC.WRONG_BLOCK_SEQUENCE_COUNTER)

        chunk = request[2:]
        if len(self._download.data) + len(chunk) > self._download.size:
            # 超出 0x34 声明的长度：不截断，直接挂起，让 tester 知道算错了。
            raise UdsNegativeResponse(NRC.TRANSFER_DATA_SUSPENDED)

        self._download.data.extend(chunk)
        self._download.next_counter = (counter + 1) & 0xFF
        return self._positive(ServiceId.TRANSFER_DATA, counter)

    # ---------------------------------------------------------------- 0x37
    def _request_transfer_exit(self, request: bytes) -> bytes:
        self._require_programming()
        if self._download is None:
            raise UdsNegativeResponse(NRC.REQUEST_SEQUENCE_ERROR)
        if len(request) != 1:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        download = self._download
        if len(download.data) != download.size:
            # 少传了：不写进去，也不悄悄当成功。
            raise UdsNegativeResponse(NRC.REQUEST_SEQUENCE_ERROR)

        flash = self._ensure_flash()
        flash[download.address : download.address + download.size] = download.data
        self._download = None
        logger.debug("flashed %d bytes at 0x%X", download.size, download.address)
        return self._positive(ServiceId.REQUEST_TRANSFER_EXIT)

    def _ensure_flash(self) -> bytearray:
        """懒分配刷写区：只有真擦或真写才占这块内存。"""
        if self._flash is None:
            self._flash = bytearray(self.config.flash_size)
        return self._flash

    def _require_programming(self) -> None:
        """三个刷写服务的共同前置条件：编程会话 + 已解锁。"""
        if self.session is not Session.PROGRAMMING:
            raise UdsNegativeResponse(NRC.SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION)
        if not self.security_level:
            raise UdsNegativeResponse(NRC.SECURITY_ACCESS_DENIED)

    # ------------------------------------------------------------- 内部查询
    def flash_image(self) -> bytes:
        """返回刷写区内容，供测试断言写入结果。"""
        if self._flash is None:
            return bytes(self.config.flash_size)
        return bytes(self._flash)

    # ---------------------------------------------------------------- 0x11
    def _ecu_reset(self, request: bytes) -> bytes:
        if len(request) != 2:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        raw = request[1]
        sub = raw & SUB_FUNCTION_MASK
        if sub not in (0x01, 0x03):
            raise UdsNegativeResponse(NRC.SUB_FUNCTION_NOT_SUPPORTED)

        self._reset_to_default()
        # 复位等于重新上电：会话回默认、安全锁上、半截刷写事务丢掉。
        # 计数器也清零——这是真实 ECU 的已知弱点（断电就能绕过 0x27 锁定），
        # 生产项目把计数写进 NVM，这里没有 NVM，如实按"重启清零"实现。
        self.failed_attempts = 0
        self.lockout_until = 0.0
        self._seeds.reset()
        self.last_activity = self._clock()
        if self._suppress(raw):
            return b""
        return self._positive(ServiceId.ECU_RESET, sub)

    # ---------------------------------------------------------------- 0x31
    def _routine_control(self, request: bytes) -> bytes:
        """RoutineControl：这里只实现刷写用的 FF00 擦除和 FF01 校验。

        只支持 startRoutine（子功能 01）。stop（02）和 requestResults（03）
        回 0x12——不是忘了，是这两条在刷写序列里用不到，做了也没有用例能验证。
        """
        self._require_programming()
        if len(request) < 4:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)

        raw = request[1]
        sub = raw & SUB_FUNCTION_MASK
        if sub != 0x01:
            raise UdsNegativeResponse(NRC.SUB_FUNCTION_NOT_SUPPORTED)

        routine = int.from_bytes(request[2:4], "big")
        params = request[4:]
        if routine == 0xFF00:
            body = self._erase(params)
        elif routine == 0xFF01:
            body = self._verify(params)
        else:
            raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)

        if self._suppress(raw):
            return b""
        return self._positive(ServiceId.ROUTINE_CONTROL, sub, routine.to_bytes(2, "big") + body)

    def _erase(self, params: bytes) -> bytes:
        """31 01 FF00：不带参数擦整片，带 8 字节则擦指定 [地址, 长度]。"""
        if self._download is not None:
            # 一边下载一边擦，等于把要写的区清掉。
            raise UdsNegativeResponse(NRC.REQUEST_SEQUENCE_ERROR)

        flash = self._ensure_flash()
        if not params:
            flash[:] = bytes(len(flash))
            logger.debug("erased whole flash (%d bytes)", len(flash))
            return b"\x00"

        if len(params) != 8:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        address = int.from_bytes(params[:4], "big")
        size = int.from_bytes(params[4:], "big")
        if size == 0 or address + size > len(flash):
            raise UdsNegativeResponse(NRC.REQUEST_OUT_OF_RANGE)
        flash[address : address + size] = bytes(size)
        logger.debug("erased 0x%X..0x%X", address, address + size)
        return b"\x00"

    def _verify(self, params: bytes) -> bytes:
        """31 01 FF01：不带参数回报整片 CRC32，带 4 字节则比对。

        回一个字节 0x00 通过 / 0x01 失败，tester 据此决定要不要 11 01 复位。
        """
        actual = zlib.crc32(bytes(self._ensure_flash())).to_bytes(4, "big")
        if not params:
            return actual
        if len(params) != 4:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        return b"\x00" if params == actual else b"\x01"
