"""A small but faithful UDS server (ISO 14229-1).

Implemented services: 0x10, 0x27, 0x22, 0x2E, 0x19 plus 0x3E for session
keep-alive.  The server is transport agnostic: it takes a raw UDS request and
returns a raw UDS response, so it can be driven from DoIP, ISO-TP or a unit
test without any socket.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable

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
        self._handlers: dict[int, Handler] = {
            ServiceId.DIAGNOSTIC_SESSION_CONTROL: self._diagnostic_session_control,
            ServiceId.SECURITY_ACCESS: self._security_access,
            ServiceId.READ_DATA_BY_IDENTIFIER: self._read_data_by_identifier,
            ServiceId.WRITE_DATA_BY_IDENTIFIER: self._write_data_by_identifier,
            ServiceId.READ_DTC_INFORMATION: self._read_dtc_information,
            ServiceId.TESTER_PRESENT: self._tester_present,
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
        self.session = Session.DEFAULT
        self.security_level = 0
        self.pending_seed = None
        self.failed_attempts = 0
        self.lockout_until = 0.0

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
        return self._clock() < self.lockout_until

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
        mask = request[2]
        count = len(self.state.dtcs(mask))
        return bytes([mask, 0x01]) + count.to_bytes(2, "big")

    def _report_dtc_by_status(self, request: bytes) -> bytes:
        if len(request) != 3:
            raise UdsNegativeResponse(NRC.INCORRECT_MESSAGE_LENGTH)
        mask = request[2]
        return bytes([mask]) + self._dtc_records(self.state.dtcs(mask))

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
