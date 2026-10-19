"""Synchronous DoIP client used by the test suite and the CLI.

The client is intentionally low level: every method maps to one payload type
and returns decoded fields, so a test case can assert on the wire format
without fighting an abstraction layer.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import time
from collections import deque
from dataclasses import dataclass

from ..uds.constants import Session
from .constants import (
    ActivationType,
    DiagnosticNackCode,
    PayloadType,
    RoutingActivationResponseCode,
)
from .frame import DoIPFrame, DoIPFrameParser, ProtocolError


class DoIPClientError(Exception):
    """Base class for client side DoIP errors."""


class DoIPConnectionClosed(DoIPClientError):
    """The peer closed the TCP connection."""


class DoIPTimeout(DoIPClientError):
    """No matching frame arrived before the deadline."""


class DiagnosticRejected(DoIPClientError):
    """The ECU answered a diagnostic message with 0x8003."""

    def __init__(self, code: int, source: int = 0, target: int = 0) -> None:
        super().__init__(f"diagnostic message rejected with NACK 0x{code:02X}")
        self.code = code
        self.source = source
        self.target = target


@dataclass(frozen=True)
class RoutingActivationResult:
    """Decoded 0x0006 response."""

    client_address: int
    entity_address: int
    response_code: int

    @property
    def accepted(self) -> bool:
        return self.response_code == RoutingActivationResponseCode.ACCEPTED


@dataclass(frozen=True)
class EntityStatus:
    """Decoded 0x4002 response."""

    node_type: int
    max_concurrent_sockets: int
    open_sockets: int
    max_data_size: int


@dataclass(frozen=True)
class VehicleAnnouncement:
    """Decoded 0x0004 response."""

    vin: str
    logical_address: int
    eid: bytes
    gid: bytes
    further_action: int


class DoIPClient:
    """Small synchronous DoIP tester."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 13400,
        *,
        client_address: int = 0x0E00,
        ecu_address: int = 0x1001,
        timeout: float = 2.0,
        connect_timeout: float = 2.0,
    ) -> None:
        self.host = host
        self.port = port
        self.client_address = client_address
        self.ecu_address = ecu_address
        self.timeout = timeout
        self.connect_timeout = connect_timeout
        self._sock: socket.socket | None = None
        self._parser = DoIPFrameParser()
        self._pending: deque[DoIPFrame] = deque()

    # ------------------------------------------------------------- lifecycle
    def connect(self) -> DoIPClient:
        """Open the TCP connection (no routing activation is performed)."""
        if self._sock is not None:
            return self
        sock = socket.create_connection((self.host, self.port), timeout=self.connect_timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(self.timeout)
        self._sock = sock
        self._parser.reset()
        self._pending.clear()
        return self

    def close(self) -> None:
        """Close the connection; safe to call twice."""
        sock, self._sock = self._sock, None
        if sock is None:
            return
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        sock.close()

    def __enter__(self) -> DoIPClient:
        return self.connect()

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    @property
    def is_open(self) -> bool:
        return self._sock is not None

    def clear_rx(self) -> None:
        """Drop frames that were received but not consumed yet."""
        self._pending.clear()
        self._parser.reset()

    # --------------------------------------------------------------- framing
    def receive_frame(self, timeout: float | None = None) -> DoIPFrame:
        """Return the next frame of any payload type (test/debug helper)."""
        return self._next_frame(timeout)

    def send_frame(self, frame: DoIPFrame) -> None:
        """Send an arbitrary frame (used to inject malformed traffic)."""
        self._require_open()
        assert self._sock is not None
        self._sock.sendall(frame.encode())

    def send_raw(self, data: bytes) -> None:
        """Send raw bytes, bypassing the encoder entirely."""
        self._require_open()
        assert self._sock is not None
        self._sock.sendall(data)

    def _require_open(self) -> None:
        if self._sock is None:
            raise DoIPClientError("client is not connected")

    def _next_frame(self, timeout: float | None = None) -> DoIPFrame:
        """Return the next frame, honouring a deadline across recv calls."""
        if self._pending:
            return self._pending.popleft()

        assert self._sock is not None
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DoIPTimeout("no DoIP frame received before the deadline")
            self._sock.settimeout(remaining)
            try:
                chunk = self._sock.recv(4096)
            except TimeoutError as exc:
                raise DoIPTimeout("timed out waiting for a DoIP frame") from exc
            if not chunk:
                raise DoIPConnectionClosed("peer closed the connection")
            try:
                frames = self._parser.feed(chunk)
            except ProtocolError as exc:  # pragma: no cover - client side guard
                raise DoIPClientError(str(exc)) from exc
            if frames:
                self._pending.extend(frames)
                return self._pending.popleft()

    def _expect(self, payload_type: int, timeout: float | None = None) -> DoIPFrame:
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            frame = self._next_frame(remaining)
            if frame.payload_type == payload_type:
                return frame
            if frame.payload_type == PayloadType.GENERIC_NEGATIVE_ACK:
                original = (
                    int.from_bytes(frame.payload[0:2], "big") if len(frame.payload) >= 2 else -1
                )
                code = frame.payload[2] if len(frame.payload) >= 3 else -1
                raise DoIPClientError(
                    f"generic NACK for payload 0x{original:04X}, code 0x{code:02X}"
                )
            # Unrelated frames (alive check, announcement, ...) are ignored.

    # ------------------------------------------------------------ DoIP services
    def routing_activation(
        self,
        activation_type: int = ActivationType.DEFAULT,
        *,
        oem: bytes | None = None,
    ) -> RoutingActivationResult:
        """Send 0x0005 and return the decoded 0x0006."""
        payload = self.client_address.to_bytes(2, "big") + bytes([activation_type]) + bytes(4)
        if oem is not None:
            if len(oem) != 4:
                raise ValueError("OEM specific data must be 4 bytes")
            payload += oem
        self.send_frame(DoIPFrame(PayloadType.ROUTING_ACTIVATION_REQUEST, payload))
        response = self._expect(PayloadType.ROUTING_ACTIVATION_RESPONSE)
        if len(response.payload) < 9:
            raise DoIPClientError("routing activation response is too short")
        return RoutingActivationResult(
            client_address=int.from_bytes(response.payload[0:2], "big"),
            entity_address=int.from_bytes(response.payload[2:4], "big"),
            response_code=response.payload[4],
        )

    def alive_check(self, timeout: float | None = None) -> int:
        """Send 0x0007 and return the source address echoed by 0x0008."""
        self.send_frame(DoIPFrame(PayloadType.ALIVE_CHECK_REQUEST))
        response = self._expect(PayloadType.ALIVE_CHECK_RESPONSE, timeout)
        return int.from_bytes(response.payload[:2], "big")

    def entity_status(self, timeout: float | None = None) -> EntityStatus:
        """Send 0x4001 and decode 0x4002."""
        self.send_frame(DoIPFrame(PayloadType.ENTITY_STATUS_REQUEST))
        response = self._expect(PayloadType.ENTITY_STATUS_RESPONSE, timeout)
        if len(response.payload) < 7:
            raise DoIPClientError("entity status response is too short")
        return EntityStatus(
            node_type=response.payload[0],
            max_concurrent_sockets=response.payload[1],
            open_sockets=response.payload[2],
            max_data_size=int.from_bytes(response.payload[3:7], "big"),
        )

    def read_vehicle_identification(self, timeout: float | None = None) -> VehicleAnnouncement:
        """Send 0x0001 and decode the announcement (0x0004)."""
        self.send_frame(DoIPFrame(PayloadType.VEHICLE_IDENTIFICATION_REQUEST))
        return self.wait_announcement(timeout)

    def wait_announcement(self, timeout: float | None = None) -> VehicleAnnouncement:
        """Decode the next 0x0004 without sending a request (EID/VIN variants)."""
        response = self._expect(PayloadType.VEHICLE_ANNOUNCEMENT, timeout)
        payload = response.payload
        if len(payload) < 32:
            raise DoIPClientError("vehicle announcement is too short")
        vin, logical_address, eid, gid, further_action = struct.unpack(">17sH6s6sB", payload[:32])
        return VehicleAnnouncement(
            vin=vin.decode("ascii", errors="replace"),
            logical_address=logical_address,
            eid=eid,
            gid=gid,
            further_action=further_action,
        )

    # ------------------------------------------------------------- diagnostics
    def send_diagnostic(self, uds_payload: bytes, target: int | None = None) -> None:
        """Send one UDS request inside a 0x8001 frame."""
        destination = self.ecu_address if target is None else target
        payload = (
            self.client_address.to_bytes(2, "big") + destination.to_bytes(2, "big") + uds_payload
        )
        self.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, payload))

    def wait_diagnostic(self, timeout: float | None = None) -> bytes:
        """Wait for a 0x8001 frame addressed to this tester and return the UDS payload."""
        deadline = time.monotonic() + (self.timeout if timeout is None else timeout)
        while True:
            remaining = max(0.0, deadline - time.monotonic())
            frame = self._next_frame(remaining)
            if frame.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_NACK:
                payload = frame.payload
                if len(payload) >= 5:
                    raise DiagnosticRejected(
                        payload[4],
                        int.from_bytes(payload[0:2], "big"),
                        int.from_bytes(payload[2:4], "big"),
                    )
                raise DiagnosticRejected(DiagnosticNackCode.TRANSPORT_PROTOCOL_ERROR)
            if frame.payload_type != PayloadType.DIAGNOSTIC_MESSAGE:
                continue
            if len(frame.payload) < 4:
                continue
            target = int.from_bytes(frame.payload[2:4], "big")
            if target != self.client_address:
                continue
            return frame.payload[4:]

    def request_uds(self, uds_payload: bytes, timeout: float | None = None) -> bytes:
        """Send a UDS request and return the raw UDS response."""
        self.send_diagnostic(uds_payload)
        return self.wait_diagnostic(timeout)

    # ------------------------------------------------------------- convenience
    def change_session(
        self, session: int = Session.EXTENDED, timeout: float | None = None
    ) -> bytes:
        """0x10 helper."""
        return self.request_uds(bytes([0x10, session]), timeout)

    def tester_present(self, timeout: float | None = None) -> bytes:
        """0x3E 0x00 helper (keeps the non-default session alive)."""
        return self.request_uds(b"\x3e\x00", timeout)
