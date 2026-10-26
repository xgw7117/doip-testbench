"""Threaded DoIP server that behaves like a small Ethernet ECU.

Design notes
------------
* One thread per TCP connection, one incremental frame parser per socket.  TCP
  segmentation is therefore a non-issue and the conformance suite can send
  frames byte by byte.
* Routing activation is tracked per connection (ISO 13400-2 allows one tester
  address per socket) while DID/DTC state is shared by the whole ECU.
* Every malformed payload is answered with the *correct* negative
  acknowledgement: generic NACK for payload-level errors, 0x8003 for
  diagnostic-level errors.  Mixing those two up is a classic bug in student
  projects, and the tests here pin the distinction down.
"""

from __future__ import annotations

import contextlib
import logging
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import EcuConfig, default_config
from ..uds.server import UdsServer
from ..uds.state import EcuState
from .constants import (
    ActivationType,
    DiagnosticNackCode,
    GenericNackCode,
    NodeType,
    PayloadType,
    PowerMode,
    RoutingActivationResponseCode,
)
from .frame import DoIPFrame, DoIPFrameParser, ProtocolError

logger = logging.getLogger(__name__)

#: Announcement payload is fixed by the standard: VIN(17) + LA(2) + EID(6) +
#: GID(6) + further action(1).
_ANNOUNCEMENT_FORMAT = ">17sH6s6sB"


@dataclass
class RoutingState:
    """Routing activation state of a single TCP connection."""

    activated: bool = False
    client_address: int = 0
    activation_type: int = 0


@dataclass
class _Connection:
    server: DoIPServer
    sock: socket.socket
    peer: tuple[str, int]
    routing: RoutingState = field(default_factory=RoutingState)
    uds_map: dict[int, UdsServer] = field(init=False)
    parser: DoIPFrameParser = field(init=False)

    _send_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        config = self.server.config
        addresses = config.routing_table or {config.logical_address: "ecu"}
        self.uds_map = {
            address: UdsServer(config, self.server.state_for(address)) for address in addresses
        }
        self.parser = DoIPFrameParser(max_payload_size=self.server.max_payload_size)

    # ------------------------------------------------------------------ loop
    def run(self) -> None:
        logger.info("DoIP connection from %s:%d", *self.peer)
        try:
            while not self.server.stopping:
                try:
                    chunk = self.sock.recv(4096)
                except TimeoutError:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                try:
                    frames = self.parser.feed(chunk)
                except ProtocolError as exc:
                    self._handle_protocol_error(exc)
                    break
                for frame in frames:
                    if self.server.stopping:
                        break
                    self._dispatch(frame)
        finally:
            self._close()
            logger.info("DoIP connection from %s:%d closed", *self.peer)

    def _close(self) -> None:
        with self.server._lock:  # noqa: SLF001 - tight coupling is intentional
            self.server._connections.pop(self.sock, None)  # noqa: SLF001
        with contextlib.suppress(OSError):
            self.sock.close()

    def _handle_protocol_error(self, exc: ProtocolError) -> None:
        logger.warning("protocol error from %s:%d: %s", *self.peer, exc)
        if exc.send_nack and exc.payload_type is not None:
            self._send_generic_nack(exc.payload_type, exc.nack_code or 0x00)

    # -------------------------------------------------------------- dispatch
    def _dispatch(self, frame: DoIPFrame) -> None:
        handlers: dict[int, Callable[[DoIPFrame], None]] = {
            PayloadType.VEHICLE_IDENTIFICATION_REQUEST: self._vehicle_identification,
            PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID: self._vehicle_identification,
            PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN: self._vehicle_identification,
            PayloadType.ROUTING_ACTIVATION_REQUEST: self._routing_activation,
            PayloadType.ALIVE_CHECK_REQUEST: self._alive_check,
            PayloadType.ENTITY_STATUS_REQUEST: self._entity_status,
            PayloadType.POWER_MODE_INFORMATION_REQUEST: self._power_mode,
            PayloadType.DIAGNOSTIC_MESSAGE: self._diagnostic_message,
        }
        handler = handlers.get(frame.payload_type)
        if handler is None:
            self._send_generic_nack(frame.payload_type, GenericNackCode.UNKNOWN_PAYLOAD_TYPE)
            return
        handler(frame)

    # ------------------------------------------------------------- 0x0001-4
    def _vehicle_identification(self, frame: DoIPFrame) -> None:
        config = self.server.config
        if frame.payload_type == PayloadType.VEHICLE_IDENTIFICATION_REQUEST:
            if frame.payload:
                self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
                return
        elif frame.payload_type == PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID:
            if len(frame.payload) != 6:
                self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
                return
            if frame.payload != config.eid:
                return  # not addressed to this entity: stay silent
        else:
            if len(frame.payload) != 17:
                self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
                return
            if frame.payload.decode("ascii", errors="replace") != config.vin:
                return

        payload = (
            config.vin.encode("ascii")
            + config.logical_address.to_bytes(2, "big")
            + config.eid
            + config.gid
            + bytes([0x10])  # further action: routing activation required
        )
        self._send(PayloadType.VEHICLE_ANNOUNCEMENT, payload)

    # ---------------------------------------------------------------- 0x0005
    def _routing_activation(self, frame: DoIPFrame) -> None:
        if len(frame.payload) not in (7, 11):
            self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
            return

        client_address = int.from_bytes(frame.payload[0:2], "big")
        activation_type = frame.payload[2]
        code = self._evaluate_routing_activation(client_address, activation_type)

        if code == RoutingActivationResponseCode.ACCEPTED:
            self.routing = RoutingState(True, client_address, activation_type)

        payload = (
            client_address.to_bytes(2, "big")
            + self.server.config.entity_address.to_bytes(2, "big")
            + bytes([code])
            + bytes(4)  # reserved
        )
        if len(frame.payload) == 11:
            payload += bytes(4)  # OEM specific
        self._send(PayloadType.ROUTING_ACTIVATION_RESPONSE, payload)
        logger.info(
            "routing activation from 0x%04X type 0x%02X -> 0x%02X",
            client_address,
            activation_type,
            code,
        )

    def _evaluate_routing_activation(self, client_address: int, activation_type: int) -> int:
        config = self.server.config
        if activation_type not in (
            ActivationType.DEFAULT,
            ActivationType.WWH_OBD,
            ActivationType.CENTRAL_SECURITY,
        ):
            return RoutingActivationResponseCode.DENIED_UNSUPPORTED_ROUTING_ACTIVATION_TYPE
        if client_address == 0:
            return RoutingActivationResponseCode.DENIED_UNKNOWN_SOURCE_ADDRESS
        if config.allowed_testers is not None and client_address not in config.allowed_testers:
            return RoutingActivationResponseCode.DENIED_UNKNOWN_SOURCE_ADDRESS
        if self.routing.activated:
            if client_address == self.routing.client_address:
                return RoutingActivationResponseCode.DENIED_SA_ALREADY_REGISTERED
            return RoutingActivationResponseCode.DENIED_SA_DIFFERENT_FROM_ALREADY_ACTIVATED
        if self.server.activated_sockets() >= config.max_concurrent_sockets:
            return RoutingActivationResponseCode.DENIED_ALL_SOCKETS_REGISTERED
        return RoutingActivationResponseCode.ACCEPTED

    # ---------------------------------------------------------------- 0x0007
    def _alive_check(self, frame: DoIPFrame) -> None:
        if frame.payload:
            self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
            return
        self._send(PayloadType.ALIVE_CHECK_RESPONSE, self.routing.client_address.to_bytes(2, "big"))

    # ---------------------------------------------------------------- 0x4001
    def _entity_status(self, frame: DoIPFrame) -> None:
        if frame.payload:
            self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
            return
        payload = bytes(
            [
                NodeType.NODE,
                self.server.config.max_concurrent_sockets,
                min(self.server.open_sockets(), 0xFF),
            ]
        ) + self.server.config.max_data_size.to_bytes(4, "big")
        self._send(PayloadType.ENTITY_STATUS_RESPONSE, payload)

    # ---------------------------------------------------------------- 0x4003
    def _power_mode(self, frame: DoIPFrame) -> None:
        if frame.payload:
            self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
            return
        self._send(PayloadType.POWER_MODE_INFORMATION_RESPONSE, bytes([PowerMode.READY]))

    # ---------------------------------------------------------------- 0x8001
    def _diagnostic_message(self, frame: DoIPFrame) -> None:
        payload = frame.payload
        if len(payload) < 4:
            self._send_diagnostic_nack(0, 0, DiagnosticNackCode.TRANSPORT_PROTOCOL_ERROR)
            return

        source = int.from_bytes(payload[0:2], "big")
        target = int.from_bytes(payload[2:4], "big")
        uds_request = payload[4:]

        if not self.routing.activated:
            self._send_diagnostic_nack(source, target, DiagnosticNackCode.INVALID_SOURCE_ADDRESS)
            return
        if source != self.routing.client_address:
            self._send_diagnostic_nack(source, target, DiagnosticNackCode.INVALID_SOURCE_ADDRESS)
            return
        uds = self.uds_map.get(target)
        if uds is None:
            self._send_diagnostic_nack(source, target, DiagnosticNackCode.UNKNOWN_TARGET_ADDRESS)
            return

        if len(uds_request) > self.server.config.max_data_size:
            self._send_diagnostic_nack(
                source, target, DiagnosticNackCode.DIAGNOSTIC_MESSAGE_TOO_LARGE
            )
            return
        if not uds_request:
            self._send_diagnostic_nack(source, target, DiagnosticNackCode.TRANSPORT_PROTOCOL_ERROR)
            return

        uds_response = uds.handle(uds_request)
        if not uds_response:
            return  # positive response suppressed by the tester

        response = (
            target.to_bytes(2, "big")
            + self.routing.client_address.to_bytes(2, "big")
            + uds_response
        )

        self._send(PayloadType.DIAGNOSTIC_MESSAGE, response)

    # -------------------------------------------------------------- tx helpers
    def _send(self, payload_type: int, payload: bytes = b"") -> None:
        frame = DoIPFrame(payload_type, payload)
        with self._send_lock, contextlib.suppress(OSError):
            self.sock.sendall(frame.encode())

    def _send_generic_nack(self, original_payload_type: int, code: int) -> None:
        payload = original_payload_type.to_bytes(2, "big") + bytes([code])
        self._send(PayloadType.GENERIC_NEGATIVE_ACK, payload)

    def _send_diagnostic_nack(self, source: int, target: int, code: int) -> None:
        payload = source.to_bytes(2, "big") + target.to_bytes(2, "big") + bytes([code])
        self._send(PayloadType.DIAGNOSTIC_MESSAGE_NACK, payload)


class DoIPServer:
    """Context manager friendly DoIP server bound to ``host:port``."""

    def __init__(
        self,
        config: EcuConfig | None = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        max_payload_size: int = 65536,
    ) -> None:
        self.config = config or default_config()
        self._states: dict[int, EcuState] = {}
        self.max_payload_size = max_payload_size
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections: dict[socket.socket, _Connection] = {}
        self._thread: threading.Thread | None = None

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, port))
        self._listener.listen(8)
        self._listener.settimeout(0.1)
        self.host, self.port = self._listener.getsockname()[:2]

    # ------------------------------------------------------------- lifecycle
    def start(self) -> DoIPServer:
        """Start accepting connections in a background thread."""
        if self._thread is None:
            self._thread = threading.Thread(
                target=self._accept_loop, name="doip-accept", daemon=True
            )
            self._thread.start()
        return self

    def stop(self) -> None:
        """Close the listener and every client socket."""
        self._stop.set()
        with self._lock:
            connections = list(self._connections.values())
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.sock.shutdown(socket.SHUT_RDWR)
            with contextlib.suppress(OSError):
                connection.sock.close()
        with contextlib.suppress(OSError):
            self._listener.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def __enter__(self) -> DoIPServer:
        return self.start()

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    @property
    def stopping(self) -> bool:
        """True once :meth:`stop` has been called."""
        return self._stop.is_set()

    def activated_sockets(self) -> int:
        """Number of sockets that completed routing activation."""
        with self._lock:
            return sum(1 for c in self._connections.values() if c.routing.activated)

    def open_sockets(self) -> int:
        """Number of currently open TCP connections."""
        with self._lock:
            return len(self._connections)

    def state_for(self, logical_address: int) -> EcuState:
        """Return the state of one ECU, creating it on first use."""
        if logical_address not in self._states:
            self._states[logical_address] = EcuState(self.config)
        return self._states[logical_address]

    def reset_state(self) -> None:
        """Restore DID values and DTCs to their factory defaults."""
        for state in self._states.values():
            state.reset()

    # ------------------------------------------------------------- internals
    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                client, peer = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            client.settimeout(0.2)
            connection = _Connection(self, client, peer)
            with self._lock:
                self._connections[client] = connection
            threading.Thread(
                target=connection.run,
                name=f"doip-conn-{peer[1]}",
                daemon=True,
            ).start()
