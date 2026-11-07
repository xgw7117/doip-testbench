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
from .frame import (
    DoIPFrame,
    DoIPFrameParser,
    IncorrectPatternFormat,
    MessageTooLarge,
    ProtocolError,
    decode_frame,
)

logger = logging.getLogger(__name__)

#: Announcement payload is fixed by the standard: VIN(17) + LA(2) + EID(6) +
#: GID(6) + further action(1).
_ANNOUNCEMENT_FORMAT = ">17sH6s6sB"

#: Payload types ISO 13400-2 puts on UDP 13400.
#:
#: These are the ones a tester sends *before* it knows the ECU's IP address, so
#: they have to be reachable by broadcast. Everything else - routing activation,
#: diagnostic messages, alive check - belongs to one TCP connection.
UDP_PAYLOAD_TYPES = frozenset(
    {
        PayloadType.VEHICLE_IDENTIFICATION_REQUEST,
        PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID,
        PayloadType.VEHICLE_IDENTIFICATION_REQUEST_VIN,
        PayloadType.ENTITY_STATUS_REQUEST,
        PayloadType.POWER_MODE_INFORMATION_REQUEST,
    }
)


def announcement_payload(config: EcuConfig) -> bytes:
    """Build the 0x0004 payload (also used as the 0x0001-0x0003 answer)."""
    return (
        config.vin.encode("ascii")
        + config.logical_address.to_bytes(2, "big")
        + config.eid
        + config.gid
        + bytes([0x10])  # further action: routing activation required
    )


def entity_status_payload(server: DoIPServer) -> bytes:
    """Build the 0x4002 payload: node type, socket counts, max data size."""
    return bytes(
        [
            NodeType.NODE,
            server.config.max_concurrent_sockets,
            min(server.open_sockets(), 0xFF),
        ]
    ) + server.config.max_data_size.to_bytes(4, "big")


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
        self.uds_map: dict[int, UdsServer] = {
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

        payload = announcement_payload(config)
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
        if not self.routing.activated:
            logger.warning("alive check on unactivated connection from %s:%d, closing", *self.peer)
            self._close()
            return
        if frame.payload:
            self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
            return
        self._send(PayloadType.ALIVE_CHECK_RESPONSE, self.routing.client_address.to_bytes(2, "big"))

    # ---------------------------------------------------------------- 0x4001
    def _entity_status(self, frame: DoIPFrame) -> None:
        if frame.payload:
            self._send_generic_nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH)
            return
        self._send(PayloadType.ENTITY_STATUS_RESPONSE, entity_status_payload(self.server))

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


class _UdpEndpoint:
    """The UDP 13400 half of the entity (ISO 13400-2 §7.2).

    Vehicle identification has to work while the tester still does not know the
    ECU's IP address, so those requests arrive by broadcast on UDP. Anything
    that belongs to a connection - routing activation, diagnostic messages,
    alive check - must stay on TCP, and a tester that sends them here gets a
    generic NACK instead of an answer.

    There is no per-datagram state: UDP is connectionless, so every datagram is
    handled on its own and nothing is remembered between them.
    """

    def __init__(self, server: DoIPServer) -> None:
        self.server = server
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((server.host, server.port))
        self.sock.settimeout(0.2)
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="doip-udp", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        while not self.server.stopping:
            try:
                data, peer = self.sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                break
            with contextlib.suppress(OSError):
                self._handle(data, peer)

    # ------------------------------------------------------------------ rx
    def _handle(self, data: bytes, peer: tuple[str, int]) -> None:
        try:
            frame = decode_frame(data, max_payload_size=self.server.max_payload_size)
        except MessageTooLarge as exc:
            self._nack(exc.payload_type, GenericNackCode.MESSAGE_TOO_LARGE, peer)
            return
        except IncorrectPatternFormat as exc:
            self._nack(exc.payload_type, GenericNackCode.INCORRECT_PATTERN_FORMAT, peer)
            return
        except ProtocolError:
            # Truncated datagram: there is no payload type to quote back, so a
            # NACK would be a guess. Drop it and let the tester time out.
            return

        if frame.payload_type not in UDP_PAYLOAD_TYPES:
            logger.warning(
                "payload type 0x%04X is TCP-only, NACK to %s:%d",
                frame.payload_type,
                *peer,
            )
            self._nack(frame.payload_type, GenericNackCode.UNKNOWN_PAYLOAD_TYPE, peer)
            return

        udp_handlers: dict[int, Callable[[DoIPFrame, tuple[str, int]], None]] = {
            PayloadType.ENTITY_STATUS_REQUEST: self._entity_status,
            PayloadType.POWER_MODE_INFORMATION_REQUEST: self._power_mode,
        }
        handler = udp_handlers.get(frame.payload_type)
        if handler is None:
            self._vehicle_identification(frame, peer)
            return
        handler(frame, peer)

    def _vehicle_identification(self, frame: DoIPFrame, peer: tuple[str, int]) -> None:
        config = self.server.config
        if frame.payload_type == PayloadType.VEHICLE_IDENTIFICATION_REQUEST:
            if frame.payload:
                self._nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH, peer)
                return
        elif frame.payload_type == PayloadType.VEHICLE_IDENTIFICATION_REQUEST_EID:
            if len(frame.payload) != 6:
                self._nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH, peer)
                return
            if frame.payload != config.eid:
                return  # addressed to another entity: stay silent
        else:
            if len(frame.payload) != 17:
                self._nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH, peer)
                return
            if frame.payload.decode("ascii", errors="replace") != config.vin:
                return

        self._send(PayloadType.VEHICLE_ANNOUNCEMENT, announcement_payload(config), peer)

    def _entity_status(self, frame: DoIPFrame, peer: tuple[str, int]) -> None:
        if frame.payload:
            self._nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH, peer)
            return
        self._send(PayloadType.ENTITY_STATUS_RESPONSE, entity_status_payload(self.server), peer)

    def _power_mode(self, frame: DoIPFrame, peer: tuple[str, int]) -> None:
        if frame.payload:
            self._nack(frame.payload_type, GenericNackCode.INVALID_PAYLOAD_LENGTH, peer)
            return
        self._send(PayloadType.POWER_MODE_INFORMATION_RESPONSE, bytes([PowerMode.READY]), peer)

    # ------------------------------------------------------------------ tx
    def _send(self, payload_type: int, payload: bytes, peer: tuple[str, int]) -> None:
        self.sock.sendto(DoIPFrame(payload_type, payload).encode(), peer)

    def _nack(self, payload_type: int | None, code: int, peer: tuple[str, int]) -> None:
        quoted = (payload_type or 0).to_bytes(2, "big")
        self._send(PayloadType.GENERIC_NEGATIVE_ACK, quoted + bytes([code]), peer)


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
        self._udp: _UdpEndpoint | None = None

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
            self._udp = _UdpEndpoint(self)
            self._udp.start()
        return self

    def stop(self) -> None:
        """Close the listener and every client socket."""
        self._stop.set()
        if self._udp is not None:
            self._udp.stop()
            self._udp = None
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
        """Return the state object of one ECU, creating it on first use.

        ``_states`` 会被多个连接线程同时读写，``dict`` 的"先查再写"不是原子操作：
        两个线程同时进来会各建一个 ``EcuState``，后写的覆盖先写的，先拿到的那个
        实例从此成了孤儿——对它做的 DID 写入、DTC 清除全部丢失。
        """
        with self._lock:
            state = self._states.get(logical_address)
            if state is None:
                state = EcuState(self.config)
                self._states[logical_address] = state
            return state

    def reset_state(self) -> None:
        """Restore DID values and DTCs to their factory defaults."""
        with self._lock:
            states = list(self._states.values())
        for state in states:
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
            # 先查硬上限，再起线程：否则空连接（连上不动、不激活）可以无限堆积，
            # 每个连接一个线程 + 一个句柄，几百个就足够把进程拖死。
            with self._lock:
                over_limit = len(self._connections) >= self.config.max_open_sockets
            if over_limit:
                logger.warning(
                    "connection limit %d reached, dropping %s:%d",
                    self.config.max_open_sockets,
                    *peer,
                )
                with contextlib.suppress(OSError):
                    client.close()
                continue
            connection = _Connection(self, client, peer)
            with self._lock:
                self._connections[client] = connection
            threading.Thread(
                target=connection.run,
                name=f"doip-conn-{peer[1]}",
                daemon=True,
            ).start()
