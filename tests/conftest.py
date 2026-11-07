"""Shared pytest fixtures.

The virtual ECU is started once per session on an ephemeral port; every test
gets a fresh TCP connection and a freshly reset DID/DTC memory.  That keeps the
suite fast (no rebinding per case) without leaking state between tests.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

from doipbench.config import EcuConfig, SecurityConfig, default_config
from doipbench.doip import DoIPClient, DoIPServer
from doipbench.uds import Session, compute_key

DATA_DIR = Path(__file__).parent / "data"


def wait_for_port(host: str, port: int, timeout: float = 30.0, interval: float = 0.5) -> None:
    """Block until ``host:port`` accepts a TCP connection.

    A virtual ECU bound in-process is ready immediately, but a real ECU needs a
    few seconds to boot and a Docker container needs a few seconds to listen.
    Calling this from the fixture means the same suite works against all three
    without sprinkling ``sleep()`` through the tests.
    """
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(interval)
    raise TimeoutError(
        f"{host}:{port} did not accept connections within {timeout:.0f}s"
    ) from last_error


@pytest.fixture(scope="session")
def ecu_config() -> EcuConfig:
    """Configuration used by the shared virtual ECU."""
    return default_config(security=SecurityConfig(max_attempts=3, delay_seconds=0.5))


@pytest.fixture(scope="session")
def ecu_server(ecu_config: EcuConfig) -> Iterator[DoIPServer]:
    """Session scoped virtual ECU listening on 127.0.0.1:<ephemeral>."""
    server = DoIPServer(ecu_config).start()
    try:
        # In-process the port is already bound, but the call documents the
        # contract and becomes essential when the ECU moves to a real bench.
        wait_for_port(server.host, server.port, timeout=5.0)
        yield server
    finally:
        server.stop()


@pytest.fixture
def client(ecu_server: DoIPServer) -> Iterator[DoIPClient]:
    """Connected but *not* routing-activated tester."""
    ecu_server.reset_state()
    instance = DoIPClient(port=ecu_server.port, timeout=2.0).connect()
    try:
        yield instance
    finally:
        instance.close()


@pytest.fixture
def routed_client(client: DoIPClient) -> DoIPClient:
    """Tester with a successful routing activation."""
    result = client.routing_activation()
    assert result.accepted, f"routing activation failed: 0x{result.response_code:02X}"
    return client


@pytest.fixture
def extended_client(routed_client: DoIPClient) -> DoIPClient:
    """Tester in the extended diagnostic session."""
    response = routed_client.change_session(Session.EXTENDED)
    assert response[:2] == b"\x50\x03", response.hex()
    return routed_client


@pytest.fixture
def unlocked_client(extended_client: DoIPClient, ecu_config: EcuConfig) -> DoIPClient:
    """Tester in extended session with security level 1 unlocked."""
    response = extended_client.request_uds(b"\x27\x01")
    assert response[0] == 0x67, response.hex()
    seed = response[2:]
    key = compute_key(seed, ecu_config.security.secret)
    unlocked = extended_client.request_uds(b"\x27\x02" + key)
    assert unlocked == b"\x67\x02", unlocked.hex()
    return extended_client
