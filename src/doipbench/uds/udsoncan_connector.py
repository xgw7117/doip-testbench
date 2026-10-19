"""udsoncan adapter.

This is the interoperability bridge: it lets the project be driven by the
well-known ``udsoncan`` client while keeping the in-house DoIP stack.  The
adapter only implements the four methods ``udsoncan.connections.BaseConnection``
requires, which is a good example of how thin a transport integration can be.
"""

from __future__ import annotations

from typing import Any

from udsoncan.connections import BaseConnection

from ..doip.client import DoIPClient, DoIPTimeout


class DoIPConnection(BaseConnection):
    """``udsoncan`` connection backed by :class:`DoIPClient`."""

    def __init__(self, client: DoIPClient) -> None:
        super().__init__("DoIP")
        self._client = client

    def open(self) -> DoIPConnection:
        self._client.connect()
        return self

    def close(self) -> None:
        self._client.close()

    def is_open(self) -> bool:
        return self._client.is_open

    def empty_rxqueue(self) -> None:
        self._client.clear_rx()

    def specific_send(self, payload: bytes, timeout: float | None = None) -> None:
        del timeout  # the DoIP client applies its own request timeout
        self._client.send_diagnostic(payload)

    def specific_wait_frame(self, timeout: float | None = None) -> bytes | None:
        try:
            return self._client.wait_diagnostic(timeout)
        except DoIPTimeout:
            return None

    def __enter__(self) -> Any:  # pragma: no cover - trivial
        return self.open()
