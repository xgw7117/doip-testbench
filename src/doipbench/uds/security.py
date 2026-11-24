"""Seed/key handling for UDS service 0x27.

The algorithm below is a *demo*: it is deliberately simple so that the closed
loop can be reproduced without an OEM DLL.  Real projects load the OEM seed/key
library (or a HSM-backed service) behind the same interface.
"""

from __future__ import annotations

import hashlib
import secrets

from ..config import SecurityConfig


def compute_key(seed: bytes, secret: bytes) -> bytes:
    """Derive the expected key from a seed.

    ``key = seed XOR SHA-256(secret || seed)[:len(seed)]``
    """
    digest = hashlib.sha256(secret + seed).digest()
    return bytes(s ^ k for s, k in zip(seed, digest, strict=False))


class SeedGenerator:
    """Seed source for service 0x27.

    Seeds are deterministic for a given ``(secret, counter)`` pair so a failing
    case can be reproduced, but the counter starts at a random offset per power
    cycle.  Without that offset the first seed after every reset is
    ``SHA256(secret || 00000001)`` - a constant that can be computed offline
    from the published secret, which turns 27 01/27 02 into a replayable pair.
    """

    def __init__(self, config: SecurityConfig, start: int | None = None) -> None:
        self._config = config
        self._counter = self._initial_counter() if start is None else start
        self._fixed_start = start

    @staticmethod
    def _initial_counter() -> int:
        # 0xFFFFFFFF is reserved for "unused"; any other value is a valid start.
        return secrets.randbelow(0xFFFF_FFFF - 1) + 1

    def next_seed(self) -> bytes:
        self._counter = (self._counter + 1) & 0xFFFFFFFF
        digest = hashlib.sha256(self._config.secret + self._counter.to_bytes(4, "big")).digest()
        return digest[: self._config.seed_length]

    def reset(self) -> None:
        self._counter = self._initial_counter() if self._fixed_start is None else self._fixed_start
