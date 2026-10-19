"""Seed/key handling for UDS service 0x27.

The algorithm below is a *demo*: it is deliberately simple so that the closed
loop can be reproduced without an OEM DLL.  Real projects load the OEM seed/key
library (or a HSM-backed service) behind the same interface.
"""

from __future__ import annotations

import hashlib

from ..config import SecurityConfig


def compute_key(seed: bytes, secret: bytes) -> bytes:
    """Derive the expected key from a seed.

    ``key = seed XOR SHA-256(secret || seed)[:len(seed)]``
    """
    digest = hashlib.sha256(secret + seed).digest()
    return bytes(s ^ k for s, k in zip(seed, digest, strict=False))


class SeedGenerator:
    """Deterministic seed source.

    Seeds are reproducible for a given ``(secret, counter)`` pair, which keeps
    failing test cases debuggable, but never repeat within a power cycle.
    """

    def __init__(self, config: SecurityConfig) -> None:
        self._config = config
        self._counter = 0

    def next_seed(self) -> bytes:
        self._counter += 1
        digest = hashlib.sha256(self._config.secret + self._counter.to_bytes(4, "big")).digest()
        return digest[: self._config.seed_length]

    def reset(self) -> None:
        self._counter = 0
