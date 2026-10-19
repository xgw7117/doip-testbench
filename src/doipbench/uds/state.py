"""Mutable ECU state shared between DoIP connections.

A real ECU keeps its DID values and DTC memory across diagnostic sessions, so
the virtual one does too.  State is guarded by a re-entrant lock because the
DoIP server handles every TCP connection in its own thread.
"""

from __future__ import annotations

import copy
import threading

from ..config import DtcDefinition, EcuConfig


class EcuState:
    """DID memory and DTC store of the virtual ECU."""

    def __init__(self, config: EcuConfig) -> None:
        self._config = config
        self._lock = threading.RLock()
        self._did_values: dict[int, bytes] = {}
        self._dtcs: list[DtcDefinition] = []
        self.reset()

    def reset(self) -> None:
        """Restore the factory state (used between test cases)."""
        with self._lock:
            self._did_values = {did: bytes(defn.value) for did, defn in self._config.dids.items()}
            self._dtcs = copy.deepcopy(self._config.dtcs)

    # ------------------------------------------------------------------ DID
    def read_did(self, did: int) -> bytes:
        with self._lock:
            return self._did_values[did]

    def write_did(self, did: int, value: bytes) -> None:
        with self._lock:
            if did not in self._did_values:
                raise KeyError(f"DID 0x{did:04X} is not writable")
            self._did_values[did] = bytes(value)

    # ------------------------------------------------------------------ DTC
    def dtcs(self, status_mask: int = 0xFF) -> list[DtcDefinition]:
        """Return DTCs whose status matches ``status_mask`` (bitwise AND)."""
        with self._lock:
            return [copy.deepcopy(dtc) for dtc in self._dtcs if dtc.status & status_mask]

    def all_dtcs(self) -> list[DtcDefinition]:
        with self._lock:
            return copy.deepcopy(self._dtcs)

    def find_dtc(self, code: int) -> DtcDefinition | None:
        with self._lock:
            for dtc in self._dtcs:
                if dtc.code == code:
                    return copy.deepcopy(dtc)
            return None
