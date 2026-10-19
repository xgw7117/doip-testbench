"""doip-testbench: a hardware-free DoIP/UDS test bench.

The package is intentionally dependency-light at runtime.  PyYAML is the only
runtime dependency; the protocol stacks (DoIP, UDS, SOME/IP, gPTP, VLAN,
ISO-TP) are implemented in this repository so that every byte on the wire can
be asserted by a test case.
"""

from __future__ import annotations

__version__ = "0.5.0"
__all__ = ["__version__"]
