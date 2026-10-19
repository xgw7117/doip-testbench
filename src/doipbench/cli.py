"""Command line interface.

Four sub-commands keep the bench usable outside pytest:

``serve``     start the virtual ECU and keep it running
``run``       execute a YAML case file against a running ECU
``identify``  read the vehicle announcement from a DoIP entity
``frame``     decode a raw DoIP frame on the command line (great for debugging)
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from collections.abc import Sequence

from . import __version__
from .config import EcuConfig, SecurityConfig, default_config
from .doip import DoIPClient, DoIPServer, DoIPTimeout
from .doip.constants import PayloadType
from .doip.frame import decode_frame
from .testing.cases import Case, load_cases
from .uds import compute_key

LOGGER = logging.getLogger("doipbench")


def _build_config(args: argparse.Namespace) -> EcuConfig:
    security = SecurityConfig(
        max_attempts=args.max_attempts,
        delay_seconds=args.lockout_delay,
    )
    return default_config(vin=args.vin, security=security)


def _apply_precondition(case: Case, client: DoIPClient, config: EcuConfig) -> str | None:
    """Establish the case precondition; return an error message on failure."""
    if case.precondition.session is not None:
        response = client.change_session(case.precondition.session)
        if response[:1] != b"\x50":
            return f"cannot enter session 0x{case.precondition.session:02X}: {response.hex(' ')}"
    if case.precondition.unlock or case.precondition.seed:
        response = client.request_uds(b"\x27\x01")
        if not response or response[0] != 0x67:
            return f"seed request failed: {response.hex(' ')}"
        if case.precondition.unlock:
            key = compute_key(response[2:], config.security.secret)
            unlocked = client.request_uds(b"\x27\x02" + key)
            if unlocked[:2] != b"\x67\x02":
                return f"unlock failed: {unlocked.hex(' ')}"
    return None


def _execute_case(case: Case, client: DoIPClient, config: EcuConfig) -> tuple[bool, str]:
    error = _apply_precondition(case, client, config)
    if error:
        return False, error

    try:
        if case.expect_no_response:
            try:
                client.request_uds(case.request, timeout=0.3)
            except DoIPTimeout:
                return True, "no response (expected)"
            return False, "ECU answered although the response should be suppressed"
        response = client.request_uds(case.request)
    except DoIPTimeout:
        return False, "timeout waiting for a response"

    if case.expected_nrc is not None:
        expected = bytes([0x7F, case.service_id, case.expected_nrc])
        if response != expected:
            return False, f"expected {expected.hex(' ')}, got {response.hex(' ')}"
        return True, response.hex(" ").upper()
    if case.expected is not None and response.startswith(case.expected):
        return True, response.hex(" ").upper()
    assert case.expected is not None
    return False, f"expected prefix {case.expected.hex(' ')}, got {response.hex(' ')}"


# --------------------------------------------------------------------- commands
def cmd_serve(args: argparse.Namespace) -> int:
    config = _build_config(args)
    server = DoIPServer(config, host=args.host, port=args.port).start()
    print("doip-testbench virtual ECU")
    print(f"  VIN              {config.vin}")
    print(f"  logical address  0x{config.logical_address:04X}")
    print(f"  listening        {server.host}:{server.port} (TCP)")
    print("  press Ctrl+C to stop")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        server.stop()
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    config = _build_config(args)
    cases = load_cases(args.cases)
    print(f"loaded {len(cases)} cases from {args.cases}")

    server: DoIPServer | None = None
    if args.start_ecu:
        server = DoIPServer(config, host=args.host, port=args.port).start()
        host, port = server.host, server.port
        print(f"started virtual ECU on {host}:{port}")
    else:
        host, port = args.host, args.port

    passed = failed = 0
    failures: list[tuple[str, str]] = []

    try:
        for case in cases:
            # Every case gets a clean connection, exactly like the pytest suite.
            if server is not None:
                server.reset_state()
            client = DoIPClient(host=host, port=port, timeout=args.timeout).connect()
            try:
                activation = client.routing_activation()
                if not activation.accepted:
                    print(f"routing activation rejected: 0x{activation.response_code:02X}")
                    return 2
                ok, detail = _execute_case(case, client, config)
            finally:
                client.close()

            if ok:
                passed += 1
                print(f"  PASS  {case.id:<14} {case.title}")
            else:
                failed += 1
                failures.append((case.id, detail))
                print(f"  FAIL  {case.id:<14} {case.title}")
                print(f"        {detail}")
    finally:
        if server is not None:
            server.stop()

    print(f"\n{passed} passed, {failed} failed, {len(cases)} total")
    if failures:
        print("\nfailures:")
        for case_id, detail in failures:
            print(f"  {case_id}: {detail}")
    return 0 if failed == 0 else 1


def cmd_identify(args: argparse.Namespace) -> int:
    with DoIPClient(
        args.host, args.port, client_address=args.client_address, timeout=args.timeout
    ) as client:
        announcement = client.read_vehicle_identification()
        print(f"VIN              {announcement.vin}")
        print(f"logical address  0x{announcement.logical_address:04X}")
        print(f"EID              {announcement.eid.hex(' ').upper()}")
        print(f"GID              {announcement.gid.hex(' ').upper()}")
        print(f"further action   0x{announcement.further_action:02X}")
    return 0


def cmd_frame(args: argparse.Namespace) -> int:
    raw = bytes.fromhex(args.hex.replace(" ", "").replace("0x", ""))
    frame = decode_frame(raw)
    print(f"protocol version  0x{frame.protocol_version:02X}")
    print(f"payload type      0x{frame.payload_type:04X} ({_payload_name(frame.payload_type)})")
    print(f"payload length    {len(frame.payload)}")
    print(f"payload           {frame.payload.hex(' ').upper()}")

    if frame.payload_type == PayloadType.DIAGNOSTIC_MESSAGE and len(frame.payload) >= 4:
        print(f"  source address  0x{int.from_bytes(frame.payload[0:2], 'big'):04X}")
        print(f"  target address  0x{int.from_bytes(frame.payload[2:4], 'big'):04X}")
        print(f"  UDS              {frame.payload[4:].hex(' ').upper()}")
    return 0


def _payload_name(payload_type: int) -> str:
    try:
        return PayloadType(payload_type).name
    except ValueError:
        return "UNKNOWN"


# ----------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="doipbench",
        description="Hardware-free DoIP/UDS test bench",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    def add_ecu_options(target: argparse.ArgumentParser) -> None:
        target.add_argument("--host", default="127.0.0.1")
        target.add_argument("--port", type=int, default=13400)
        target.add_argument("--vin", default="LSVAA2BM5N2123456")
        target.add_argument("--max-attempts", type=int, default=3)
        target.add_argument("--lockout-delay", type=float, default=5.0)
        target.add_argument("--timeout", type=float, default=2.0)
        target.add_argument("--client-address", type=lambda v: int(v, 0), default=0x0E00)

    serve = sub.add_parser("serve", help="run the virtual ECU")
    add_ecu_options(serve)
    serve.set_defaults(func=cmd_serve)

    run = sub.add_parser("run", help="execute a YAML case file")
    run.add_argument("cases", help="path to a YAML case file")
    add_ecu_options(run)
    run.add_argument(
        "--start-ecu",
        action="store_true",
        help="start a local virtual ECU instead of connecting to a remote one",
    )
    run.set_defaults(func=cmd_run)

    identify = sub.add_parser("identify", help="read the vehicle announcement")
    add_ecu_options(identify)
    identify.set_defaults(func=cmd_identify)

    frame = sub.add_parser("frame", help="decode a raw DoIP frame")
    frame.add_argument("hex", help='frame bytes, e.g. "02 FD 00 01 00 00 00 00"')
    frame.set_defaults(func=cmd_frame)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)-7s %(name)s: %(message)s",
    )
    try:
        return int(args.func(args))
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
