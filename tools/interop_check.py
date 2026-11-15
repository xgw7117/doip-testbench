# Interoperability check: drive the virtual ECU with python-doipclient.
#
# A stack that only ever talks to itself proves nothing. This uses a client
# written by somebody else, so green here means another implementation agrees
# with our bytes.
#
#   python tools/interop_check.py              start a throwaway ECU on 13400
#   python tools/interop_check.py --external   use the ECU already listening

import sys

import udsoncan
from doipclient import DoIPClient
from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client

from doipbench.config import default_config
from doipbench.doip import DoIPServer

ECU = 0x1001
PORT = 13400

CFG = dict(udsoncan.configs.default_client_config)
CFG["data_identifiers"] = {0xF190: udsoncan.AsciiCodec(17)}


def main() -> int:
    host = "127.0.0.1"
    server = None

    if "--external" not in sys.argv:
        try:
            server = DoIPServer(default_config(), host=host, port=PORT).start()
        except OSError as exc:
            print(f"[FAIL] cannot bind {host}:{PORT}: {exc}")
            print("       an ECU is already running; retry with --external")
            return 2
        print(f"[..] virtual ECU     {host}:{PORT} (started in-process)")

    try:
        try:
            _, ann = DoIPClient.get_entity(ecu_ip_address=host)
        except TimeoutError:
            print(f"[FAIL] discovery      nothing answered 0x0001 on UDP {PORT}")
            return 1

        print(
            f"[ok] discovery      vin={ann.vin} "
            f"logical=0x{ann.logical_address:04X} "
            f"eid={ann.eid.hex()} gid={ann.gid.hex()} "
            f"further_action=0x{ann.further_action_required:02X}"
        )

        client = DoIPClient(host, ECU)
        try:
            print("[ok] activation     routing activation accepted")
            print(f"[ok] entity status  {client.request_entity_status()}")
            try:
                with Client(DoIPClientUDSConnector(client), config=CFG) as uds:
                    vin = uds.read_data_by_identifier(0xF190).service_data.values[0xF190]
                    print(f"[ok] uds 0x22 F190  {vin!r}")
                    uds.tester_present()
                    print("[ok] uds 0x3E 00    session kept alive")
            except TimeoutError:
                print("[FAIL] uds 0x22     no diagnostic response before the deadline")
                print("       python-doipclient waits for 0x8002 and drops a bare 0x8001")
                return 1
        finally:
            client.close()
    finally:
        if server is not None:
            server.stop()

    print("\ninteroperable: 5/5 steps passed")
    return 0


sys.exit(main())
