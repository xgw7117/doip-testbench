# Interactive UDS console for the virtual ECU.
#
#   python tools/uds_shell.py                     start a virtual ECU and talk to it
#   python tools/uds_shell.py --host 169.254.1.1  talk to an ECU that is already running
#
# Type hex bytes, e.g. "10 03", and press enter.
# Type "flash <file>" to run the whole programming sequence.

import argparse
import sys
import threading
import time
import zlib
from dataclasses import replace
from pathlib import Path

try:
    import importlib.util

    if importlib.util.find_spec("doipbench") is None:
        raise ImportError
except ImportError:
    sys.path.insert(0, str(Path(sys.argv[0]).resolve().parents[1] / "src"))

from doipbench.config import default_config
from doipbench.doip import DoIPFrame, DoIPServer, PayloadType
from doipbench.doip.client import DoIPClient, DoIPTimeout
from doipbench.uds.constants import NegativeResponseCode
from doipbench.uds.security import compute_key

ECU = 0x1001
PORT = 13400
KEEPALIVE_S = 2.0
SEND_LOCK = threading.RLock()
BLOCK = 256
FLASH_SIZE = 0x10000

HELP = "\n".join(
    [
        "  <hex>               send a request, e.g.  10 03",
        "  flash <file> [addr] program a binary, default address 0",
        "  unlock             27 01 + 27 02 in one go",
        "  secret <text>       change the key secret used by flash",
        "  ver                 compare key version: ECU vs local",
        "  disc                DoIP 0x0001 vehicle identification",
        "  status              DoIP 0x4001 entity status",
        "  alive               DoIP 0x0007 alive check",
        "  frame <type> [hex]  send any DoIP payload, e.g. frame 4003",
        "  q                   quit",
        "",
    ]
)


def hexs(data):
    return " ".join(f"{b:02X}" for b in data)


def nrc_name(code):
    try:
        return NegativeResponseCode(code).name
    except ValueError:
        return "unknown"


def send(client, payload):
    src = client.client_address
    dst = client.ecu_address
    body = src.to_bytes(2, "big") + dst.to_bytes(2, "big") + payload
    with SEND_LOCK:
        client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, body))
    print(f"  TX  0x8001  {src:04X} -> {dst:04X}  {hexs(payload)}")

    deadline = time.monotonic() + client.timeout
    while True:
        left = max(0.0, deadline - time.monotonic())
        try:
            frame = client.receive_frame(left)
        except DoIPTimeout:
            if len(payload) >= 2 and payload[1] & 0x80:
                print("  RX  <suppressed by 0x80>")
            else:
                print("  RX  <no response>")
            return None
        kind = frame.payload_type
        if kind == PayloadType.DIAGNOSTIC_MESSAGE_ACK:
            continue
        if kind == PayloadType.DIAGNOSTIC_MESSAGE_NACK:
            print(f"  RX  0x8003  {hexs(frame.payload)}")
            return None
        if kind != PayloadType.DIAGNOSTIC_MESSAGE:
            print(f"  RX  0x{kind:04X}  {hexs(frame.payload)}")
            continue
        if int.from_bytes(frame.payload[2:4], "big") != src:
            continue
        resp = frame.payload[4:]
        print(
            f"  RX  0x8001  {int.from_bytes(frame.payload[0:2], 'big'):04X} -> {src:04X}  "
            f"{hexs(resp)}"
            + (f"   NRC {nrc_name(resp[2])}" if len(resp) >= 3 and resp[0] == 0x7F else "")
        )
        return resp


def ok(resp):
    return resp is not None and len(resp) > 0 and resp[0] != 0x7F


def step(tag, text, resp):
    mark = "ok" if ok(resp) else "FAIL"
    print(f"[{tag}] {text:<12} {mark}")
    return ok(resp)


def ecu_key_version(client):
    # 0xF1A0 is OEM-defined: one byte saying which secret the ECU expects.
    # Real projects read it before 0x27 so a wrong secret shows up as a version
    # mismatch instead of an unexplained 0x35.
    resp = send(client, b"\x22\xf1\xa0")
    if resp is None or len(resp) < 4 or resp[0] != 0x62:
        return None
    return resp[3]


def keepalive(client, stop):
    # 3E 80: the ECU suppresses the positive response, so nothing has to be read
    # back here. Reset S3 before it expires, otherwise the session drops and the
    # unlock state goes with it.
    frame = (
        client.client_address.to_bytes(2, "big")
        + client.ecu_address.to_bytes(2, "big")
        + b"\x3e\x80"
    )
    while not stop.wait(KEEPALIVE_S):
        with SEND_LOCK:
            try:
                client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, frame))
            except OSError:
                return


def flash(client, path, address, secret):
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        print(f"  cannot read {path}: {exc}")
        return False
    print(f"\nflash {path}  {len(data)} bytes  ->  0x{address:04X}\n")

    if not step("1", "10 02 session", send(client, b"\x10\x02")):
        return False

    resp = send(client, b"\x27\x01")
    if not ok(resp) or len(resp) < 6:
        return False
    seed = resp[2:]
    key = compute_key(seed, secret)
    print(f"      seed {hexs(seed)}  key {hexs(key)}")
    if not step("2", "27 02 unlock", send(client, b"\x27\x02" + key)):
        return False

    if not step("3", "31 01 FF00", send(client, b"\x31\x01\xff\x00")):
        return False

    req = b"\x34\x00\x44" + address.to_bytes(4, "big") + len(data).to_bytes(4, "big")
    resp = send(client, req)
    if not ok(resp) or len(resp) < 4:
        return False
    block_max = int.from_bytes(resp[2:4], "big") - 2
    if block_max <= 0:
        block_max = BLOCK

    counter = 1
    sent = 0
    total = (len(data) + block_max - 1) // block_max
    index = 0
    while sent < len(data):
        chunk = data[sent : sent + block_max]
        resp = client.request_uds(bytes([0x36, counter]) + chunk)
        if not ok(resp) or len(resp) < 2 or resp[1] != counter:
            print(f"      block {counter} rejected: {hexs(resp or b'')}")
            return False
        sent += len(chunk)
        index += 1
        counter = (counter + 1) & 0xFF
        if index % 8 == 0 or sent == len(data):
            print(f"[4] 36 transfer   {index}/{total} blocks  {sent}/{len(data)} bytes")
    print("[4] 36 transfer   done")

    if not step("5", "37 exit", send(client, b"\x37")):
        return False

    # The ECU checksums the whole flash array, not just the bytes we sent:
    # untouched cells read as zero. Padding is what makes the two agree.
    image = bytearray(FLASH_SIZE)
    image[address : address + len(data)] = data
    crc = zlib.crc32(bytes(image)).to_bytes(4, "big")
    resp = send(client, b"\x31\x01\xff\x01" + crc)
    if not ok(resp) or resp[-1] != 0x00:
        print("      crc verify failed")
        return False
    print("[6] 31 01 FF01    verify      ok")

    send(client, b"\x11\x01")
    print("\nprogrammed. ECU reset and closed the connection - restart the shell to continue.")
    return True


def to_int(text):
    return int(text, 0)


def main():
    global FLASH_SIZE
    parser = argparse.ArgumentParser(description="interactive UDS console")
    parser.add_argument("--host", help="ECU ip; without it a virtual ECU is started")
    parser.add_argument("--port", type=to_int, default=PORT)
    parser.add_argument("--ecu", type=to_int, default=ECU, help="target logical address")
    parser.add_argument("--flash-size", type=to_int, default=FLASH_SIZE)
    parser.add_argument("--secret", help="seed/key secret, defaults to the config one")
    parser.add_argument("--no-keepalive", action="store_true", help="stop sending 3E 80")
    opts = parser.parse_args()

    port = opts.port
    ecu = opts.ecu
    FLASH_SIZE = opts.flash_size
    cfg = default_config()
    if opts.secret:
        # Same value on both sides: the ECU verifies with its config, the tester
        # derives with this one. Give them different secrets and 27 02 always
        # answers 0x35, which looks exactly like a wrong key on the tester.
        cfg = replace(cfg, security=replace(cfg.security, secret=opts.secret.encode()))
    secret = cfg.security.secret

    server = None
    if opts.host is None:
        server = DoIPServer(cfg, host="127.0.0.1", port=port).start()
        host = "127.0.0.1"
        print(f"virtual ECU listening on {host}:{port}")
        print(f"  secret {secret!r}  (ECU and tester share it)")
    else:
        host = opts.host
        print(f"connecting to ECU at {host}:{port}")
        print(f"  secret {secret!r}  (must match the ECU side)")

    client = DoIPClient(host, port=port, ecu_address=ecu)
    client.connect()
    result = client.routing_activation()
    if not result.accepted:
        print(f"routing activation refused: 0x{result.code:02X}")
        return 1
    stop = threading.Event()
    if not opts.no_keepalive:
        threading.Thread(target=keepalive, args=(client, stop), daemon=True).start()

    if secret == b"doipbench-demo":
        print("  warning: demo secret lives in source code, never ship it")
    ecu_ver = ecu_key_version(client)
    if ecu_ver is None:
        print("  key version: ECU does not publish 0xF1A0")
    elif ecu_ver != cfg.security.key_version:
        print(f"  key version: ECU v{ecu_ver}, local v{cfg.security.key_version}  MISMATCH")
        print("  27 02 will answer 0x35 until both sides use the same secret")
    else:
        print(f"  key version: v{ecu_ver} on both sides")

    print("routing activation accepted. type ? for help, q to quit.\n")

    try:
        while True:
            try:
                line = input("uds> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not line:
                continue
            head = line.split()[0].lower()

            if head in ("q", "quit", "exit"):
                break
            if head in ("?", "h", "help"):
                print(HELP)
                continue
            if head == "flash":
                parts = line.split()
                if len(parts) < 2:
                    print("usage: flash <file> [address]")
                    continue
                address = int(parts[2], 0) if len(parts) > 2 else 0
                flash(client, parts[1], address, secret)
                continue
            if head == "disc":
                ann = client.read_vehicle_identification()
                print(f"  VIN {ann.vin}  logical 0x{ann.logical_address:04X}  eid {ann.eid.hex()}")
                continue
            if head == "status":
                st = client.entity_status()
                print(
                    f"  node {st.node_type}  sockets {st.open_sockets}/{st.max_concurrent_sockets}"
                    f"  maxData 0x{st.max_data_size:X}"
                )
                continue
            if head == "alive":
                print(f"  alive response from 0x{client.alive_check():04X}")
                continue
            if head == "ver":
                v = ecu_key_version(client)
                print(f"  ECU v{v}   local v{cfg.security.key_version}   secret {secret!r}")
                continue
            if head == "unlock":
                resp = send(client, b"\x27\x01")
                if not ok(resp) or len(resp) < 6:
                    continue
                seed = resp[2:]
                key = compute_key(seed, secret)
                print(f"      seed {hexs(seed)}  key {hexs(key)}")
                send(client, b"\x27\x02" + key)
                continue
            if head == "frame":
                parts = line.split(maxsplit=1)
                if len(parts) < 2:
                    print("usage: frame <type> [payload]   e.g. frame 4003")
                    continue
                try:
                    raw = bytes.fromhex(parts[1].replace(" ", ""))
                except ValueError:
                    print("  not hex")
                    continue
                if len(raw) < 2:
                    print("  need at least the 2-byte payload type")
                    continue
                ptype = int.from_bytes(raw[:2], "big")
                client.send_frame(DoIPFrame(ptype, raw[2:]))
                print(f"  TX  0x{ptype:04X}  {hexs(raw[2:])}")
                try:
                    got = client.receive_frame(1.0)
                except DoIPTimeout:
                    print("  RX  <no response>")
                    continue
                print(f"  RX  0x{got.payload_type:04X}  {hexs(got.payload)}")
                continue
            if head == "secret":
                secret = line.split(maxsplit=1)[1].encode()
                print(f"secret set to {secret!r}")
                continue

            try:
                payload = bytes.fromhex(line.replace(" ", ""))
            except ValueError:
                print("  not hex. try: 10 03")
                continue
            send(client, payload)
    finally:
        stop.set()
        client.close()
        if server is not None:
            server.stop()
    return 0


sys.exit(main())
