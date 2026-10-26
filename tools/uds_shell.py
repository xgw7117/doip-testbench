"""交互式 UDS 终端，带 TesterPresent 保活。"""

import contextlib
import threading
import time

from doipbench.doip import DoIPClient, DoIPTimeout

client = DoIPClient(port=13400).connect()
print(f"路由激活: 0x{client.routing_activation().response_code:02X}")

lock = threading.Lock()
running = True


def keep_alive() -> None:
    while running:
        time.sleep(2)
        with lock, contextlib.suppress(Exception):
            client.request_uds(b"\x3e\x00", timeout=1)


threading.Thread(target=keep_alive, daemon=True).start()

try:
    while True:
        raw = input("\nUDS> ").strip()
        if raw.lower() in {"q", "quit", "exit"}:
            break
        if not raw:
            continue
        with lock:
            try:
                print(f"     <- {client.request_uds(bytes.fromhex(raw)).hex(' ').upper()}")
            except DoIPTimeout:
                print("     <- 超时，ECU 没回")
            except Exception as exc:
                print(f"     <- 错误: {exc}")
finally:
    running = False
    client.close()
