#!/usr/bin/env python3
"""补 0x8002 诊断消息确认（211 -> 213）。放在仓库根目录运行，幂等。"""

import contextlib
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent

ACK_CLASS = '''class DiagnosticAckCode(IntEnum):
    """Acknowledgement code carried by payload type 0x8002."""

    ACCEPTED = 0x00


'''

ACK_BLOCK = '''        if self.server.config.ack_diagnostic_messages:
            # ISO 13400-2 9.5.2：先确认再回诊断响应。SA 是发出这一帧的实体，
            # 不是请求里的目标地址；照抄请求顺序客户端会丢弃然后超时。
            ack = (
                self.server.config.entity_address.to_bytes(2, "big")
                + source.to_bytes(2, "big")
                + bytes([DiagnosticAckCode.ACCEPTED])
            )
            self._send(PayloadType.DIAGNOSTIC_MESSAGE_ACK, ack)

'''

TESTS = '''@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic acknowledgement")
def test_diagnostic_message_is_acknowledged_before_the_response(
    routed_client: DoIPClient, ecu_config: EcuConfig
) -> None:
    """0x8002 first, then 0x8001 carrying the UDS answer."""
    routed_client.send_diagnostic(b"\\x22\\xf1\\x90")

    ack = routed_client.receive_frame()
    assert ack.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_ACK
    assert ack.payload == (
        ecu_config.logical_address.to_bytes(2, "big")
        + routed_client.client_address.to_bytes(2, "big")
        + bytes([DiagnosticAckCode.ACCEPTED])
    )

    response = routed_client.receive_frame()
    assert response.payload_type == PayloadType.DIAGNOSTIC_MESSAGE
    assert response.payload[4:].startswith(b"\\x62\\xf1\\x90")


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic acknowledgement")
def test_acknowledgement_can_be_disabled_for_internal_nodes() -> None:
    """A node behind a gateway must not ack: the edge node already did."""
    config = default_config(ack_diagnostic_messages=False)
    with DoIPServer(config) as server:
        with DoIPClient(port=server.port, timeout=2.0).connect() as client:
            assert client.routing_activation().accepted
            client.send_diagnostic(b"\\x22\\xf1\\x90")
            frame = client.receive_frame()
            assert frame.payload_type == PayloadType.DIAGNOSTIC_MESSAGE
            assert frame.payload[4:].startswith(b"\\x62\\xf1\\x90")


'''

ACK_ANCHOR = '''@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic messages")
def test_truncated_diagnostic_message_is_nacked(client: DoIPClient) -> None:'''

INTEROP = '''"""Drive the virtual ECU with python-doipclient, a third-party implementation.

    python tools/interop_check.py              # starts a throwaway ECU on 13400
    python tools/interop_check.py --external   # talks to an ECU already listening
"""

from __future__ import annotations

import argparse
import sys

import udsoncan
from doipclient import DoIPClient
from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client

from doipbench.config import default_config
from doipbench.doip import DoIPServer

ECU = 0x1001
DISCOVERY_PORT = 13400  # get_entity() hard-codes it, so an in-process ECU sits here

CONFIG = dict(udsoncan.configs.default_client_config)
CONFIG["data_identifiers"] = {0xF190: udsoncan.AsciiCodec(17)}


def run(host: str, port: int) -> int:
    try:
        address, ann = DoIPClient.get_entity(ecu_ip_address=host)
    except TimeoutError:
        print(f"[FAIL] discovery      nothing answered 0x0001 on UDP {DISCOVERY_PORT}")
        return 1
    print(
        f"[ok] discovery      {address[0]}:{address[1]} vin={ann.vin} "
        f"logical=0x{ann.logical_address:04X} eid={ann.eid.hex()} gid={ann.gid.hex()} "
        f"further_action=0x{ann.further_action_required:02X}"
    )

    client = DoIPClient(host, ECU, tcp_port=port)
    try:
        print("[ok] activation     routing activation accepted")
        print(f"[ok] entity status  {client.request_entity_status()}")
        try:
            with Client(DoIPClientUDSConnector(client), config=CONFIG) as uds:
                r = uds.read_data_by_identifier(0xF190)
                print(f"[ok] uds 0x22 F190  {r.service_data.values[0xF190]!r}")
                uds.tester_present()
                print("[ok] uds 0x3E 00    session kept alive")
        except TimeoutError:
            print("[FAIL] uds 0x22     no diagnostic response before the deadline")
            print("       python-doipclient waits for 0x8002 and drops a bare 0x8001")
            return 1
    finally:
        client.close()

    print("\\ninteroperable: 5/5 steps passed")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DISCOVERY_PORT)
    ap.add_argument("--external", action="store_true")
    args = ap.parse_args()

    if not args.external and args.port != DISCOVERY_PORT:
        print(f"[FAIL] --port {args.port}: 0x0001 always goes to UDP {DISCOVERY_PORT}")
        return 2

    server = None
    if not args.external:
        try:
            server = DoIPServer(default_config(), host=args.host, port=args.port).start()
        except OSError as exc:
            print(f"[FAIL] cannot bind {args.host}:{args.port}: {exc}")
            print("       another ECU is running; use --external")
            return 2
        print(f"[..] virtual ECU     {args.host}:{args.port} (started in-process)")
    try:
        return run(args.host, args.port)
    finally:
        if server is not None:
            server.stop()


if __name__ == "__&#8203;main__":
    sys.exit(main())
'''

EDITS = [
    (
        "src/doipbench/config.py",
        "ack_diagnostic_messages",
        "    p2_ms: int = 50\n",
        "    #: 收到 0x8001 后是否先回一帧 0x8002。python-doipclient 要等到确认才认诊断\n"
        "    #: 响应；直连的边缘节点开启，网关后面的内部节点关闭（否则 tester 收两份确认）。\n"
        "    ack_diagnostic_messages: bool = True\n"
        "    p2_ms: int = 50\n",
    ),
    (
        "src/doipbench/doip/constants.py",
        "class DiagnosticAckCode",
        'class DiagnosticNackCode(IntEnum):\n    """NACK codes carried by payload type 0x8003."""',
        ACK_CLASS + 'class DiagnosticNackCode(IntEnum):\n    """NACK codes carried by payload type 0x8003."""',
    ),
    (
        "src/doipbench/doip/server.py",
        "    DiagnosticAckCode,",
        "    DiagnosticNackCode,\n",
        "    DiagnosticAckCode,\n    DiagnosticNackCode,\n",
    ),
    (
        "src/doipbench/doip/server.py",
        "ack_diagnostic_messages",
        "        uds_response = uds.handle(uds_request)\n",
        ACK_BLOCK + "        uds_response = uds.handle(uds_request)\n",
    ),
    (
        "src/doipbench/doip/__init__.py",
        "    DiagnosticAckCode,",
        "    DiagnosticNackCode,\n",
        "    DiagnosticAckCode,\n    DiagnosticNackCode,\n",
    ),
    (
        "src/doipbench/doip/__init__.py",
        '"DiagnosticAckCode"',
        '    "DiagnosticNackCode",\n',
        '    "DiagnosticAckCode",\n    "DiagnosticNackCode",\n',
    ),
    (
        "tests/conformance/test_doip_conformance.py",
        "    DiagnosticAckCode,",
        "    DiagnosticNackCode,\n",
        "    DiagnosticAckCode,\n    DiagnosticNackCode,\n",
    ),
    (
        "tests/conformance/test_doip_conformance.py",
        "test_diagnostic_message_is_acknowledged_before_the_response",
        ACK_ANCHOR,
        TESTS + ACK_ANCHOR,
    ),
    (
        "tests/functional/test_gateway.py",
        "DIAGNOSTIC_MESSAGE_ACK",
        "    gateway_client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, payload))\n"
        "\n"
        "    frame = gateway_client.receive_frame()",
        "    gateway_client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, payload))\n"
        "\n"
        "    # 网关是边缘节点：转发前先代答 0x8002，所以确认先到。\n"
        '    ack = gateway_client.receive_frame()\n'
        "    assert ack.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_ACK\n"
        '    assert int.from_bytes(ack.payload[0:2], "big") == GATEWAY\n'
        "\n"
        "    frame = gateway_client.receive_frame()",
    ),
]

README_SECTION = """## 互操作性

自己测自己不算证明：套件里的 client 和 server 是同一套代码写的，两边一起错也照样全绿。
`tools/interop_check.py` 换一个第三方实现（python-doipclient）当 tester，走完车辆发现、
路由激活、实体状态、UDS 读写四步：

```bash
pip install doipclient udsoncan
python tools/interop_check.py     # interoperable: 5/5 steps passed
```

脚本自己拉起一台临时 ECU（127.0.0.1:13400，跑完即关），不需要另开终端；
要打真台架加 `--external --host <ecu-ip>`。

这一步抓出过一个真问题：早期实现不回 `0x8002` 正向确认，`python-doipclient`
收到 `0x8001` 后判定为意外消息直接丢弃，在 tester 侧表现成 ECU 不响应。

"""


def apply(path: pathlib.Path, marker: str, old: str, new: str) -> str:
    text = path.read_text(encoding="utf-8")
    if marker in text:
        return "skip"
    if old not in text:
        return "MISS"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return "ok"


def main() -> int:
    with contextlib.suppress(AttributeError, ValueError):
        sys.stdout.reconfigure(line_buffering=True)

    states = []
    for rel, marker, old, new in EDITS:
        path = REPO / rel
        state = apply(path, marker, old, new) if path.is_file() else "MISS"
        states.append((state, rel))
        print(f"[{state:>4}] {rel}")

    script = REPO / "tools" / "interop_check.py"
    current = script.read_text(encoding="utf-8") if script.exists() else None
    if current == INTEROP:
        print("[skip] tools/interop_check.py")
    else:
        script.write_text(INTEROP, encoding="utf-8")
        print("[  ok] tools/interop_check.py")

    readme = REPO / "README.md"
    original = readme.read_text(encoding="utf-8")
    text = original
    if "## 互操作性" not in text:
        text = text.replace("\n## 目录\n", "\n" + README_SECTION + "\n## 目录\n", 1)
    text = (
        text.replace("211 条自动化用例", "213 条自动化用例")
        .replace("**当被测对象**：211 条用例", "**&#8203;当被测对象**：213 条用例")
        .replace("一共 211 条", "一共 213 条")
        .replace(
            "| 协议一致性 | 83 | 41 条 UDS 服务用例（YAML 数据驱动）+ 30 条 TCP 报文用例",
            "| 协议一致性 | 85 | 41 条 UDS 服务用例（YAML 数据驱动）+ 32 条 TCP 报文用例",
        )
    )
    if text != original:
        readme.write_text(text, encoding="utf-8")
        print("[  ok] README.md")
    else:
        print("[skip] README.md")

    diagram = REPO / "tools" / "render_architecture.py"
    dorig = diagram.read_text(encoding="utf-8")
    dtext = dorig.replace("211 条自动化用例", "213 条自动化用例")
    if dtext != dorig:
        diagram.write_text(dtext, encoding="utf-8")
        print("[  ok] tools/render_architecture.py")
    else:
        print("[skip] tools/render_architecture.py")

    missing = [rel for state, rel in states if state == "MISS"]
    if missing:
        print("\n未匹配的锚点（这些没改，其余已应用）：")
        for rel in dict.fromkeys(missing):
            print("  -", rel)

    print("\n运行测试...")
    return subprocess.call([sys.executable, "-m", "pytest", "-q"], cwd=REPO)


if __name__ == "__&#8203;main__":
    sys.exit(main())
