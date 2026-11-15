#!/usr/bin/env python3
"""补 0x8002 诊断确认（211 -> 213）。放在仓库根目录运行，幂等。"""

import pathlib
import subprocess
import sys

R = pathlib.Path(__file__).resolve().parent

ACK_ENUM = '''class DiagnosticAckCode(IntEnum):
    """Acknowledgement code carried by payload type 0x8002."""

    ACCEPTED = 0x00


'''

ACK_BLOCK = '''        if self.server.config.ack_diagnostic_messages:
            # SA 是发出这一帧的实体，不是请求里的目标地址。
            ack = (
                self.server.config.entity_address.to_bytes(2, "big")
                + source.to_bytes(2, "big")
                + bytes([DiagnosticAckCode.ACCEPTED])
            )
            self._send(PayloadType.DIAGNOSTIC_MESSAGE_ACK, ack)

'''

GW_OLD = (
    "    gateway_client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, payload))\n"
    "    frame = gateway_client.receive_frame()"
)
GW_NEW = (
    "    gateway_client.send_frame(DoIPFrame(PayloadType.DIAGNOSTIC_MESSAGE, payload))\n"
    "\n"
    "    ack = gateway_client.receive_frame()\n"
    "    assert ack.payload_type == PayloadType.DIAGNOSTIC_MESSAGE_ACK\n"
    '    assert int.from_bytes(ack.payload[0:2], "big") == GATEWAY\n'
    "\n"
    "    frame = gateway_client.receive_frame()"
)

TEST_SRC = '''"""0x8002 diagnostic message acknowledgement (ISO 13400-2 9.5.2)."""

from __future__ import annotations

import allure
import pytest

from doipbench.config import EcuConfig, default_config
from doipbench.doip import DoIPClient, DoIPServer, PayloadType
from doipbench.doip.constants import DiagnosticAckCode


@pytest.mark.conformance
@allure.feature("DoIP conformance")
@allure.story("Diagnostic acknowledgement")
def test_diagnostic_message_is_acknowledged_before_the_response(
    routed_client: DoIPClient, ecu_config: EcuConfig
) -> None:
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
    config = default_config(ack_diagnostic_messages=False)
    with DoIPServer(config) as server:
        with DoIPClient(port=server.port, timeout=2.0).connect() as client:
            assert client.routing_activation().accepted
            client.send_diagnostic(b"\\x22\\xf1\\x90")
            frame = client.receive_frame()
            assert frame.payload_type == PayloadType.DIAGNOSTIC_MESSAGE
            assert frame.payload[4:].startswith(b"\\x62\\xf1\\x90")
'''

JOBS = [
    (
        "src/doipbench/config.py",
        "ack_diagnostic_messages",
        "    p2_ms: int = 50\n",
        "    ack_diagnostic_messages: bool = True\n    p2_ms: int = 50\n",
    ),
    (
        "src/doipbench/doip/constants.py",
        "class DiagnosticAckCode",
        "class DiagnosticNackCode(IntEnum):",
        ACK_ENUM + "class DiagnosticNackCode(IntEnum):",
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
    ("tests/functional/test_gateway.py", "DIAGNOSTIC_MESSAGE_ACK", GW_OLD, GW_NEW),
]


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)
    bad = []

    for rel, marker, old, new in JOBS:
        path = R / rel
        if not path.is_file():
            print(f"[MISS] {rel} 文件不存在")
            bad.append(rel)
            continue
        text = path.read_text(encoding="utf-8")
        if marker in text:
            print(f"[skip] {rel}")
        elif old not in text:
            print(f"[MISS] {rel} 锚点没找到")
            bad.append(rel)
        else:
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
            print(f"[  ok] {rel}")

    conf = R / "tests/conformance/test_doip_conformance.py"
    target = R / "tests/conformance/test_diagnostic_ack.py"
    inline = conf.is_file() and "test_diagnostic_message_is_acknowledged" in conf.read_text(
        encoding="utf-8"
    )
    if inline:
        print("[skip] 用例已在 conformance 里")
    elif target.exists():
        print("[skip] tests/conformance/test_diagnostic_ack.py")
    else:
        target.write_text(TEST_SRC, encoding="utf-8")
        print("[  ok] tests/conformance/test_diagnostic_ack.py")

    readme = R / "README.md"
    if readme.is_file():
        text = readme.read_text(encoding="utf-8")
        new = (
            text.replace("一共 211 条", "一共 213 条")
            .replace("| 协议一致性 | 83 |", "| 协议一致性 | 85 |")
            .replace("+ 30 条 TCP 报文用例", "+ 32 条 TCP 报文用例")
        )
        if new != text:
            readme.write_text(new, encoding="utf-8")
            print("[  ok] README.md")
        else:
            print("[skip] README.md")

    if bad:
        print("\n上面标 MISS 的没改到，把这一屏发我。")
    print("\n运行测试...")
    return subprocess.call([sys.executable, "-m", "pytest", "-q"], cwd=R)


if __name__ == "__&#8203;main__":
    sys.exit(main())
