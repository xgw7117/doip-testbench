# doip-testbench

一个用 Python 写的车载诊断练习项目：虚拟 ECU + 一套 pytest 测试用例。

虚拟 ECU 同时监听 UDP 和 TCP 13400：车辆识别、实体状态、电源模式走 UDP（tester 还不知道 ECU 的 IP，只能靠广播发现），路由激活、诊断消息、Alive Check 走 TCP。DoIP 侧实现 0x0001–0x0004、0x0005 / 0x0006、0x0007 / 0x0008、0x4001–0x4004、0x8001 / 0x8003；UDS 侧实现 0x10 / 0x27 / 0x22 / 0x2E / 0x19 / 0x3E / 0x11 / 0x31 / 0x34 / 0x36 / 0x37 十一个服务。配置里填了路由表之后，它就是一个网关：按目标逻辑地址把请求转发给挂在下挂的多个 ECU，未知地址回 0x8003。测试用例不需要 CANoe 或真实硬件，clone 下来装个依赖就能跑。

[![CI](https://github.com/xgw7117/doip-testbench/actions/workflows/ci.yml/badge.svg)](https://github.com/xgw7117/doip-testbench/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 实现范围

| 协议 | 做了什么 |
| --- | --- |
| DoIP over TCP（ISO 13400-2） | 8 字节头解析与组帧、路由激活、诊断消息、Alive Check、0x8001 / 0x8003；按目标逻辑地址转发（网关模式） |
| DoIP over UDP（ISO 13400-2） | 车辆识别（0x0001 / 0x0002 / 0x0003）、实体状态、电源模式；TCP 专属报文走 UDP 一律回 generic NACK 0x01 |
| UDS（ISO 14229-1） | 0x10 会话、0x27 安全访问、0x22 读数据、0x2E 写数据、0x19 读 DTC、0x3E 保持连接；0x34 / 0x36 / 0x37 刷写数据传输、0x31 擦除与 CRC 校验、0x11 复位；13 类 NRC |
| SOME/IP | 头部和 SD 报文的编解码，**没有做服务端** |
| gPTP / VLAN | IEEE 802.1AS 头部解析、802.1Q 标签 |
| ISO-TP（ISO 15765-2） | 分段和重组，用于理解 CAN 侧的长报文传输 |

## 怎么跑

```bash
git clone https://github.com/xgw7117/doip-testbench.git
cd doip-testbench
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

不需要硬件，也不用 root 或 vcan，测试都在 127.0.0.1 的临时端口上跑。

也可以手动发指令看看：

```bash
doipbench serve --port 13400          # 终端 1：启动虚拟 ECU
doipbench identify --port 13400       # 终端 2：读车辆信息
doipbench run tests/data/uds_cases.yaml --start-ecu --port 0
```

网关模式目前没有 CLI 开关，要在代码里传路由表（键是逻辑地址，值是下挂 ECU 的名字）：

```python
from doipbench.config import default_config
from doipbench.doip.server import DoIPServer

config = default_config(routing_table={0x1000: "gateway", 0x1010: "ecu_a"})
with DoIPServer(config, port=13400) as server:
    ...  # 发到 0x1000 由网关自己答，发到 0x1010 转给 ecu_a，其他地址回 0x8003
```

## 测试

一共 208 条，跑完 `pytest` 的最后一行就是这个数：

| 层 | 条数 | 测什么 | 位置 |
| --- | --- | --- | --- |
| 单元 | 114 | 编解码、状态机、YAML 加载器，不碰网络 | `tests/unit/` |
| 协议一致性 | 80 | 41 条 UDS 服务用例（YAML 数据驱动）+ 27 条 TCP 报文用例 + 10 条 UDP 报文用例 | `tests/conformance/` |
| 端到端 | 14 | 会话切换、安全锁定、两个 tester 同时连接、网关转发 | `tests/functional/` |

GitHub Actions 上用 Python 3.10 / 3.11 / 3.12 各跑一遍。

用例写在 `tests/data/uds_cases.yaml`，加一条不用改代码：

```yaml
cases:
  - id: UDS-WDBI-002
    title: Write is rejected in the default session
    request: "2E 01 00 11 22 33 44 55 66 77 88"
    expected_nrc: 0x7F
    tags: [wdbi, negative]
    severity: critical
```

注意 `-` 要缩进到 `cases:` 底下。顶格写成纯列表，加载器会直接报
`CaseSchemaError: expected a mapping with a 'cases' list`——它不接受「整个文件就是一个列表」。

## 目录

```
src/doipbench/
├── doip/         帧解析、服务端、客户端
├── uds/          十一个服务、会话与安全状态机
├── someip/       SOME/IP 头 + SD
├── net/          VLAN、gPTP
├── transport/    ISO-TP
├── testing/      YAML 用例加载
├── config.py     ECU 配置
└── cli.py        serve / run / identify / frame
tests/
├── unit/         单元测试
├── conformance/  协议一致性
├── functional/   端到端
└── data/         YAML 用例
```

## 说明

- 这个项目是为了学协议和测试写的，没有和真实 ECU 对接过。
- 安全访问用的是简化的哈希算法，真实项目里这一步由 OEM 提供的 SeedKey DLL 完成。
- UDP 只放发现类报文（识别 / 实体状态 / 电源模式）。诊断和 Alive Check 只能走 TCP，往 UDP 上发会收到 generic NACK——不是没实现，是标准不允许。
- 网关是**进程内的逻辑地址路由**：按目标地址把请求分发到下挂的 UDS 实例，不是真的两跳网络。DoIP 的 entity 多跳（跨 entity 转发）没做，Alive Check 也只做了被动的 0x0007 → 0x0008 应答，没有主动探活回收空闲连接。

## 参考标准

- ISO 13400-2 — DoIP
- ISO 14229-1 — UDS
- ISO 15765-2 — ISO-TP
- AUTOSAR SOME/IP Protocol Specification
- IEEE 802.1AS / 802.1Q

## License

MIT
