# doip-testbench

一个用 Python 写的车载诊断练习项目：虚拟 ECU + 一套 pytest 测试用例。

虚拟 ECU 监听 TCP 13400，能响应 DoIP 的车辆识别、路由激活和诊断消息，支持 UDS 的 0x10 / 0x27 / 0x22 / 0x2E / 0x19 五个服务。测试用例不需要 CANoe 或真实硬件，clone 下来装个依赖就能跑。

[![CI](https://github.com/xgw7117/doip-testbench/actions/workflows/ci.yml/badge.svg)](https://github.com/xgw7117/doip-testbench/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## 实现范围

| 协议 | 做了什么 |
| --- | --- |
| DoIP（ISO 13400-2） | 8 字节头解析与组帧、车辆识别、路由激活、Alive Check、实体状态、0x8001 / 0x8003 |
| UDS（ISO 14229-1） | 0x10 会话、0x27 安全访问、0x22 读数据、0x2E 写数据、0x19 读 DTC，以及常见 NRC |
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

## 测试

一共 155 条：

- 单元测试 77 条，测编解码和状态机，不碰网络
- 协议一致性 68 条，其中 41 条 UDS 服务用例写在 YAML 里，27 条是 DoIP 协议用例
- 端到端 10 条，测会话超时、安全锁定、两个 tester 同时连接这些

覆盖率 88%。GitHub Actions 上用 Python 3.10 / 3.11 / 3.12 各跑一遍。

用例写在 `tests/data/uds_cases.yaml`，加一条不用改代码：

```yaml
- id: UDS-WDBI-002
  title: Write is rejected in the default session
  request: "2E 01 00 11 22 33 44 55 66 77 88"
  expected_nrc: 0x7F
  tags: [wdbi, negative]
  severity: critical
```

## 目录

```
src/doipbench/
├── doip/         帧解析、服务端、客户端
├── uds/          五个服务、会话与安全状态机
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
- 项目的思路和整体框架是自己想的，实现过程中用了 AI 辅助写代码。
- 这个项目是为了学协议和测试写的，没有和真实 ECU 对接过。
- 安全访问用的是简化的哈希算法，真实项目里这一步由 OEM 提供的 SeedKey DLL 完成。
- 车上的网关场景（一个 entity 转发到多个 ECU）没有实现，现在虚拟 ECU 是直连的。

## 参考标准

- ISO 13400-2 — DoIP
- ISO 14229-1 — UDS
- ISO 15765-2 — ISO-TP
- AUTOSAR SOME/IP Protocol Specification
- IEEE 802.1AS / 802.1Q

## License

MIT
