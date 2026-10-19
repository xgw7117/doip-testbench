# 测试用例矩阵

> 本文件由 `tools/gen_test_matrix.py` 从 `tests/data/uds_cases.yaml` 生成，请勿手工编辑。

共 **41** 条 UDS 服务用例。另有 27 条 DoIP 协议一致性用例，见 `tests/conformance/test_doip_conformance.py`。

| 服务 | 用例数 | 正例 | 负例 |
| --- | ---: | ---: | ---: |
| 0x10 DiagnosticSessionControl | 6 | 4 | 2 |
| 0x27 SecurityAccess | 7 | 2 | 5 |
| 0x22 ReadDataByIdentifier | 7 | 4 | 3 |
| 0x2E WriteDataByIdentifier | 6 | 1 | 5 |
| 0x19 ReadDTCInformation | 11 | 8 | 3 |
| 0x3E TesterPresent | 3 | 2 | 1 |

## 0x10 DiagnosticSessionControl

| ID | 用例 | 请求 | 期望 | 前置条件 | 级别 |
| --- | --- | --- | --- | --- | --- |
| `UDS-SES-001` | Default session switches to extended session | `10 03` | `50 03 00 32 01 F4` (prefix) | — | blocker |
| `UDS-SES-002` | Extended session returns to default session | `10 01` | `50 01` | session 0x03 | critical |
| `UDS-SES-003` | Programming session is supported | `10 02` | `50 02` | — | critical |
| `UDS-SES-004` | Suppress positive response bit is honoured | `10 83` | 无响应（suppress） | — | normal |
| `UDS-SES-005` | Unknown session type is rejected with 0x12 | `10 05` | NRC 0x12 | — | critical |
| `UDS-SES-006` | Truncated session control request is rejected with 0x13 | `10` | NRC 0x13 | — | normal |

## 0x27 SecurityAccess

| ID | 用例 | 请求 | 期望 | 前置条件 | 级别 |
| --- | --- | --- | --- | --- | --- |
| `UDS-SEC-001` | Security access is not available in the default session | `27 01` | NRC 0x7F | — | blocker |
| `UDS-SEC-002` | Seed request returns a 4 byte seed | `27 01` | `67 01` | session 0x03 | blocker |
| `UDS-SEC-003` | Wrong key is rejected with 0x35 | `27 02 DE AD BE EF` | NRC 0x35 | session 0x03 + 请求 seed | critical |
| `UDS-SEC-004` | Send key without a preceding seed request yields 0x24 | `27 02 DE AD BE EF` | NRC 0x24 | session 0x03 | critical |
| `UDS-SEC-005` | Seed request with trailing bytes is rejected with 0x13 | `27 01 00` | NRC 0x13 | session 0x03 | normal |
| `UDS-SEC-006` | Unsupported security sub-function yields 0x12 | `27 05` | NRC 0x12 | session 0x03 | normal |
| `UDS-SEC-007` | Seed request with suppress bit returns nothing | `27 81` | 无响应（suppress） | session 0x03 | minor |

## 0x22 ReadDataByIdentifier

| ID | 用例 | 请求 | 期望 | 前置条件 | 级别 |
| --- | --- | --- | --- | --- | --- |
| `UDS-RDBI-001` | VIN can be read with service 0x22 | `22 F1 90` | `62 F1 90 4C 53 56 41 41 32 42 4D 35 4E 32 31 32 33 34 35 36` (prefix) | — | blocker |
| `UDS-RDBI-002` | Multiple DIDs are returned in request order | `22 F1 90 F1 87` | `62 F1 90` | — | critical |
| `UDS-RDBI-003` | Unknown DID is rejected with 0x31 | `22 12 34` | NRC 0x31 | — | critical |
| `UDS-RDBI-004` | One byte DID is rejected with 0x13 | `22 F1` | NRC 0x13 | — | normal |
| `UDS-RDBI-005` | Odd number of DID bytes is rejected with 0x13 | `22 F1 90 F1` | NRC 0x13 | — | normal |
| `UDS-RDBI-006` | Active diagnostic session DID reflects the current session | `22 F1 86` | `62 F1 86 01` | — | critical |
| `UDS-RDBI-007` | Session DID reflects the extended session | `22 F1 86` | `62 F1 86 03` | session 0x03 | normal |

## 0x2E WriteDataByIdentifier

| ID | 用例 | 请求 | 期望 | 前置条件 | 级别 |
| --- | --- | --- | --- | --- | --- |
| `UDS-WDBI-001` | Writable DID accepts a new value in extended session | `2E 01 00 11 22 33 44 55 66 77 88` | `6E 01 00` | session 0x03 + 已解锁 | blocker |
| `UDS-WDBI-002` | Write is rejected in the default session with 0x7F | `2E 01 00 11 22 33 44 55 66 77 88` | NRC 0x7F | — | critical |
| `UDS-WDBI-003` | Write without security access yields 0x33 | `2E 01 00 11 22 33 44 55 66 77 88` | NRC 0x33 | session 0x03 | blocker |
| `UDS-WDBI-004` | Read only DID cannot be written even when unlocked | `2E F1 90 4C 53 56 41 41 32 42 4D 35 4E 32 31 32 33 34 35 36` | NRC 0x31 | session 0x03 + 已解锁 | critical |
| `UDS-WDBI-005` | Write with wrong payload length yields 0x13 | `2E 01 00 00 00` | NRC 0x13 | session 0x03 + 已解锁 | normal |
| `UDS-WDBI-006` | Write to an unknown DID yields 0x31 | `2E 12 34 00` | NRC 0x31 | session 0x03 + 已解锁 | normal |

## 0x19 ReadDTCInformation

| ID | 用例 | 请求 | 期望 | 前置条件 | 级别 |
| --- | --- | --- | --- | --- | --- |
| `UDS-DTC-001` | DTC count with status mask 0xFF returns three records | `19 01 FF` | `59 01 FF 01 00 03` (prefix) | — | blocker |
| `UDS-DTC-002` | DTC list with status mask 0xFF starts with the confirmed DTC | `19 02 FF` | `59 02 FF C1 23 45 09` (prefix) | — | blocker |
| `UDS-DTC-003` | Supported DTC list contains all stored DTCs | `19 0A` | `59 0A FF` | — | critical |
| `UDS-DTC-004` | Snapshot record of DTC 0xC12345 is readable | `19 04 C1 23 45 01` | `59 04 C1 23 45 09 01` (prefix) | — | critical |
| `UDS-DTC-005` | Extended data record of DTC 0xC12345 is readable | `19 06 C1 23 45 01` | `59 06 C1 23 45 09 01 01 2C 00 64` (prefix) | — | normal |
| `UDS-DTC-006` | Status mask 0x08 filters out pending DTCs | `19 02 08` | `59 02 08 C1 23 45 09 01 23 45 08` (prefix) | — | critical |
| `UDS-DTC-007` | Status mask 0x00 matches no DTC | `19 02 00` | `59 02 00` | — | normal |
| `UDS-DTC-008` | Unsupported report type yields 0x12 | `19 03 FF` | NRC 0x12 | — | normal |
| `UDS-DTC-009` | DTC report without status mask yields 0x13 | `19 02` | NRC 0x13 | — | normal |
| `UDS-DTC-010` | Snapshot request for an unknown DTC yields 0x31 | `19 04 AA BB CC 01` | NRC 0x31 | — | normal |
| `UDS-DTC-011` | DTC report with suppress bit returns nothing | `19 81 FF` | 无响应（suppress） | — | minor |

## 0x3E TesterPresent

| ID | 用例 | 请求 | 期望 | 前置条件 | 级别 |
| --- | --- | --- | --- | --- | --- |
| `UDS-TP-001` | Tester present is acknowledged | `3E 00` | `7E 00` | — | critical |
| `UDS-TP-002` | Tester present with suppress bit returns nothing | `3E 80` | 无响应（suppress） | — | normal |
| `UDS-TP-003` | Unknown tester present sub-function yields 0x12 | `3E 01` | NRC 0x12 | — | minor |
