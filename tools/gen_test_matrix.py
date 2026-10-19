"""Generate docs/test-matrix.md from the YAML case files.

Keeping the matrix generated guarantees that the documentation cannot drift
away from the executable suite.
"""

from __future__ import annotations

from pathlib import Path

from doipbench.testing.cases import Case, load_cases

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "tests" / "data" / "uds_cases.yaml"
OUT = ROOT / "docs" / "test-matrix.md"

SERVICES = {
    0x10: "0x10 DiagnosticSessionControl",
    0x27: "0x27 SecurityAccess",
    0x22: "0x22 ReadDataByIdentifier",
    0x2E: "0x2E WriteDataByIdentifier",
    0x19: "0x19 ReadDTCInformation",
    0x3E: "0x3E TesterPresent",
}


def expectation(case: Case) -> str:
    if case.expected_nrc is not None:
        return f"NRC 0x{case.expected_nrc:02X}"
    if case.expect_no_response:
        return "无响应（suppress）"
    assert case.expected is not None
    text = case.expected.hex(" ").upper()
    return f"`{text}` (prefix)" if len(case.expected) > 4 else f"`{text}`"


def precondition(case: Case) -> str:
    parts: list[str] = []
    if case.precondition.session is not None:
        parts.append(f"session 0x{case.precondition.session:02X}")
    if case.precondition.seed:
        parts.append("请求 seed")
    if case.precondition.unlock:
        parts.append("已解锁")
    return " + ".join(parts) if parts else "—"


def main() -> None:
    cases = load_cases(CASES)
    lines = [
        "# 测试用例矩阵",
        "",
        "> 本文件由 `tools/gen_test_matrix.py` 从 `tests/data/uds_cases.yaml` 生成，请勿手工编辑。",
        "",
        f"共 **{len(cases)}** 条 UDS 服务用例。另有 27 条 DoIP 协议一致性用例，"
        "见 `tests/conformance/test_doip_conformance.py`。",
        "",
        "| 服务 | 用例数 | 正例 | 负例 |",
        "| --- | ---: | ---: | ---: |",
    ]

    for service_id in SERVICES:
        subset = [case for case in cases if case.service_id == service_id]
        if not subset:
            continue
        negative = sum(1 for case in subset if case.expected_nrc is not None)
        lines.append(
            f"| {SERVICES[service_id]} | {len(subset)} | {len(subset) - negative} | {negative} |"
        )

    lines.append("")

    for service_id, name in SERVICES.items():
        subset = [case for case in cases if case.service_id == service_id]
        if not subset:
            continue
        lines += [
            f"## {name}",
            "",
            "| ID | 用例 | 请求 | 期望 | 前置条件 | 级别 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for case in subset:
            lines.append(
                f"| `{case.id}` | {case.title} | `{case.request.hex(' ').upper()}` | "
                f"{expectation(case)} | {precondition(case)} | {case.severity} |"
            )
        lines.append("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
