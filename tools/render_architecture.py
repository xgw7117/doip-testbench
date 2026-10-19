"""Render the architecture diagram used in the README.

Run with::

    python tools/render_architecture.py

The script is committed so the diagram can be regenerated after an
architectural change instead of being an unmaintainable binary blob.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

# Matplotlib cannot index .ttc collections by family name, so register the
# faces explicitly.  The JP face covers all simplified Chinese glyphs used here.
for _face in ("NotoSansCJK-Regular.ttc", "NotoSansCJK-Bold.ttc"):
    font_manager.fontManager.addfont(f"/usr/share/fonts/opentype/noto/{_face}")

FONT = "Noto Sans CJK JP"
matplotlib.rcParams["font.sans-serif"] = [FONT, "DejaVu Sans"]
matplotlib.rcParams["axes.unicode_minus"] = False

INK = "#1F2933"
MUTED = "#5B6770"
ACCENT = "#C8553D"
BLUE = "#2E5E8C"
PAPER = "#FFFFFF"
FILL_TEST = "#F4F1EC"
FILL_PROTO = "#EAF0F6"
FILL_TRANS = "#F7EFEA"
FILL_CI = "#EEF3EF"

OUT = Path(__file__).resolve().parents[1] / "docs" / "images" / "architecture.png"


def box(
    ax: plt.Axes,
    x: float,
    y: float,
    w: float,
    h: float,
    *,
    facecolor: str,
    edgecolor: str = "none",
    radius: float = 1.2,
    alpha: float = 1.0,
) -> None:
    ax.add_patch(
        FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle=f"round,pad=0.0,rounding_size={radius}",
            linewidth=1.0,
            edgecolor=edgecolor,
            facecolor=facecolor,
            alpha=alpha,
        )
    )


def label(
    ax: plt.Axes,
    x: float,
    y: float,
    text: str,
    *,
    size: float = 10,
    color: str = INK,
    weight: str = "normal",
    ha: str = "left",
) -> None:
    ax.text(x, y, text, fontsize=size, color=color, fontweight=weight, ha=ha, va="center")


def arrow(ax: plt.Axes, start: tuple[float, float], end: tuple[float, float]) -> None:
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=12,
            linewidth=1.2,
            color=MUTED,
            shrinkA=2,
            shrinkB=2,
        )
    )


def main() -> None:
    fig, ax = plt.subplots(figsize=(12, 7.4), dpi=180)
    ax.set_xlim(0, 120)
    ax.set_ylim(0, 74)
    ax.axis("off")
    fig.patch.set_facecolor(PAPER)

    label(ax, 6, 68.5, "doip-testbench", size=20, weight="bold")
    label(ax, 6, 63.6, "整车以太网诊断测试台 · 纯软件虚拟 ECU，零硬件依赖", size=10.5, color=MUTED)

    # ---------------------------------------------------------- test layer
    box(ax, 6, 47, 82, 12.4, facecolor=FILL_TEST)
    label(ax, 9, 56.6, "测试与编排层", size=11, weight="bold", color=ACCENT)
    label(ax, 9, 51.2, "YAML 用例（41）  ·  pytest 数据驱动  ·  Allure 报告  ·  CLI（serve / run / identify / frame）", size=9.2, color=MUTED)

    # ------------------------------------------------------- protocol layer
    box(ax, 6, 25.5, 82, 18.5, facecolor=FILL_PROTO)
    label(ax, 9, 40.6, "协议栈层 · 自研实现，按标准逐字节可断言", size=11, weight="bold", color=BLUE)

    tiles = [
        (9.5, "DoIP", "ISO 13400-2\n帧编解码 / 路由激活\n流式分帧"),
        (29.5, "UDS", "ISO 14229-1\n0x10 0x27 0x22 0x2E 0x19\nNRC 异常矩阵"),
        (49.5, "SOME/IP", "AUTOSAR\n头 + SD 服务发现\nOffer / Find"),
        (69.5, "gPTP · VLAN", "IEEE 802.1AS / 802.1Q\n时钟同步 / 优先级"),
    ]
    for x, title, body in tiles:
        box(ax, x, 28.5, 18, 9.2, facecolor=PAPER, edgecolor="#D5DEE7", radius=0.9)
        label(ax, x + 1.2, 35.6, title, size=10.5, weight="bold", color=INK)
        ax.text(x + 1.2, 31.0, body, fontsize=7.6, color=MUTED, va="center", linespacing=1.5)

    # -------------------------------------------------------- transport layer
    box(ax, 6, 6.5, 82, 15.0, facecolor=FILL_TRANS)
    label(ax, 9, 18.4, "传输与仿真层", size=11, weight="bold", color=ACCENT)
    label(ax, 9, 13.6, "TCP :13400 诊断  ·  UDP 车辆发现  ·  多线程连接 / 并发 socket 限制", size=9.0, color=MUTED)
    label(ax, 9, 9.6, "ECU 状态机：DID 内存 · DTC 存储 · 会话 S3 · 安全访问尝试次数与锁定", size=9.0, color=MUTED)

    # ------------------------------------------------------------------ CI
    box(ax, 92, 6.5, 22, 53, facecolor=FILL_CI)
    label(ax, 95, 55.4, "CI / CD", size=11, weight="bold", color="#3B6B4A")
    ci_lines = [
        "ruff · mypy",
        "pytest 3.10 / 3.11 / 3.12",
        "覆盖率 88%",
        "Allure 报告",
        "GitHub Pages 发布",
    ]
    y = 49.0
    for line in ci_lines:
        label(ax, 95, y, "· " + line, size=8.6, color=MUTED)
        y -= 5.4

    # --------------------------------------------------------------- arrows
    arrow(ax, (47, 47.0), (47, 44.2))
    arrow(ax, (47, 25.4), (47, 21.7))
    arrow(ax, (88.2, 40), (91.8, 40))

    label(ax, 6, 2.4, "155 条自动化用例 · Python 3.10+ · MIT License", size=8.5, color="#8A959E")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT, bbox_inches="tight", facecolor=PAPER)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
