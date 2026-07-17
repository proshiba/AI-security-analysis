"""難解析ケースの集約Markdownに固有な決定論的一行翻訳。"""

from __future__ import annotations

import re


_EXACT = {
    "# Deep static triage": "# 難解析ケースの静的深掘り",
    "This report was produced without sample execution, emulation, network contact, or raw-artifact persistence.":
        "この報告は、検体の実行、エミュレーション、ネットワーク接続、"
        "および生アーティファクトの永続化を行わずに生成しました。",
    "## Summary": "## 集計",
    "| SHA-256 | Family | Category | Status | Layers | Markers | Missing expected layers |":
        "| SHA-256 | ファミリー | 分類 | 状態 | レイヤー数 | マーカー | 不足している想定レイヤー |",
    "## Case details": "## ケース詳細",
}

_LAYER = re.compile(
    r"^- Layer (?P<digest>[0-9a-fA-F]{64}): "
    r"format=(?P<format>[^;]+); "
    r"markers=(?P<markers>[^;]+); "
    r"native-routing=(?P<native>[^;]+); "
    r"managed-routing=(?P<managed>.+)$"
)


def _margins(line: str) -> tuple[str, str, str]:
    leading = line[: len(line) - len(line.lstrip())]
    body_with_end = line[len(leading):]
    trailing = body_with_end[len(body_with_end.rstrip()):]
    body = (
        body_with_end[: len(body_with_end) - len(trailing)]
        if trailing
        else body_with_end
    )
    return leading, body, trailing


def translate_line(line: str) -> str:
    """既存localizer適用後の難解析ケース固有ラベルを日本語化する。"""
    leading, body, trailing = _margins(line)
    exact = _EXACT.get(body)
    if exact is not None:
        return leading + exact + trailing
    match = _LAYER.fullmatch(body)
    if match is None:
        return line
    return (
        leading
        + f"- レイヤー {match.group('digest')}: "
        + f"形式={match.group('format')}; "
        + f"マーカー={match.group('markers')}; "
        + f"ネイティブルーティング={match.group('native')}; "
        + f"マネージドルーティング={match.group('managed')}"
        + trailing
    )
