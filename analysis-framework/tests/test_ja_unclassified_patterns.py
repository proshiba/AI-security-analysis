"""未分類 case 固有の日本語化 pattern を検証する。"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
import sys

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import _ja_unclassified_patterns as patterns  # noqa: E402
import localize_result_markdown as localize  # noqa: E402


CURRENT_REPORT = REPOSITORY / ".work" / "result-localization-current.json"
TARGET_PREFIXES = (
    "analysis-results/malware/unclassified/",
    "analysis-results/collections/malwarebazaar-unknown-20260717/",
)
INLINE = re.compile(r"(\x60+)([^\r\n]*?)\1")
URL = re.compile(r"https?://[^\s<>)]+")
HASH = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")
ENUM = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")
DESTINATION = re.compile(r"(?<=\]\()[^\r\n)]+(?=\))")


def _critical_values(line: str) -> dict[str, Counter[str]]:
    return {
        "url": Counter(URL.findall(line)),
        "hash": Counter(HASH.findall(line)),
        "enum": Counter(ENUM.findall(line)),
        "destination": Counter(DESTINATION.findall(line)),
    }


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "- MalwareBazaar first seen: `2026-07-16 02:23:46`",
            "- MalwareBazaar初回観測: `2026-07-16 02:23:46`",
        ),
        (
            "- Depth 2: `script` `a` "
            "(2030 bytes, artifacts_recovered)",
            "- 深度2: `script` `a` "
            "（2030バイト、artifacts_recovered）",
        ),
        (
            "| endpoint | 216.126.225.243:8085 | "
            "static_ip_candidate | inferred | iocs.json |",
            "| エンドポイント | 216.126.225.243:8085 | "
            "static_ip_candidate | 推定 | iocs.json |",
        ),
        (
            "## Source coverage",
            "## 情報源網羅状況",
        ),
        (
            "- [IRAHook Fabric mod structure]"
            "(rules/yara/irahook_fabric_mod_2026.yar): medium confidence, "
            "low expected false-positive risk after the full package-path "
            "conjunction.",
            "- [IRAHook拡張モジュール構造]"
            "(rules/yara/irahook_fabric_mod_2026.yar): 中信頼度です。"
            "パッケージパスの全条件を組み合わせた場合、"
            "想定誤検知リスクは低くなります。",
        ),
        (
            "Low-confidence and unidentified cases were correlated using "
            "hash-only public intelligence. Family attribution is promoted "
            "to medium only when at least two independent providers agree. "
            "Aggregator transports do not count as an extra vote.",
            "低信頼度または未識別のケースを、ハッシュだけを使う公開情報で"
            "関連付けました。ファミリ帰属を中信頼度へ昇格するには、"
            "独立した情報提供元が2つ以上一致する必要があります。"
            "集約サービスの転送経路は追加の1票として数えません。",
        ),
    ],
)
def test_translate_line_localizes_representative_lines_and_preserves_values(
    source: str, expected: str
) -> None:
    source = source.replace("`a`", "`" + "a" * 64 + "`")
    expected = expected.replace("`a`", "`" + "a" * 64 + "`")
    translated = patterns.translate_line(source)
    assert translated == expected
    assert localize._preserved_values(translated) == localize._preserved_values(source)
    assert [match.group(0) for match in INLINE.finditer(translated)] == [
        match.group(0) for match in INLINE.finditer(source)
    ]
    assert _critical_values(translated) == _critical_values(source)
    assert not localize.find_unresolved_english(translated + "\n")


def test_current_unclassified_report_has_no_unresolved_lines_after_patterns() -> None:
    if not CURRENT_REPORT.is_file():
        pytest.skip("private current-localization report is not available")
    report = json.loads(CURRENT_REPORT.read_text(encoding="utf-8"))
    selected = [
        (entry["path"], item["line"], item["text"])
        for entry in report["files"]
        if entry["path"].startswith(TARGET_PREFIXES)
        for item in entry["unresolved_english"]
    ]
    remaining: list[tuple[str, int, str]] = []
    for path, number, source in selected:
        translated = patterns.translate_line(source)
        assert localize._preserved_values(translated) == localize._preserved_values(source)
        assert [match.group(0) for match in INLINE.finditer(translated)] == [
            match.group(0) for match in INLINE.finditer(source)
        ]
        assert _critical_values(translated) == _critical_values(source)
        if localize.find_unresolved_english(translated + "\n"):
            remaining.append((path, number, translated))

    assert remaining == []
