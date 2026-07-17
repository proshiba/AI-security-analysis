"""旧ファミリー向け追加日本語化パターンの回帰テスト。"""

from __future__ import annotations

import json
from pathlib import Path
import re
import sys

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import _ja_legacy_family_patterns as legacy  # noqa: E402
import localize_result_markdown as localize  # noqa: E402


FAMILIES = {
    "agenttesla",
    "latrodectus",
    "remcosrat",
    "stealc",
    "valleyrat",
    "venomrat",
    "vidar",
}
SCOPE = re.compile(
    r"^analysis-results/malware/(?:" + "|".join(sorted(FAMILIES)) + r")/"
)
NUMBER = re.compile(
    r"(?<![A-Za-z0-9._-])\d+(?:[.,:/-]\d+)*(?![A-Za-z0-9._-])"
)
REPORT = REPOSITORY / ".work" / "result-localization-current.json"


def _baseline_lines() -> list[tuple[str, str]]:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    return [
        (entry["path"], finding["text"])
        for entry in report["files"]
        if SCOPE.match(entry["path"])
        for finding in entry["unresolved_english"]
        if not localize.JAPANESE.search(finding["text"])
    ]


def _explicit_prose_numbers(text: str) -> tuple[str, ...]:
    """保護対象の内部を除き、説明文で明示された数値だけを返す。"""
    projected = text
    for pattern in (
        localize.INLINE_CODE,
        localize.BARE_URL,
        localize.MARKDOWN_DESTINATION,
        localize.LONG_HASH,
        localize.TECHNICAL_ENUM,
        localize.TECHNICAL_FILENAME,
        localize.DOTTED_IDENTIFIER,
        localize.REPOSITORY_IDENTIFIER,
    ):
        projected = pattern.sub(" ", projected)
    return tuple(NUMBER.findall(projected))


def _numbers_preserved_in_order(source: str, translated: str) -> bool:
    """数詞の翻訳で追加された数字を許し、原文の明示数値の順序を検証する。"""
    expected = iter(_explicit_prose_numbers(source))
    current = next(expected, None)
    if current is None:
        return True
    for value in _explicit_prose_numbers(translated):
        if value == current:
            current = next(expected, None)
            if current is None:
                return True
    return False


def test_translate_line_preserves_contract_values_and_line_shape() -> None:
    digest = "a" * 64
    source = (
        "  - Distribution separation: `https://stage.example/a1` are loader/stage "
        f"locations; enum_value, {digest}, 192.0.2.4:443, 7.2.6 and "
        "[reference](https://example.test/path) remain ordered.\r\n"
    )
    translated = legacy.translate_line(source)

    assert translated.startswith("  - ")
    assert translated.endswith("\r\n")
    assert localize._preserved_values(source) == localize._preserved_values(translated)
    assert _numbers_preserved_in_order(source, translated)
    assert localize.find_unresolved_english(translated) == ()


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        ("## VX-Underground batch, 2026-07-16", "バッチ"),
        ("# ValleyRAT / Winos4.0", "# バレーラット / ウィノス4.0"),
        ("- Source: VX-Underground StealC family directory", "情報源"),
        ("- Static config: not recovered", "静的設定"),
        ("- No active C2 check-in was performed", "能動的"),
        ("- Distribution separation: loader locations remain ordered.", "配布系統の分離"),
        ("- False positives are unlikely when three signals correlate.", "誤検知"),
    ),
)
def test_representative_family_lines_are_localized(source: str, expected: str) -> None:
    translated = legacy.translate_line(source)

    assert expected in translated
    assert localize._preserved_values(source) == localize._preserved_values(translated)
    assert _numbers_preserved_in_order(source, translated)
    assert localize.find_unresolved_english(translated + "\n") == ()


@pytest.mark.skipif(not REPORT.exists(), reason="private localization audit report is absent")
def test_assigned_legacy_scope_has_no_unresolved_english_after_patterns() -> None:
    failures: list[str] = []
    for path, source in _baseline_lines():
        translated = legacy.translate_line(source)
        if localize._preserved_values(source) != localize._preserved_values(translated):
            failures.append(f"{path}: 保護値が変化: {source!r}")
            continue
        if not _numbers_preserved_in_order(source, translated):
            failures.append(f"{path}: 数値の順序が変化: {source!r}")
            continue
        unresolved = localize.find_unresolved_english(translated + "\n")
        if unresolved:
            failures.append(f"{path}: {translated}")

    assert not failures, "未解決の英語説明:\n" + "\n".join(failures[:80])
