"""指定コレクション向け日本語化パターンの回帰テスト。"""

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

import _ja_collection_patterns as collection  # noqa: E402
import _ja_legacy_family_patterns as legacy  # noqa: E402
import localize_result_markdown as localize  # noqa: E402


COLLECTIONS = {
    "refresh-20260715",
    "vx-underground-20260716",
    "malwarebazaar-20260717",
}
SCOPE = re.compile(
    r"^analysis-results/collections/(?:"
    + "|".join(sorted(COLLECTIONS))
    + r")/"
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
    ]


def _explicit_prose_numbers(text: str) -> tuple[str, ...]:
    """保護対象と英数字識別子の内部を除き、明示数値だけを返す。"""
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


def _assert_contract(source: str, translated: str) -> None:
    assert localize._preserved_values(source) == localize._preserved_values(translated)
    assert _numbers_preserved_in_order(source, translated)
    assert localize.find_unresolved_english(translated + "\n") == ()


@pytest.mark.parametrize(
    ("source", "expected"),
    (
        (
            "# MalwareBazaar refresh analysis — 2026-07-15",
            "# マルウェアバザール更新解析 — 2026-07-15",
        ),
        (
            "# コレクション：vx-underground-20260716",
            "# コレクション：20260716版ブイエックス・アンダーグラウンド",
        ),
        (
            "10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.",
            "新規提出検体10件",
        ),
        (
            "35 `vx-underground` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.",
            "提出検体35件",
        ),
        (
            "## Validated config values",
            "## 検証済み設定値",
        ),
        (
            "| High | Exact reviewed SHA-256 | Very low false positives; misses every rebuild or repack. |",
            "確認済みSHA-256との完全一致",
        ),
        (
            "- ValleyRAT case [`42420ed30965…`](../../malware/valleyrat/versions/unknown/cases/42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5/README.md): `103.43.11.40:1443` was recovered from the reversed vvaS configuration and is therefore a confirmed embedded C2 value. Current liveness and ownership were not tested.",
            "確認済みの埋め込みC2値",
        ),
    ),
)
def test_representative_collection_lines_are_localized(
    source: str, expected: str
) -> None:
    translated = collection.translate_line(source)

    assert expected in translated
    _assert_contract(source, translated)


def test_translate_line_preserves_line_shape_and_contract_values() -> None:
    digest = "b" * 64
    source = (
        "  - Distribution separation: `https://stage.example/a1` are loader/stage "
        f"locations; enum_value, {digest}, 192.0.2.4:443, 7.2.6 and "
        "[reference](https://example.test/path) remain ordered.\r\n"
    )
    translated = collection.translate_line(source)

    assert translated.startswith("  - ")
    assert translated.endswith("\r\n")
    _assert_contract(source, translated)


def test_collection_rules_accept_common_localizer_output() -> None:
    source = (
        "Ten newest samples selected by exact MalwareBazaar signature were "
        "downloaded and analyzed statically. Inner hashes were verified; no "
        "sample or recovered payload was executed and no candidate infrastructure "
        "was contacted."
    )
    common_output = legacy.translate_line(source)
    translated = collection.translate_line(common_output)

    assert "最新10検体" in translated
    _assert_contract(source, translated)


@pytest.mark.skipif(not REPORT.exists(), reason="private localization audit report is absent")
def test_assigned_collection_scope_has_no_unresolved_english() -> None:
    failures: list[str] = []
    for path, source in _baseline_lines():
        translated = collection.translate_line(source)
        if localize._preserved_values(source) != localize._preserved_values(translated):
            failures.append(f"{path}: 保護値が変化: {source!r}")
            continue
        if not _numbers_preserved_in_order(source, translated):
            failures.append(f"{path}: 数値の順序が変化: {source!r}")
            continue
        if localize.find_unresolved_english(translated + "\n"):
            failures.append(f"{path}: {translated}")

    assert not failures, "未解決の英語説明:\n" + "\n".join(failures[:80])
