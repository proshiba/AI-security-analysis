"""追加9ファミリ向け日本語化パターンの回帰テスト。"""

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

import _ja_other_family_patterns as patterns  # noqa: E402
import localize_result_markdown as localize  # noqa: E402


CURRENT_REPORT = REPOSITORY / ".work" / "result-localization-integrated.json"
FAMILIES = (
    "amadey",
    "shadowpad",
    "spyglace",
    "remusstealer",
    "amosstealer",
    "lummastealer",
    "formbook",
    "donutloader",
    "purehvnc",
)
TARGET_PREFIXES = tuple(
    f"analysis-results/malware/{family}/" for family in FAMILIES
)
INLINE = re.compile(r"(`+)([^\r\n]*?)\1")
NUMBERS = re.compile(r"\d+")
FULLWIDTH_ALNUM = re.compile(r"[Ａ-Ｚａ-ｚ０-９]")


def _inline_tokens(line: str) -> list[str]:
    return [match.group(0) for match in INLINE.finditer(line)]


def _assert_contract(source: str, translated: str) -> None:
    assert localize._preserved_values(translated) == localize._preserved_values(source)
    assert _inline_tokens(translated) == _inline_tokens(source)
    assert NUMBERS.findall(translated) == NUMBERS.findall(source)
    assert not FULLWIDTH_ALNUM.search(translated)
    assert not localize.find_unresolved_english(translated + "\n")


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "| none recovered | - | - | static extraction incomplete |",
            "| 復元なし | - | - | 静的抽出未完了 |",
        ),
        (
            "- Confirmed C2 status requires the reviewed "
            "custom-alphabet/Base64 config structure; literal-only URLs "
            "remain candidates.",
            "- 確認済みの指令制御（C2）先と判断するには、精査済みの独自文字表／"
            "基数64設定構造が必要です。文字列だけの接続先は候補に留めます。",
        ),
        (
            "- Themida/WinLicense wrappers require a recovered inner PE "
            "before configuration extraction can be complete.",
            "- Themida／WinLicenseラッパーでは、"
            "内部実行形式を復元しない限り設定抽出は完了しません。",
        ),
        (
            "## VX-Underground batch, 2026-07-16",
            "## VX-Underground 解析結果（2026-07-16）",
        ),
        (
            "- [Dr.Web BackDoor.ShadowPad.1 technical description]"
            "(https://vms.drweb.com/virus/?i=21995048)",
            "- [Dr.Web BackDoor.ShadowPad.1 技術解説]"
            "(https://vms.drweb.com/virus/?i=21995048)",
        ),
        (
            "- Certificate validity: 2026-07-04 15:16:54Z "
            "to 2027-07-05 15:16:54Z",
            "- 証明書の有効期間: 2026-07-04 15:16:54Z "
            "から 2027-07-05 15:16:54Z",
        ),
    ],
)
def test_representative_tracked_fixtures(
    source: str,
    expected: str,
) -> None:
    translated = patterns.translate_line(source)
    assert translated == expected
    _assert_contract(source, translated)


@pytest.mark.parametrize(
    "source",
    [
        (
            "- The `/ledger/` URL pattern is treated as probable exfil/C2 "
            "infrastructure, not proof of server ownership."
        ),
        (
            "| endpoint | 31.77.168.180:5000 | c2_or_network_ioc | "
            "recorded | README:Config and C2 evidence |"
        ),
        (
            "- Encoded SHA-256: "
            "9394627e9c44cf2226ddf50012e5cf47ccf7d3bd8afa2395c635a93637e23502"
        ),
        (
            "The sample hash and Casper algorithm/layout remain useful. "
            "Do not block `10.0.123.1` globally based on this report."
        ),
    ],
)
def test_generic_translation_preserves_machine_values(source: str) -> None:
    translated = patterns.translate_line(source)
    assert translated != source
    _assert_contract(source, translated)


@pytest.mark.parametrize("identifier", ["C2", "RC4", "SHA-256"])
def test_ascii_technical_identifiers_remain_byte_exact(identifier: str) -> None:
    source = f"- Confirmed {identifier} marker remains static."
    translated = patterns.translate_line(source)
    assert translated.count(identifier) == source.count(identifier)
    _assert_contract(source, translated)


def test_current_private_scope_has_no_unresolved_lines_after_patterns() -> None:
    if not CURRENT_REPORT.is_file():
        pytest.skip("private integrated localization report is not available")
    report = json.loads(CURRENT_REPORT.read_text(encoding="utf-8"))
    selected = [
        (entry["path"], finding["line"], finding["text"])
        for entry in report["files"]
        if entry["path"].startswith(TARGET_PREFIXES)
        for finding in entry.get("unresolved_english", [])
    ]

    remaining: list[tuple[str, int, str]] = []
    for path, number, source in selected:
        translated = patterns.translate_line(source)
        _assert_contract(source, translated)
        if localize.find_unresolved_english(translated + "\n"):
            remaining.append((path, number, translated))

    assert remaining == []
