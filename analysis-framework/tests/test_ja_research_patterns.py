"""研究・監査文書向けの限定日本語化規則を検証する。"""

from __future__ import annotations

from _ja_research_patterns import translate_line


def test_exact_translation_preserves_inline_values() -> None:
    source = (
        "- NSIS decompilationからワードXOR鍵 `0x17d68b37` と"
        "1,024-byte command stream `b2d8fcd1...` を復元した。"
    )
    target = translate_line(source)
    assert target == (
        "- NSIS の逆コンパイル結果からワード単位の XOR 鍵 `0x17d68b37` と"
        "1,024バイトのコマンド列 `b2d8fcd1...` を復元した。"
    )
    assert "`0x17d68b37`" in target
    assert "`b2d8fcd1...`" in target


def test_terminal_pe_row_translates_only_status() -> None:
    first = "a" * 64
    terminal = "b" * 64
    source = (
        f"| `{first}` | UTF-16 JS → PowerShell | `{terminal}` | "
        "361,984 | x64 .NET / not packed |"
    )
    target = translate_line(source)
    assert target == (
        f"| `{first}` | UTF-16 JS → PowerShell | `{terminal}` | "
        "361,984 | x64 .NET／パッキングなし |"
    )


def test_news_status_rows_are_fully_japanese() -> None:
    source = (
        "| 7 | axios npm供給網侵害 | setup.jsを静的に confirmed | "
        "[実検体解析](../../supply-chain/npm/axios-plain-crypto-js-2026/"
        "cases/e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09/"
        "README.md)、復号器・監査器 |"
    )
    assert "静的に確認済み" in translate_line(source)
    assert " confirmed" not in translate_line(source)


def test_unknown_line_is_unchanged() -> None:
    source = "Unreviewed research sentence"
    assert translate_line(source) == source


def test_static_linter_result_is_natural_japanese() -> None:
    assert translate_line("- Ruff: unpackers全体でpass。") == (
        "- Ruff によるアンパッカー全体の検査に合格。"
    )
