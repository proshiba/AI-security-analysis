"""残る11ファミリーの限定変換を検証する。"""

from __future__ import annotations

from _ja_remaining_family_patterns import translate_line


def test_case_family_contract_preserves_inline_enum() -> None:
    source = (
        "- Family: `quasarrat` (high confidence from exact "
        "MalwareBazaar signature selection and verified SHA-256)"
    )
    target = translate_line(source)
    assert "`quasarrat`" in target
    assert "高信頼度" in target


def test_citation_title_is_localized() -> None:
    source = (
        "[出典：Proofpoint「New RedLine Stealer Distributed Using "
        "Coronavirus-themed Email Campaign」](<https://example.test/>)"
    )
    target = translate_line(source)
    assert "プルーフポイント" in target
    assert "新型コロナウイルス題材" in target
    assert "https://example.test/" in target


def test_unknown_line_is_unchanged() -> None:
    source = "Unreviewed family-specific sentence"
    assert translate_line(source) == source
