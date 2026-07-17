"""ValleyRAT／VenomRAT の最終整形規則を検証する。"""

from __future__ import annotations

from _ja_family_residual_patterns import translate_line


def test_detection_heading_is_fully_japanese() -> None:
    assert translate_line("## Sigma／YARA／Shodan用材料") == (
        "## 検出ルールと受動観測向けの材料"
    )


def test_unknown_line_is_unchanged() -> None:
    source = "Unreviewed family sentence"
    assert translate_line(source) == source
