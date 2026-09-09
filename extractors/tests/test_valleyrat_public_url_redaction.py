"""ValleyRAT設定URLの公開境界を検証する。"""

from __future__ import annotations

import pytest

from extractors.valleyrat import extractor, n520


@pytest.mark.parametrize(
    "token",
    (
        "0123456789abcdef0123456789abcdef",
        "A" * 40,
        "a-b_C" * 12 + "tail",
        "9" * 64,
    ),
)
def test_n520_redacts_short_opaque_path_tokens(token: str) -> None:
    """32～64文字の無名tokenも公開URLへ残さない。"""

    assert n520._public_url(  # noqa: SLF001 - 公開境界の直接回帰検証
        f"https://example.test/stage/{token}?credential=hidden#fragment"
    ) == "https://example.test/stage/[REDACTED]"


def test_n520_preserves_non_sensitive_stage_path() -> None:
    """通常の配布pathはIOCとして保持し、queryとfragmentだけを除く。"""

    assert n520._public_url(  # noqa: SLF001 - 公開境界の直接回帰検証
        "https://example.test/releases/stage.bin?tracking=removed#fragment"
    ) == "https://example.test/releases/stage.bin"


@pytest.mark.parametrize(
    "token",
    (
        "0123456789abcdef" * 4 + ".bin",
        "Ab_-09" * 8 + ".dat",
    ),
)
def test_n520_redacts_opaque_stem_with_safe_extension(token: str) -> None:
    """長いopaque stemは拡張子付きでも公開URLへ残さない。"""

    assert n520._public_url(  # noqa: SLF001 - 公開境界の直接回帰検証
        f"https://example.test/stage/{token}"
    ) == "https://example.test/stage/[REDACTED]"


@pytest.mark.parametrize(
    "token",
    (
        "0123456789abcdef" * 4 + ".bin",
        "Ab_-09" * 8 + ".dat",
    ),
)
def test_shared_extractor_redacts_opaque_stem_with_safe_extension(
    token: str,
) -> None:
    """共通extractorも長いopaque stemと拡張子をまとめて伏字化する。"""

    assert extractor._public_urls(  # noqa: SLF001
        [f"https://example.test/stage/{token}"]
    ) == ["https://example.test/[REDACTED]"]
