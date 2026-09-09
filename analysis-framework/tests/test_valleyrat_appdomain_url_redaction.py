"""AppDomainManager型loaderのstage URL公開境界を検証する。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

ANALYZER_PATH = (
    REPOSITORY_ROOT
    / "analysis-framework"
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "appdomainmanager_pixel_loader"
    / "analyze.py"
)
SPEC = importlib.util.spec_from_file_location(
    "valleyrat_appdomain_url_redaction",
    ANALYZER_PATH,
)
assert SPEC is not None and SPEC.loader is not None
APPDOMAIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(APPDOMAIN)


@pytest.mark.parametrize(
    "token",
    (
        "0123456789abcdef0123456789abcdef",
        "A" * 40,
        "b-7_C" * 12 + "tail",
        "9" * 64,
    ),
)
def test_appdomain_redacts_short_opaque_path_tokens(token: str) -> None:
    """短いopaque tokenを含むpath全体を伏字化する。"""

    data = f"https://example.test/stage/{token}?secret=hidden#fragment".encode()
    assert APPDOMAIN._public_urls(data) == [  # noqa: SLF001
        "https://example.test/[REDACTED]"
    ]


def test_appdomain_preserves_non_sensitive_stage_path() -> None:
    """通常のstage pathは残し、queryとfragmentは公開しない。"""

    assert APPDOMAIN._public_urls(  # noqa: SLF001
        b"https://example.test/releases/stage.bin?tracking=removed#fragment"
    ) == ["https://example.test/releases/stage.bin"]


@pytest.mark.parametrize(
    "token",
    (
        "0123456789abcdef" * 4 + ".bin",
        "Ab_-09" * 8 + ".dat",
    ),
)
def test_appdomain_redacts_opaque_stem_with_safe_extension(token: str) -> None:
    """長いopaque stemは安全そうな拡張子付きでも全体を伏字化する。"""

    data = f"https://example.test/stage/{token}".encode()
    assert APPDOMAIN._public_urls(data) == [  # noqa: SLF001
        "https://example.test/[REDACTED]"
    ]
