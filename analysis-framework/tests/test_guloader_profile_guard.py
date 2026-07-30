"""GuLoader共有プロファイルの誤検出防止テスト。"""

from __future__ import annotations

from pathlib import Path
import sys


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import profiled_family_detector as detector  # noqa: E402


def test_guloader_rejects_generic_windows_apis_and_benign_product_urls(
    monkeypatch,
) -> None:
    """一般API・設定語・製品URLだけではGuLoaderへ昇格しない。"""

    monkeypatch.setattr(detector, "known_hashes", lambda _family: set())
    data = (
        b"CallWindowProc EnumSystemLocales VirtualAlloc URL Password Method "
        b"https://support.rightpdf.com/product/help"
    )
    result = detector.detect_family("guloader", data, Path("disc-image.img"))
    assert result["matched"] is False
    assert result["observations"]["required_marker_satisfied"] is False
    assert result["observations"]["required_marker_hits"] == []


def test_guloader_accepts_corroborated_unique_name_profile(monkeypatch) -> None:
    """固有名と独立marker・設定・stage URLが揃う場合は候補として受理する。"""

    monkeypatch.setattr(detector, "known_hashes", lambda _family: set())
    data = (
        b"GuLoader CallWindowProc EnumSystemLocales URL Password Method "
        b"https://payload.example.org/stage.exe"
    )
    result = detector.detect_family("guloader", data, Path("loader.exe"))
    assert result["matched"] is True
    assert result["observations"]["required_marker_satisfied"] is True
    assert result["observations"]["required_marker_hits"] == ["guloader"]
