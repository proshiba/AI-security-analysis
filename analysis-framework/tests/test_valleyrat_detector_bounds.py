"""ValleyRAT detectorの境界超過fail-closed回帰テスト。"""

from __future__ import annotations

import importlib.util
import io
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
SPEC = importlib.util.spec_from_file_location("valleyrat_bounded_detect", MODULE_PATH)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def _zip_fixture() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("fixture-a.bin", b"fixture-a")
        archive.writestr("fixture-b.bin", b"fixture-b")
    return stream.getvalue()


def test_archive_limit_is_unmatched_observation_not_detector_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject(_data: bytes):
        raise DETECT.ArchiveValidationError("member exceeds bounded limit")

    monkeypatch.setattr(DETECT, "inspect_zip", reject)
    result = DETECT.detect(_zip_fixture(), Path("sample.zip"))
    assert result["matched"] is False
    assert result["campaigns"] == []
    assert result["observations"]["archive_scan"] == "bounded_rejection"
    assert "ArchiveValidationError" in result["observations"]["reason"]


def test_raw_msi_requires_packed_valleyrat_pe_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """展開済みraw MSIでもCABと保護stub形状が揃う場合だけ候補にする。"""

    raw_msi = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fixture"
    monkeypatch.setattr(
        DETECT,
        "inspect_msi_structure",
        lambda _data: {
            "stream_count": 3,
            "cab_count": 1,
            "pe_count": 1,
            "packed_valleyrat_pe_count": 1,
            "streams": [],
        },
    )
    result = DETECT.detect(raw_msi, Path("sample.msi"))
    assert result["matched"] is True
    assert result["campaigns"][0]["campaign_type"] == "msi_embedded_cab_custom_actions"
    assert result["campaigns"][0]["confidence"] == "medium"


def test_generic_msi_with_cab_and_pe_is_not_attributed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """一般的なCAB+PE MSIだけではValleyRATへ帰属しない。"""

    raw_msi = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fixture"
    monkeypatch.setattr(
        DETECT,
        "inspect_msi_structure",
        lambda _data: {
            "stream_count": 3,
            "cab_count": 1,
            "pe_count": 1,
            "packed_valleyrat_pe_count": 0,
            "streams": [],
        },
    )
    result = DETECT.detect(raw_msi, Path("benign.msi"))
    assert result["matched"] is False
    assert result["campaigns"] == []


def test_appdomainmanager_pixel_loader_requires_correlated_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    directories = [SimpleNamespace(Size=0) for _ in range(15)]
    directories[14] = SimpleNamespace(Size=72)
    fake_pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories))
    monkeypatch.setattr(DETECT.pefile, "PE", lambda **_kwargs: fake_pe)
    data = b"MZ fixture MyAppDomainManager InitializeNewDomain VirtualAllocExNuma EnumUILanguagesA Win32_CacheMemory"

    result = DETECT.detect(data, Path("loader.dll"))

    assert result["matched"] is True
    assert result["campaigns"][0]["campaign_type"] == "appdomainmanager_pixel_loader"
    assert result["campaigns"][0]["confidence"] == "high"
