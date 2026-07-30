"""ValleyRAT detectorの境界超過fail-closed回帰テスト。"""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path
import zipfile

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
