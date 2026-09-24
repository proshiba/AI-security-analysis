"""認証済み静的レイヤーの私有出力契約を検証する。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pyzipper
import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import export_verified_static_layer as exporter  # noqa: E402
from static_layer_pipeline import InputUnit, StaticLayer  # noqa: E402


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_export_encrypts_only_verified_child(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = b"MZroot"
    child = b"MZchild"
    root_sha = _digest(root)
    child_sha = _digest(child)
    outer_sha = "a" * 64
    unit = InputUnit("root.exe", root, "authenticated_single_member_zip", outer_sha, 123)
    layer = StaticLayer("child.exe", child, child_sha, root_sha, 1, "embedded-pe")
    monkeypatch.setattr(exporter, "read_input_unit", lambda *args, **kwargs: unit)
    monkeypatch.setattr(
        exporter,
        "recover_static_layers",
        lambda *args, **kwargs: ([layer], {"limit_events": []}),
    )
    output = tmp_path / "child.zip"
    result = exporter.export_verified_layer(
        tmp_path / "source.zip",
        output,
        expected_outer_sha256=outer_sha,
        expected_root_sha256=root_sha,
        target_sha256=child_sha,
        target_parent_sha256=root_sha,
    )
    assert result["target_sha256"] == child_sha
    assert result["sample_executed"] is False
    with pyzipper.AESZipFile(output) as archive:
        archive.setpassword(b"infected")
        assert archive.read(f"{child_sha}.quarantine.bin") == child


def test_parent_mismatch_does_not_create_archive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = b"MZroot"
    child = b"MZchild"
    root_sha = _digest(root)
    child_sha = _digest(child)
    unit = InputUnit("root.exe", root, "authenticated_single_member_zip", "a" * 64, 123)
    layer = StaticLayer("child.exe", child, child_sha, root_sha, 1, "embedded-pe")
    monkeypatch.setattr(exporter, "read_input_unit", lambda *args, **kwargs: unit)
    monkeypatch.setattr(
        exporter,
        "recover_static_layers",
        lambda *args, **kwargs: ([layer], {"limit_events": []}),
    )
    output = tmp_path / "child.zip"
    with pytest.raises(ValueError, match="親SHA-256"):
        exporter.export_verified_layer(
            tmp_path / "source.zip",
            output,
            expected_outer_sha256="a" * 64,
            expected_root_sha256=root_sha,
            target_sha256=child_sha,
            target_parent_sha256="b" * 64,
        )
    assert not output.exists()


def test_repository_destination_is_rejected() -> None:
    with pytest.raises(ValueError, match="repository外"):
        exporter._private_destination(exporter.REPOSITORY_ROOT / "malware.zip")


def test_exclusive_archive_creation_preserves_existing_file(tmp_path: Path) -> None:
    output = tmp_path / "child.zip"
    existing = b"user-owned archive"
    output.write_bytes(existing)
    with pytest.raises(FileExistsError):
        exporter._write_verified_archive(output, digest=_digest(b"child"), data=b"child")
    assert output.read_bytes() == existing
