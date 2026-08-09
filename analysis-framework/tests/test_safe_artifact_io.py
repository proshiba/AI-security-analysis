"""解析成果物のidentity保護付きcleanupを検証する。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from safe_artifact_io import unlink_created_file_if_unchanged


def test_cleanup_removes_only_original_created_file(tmp_path: Path) -> None:
    target = tmp_path / "partial.json"
    target.write_bytes(b"partial")
    created = target.stat()

    assert unlink_created_file_if_unchanged(target, created) is True
    assert not target.exists()


def test_cleanup_preserves_replacement_identity(tmp_path: Path) -> None:
    target = tmp_path / "partial.json"
    target.write_bytes(b"partial")
    created = target.stat()
    target.unlink()
    target.write_bytes(b"replacement")

    assert unlink_created_file_if_unchanged(target, created) is False
    assert target.read_bytes() == b"replacement"


def test_cleanup_preserves_hardlink_and_missing_path(tmp_path: Path) -> None:
    target = tmp_path / "partial.json"
    target.write_bytes(b"partial")
    created = target.stat()
    linked = tmp_path / "linked.json"
    linked.hardlink_to(target)

    assert unlink_created_file_if_unchanged(target, created) is False
    assert target.exists()
    target.unlink()
    linked.unlink()
    assert unlink_created_file_if_unchanged(target, created) is False


def test_cleanup_does_not_delete_same_path_replacement_after_identity_check(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "partial.json"
    target.write_bytes(b"partial")
    created = target.stat()
    original_rename = os.rename
    raced = False

    def replace_before_quarantine(
        source: os.PathLike[str] | str,
        destination: os.PathLike[str] | str,
    ) -> None:
        nonlocal raced
        if Path(source) == target and not raced:
            raced = True
            target.unlink()
            target.write_bytes(b"replacement")
        original_rename(source, destination)

    monkeypatch.setattr(os, "rename", replace_before_quarantine)

    assert unlink_created_file_if_unchanged(target, created) is False
    assert raced is True
    assert target.read_bytes() == b"replacement"
    assert not list(tmp_path.glob(f".{target.name}.cleanup-*"))
