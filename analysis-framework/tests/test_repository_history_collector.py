"""Unit tests for historical Git blob collection."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from repository_history_collector import collect_repository, detect_format, safe_suffix, static_iocs


def git(cwd: Path, *arguments: str) -> None:
    """Run Git while constructing a test-only repository."""
    subprocess.run(["git", *arguments], cwd=cwd, check=True, capture_output=True)


def test_format_suffix_and_iocs() -> None:
    """Classify common bytes and extract bounded literal indicators."""
    assert detect_format(b"MZ" + bytes(10)) == "pe"
    assert detect_format(b"PK\x03\x04") == "zip"
    assert detect_format(b"hello\n") == "text"
    assert safe_suffix("a/B.JS") == ".js"
    assert safe_suffix("no-extension") == ".blob"
    assert static_iocs(b"https://example.test/a 192.0.2.10")["ipv4"] == ["192.0.2.10"]


def test_collects_deleted_history_without_execution(tmp_path: Path) -> None:
    """Retain blobs deleted from the tip and export them by SHA-256."""
    work = tmp_path / "work"
    mirror = tmp_path / "mirror.git"
    export = tmp_path / "export"
    work.mkdir()
    git(work, "init")
    git(work, "config", "user.email", "lab@example.test")
    git(work, "config", "user.name", "Lab")
    payload = work / "payload.dat"
    payload.write_bytes(b"MZhttps://example.test/stage")
    git(work, "add", "payload.dat")
    git(work, "commit", "-m", "add")
    payload.unlink()
    git(work, "add", "-u")
    git(work, "commit", "-m", "delete")
    subprocess.run(["git", "clone", "--mirror", str(work), str(mirror)], check=True, capture_output=True)
    report = collect_repository(mirror, export)
    assert report["commit_count"] == 2
    assert report["blob_count"] == 1
    assert report["blobs"][0]["format"] == "pe"
    assert report["blobs"][0]["iocs"]["urls"] == ["https://example.test/stage"]
    assert list(export.iterdir())
    with pytest.raises(ValueError):
        collect_repository(mirror, maximum_blob_size=0)
