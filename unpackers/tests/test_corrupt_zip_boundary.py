"""Regression test for malformed ZIP parser isolation."""

from __future__ import annotations

import zipfile

import unpackers.static_unpacker as static_unpacker


def test_unpack_bytes_isolates_bad_zip(monkeypatch) -> None:
    """Record a corrupt ZIP layer instead of aborting the entire batch."""
    monkeypatch.setattr(static_unpacker, "detect_format", lambda data, name="sample": "zip")
    monkeypatch.setattr(
        static_unpacker,
        "recover_zip",
        lambda data: (_ for _ in ()).throw(zipfile.BadZipFile("corrupt extra field")),
    )
    report, artifacts = static_unpacker.unpack_bytes(b"fixture", "broken.zip")
    assert report["unpack_status"] == "bounded_limit"
    assert "corrupt extra field" in report["zip_error"]
    assert artifacts == []
