"""破損ZIPパーサーの例外隔離を回帰検証する。"""

from __future__ import annotations

import zipfile

import unpackers.static_unpacker as static_unpacker


def test_unpack_bytes_isolates_bad_zip(monkeypatch) -> None:
    """破損ZIPを記録し、一括解析全体の中断を防ぐ。"""
    monkeypatch.setattr(static_unpacker, "detect_format", lambda data, name="sample": "zip")
    monkeypatch.setattr(
        static_unpacker,
        "recover_zip",
        lambda data, **_kwargs: (_ for _ in ()).throw(zipfile.BadZipFile("corrupt extra field")),
    )
    report, artifacts = static_unpacker.unpack_bytes(b"fixture", "broken.zip")
    assert report["unpack_status"] == "bounded_limit"
    assert "corrupt extra field" in report["zip_error"]
    assert artifacts == []
