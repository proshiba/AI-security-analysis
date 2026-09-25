"""Node SEAの無害な合成fixtureを用いた境界・復元テスト。"""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from unpackers import node_sea_static as target


def _member(value: bytes) -> bytes:
    return struct.pack("<Q", len(value)) + value


def _blob(
    *, name: bytes = b"dist/main.js", asset_name: bytes = b"data/config.json"
) -> bytes:
    return (
        target.MAGIC
        + struct.pack("<I", 9)
        + b"\x01"
        + _member(name)
        + _member(b"console.log('fixture')")
        + struct.pack("<Q", 1)
        + _member(asset_name)
        + _member(b"{}")
    )


def test_recovers_complete_main_and_asset() -> None:
    report, artifacts = target.parse_node_sea_blob(_blob())
    assert report["status"] == "recovered"
    assert [item[1] for item in artifacts] == [b"console.log('fixture')", b"{}"]
    assert report["members"][0]["name"] == "dist/main.js"
    assert report["candidate_only"] is True
    assert report["c2_confirmation_allowed"] is False


@pytest.mark.parametrize(
    "blob",
    [
        _blob(name=b"../evil.js"),
        _blob(asset_name=b"C:\\evil.py"),
        _blob()[:-1],
        _blob() + b"tail",
        _blob()[:9] + struct.pack("<Q", 2**63) + _blob()[17:],
    ],
)
def test_malformed_or_unsafe_blob_fails_closed(blob: bytes) -> None:
    report, artifacts = target.parse_node_sea_blob(blob)
    assert report["status"] == "parse_failed"
    assert artifacts == []


def test_aggregate_budget_fails_closed() -> None:
    report, artifacts = target.parse_node_sea_blob(_blob(), max_total_size=16)
    assert report["status"] == "parse_failed"
    assert artifacts == []


def test_pe_resource_requires_unique_named_rcdata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blob = _blob()
    data = b"MZ" + b"NODE_SEA_BLOB" + b"\0" * 20 + blob
    leaf = SimpleNamespace(
        data=SimpleNamespace(
            struct=SimpleNamespace(OffsetToData=0x3000, Size=len(blob))
        )
    )
    name = SimpleNamespace(
        name=target.RESOURCE_NAME, directory=SimpleNamespace(entries=[leaf])
    )
    typ = SimpleNamespace(id=10, directory=SimpleNamespace(entries=[name]))
    image = SimpleNamespace(
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[typ]),
        parse_data_directories=lambda **_kwargs: None,
        get_offset_from_rva=lambda _rva: len(data) - len(blob),
    )
    monkeypatch.setattr(target.pefile, "PE", lambda **_kwargs: image)
    report, artifacts = target.recover_node_sea_pe(data)
    assert report["status"] == "recovered"
    assert len(artifacts) == 2
    name.directory.entries.append(leaf)
    report, artifacts = target.recover_node_sea_pe(data)
    assert report["status"] == "ambiguous_resource"
    assert artifacts == []


def test_no_resource_marker_skips_pe_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        target.pefile, "PE", lambda **_kwargs: pytest.fail("unexpected PE parse")
    )
    assert target.recover_node_sea_pe(b"MZ-no-marker")[0]["status"] == "not_detected"
