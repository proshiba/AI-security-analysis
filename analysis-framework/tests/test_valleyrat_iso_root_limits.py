"""ValleyRAT signed-proxy ISO root parserのresource境界を検証する。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "malware/valleyrat/campaigns/signed_proxy_sideload/analyze.py"
)
SPEC = importlib.util.spec_from_file_location("valleyrat_iso_root_limits", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

SECTOR = 2_048


def _record(name: bytes, extent: int, size: int, flags: int = 0) -> bytes:
    length = 33 + len(name) + (1 if len(name) % 2 == 0 else 0)
    record = bytearray(length)
    record[0] = length
    record[2:6] = extent.to_bytes(4, "little")
    record[10:14] = size.to_bytes(4, "little")
    record[25] = flags
    record[32] = len(name)
    record[33 : 33 + len(name)] = name
    return bytes(record)


def _iso(
    records: list[bytes],
    payloads: dict[int, bytes] | None = None,
    *,
    root_size: int = SECTOR,
) -> bytes:
    image = bytearray(32 * SECTOR)
    image[16 * SECTOR + 1 : 16 * SECTOR + 6] = b"CD001"
    root = _record(b"\x00", 20, root_size, flags=2)
    image[16 * SECTOR + 156 : 16 * SECTOR + 156 + len(root)] = root
    directory = b"".join(records)
    assert len(directory) <= SECTOR
    image[20 * SECTOR : 20 * SECTOR + len(directory)] = directory
    for extent, payload in (payloads or {}).items():
        start = extent * SECTOR
        image[start : start + len(payload)] = payload
    return bytes(image)


def _small_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_DIRECTORY_SIZE", SECTOR)
    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_MEMBERS", 2)
    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_MEMBER_SIZE", 4)
    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_RETAINED_BYTES", 8)
    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_UNIQUE_EXTENTS", 2)


def test_iso_root_accepts_exact_member_and_total_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """単体、累積、件数、unique extentの上限値ちょうどは受理する。"""

    _small_limits(monkeypatch)
    image = _iso(
        [
            _record(b"A.BIN;1", 21, 4),
            _record(b"B.DAT;1", 22, 4),
        ],
        {21: b"AAAA", 22: b"BBBB"},
    )

    assert MODULE._iso_root_files(image) == [
        ("A.BIN", b"AAAA"),
        ("B.DAT", b"BBBB"),
    ]


def test_iso_root_rejects_member_count_before_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """root member件数超過では部分結果もblob copyも返さない。"""

    _small_limits(monkeypatch)
    image = _iso(
        [
            _record(b"A.BIN;1", 21, 1),
            _record(b"B.BIN;1", 22, 1),
            _record(b"C.BIN;1", 23, 1),
        ]
    )
    monkeypatch.setattr(
        MODULE,
        "_materialize_iso_root_files",
        lambda *_args: pytest.fail("件数検証前にextentをcopyしてはならない"),
    )

    assert MODULE._iso_root_files(image) == []


def test_iso_root_rejects_member_and_cumulative_size_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """単体sizeと累積保持bytesのどちらの超過もfail-closedにする。"""

    _small_limits(monkeypatch)
    oversized = _iso([_record(b"A.BIN;1", 21, 5)])
    assert MODULE._iso_root_files(oversized) == []

    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_MEMBER_SIZE", 8)
    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_RETAINED_BYTES", 7)
    cumulative = _iso(
        [_record(b"A.BIN;1", 21, 4), _record(b"B.BIN;1", 22, 4)]
    )
    assert MODULE._iso_root_files(cumulative) == []


def test_iso_root_rejects_unique_extent_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """member上限内でもunique extent上限を超えれば拒否する。"""

    _small_limits(monkeypatch)
    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_MEMBERS", 3)
    image = _iso(
        [
            _record(b"A.BIN;1", 21, 1),
            _record(b"B.BIN;1", 22, 1),
            _record(b"C.BIN;1", 23, 1),
        ]
    )

    assert MODULE._iso_root_files(image) == []


@pytest.mark.parametrize(
    "records",
    (
        [
            _record(b"A.BIN;1", 21, 4),
            _record(b"B.BIN;1", 21, 4),
        ],
        [
            _record(b"A.BIN;1", 21, SECTOR + 4),
            _record(b"B.BIN;1", 22, 4),
        ],
        [
            _record(b"A.BIN;1", 21, 4),
            _record(b"a.bin;2", 22, 4),
        ],
    ),
    ids=("duplicate_extent", "overlapping_extent", "name_alias"),
)
def test_iso_root_rejects_duplicate_overlap_and_alias(
    monkeypatch: pytest.MonkeyPatch,
    records: list[bytes],
) -> None:
    """重複extent、部分overlap、正規化後の名前aliasを全て拒否する。"""

    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_MEMBER_SIZE", 2 * SECTOR)
    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_RETAINED_BYTES", 4 * SECTOR)
    image = _iso(records)

    assert MODULE._iso_root_files(image) == []


def test_repeated_extent_never_reaches_blob_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じ巨大extentの繰返しはslice copyを開始する前に停止する。"""

    image = _iso(
        [
            _record(b"A.BIN;1", 21, 3 * SECTOR),
            _record(b"B.BIN;1", 21, 3 * SECTOR),
        ]
    )
    monkeypatch.setattr(
        MODULE,
        "_materialize_iso_root_files",
        lambda *_args: pytest.fail("重複extentをcopyしてはならない"),
    )

    assert MODULE._iso_root_files(image) == []


def test_malformed_record_discards_preceding_valid_member(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """後続record破損時も先行memberだけを部分返却しない。"""

    malformed = bytearray(_record(b"B.BIN;1", 22, 4))
    malformed[0] = 33
    image = _iso(
        [_record(b"A.BIN;1", 21, 4), bytes(malformed)],
        {21: b"AAAA", 22: b"BBBB"},
    )
    monkeypatch.setattr(
        MODULE,
        "_materialize_iso_root_files",
        lambda *_args: pytest.fail("全record検証前にcopyしてはならない"),
    )

    assert MODULE._iso_root_files(image) == []


def test_root_directory_size_limit_and_raw_pe_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """巨大rootは拒否し、非ISOのraw PE経路は従来どおり維持する。"""

    monkeypatch.setattr(MODULE, "MAXIMUM_ISO_ROOT_DIRECTORY_SIZE", SECTOR - 1)
    assert MODULE._iso_root_files(_iso([])) == []
    assert MODULE._iso_root_files(b"MZ raw PE fixture") == []

    summary = {
        "name": "sample.exe",
        "sha256": "a" * 64,
        "proxy_type": None,
        "injection_or_decryption_apis": [],
        "sections": [],
        "imports": {},
    }
    monkeypatch.setattr(MODULE, "_pe_summary", lambda *_args: summary)
    result = MODULE.analyze(b"MZ raw PE fixture", "sample.exe")
    assert result["components"] == [summary]
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_signed_proxy_public_names_drop_caller_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sample/component名へ呼出元の絶対pathを公開しない。"""

    assert MODULE._safe_name(r"C:\private\case\proxy.dll") == "proxy.dll"
    summary = {
        "name": "proxy.dll",
        "sha256": "a" * 64,
        "proxy_type": None,
        "injection_or_decryption_apis": [],
        "sections": [],
        "imports": {},
    }
    monkeypatch.setattr(MODULE, "_pe_summary", lambda *_args: summary)

    result = MODULE.analyze(
        b"MZ raw PE fixture",
        r"C:\private\case\proxy.dll",
    )

    assert result["sample_name"] == "proxy.dll"
    assert "C:\\private" not in str(result)
