"""大容量PEの静的走査budgetと証跡出力を検証する。"""

from __future__ import annotations

import struct

import pytest

from unpackers import static_control_flow
from unpackers import static_unpacker
from unpackers.bounded_pe_scan import (
    BoundedExtent,
    inspect_structural_pe_extent,
    scan_embedded_pe_candidates,
)


def _minimal_pe(code: bytes = b"\xc3") -> bytes:
    """1 sectionの小さなPE32 fixtureを返す。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200 : 0x200 + len(code)] = code
    return bytes(data)


def test_structural_extent_rejects_false_magic_without_tail_copy() -> None:
    """固定長ヘッダだけで正規候補を採用し、偽MZを保守的に拒否する。"""

    valid = inspect_structural_pe_extent(_minimal_pe())
    assert valid.extent == 0x400
    assert valid.reason == "structural_headers_coherent"

    false_magic = b"MZ" + b"\0" * (2 * 1024 * 1024)
    rejected = inspect_structural_pe_extent(false_magic)
    assert rejected.extent is None
    assert rejected.reason == "pe_header_offset_out_of_bounds"


def test_candidate_budget_is_partial_and_structured() -> None:
    """候補数上限到達時に、完全走査と誤表示せず理由を残す。"""

    data = b"X" + (b"MZxx" * 20)
    calls: list[int] = []

    def reject(_data: bytes, offset: int) -> None:
        calls.append(offset)
        return None

    candidates, report = scan_embedded_pe_candidates(
        data,
        reject,
        max_candidates=3,
        max_results=2,
    )

    assert candidates == []
    assert len(calls) == 3
    assert report["status"] == "partial"
    assert report["exhausted_reasons"] == ["candidate_count_budget"]
    assert report["candidate_magic_count"] == 3
    assert report["unscanned_scope_bytes"] > 0


def test_input_budget_scans_prefix_and_suffix_with_provenance() -> None:
    """入力上限超過時も先頭と末尾を調べ、中間未走査を明示する。"""

    data = bytearray(b"X" * 100)
    data[2:4] = b"MZ"
    data[96:98] = b"MZ"

    def accept(_data: bytes, _offset: int) -> BoundedExtent:
        return BoundedExtent(2, validation_method="fixture")

    candidates, report = scan_embedded_pe_candidates(
        bytes(data),
        accept,
        max_scan_bytes=20,
        max_candidates=8,
        max_results=8,
    )

    assert candidates == [(2, 2), (96, 2)]
    assert report["status"] == "partial"
    assert report["exhausted_reasons"] == ["input_scan_budget"]
    assert report["scanned_bytes"] == 20
    assert report["validation_methods"] == {"fixture": 2}


def test_elapsed_budget_is_reported_without_candidate_parse() -> None:
    """経過時間budgetの枯渇を候補未検証のまま構造化して返す。"""

    ticks = iter((0.0, 2.0))
    candidates, report = scan_embedded_pe_candidates(
        b"XMZfixture",
        lambda _data, _offset: pytest.fail("validator must not run"),
        max_elapsed_seconds=1.0,
        clock=lambda: next(ticks),
    )

    assert candidates == []
    assert report["status"] == "partial"
    assert report["exhausted_reasons"] == ["elapsed_time_budget"]
    assert report["candidate_magic_count"] == 0


def test_many_false_mz_candidates_do_not_call_pefile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """大容量入力の偽MZごとに巨大末尾をpefileへ渡さない。"""

    data = bytearray(2 * 1024 * 1024)
    for offset in range(1024, 1024 * 1024, 1024):
        data[offset : offset + 2] = b"MZ"

    def forbidden(**_kwargs):
        raise AssertionError("large false candidate reached pefile")

    monkeypatch.setattr(static_unpacker.pefile, "PE", forbidden)
    artifacts = static_unpacker.carve_embedded_pes(bytes(data))

    assert artifacts == []
    assert artifacts.scan_report["status"] == "complete"
    assert artifacts.scan_report["candidate_magic_count"] == 1023
    assert artifacts.scan_report["rejected_candidate_count"] == 1023


def test_pe_summary_and_cfg_use_explicit_directory_parse() -> None:
    """fast-load後に必要なimports/resourcesだけを明示解析する。"""

    sample = _minimal_pe()
    summary, artifacts = static_unpacker.pe_summary(sample)
    assert artifacts == []
    assert summary["directory_parse"] == {
        "imports": {"status": "parsed"},
        "resources": {"status": "parsed"},
    }
    cfg = static_control_flow.analyze_pe_control_flow(sample)
    assert cfg["status"] == "analyzed"
    assert cfg["static_context"]["import_directory_parse"] == {"status": "parsed"}


def test_unpack_report_keeps_embedded_scan_evidence() -> None:
    """下位走査証跡をstatic layer reportへ渡せる位置に保持する。"""

    report, artifacts = static_unpacker.unpack_bytes(b"plain fixture", "plain.bin")
    assert artifacts == []
    scan = report["embedded_pe_scan"]
    assert scan["status"] == "complete"
    assert scan["budget_exhausted"] is False
    assert scan["executed"] is False
    assert scan["network_contacted"] is False
