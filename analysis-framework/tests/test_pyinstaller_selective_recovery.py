"""汎用PyInstaller CArchiveのbytes-only選択復元contractを検証する。"""

from __future__ import annotations

import json
import struct
import sys
import zlib
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import extract_pyinstaller_archive as target  # noqa: E402

EntrySpec = tuple[str, bytes, bool, str]


def build_carchive(entries: list[EntrySpec], *, prefix: bytes = b"MZ" + b"\0" * 126) -> bytes:
    """任意typecodeの最小CArchiveを検体実行なしで合成する。"""

    data_region = bytearray()
    toc = bytearray()
    for name, payload, compressed, typecode in entries:
        stored = zlib.compress(payload) if compressed else payload
        offset = len(data_region)
        data_region.extend(stored)
        encoded_name = name.encode("utf-8") + b"\0"
        encoded_name = encoded_name.ljust(((len(encoded_name) + 15) // 16) * 16, b"\0")
        entry_length = target.MemoryCArchiveReader.TOC_ENTRY_LENGTH + len(encoded_name)
        toc.extend(
            struct.pack(
                target.MemoryCArchiveReader.TOC_ENTRY_FORMAT,
                entry_length,
                offset,
                len(stored),
                len(payload),
                int(compressed),
                typecode.encode("ascii"),
            )
        )
        toc.extend(encoded_name)
    archive_length = len(data_region) + len(toc) + target.MemoryCArchiveReader.COOKIE_LENGTH
    cookie = struct.pack(
        target.MemoryCArchiveReader.COOKIE_FORMAT,
        target.MemoryCArchiveReader.COOKIE_MAGIC,
        archive_length,
        len(data_region),
        len(toc),
        313,
        b"python313.dll".ljust(64, b"\0"),
    )
    return prefix + bytes(data_region) + bytes(toc) + cookie


def toc_start(sample: bytes) -> int:
    cookie_offset = sample.rfind(target.MemoryCArchiveReader.COOKIE_MAGIC)
    _magic, archive_length, toc_offset, _toc_size, _python, _library = struct.unpack_from(
        target.MemoryCArchiveReader.COOKIE_FORMAT,
        sample,
        cookie_offset,
    )
    archive_start = cookie_offset + target.MemoryCArchiveReader.COOKIE_LENGTH - archive_length
    return archive_start + toc_offset


def minimal_pe() -> bytes:
    """section tableまで境界が整合する最小PE風payloadを返す。"""

    payload = bytearray(512)
    payload[:2] = b"MZ"
    struct.pack_into("<I", payload, 0x3C, 0x80)
    payload[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", payload, 0x86, 1)
    struct.pack_into("<H", payload, 0x94, 0xE0)
    return bytes(payload)


def test_priority_recovery_is_deterministic_and_bytes_only() -> None:
    sample = build_carchive(
        [
            ("bulk/picture.dat", b"bulk", True, "x"),
            ("nested.zip", b"PK\x03\x04archive", True, "b"),
            ("native/helper.dll", minimal_pe(), True, "b"),
            ("PYZ.pyz", b"PYZ\0modules", False, "z"),
            ("runtime_module", b"marshal-module", True, "m"),
            ("entrypoint", b"marshal-script", True, "s"),
            ("config/settings.json", b'{"mode":"test"}', True, "x"),
            ("pyi-contents-directory _internal", b"", False, "o"),
        ]
    )

    first = target.analyze_carchive_bytes(sample, preferred_names=("config/settings.json",))
    second = target.recover_prioritized_entries_from_bytes(
        sample,
        preferred_names=("config/settings.json",),
    )

    assert first.report == second.report
    assert first.recovered_entries == second.recovered_entries
    assert first.report["complete"] is True
    assert first.report["blockers"] == []
    assert [item.category for item in first.recovered_entries] == [
        "caller_preferred",
        "python_script",
        "python_module",
        "pyz_archive",
        "pe_name_candidate",
        "nested_archive",
    ]
    assert first.recovered_entries[0].payload == b'{"mode":"test"}'
    assert first.report["classification"] == {
        "packaging": "PyInstaller CArchive",
        "malware_family": "not_inferred_from_packaging",
        "malicious_intent": "not_inferred_from_packaging",
    }
    assert first.report["selection"]["status"] == "selective_recovery"
    assert first.report["selection"]["omitted_entry_count"] == 1
    assert first.report["selection"]["blockers"] == []
    assert first.report["content_validation"]["full_content_validation"] is True
    assert first.report["content_validation"]["validated_entry_count"] == 7
    assert first.report["content_validation"]["discarded_after_validation_count"] == 1
    assert first.report["content_validation"]["format_classification_complete"] is True
    assert first.report["content_validation"]["format_counts"] == {
        "portable_executable": 1,
        "pyinstaller_python_module_entry": 1,
        "pyinstaller_python_script_entry": 1,
        "pyinstaller_pyz": 1,
        "unknown_binary_or_data": 2,
        "zip": 1,
    }
    assert first.report["archive"]["option_count"] == 1
    assert first.report["archive"]["toc_record_count"] == 8
    assert len(first.report["content_validation"]["content_commitment"]["sha256"]) == 64
    assert first.report["safety"]["sample_executed"] is False
    assert first.report["safety"]["external_process_started"] is False
    assert first.report["safety"]["network_contacted"] is False
    assert first.report["safety"]["file_written"] is False
    assert first.report["safety"]["all_payload_formats_classified"] is True
    assert all("payload" not in item for item in first.report["selection"]["selected_entries"])
    assert all("payload_format" in item for item in first.report["selection"]["selected_entries"])


def test_large_7971_entry_inventory_is_committed_without_public_expansion() -> None:
    entries = [(f"bulk/{index:04d}.dat", bytes([index % 251]), False, "x") for index in range(7_971)]
    sample = build_carchive(entries)

    result = target.analyze_carchive_bytes(sample)
    archive = result.report["archive"]

    assert archive["entry_count"] == 7_971
    assert archive["toc_record_count"] == 7_971
    assert archive["type_counts"] == {"x": 7_971}
    assert archive["inventory_commitment"]["record_count"] == 7_971
    assert len(archive["inventory_commitment"]["sha256"]) == 64
    assert archive["full_inventory_published"] is False
    assert result.report["selection"]["status"] == "inventory_only"
    assert result.report["complete"] is True
    assert result.report["selection"]["retained_count"] == 0
    assert result.report["content_validation"]["full_content_validation"] is True
    assert result.report["content_validation"]["discarded_after_validation_count"] == 7_971
    assert result.recovered_entries == ()
    assert len(json.dumps(result.report, ensure_ascii=False)) < 8_000

    with pytest.raises(target.MemoryCArchiveError, match="entry数"):
        target.analyze_carchive_bytes(sample, max_toc_entries=7_970)


def test_unselected_overlap_and_path_collision_fail_closed() -> None:
    overlapping = bytearray(
        build_carchive(
            [
                ("bulk/a.dat", b"A" * 32, False, "x"),
                ("bulk/b.dat", b"B" * 32, False, "x"),
            ]
        )
    )
    first_length = struct.unpack_from("!I", overlapping, toc_start(overlapping))[0]
    struct.pack_into("!I", overlapping, toc_start(overlapping) + first_length + 4, 0)
    with pytest.raises(target.MemoryCArchiveError, match="range"):
        target.analyze_carchive_bytes(bytes(overlapping))

    collision = build_carchive(
        [
            ("Data/Caf\u00e9.dat", b"a", False, "x"),
            ("data/Cafe\u0301.DAT", b"b", False, "x"),
        ]
    )
    with pytest.raises(target.MemoryCArchiveError, match="正規化後に衝突"):
        target.analyze_carchive_bytes(collision)


def test_retention_count_and_size_budgets_are_fail_closed() -> None:
    scripts = [(f"script_{index:03d}", b"x", True, "s") for index in range(130)]
    result = target.analyze_carchive_bytes(build_carchive(scripts))
    assert len(result.recovered_entries) == 128
    assert result.report["complete"] is False
    assert result.report["selection"]["excluded_candidate_counts"] == {"retained_entry_limit": 2}

    with pytest.raises(ValueError, match="128以下"):
        target.analyze_carchive_bytes(build_carchive(scripts[:1]), max_retained_entries=129)
    with pytest.raises(ValueError, match="128以下"):
        target.extract_selected_entries_from_bytes(
            build_carchive(scripts),
            prefixes=("script_",),
            max_files=129,
        )

    sample = build_carchive(
        [
            ("a", b"A" * 10, False, "s"),
            ("b", b"B" * 10, False, "s"),
            ("large", b"C" * 30, False, "s"),
        ]
    )
    bounded = target.analyze_carchive_bytes(
        sample,
        max_entry_compressed_size=20,
        max_entry_uncompressed_size=20,
        max_total_compressed_size=15,
        max_total_uncompressed_size=15,
    )
    assert [entry.name for entry in bounded.recovered_entries] == ["a"]
    assert bounded.report["selection"]["excluded_candidate_counts"] == {
        "entry_compressed_size_limit": 1,
        "total_compressed_size_limit": 1,
    }


def test_corrupt_zlib_eof_and_declared_sizes_fail_closed() -> None:
    sample = bytearray(build_carchive([("entrypoint", b"important script" * 20, True, "s")]))
    toc = toc_start(sample)
    compressed_size = struct.unpack_from("!I", sample, toc + 8)[0]
    struct.pack_into("!I", sample, toc + 8, compressed_size - 1)
    with pytest.raises(target.MemoryCArchiveError, match="zlib stream"):
        target.analyze_carchive_bytes(bytes(sample))

    unselected = bytearray(build_carchive([("bulk/data.dat", b"bulk" * 100, True, "x")]))
    toc = toc_start(unselected)
    compressed_size = struct.unpack_from("!I", unselected, toc + 8)[0]
    struct.pack_into("!I", unselected, toc + 8, compressed_size - 1)
    with pytest.raises(target.MemoryCArchiveError, match="zlib stream"):
        target.analyze_carchive_bytes(bytes(unselected))

    declared = bytearray(build_carchive([("entrypoint", b"payload", True, "s")]))
    toc = toc_start(declared)
    unpacked_size = struct.unpack_from("!I", declared, toc + 12)[0]
    struct.pack_into("!I", declared, toc + 12, unpacked_size + 1)
    with pytest.raises(target.MemoryCArchiveError, match="展開サイズ"):
        target.analyze_carchive_bytes(bytes(declared))

    raw = bytearray(build_carchive([("bulk/raw.dat", b"payload", False, "x")]))
    toc = toc_start(raw)
    unpacked_size = struct.unpack_from("!I", raw, toc + 12)[0]
    struct.pack_into("!I", raw, toc + 12, unpacked_size + 1)
    with pytest.raises(target.MemoryCArchiveError, match="宣言サイズ"):
        target.analyze_carchive_bytes(bytes(raw))


def test_cookie_toc_relationship_and_invalid_preferred_path_fail_closed() -> None:
    sample = bytearray(build_carchive([("entrypoint", b"payload", True, "s")]))
    cookie = sample.rfind(target.MemoryCArchiveReader.COOKIE_MAGIC)
    archive_length = struct.unpack_from("!I", sample, cookie + 8)[0]
    struct.pack_into("!I", sample, cookie + 8, archive_length - 1)
    with pytest.raises(target.MemoryCArchiveError, match="長さ関係"):
        target.analyze_carchive_bytes(bytes(sample))

    normal = build_carchive([("entrypoint", b"payload", True, "s")])
    with pytest.raises(target.MemoryCArchiveError, match="相対移動"):
        target.analyze_carchive_bytes(normal, preferred_names=("../escape",))

    payload_option = build_carchive([("pyi-option", b"hidden", False, "o")])
    with pytest.raises(target.MemoryCArchiveError, match="option record"):
        target.analyze_carchive_bytes(payload_option)

    oversized_name = build_carchive([("a" * (target.MAX_ENTRY_NAME_BYTES + 17), b"x", False, "x")])
    with pytest.raises(target.MemoryCArchiveError, match="entry名領域"):
        target.analyze_carchive_bytes(oversized_name)


def test_full_content_validation_reports_budget_and_time_partial_states(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = build_carchive(
        [
            ("bulk/a.dat", b"A" * 10, False, "x"),
            ("bulk/b.dat", b"B" * 10, False, "x"),
        ]
    )
    budget_limited = target.analyze_carchive_bytes(
        sample,
        max_validation_total_compressed_size=15,
        max_validation_total_uncompressed_size=15,
    )
    assert budget_limited.report["analysis_status"] == "partial_content_validation"
    assert budget_limited.report["content_validation"]["status"] == "partial_budget_limit"
    assert budget_limited.report["content_validation"]["validated_entry_count"] == 0
    assert budget_limited.report["content_validation"]["content_commitment"] is None
    assert "full_content_validation_exceeds_budget" in budget_limited.report["selection"]["blockers"]

    clock = iter((0.0, 0.0, 2.0))
    monkeypatch.setattr(target.time, "monotonic", lambda: next(clock))
    time_limited = target.analyze_carchive_bytes(sample, max_validation_seconds=1.0)
    assert time_limited.report["content_validation"]["status"] == "partial_time_limit"
    assert time_limited.report["content_validation"]["validated_entry_count"] == 1
    assert time_limited.report["content_validation"]["format_classification_complete"] is False
    assert time_limited.report["content_validation"]["time_limit_reached"] is True
    assert "full_content_validation_time_limit_reached" in time_limited.report["selection"]["blockers"]
