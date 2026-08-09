"""full process dumpからのPE回収処理を検証する。"""

from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path

import pefile
import pytest

FRAMEWORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRAMEWORK))

from common import recover_process_dump_pe as recover


def _pe_fixture(
    *,
    mapped: bool,
    raw_size: int = 0x200,
    virtual_size: int = 0x180,
    section_name: bytes = b".text",
) -> bytes:
    """raw offsetとRVAが異なる最小PE32をfileまたはmapped配置で作る。"""

    file_alignment = 0x200
    section_alignment = 0x1000
    size_of_image = ((0x1000 + max(virtual_size, raw_size) + 0xFFF) // 0x1000) * 0x1000
    file_size = 0x200 + raw_size
    data = bytearray(size_of_image if mapped else file_size)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, section_alignment, file_alignment)
    struct.pack_into("<I", data, optional + 56, size_of_image)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = section_name.ljust(8, b"\0")[:8]
    struct.pack_into("<IIII", data, section + 8, virtual_size, 0x1000, raw_size, 0x200 if raw_size else 0)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    content_size = virtual_size if mapped else raw_size
    content_offset = 0x1000 if mapped else 0x200
    if content_size:
        data[content_offset : content_offset + content_size] = b"\x90\x90\xCC\xC3" + bytes(
            content_size - 4
        )
    return bytes(data)


def _output_section(payload: bytes) -> tuple[int, int]:
    image = pefile.PE(data=payload, fast_load=True)
    try:
        section = image.sections[0]
        return int(section.PointerToRawData), int(section.SizeOfRawData)
    finally:
        image.close()


def test_recovers_file_layout_at_nonzero_offset() -> None:
    prefix = b"prefix-without-magic"
    source = prefix + _pe_fixture(mapped=False) + b"tail"

    outputs, report = recover.recover_process_dump_bytes(source)

    assert len(outputs) == 1
    assert outputs[0].metadata["layout"] == "file"
    assert outputs[0].metadata["offset"] == len(prefix)
    assert outputs[0].payload[0x200:0x204] == b"\x90\x90\xCC\xC3"
    assert report["outputs"][0]["source_sha256"] == report["source"]["sha256"]
    assert report["outputs"][0]["candidate_sha256"]
    assert report["outputs"][0]["output_sha256"]


def test_recovers_mapped_layout_to_original_raw_offsets() -> None:
    source = b"A" * 37 + _pe_fixture(mapped=True)

    outputs, _ = recover.recover_process_dump_bytes(
        source,
        mapped_mode="original_raw",
    )

    assert len(outputs) == 1
    assert outputs[0].metadata["layout"] == "mapped"
    assert outputs[0].metadata["mapped_mode"] == "original_raw"
    assert outputs[0].payload[0x200:0x204] == b"\x90\x90\xCC\xC3"


def test_expands_memory_only_section_and_updates_section_header() -> None:
    virtual_size = 0x1A37
    source = _pe_fixture(
        mapped=True,
        raw_size=0,
        virtual_size=virtual_size,
        section_name=b".themida",
    )

    outputs, report = recover.recover_process_dump_bytes(source)

    assert len(outputs) == 1
    item = outputs[0]
    assert item.metadata["layout"] == "mapped"
    assert item.metadata["mapped_mode"] == "expanded_memory_sections"
    raw_offset, raw_size = _output_section(item.payload)
    assert raw_offset == 0x200
    assert raw_size == 0x1C00
    assert item.payload[raw_offset : raw_offset + 4] == b"\x90\x90\xCC\xC3"
    assert item.payload[raw_offset + virtual_size : raw_offset + raw_size] == bytes(
        raw_size - virtual_size
    )
    layout_evidence = report["outputs"][0]["validation_evidence"]["layout"]
    assert layout_evidence["memory_only_sections_recovered"] == 1
    assert layout_evidence["sections"][0]["memory_only_section_recovered"] is True


def test_expanded_mode_preserves_memory_extent_when_raw_exceeds_virtual() -> None:
    source = bytearray(
        _pe_fixture(mapped=True, raw_size=0x600, virtual_size=0x180)
    )
    marker = b"MEMORY-TAIL"
    source[0x1000 + 0x400 : 0x1000 + 0x400 + len(marker)] = marker

    outputs, _ = recover.recover_process_dump_bytes(
        bytes(source),
        mapped_mode="expanded_memory_sections",
    )

    assert len(outputs) == 1
    raw_offset, raw_size = _output_section(outputs[0].payload)
    assert raw_size == 0x600
    assert (
        outputs[0].payload[raw_offset + 0x400 : raw_offset + 0x400 + len(marker)]
        == marker
    )


def test_false_and_truncated_mz_candidates_are_recorded_without_output() -> None:
    source = b"MZfalse" + bytes(10) + b"MZ"

    outputs, report = recover.recover_process_dump_bytes(source)

    assert outputs == []
    assert report["summary"]["mz_candidates"] == 2
    assert report["summary"]["rejected_candidates"] == 2
    assert all(candidate["status"] == "rejected" for candidate in report["candidates"])


def test_exact_input_boundary_is_accepted_and_trailing_boundary_mz_is_rejected() -> None:
    valid = _pe_fixture(mapped=False)
    outputs, report = recover.recover_process_dump_bytes(valid + b"MZ")

    assert len(outputs) == 1
    assert report["summary"]["mz_candidates"] == 2
    assert report["candidates"][0]["status"] == "recovered"
    assert report["candidates"][1]["status"] == "rejected"


def test_duplicate_output_sha_is_written_only_once() -> None:
    sample = _pe_fixture(mapped=False)
    source = sample + b"padding" + sample

    outputs, report = recover.recover_process_dump_bytes(source)

    assert len(outputs) == 1
    assert report["summary"]["duplicate_candidates"] == 1
    duplicate_attempt = report["candidates"][1]["attempts"][-1]
    assert duplicate_attempt["status"] == "duplicate_output"
    assert duplicate_attempt["output_sha256"] == outputs[0].metadata["output_sha256"]


def test_input_candidate_and_output_budgets_fail_closed() -> None:
    sample = _pe_fixture(mapped=False)
    with pytest.raises(recover.ProcessDumpPEError, match="入力サイズ"):
        recover.recover_process_dump_bytes(sample, max_input_bytes=len(sample) - 1)
    with pytest.raises(recover.ProcessDumpPEError, match="MZ候補数"):
        recover.recover_process_dump_bytes(b"MZMZ", max_candidates=1)

    outputs, report = recover.recover_process_dump_bytes(
        sample,
        max_candidate_bytes=0x1000,
    )
    assert outputs == []
    assert "candidate budget" in report["candidates"][0]["reason"]

    duplicated = sample + b"X" + bytearray(sample)
    duplicated = bytearray(duplicated)
    duplicated[len(sample) + 1 + 0x200] = 0xCC
    with pytest.raises(recover.ProcessDumpPEError, match="出力合計サイズ"):
        recover.recover_process_dump_bytes(
            bytes(duplicated),
            max_output_bytes=len(sample),
        )


def test_file_api_writes_json_and_rejects_hardlinked_input(tmp_path: Path) -> None:
    input_path = tmp_path / "process.dmp"
    input_path.write_bytes(b"prefix" + _pe_fixture(mapped=False))
    output_dir = tmp_path / "recovered"

    report = recover.recover_process_dump_file(input_path, output_dir)

    report_path = output_dir / recover.REPORT_NAME
    assert report_path.is_file()
    stored = json.loads(report_path.read_text(encoding="utf-8"))
    assert stored["source"]["sha256"] == report["source"]["sha256"]
    output_path = output_dir / stored["outputs"][0]["output_name"]
    assert output_path.is_file()
    assert os.stat(output_path).st_nlink == 1

    linked_source = tmp_path / "linked-source.dmp"
    hardlink = tmp_path / "linked-alias.dmp"
    linked_source.write_bytes(_pe_fixture(mapped=False))
    try:
        os.link(linked_source, hardlink)
    except OSError as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")
    with pytest.raises(recover.ProcessDumpPEError, match="ハードリンク"):
        recover.recover_process_dump_file(linked_source, tmp_path / "hardlink-output")


def test_file_api_rejects_reparse_input_when_supported(tmp_path: Path) -> None:
    source = tmp_path / "source.dmp"
    source.write_bytes(_pe_fixture(mapped=False))
    link = tmp_path / "source-link.dmp"
    try:
        link.symlink_to(source)
    except OSError as exc:
        pytest.skip(f"この環境ではsymlinkを作成できません: {exc}")
    with pytest.raises(recover.ProcessDumpPEError, match="reparse point"):
        recover.recover_process_dump_file(link, tmp_path / "link-output")
