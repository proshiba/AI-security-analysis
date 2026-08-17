"""StealC taggant／aPLib静的復元器の合成回帰試験。"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import struct
import sys

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
MODULE_PATH = REPOSITORY / "analysis-framework" / "malware" / "stealc" / "taggant_aplib_recovery.py"
SPEC = importlib.util.spec_from_file_location("stealc_taggant_aplib_recovery", MODULE_PATH)
assert SPEC and SPEC.loader
recovery = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = recovery
SPEC.loader.exec_module(recovery)


def _literal_aplib(clear: bytes) -> bytes:
    """合成byte列をliteral tokenだけのaPLib streamへする。"""

    assert clear
    stream = bytearray([clear[0]])
    tag_index = -1
    mask = 0

    def bit(value: int) -> None:
        nonlocal mask, tag_index
        if mask == 0:
            tag_index = len(stream)
            stream.append(0)
            mask = 0x80
        if value:
            stream[tag_index] |= mask
        mask >>= 1

    for value in clear[1:]:
        bit(0)
        stream.append(value)
    for value in (1, 1, 0):
        bit(value)
    stream.append(0)
    return bytes(stream)


def _synthetic_section() -> tuple[bytearray, recovery.RecoveryProfile, bytes]:
    destination_rva = 0x2000
    entry_offset = 0x10
    expanded = bytearray(b"\x90" * 600)
    expanded[0] = 0xE9
    struct.pack_into("<i", expanded, 1, entry_offset - 5)
    marker_offset = 32
    expanded[marker_offset : marker_offset + len(recovery.PERSISTENCE_MARKER)] = recovery.PERSISTENCE_MARKER
    stream = _literal_aplib(bytes(expanded))
    section = bytearray(recovery.PAGE_SIZE)
    section[recovery.SOURCE_OFFSET : recovery.SOURCE_OFFSET + len(stream)] = stream
    page_sha256 = hashlib.sha256(section).hexdigest()
    profile = recovery.RecoveryProfile(
        input_size=0,
        section_rva=0x5000,
        section_raw_size=len(section),
        xor_key=0,
        add_key=0,
        encrypted_page_sha256=page_sha256,
        decrypted_page_sha256=page_sha256,
        source_rva=0x5000 + recovery.SOURCE_OFFSET,
        destination_rva=destination_rva,
        compressed_consumed_size=len(stream),
        expanded_size=len(expanded),
        expanded_sha256=hashlib.sha256(expanded).hexdigest(),
        expanded_entry_rva=destination_rva + entry_offset,
        entry_window_sha256=hashlib.sha256(expanded[entry_offset : entry_offset + 512]).hexdigest(),
        persistence_marker_offset=marker_offset,
    )
    return section, profile, bytes(expanded)


def test_reviewed_profile_set_is_exact_and_terminal_safe() -> None:
    assert len(recovery.REVIEWED_PROFILES) == 11
    assert all(len(sha256) == 64 for sha256 in recovery.REVIEWED_PROFILES)
    assert all(profile.expanded_size < recovery.MAX_EXPANDED_SIZE for profile in recovery.REVIEWED_PROFILES.values())
    assert all(profile.source_rva == profile.section_rva + recovery.SOURCE_OFFSET for profile in recovery.REVIEWED_PROFILES.values())


def test_aplib_literal_and_short_match_vectors() -> None:
    assert recovery._decompress_aplib(b"A\xc0\x00", 16) == (b"A", 3)
    assert recovery._decompress_aplib(b"A\xd8\x02\x00", 16) == (b"AAA", 4)
    clear = b"synthetic literal-only output"
    assert recovery._decompress_aplib(_literal_aplib(clear), 128)[0] == clear


@pytest.mark.parametrize(
    "source,maximum",
    [
        (b"", 16),
        (b"A", 16),
        (b"A\xfe", 16),
        (b"A\xd8\x02\x00", 2),
    ],
)
def test_aplib_malformed_or_oversized_input_fails_closed(source: bytes, maximum: int) -> None:
    with pytest.raises(recovery.TaggantAplibRecoveryError):
        recovery._decompress_aplib(source, maximum)


@pytest.mark.parametrize("maximum", [0, recovery.MAX_EXPANDED_SIZE + 1])
def test_aplib_invalid_output_budget_is_rejected(maximum: int) -> None:
    with pytest.raises(recovery.TaggantAplibRecoveryError, match="出力上限"):
        recovery._decompress_aplib(b"A\xc0\x00", maximum)


def test_synthetic_section_recovers_only_publish_safe_metadata() -> None:
    section, profile, expanded = _synthetic_section()
    result = recovery._recover_section(section, profile)
    assert result["aplib"]["expanded_sha256"] == hashlib.sha256(expanded).hexdigest()
    assert result["expanded_region"] == {
        "destination_rva": 0x2000,
        "entry_rva": 0x2010,
        "entry_window_size": 512,
        "entry_window_sha256": hashlib.sha256(expanded[0x10:0x210]).hexdigest(),
        "persistence_marker": "%userappdata%\\RestartApp.exe",
        "persistence_marker_offset": 32,
        "embedded_pe_count": 0,
        "raw_bytes_published": False,
    }
    assert "expanded" not in result["expanded_region"]


def test_page_or_profile_mutation_is_rejected() -> None:
    section, profile, _expanded = _synthetic_section()
    section[0] ^= 1
    with pytest.raises(recovery.TaggantAplibRecoveryError, match="暗号化page"):
        recovery._recover_section(section, profile)


def test_unreviewed_input_is_rejected_before_pe_parsing() -> None:
    with pytest.raises(recovery.TaggantAplibRecoveryError, match="review済みprofile"):
        recovery.analyze_bytes(b"MZ synthetic unreviewed bytes")


def test_input_reader_enforces_budget_before_analysis(tmp_path: Path) -> None:
    path = tmp_path / "oversized.bin"
    path.write_bytes(b"A" * (recovery.MAX_INPUT_SIZE + 1))
    with pytest.raises(recovery.TaggantAplibRecoveryError, match="size上限"):
        recovery._read_bounded_input(path)


def test_strict_embedded_pe_counter_ignores_incidental_mz() -> None:
    data = bytearray(b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40) + b"PE\0\0")
    assert recovery._count_embedded_pe(bytes(data)) == 1
    data[0x40:0x44] = b"PX\0\0"
    assert recovery._count_embedded_pe(bytes(data)) == 0
