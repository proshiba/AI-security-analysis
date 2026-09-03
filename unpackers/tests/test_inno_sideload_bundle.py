from __future__ import annotations

import struct
from types import SimpleNamespace

import unpackers.inno_sideload_bundle as inno
from unpackers.inno_sideload_bundle import (
    MAX_SEGMENT_OUTPUT,
    recover_inno_sideload_bundle,
    recover_scene_record,
    recover_scene_record_artifacts,
    recover_segmented_volume,
)


def _scene_fixture() -> tuple[bytes, bytes, dict[str, bytes | int]]:
    name = b"tapisrv.dll\0"
    code = b"\x55\x8b\xec" + b"\x90" * (0x200 - 3)
    trailer = bytearray(0x14B)
    trailer[0x9C:0xA0] = b"????"
    trailer[0xC0:0xC4] = b"IDAT"
    trailer[0xB0:0xB4] = struct.pack("<I", 0x00112233)
    decoded = (
        bytes([len(name) + 1])
        + name
        + struct.pack("<III", 0, 0x40, len(code))
        + code
        + trailer
    )
    assert len(decoded) % 4 == 0
    key = 0x13579BDF
    encoded = b"".join(
        struct.pack("<I", (value - key) & 0xFFFFFFFF)
        for (value,) in struct.iter_unpack("<I", decoded)
    )
    prefix = b"PDB-FIXTURE" + b"\0" * 21
    assert len(prefix) % 4 == 0
    source = prefix + struct.pack("<II", len(encoded), key) + encoded
    profile = {
        "wildcard_prefix": b"????",
        "marker_suffix": b"IDAT",
        "sentinel": struct.pack("<I", 0x00112233),
    }
    return source, decoded, profile


def test_scene_record_is_recovered_without_fixed_offset() -> None:
    source, decoded, profile = _scene_fixture()

    report, artifacts, observed_profile = recover_scene_record(source)

    assert report["status"] == "record_recovered"
    assert report["module_name"] == "tapisrv.dll"
    assert report["entry_offset"] == 0x40
    assert report["copy_size"] == 0x200
    assert report["volume_marker_mask"] == "????????49444154"
    assert observed_profile == profile
    assert artifacts[0] == ("inno-scene-record", decoded)
    assert artifacts[1][0] == "inno-stomp-code"
    assert "13579bdf" not in str(report).lower()


def test_single_file_fixed_point_entry_is_suffix_gated() -> None:
    source, _, _ = _scene_fixture()
    report, artifacts = recover_scene_record_artifacts(source, "sceneprime29.pdb")
    assert report["status"] == "record_recovered"
    assert len(artifacts) == 2

    report, artifacts = recover_scene_record_artifacts(source, "sceneprime29.bin")
    assert report["status"] == "not_candidate"
    assert artifacts == []


def test_segmented_volume_uses_unique_sentinel_and_bounded_xor() -> None:
    _, _, profile = _scene_fixture()
    key = 0xA5A5A5A5
    payload = b"ABCDEFGH"
    body_size = len(payload)
    final = bytearray(struct.pack("<IIII", 0, key, body_size, 16) + payload)
    encoded = bytearray(final)
    for offset in range(16, len(encoded), 4):
        value = struct.unpack_from("<I", encoded, offset)[0]
        struct.pack_into("<I", encoded, offset, value ^ key)
    record = profile["sentinel"] + b"SEGM" + bytes(encoded) + b"padding"
    volume = b"cover" + struct.pack(">I", 0x2000) + b"IDAT" + record

    report, artifacts = recover_segmented_volume(volume, profile)

    assert report["status"] == "segmented_buffer_recovered"
    assert report["segments_used"] == 1
    assert report["lznt1_source_size"] == body_size
    assert report["lznt1_destination_size"] == 16
    assert artifacts == [("inno-volume-segmented-buffer", bytes(final))]


def test_segmented_volume_skips_leading_partial_marker_suffixes() -> None:
    _, _, profile = _scene_fixture()
    key = 0xA5A5A5A5
    payload = b"ABCDEFGH"
    body_size = len(payload)
    final = bytearray(struct.pack("<IIII", 0, key, body_size, 16) + payload)
    encoded = bytearray(final)
    for position in range(16, len(encoded), 4):
        value = struct.unpack_from("<I", encoded, position)[0]
        struct.pack_into("<I", encoded, position, value ^ key)
    valid_volume = (
        b"cover"
        + struct.pack(">I", 0x2000)
        + b"IDAT"
        + profile["sentinel"]
        + b"SEGM"
        + bytes(encoded)
        + b"padding"
    )

    for offset in range(4):
        volume = b"x" * offset + b"IDAT" + valid_volume
        report, artifacts = recover_segmented_volume(volume, profile)
        assert report["status"] == "segmented_buffer_recovered"
        assert report["marker_count"] == 1
        assert artifacts == [("inno-volume-segmented-buffer", bytes(final))]


def test_segmented_volume_fails_closed_on_ambiguous_sentinel() -> None:
    _, _, profile = _scene_fixture()
    record = profile["sentinel"] + b"\0" * 64
    volume = (
        struct.pack(">I", 0x2000)
        + b"IDAT"
        + record
        + struct.pack(">I", 0x2000)
        + b"IDAT"
        + record
    )
    report, artifacts = recover_segmented_volume(volume, profile)
    assert report["status"] == "sentinel_ambiguous"
    assert artifacts == []


def test_segmented_volume_blocks_declared_output_over_ceiling() -> None:
    _, _, profile = _scene_fixture()
    record = (
        profile["sentinel"]
        + b"SEGM"
        + struct.pack("<IIII", 0, 0x10203040, MAX_SEGMENT_OUTPUT, 32)
        + b"\0" * 16
    )
    volume = struct.pack(">I", 0x2000) + b"IDAT" + record
    report, artifacts = recover_segmented_volume(volume, profile)
    assert report["status"] == "output_size_blocked"
    assert report["marker_count"] == 1
    assert report["sentinel_count"] == 1
    assert report["allocation_size"] == MAX_SEGMENT_OUTPUT + 16
    assert artifacts == []


def test_segmented_volume_rejects_truncated_sentinel_header() -> None:
    _, _, profile = _scene_fixture()
    volume = b"x" * 20 + b"ABCDIDAT" + profile["sentinel"] + b"\0" * 8

    report, artifacts = recover_segmented_volume(volume, profile)

    assert report["status"] == "sentinel_not_found"
    assert report["marker_count"] == 1
    assert report["sentinel_count"] == 0
    assert artifacts == []


def test_segmented_volume_rejects_copy_across_next_marker() -> None:
    _, _, profile = _scene_fixture()
    first = profile["sentinel"] + b"SEGM" + struct.pack("<IIII", 0, 0x10203040, 32, 16)
    second = b"NOT!" + b"SEGM" + b"tail"
    volume = b"ABCDIDAT" + first + b"WXYZIDAT" + second

    report, artifacts = recover_segmented_volume(volume, profile)

    assert report["status"] == "segment_boundary_violation"
    assert report["available_before_next_marker"] == 16
    assert report["required_for_allocation"] == 48
    assert artifacts == []


def test_bundle_rejects_non_bytes_member_without_coercion() -> None:
    report, artifacts = recover_inno_sideload_bundle(
        {"ProcessorMeta.exe": bytearray(b"MZ")}
    )
    assert report["status"] == "invalid_member"
    assert artifacts == []


def test_scene_record_large_false_candidate_only_decodes_preview(monkeypatch) -> None:
    data = bytearray(1024 * 1024)
    declared = len(data) - 8
    key = (13 - declared) & 0xFF
    struct.pack_into("<II", data, 0, declared, key)
    decoded_sizes: list[int] = []
    original = inno._decode_additive_dwords

    def observed(blob: bytes, add_key: int) -> bytes:
        decoded_sizes.append(len(blob))
        return original(blob, add_key)

    monkeypatch.setattr(inno, "_decode_additive_dwords", observed)
    report, _, _ = recover_scene_record(bytes(data))
    assert report["status"] == "not_found"
    assert decoded_sizes
    assert max(decoded_sizes) <= 128


def test_bundle_rejects_windows_drive_and_trailing_dot_names() -> None:
    for name in ("C:/ProcessorMeta.exe", "tmp/ProcessorMeta.exe."):
        report, artifacts = recover_inno_sideload_bundle({name: b"MZ"})
        assert report["status"] == "invalid_member"
        assert artifacts == []


def test_pe_summary_handles_absent_or_short_data_directory(monkeypatch) -> None:
    for count, directories in ((0, []), (16, [SimpleNamespace()] * 4)):
        fake_pe = SimpleNamespace(
            DIRECTORY_ENTRY_IMPORT=[],
            FILE_HEADER=SimpleNamespace(Machine=0x14C),
            OPTIONAL_HEADER=SimpleNamespace(
                AddressOfEntryPoint=0,
                NumberOfRvaAndSizes=count,
                DATA_DIRECTORY=directories,
            ),
            get_data=lambda _rva, _size: b"",
        )
        monkeypatch.setattr(inno.pefile, "PE", lambda _pe=fake_pe, **_kwargs: _pe)

        result = inno._pe_summary(b"MZ synthetic")

        assert result["status"] == "parsed"
        assert result["certificate_table_present"] is False
