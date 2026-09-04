#!/usr/bin/env python3
"""Innoで配布されたside-loading bundleを非実行で有界解析する。"""

from __future__ import annotations

import hashlib
import re
import struct
from collections.abc import Mapping
from pathlib import PurePosixPath

import pefile

from unpackers.path_safety import safe_member_name

MAX_BUNDLE_MEMBERS = 64
MAX_MEMBER_SIZE = 64 * 1024 * 1024
MAX_BUNDLE_SIZE = 128 * 1024 * 1024
MAX_PDB_SIZE = 16 * 1024 * 1024
MAX_DECODED_RECORD = 4 * 1024 * 1024
MAX_STOMP_CODE = 2 * 1024 * 1024
MAX_VOLUME_SIZE = 64 * 1024 * 1024
MAX_SEGMENT_OUTPUT = 128 * 1024 * 1024
MAX_SEGMENTS = 8192
MAX_NAME_BYTES = 96
MAX_SCENE_HEADER_CANDIDATES = 8
MAX_IMPORT_DESCRIPTORS = 64
MAX_IMPORT_SYMBOLS_PER_DESCRIPTOR = 128


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    """archive member名を相対POSIX pathへ限定する。"""

    normalized = safe_member_name(name, kind="Inno")
    parts = normalized.split("/")
    if any(
        part == "."
        or part.rstrip(" .") != part
        or ":" in part
        or any(ord(character) < 0x20 for character in part)
        for part in parts
    ):
        raise ValueError("unsafe member name")
    return normalized


def _nibble_decimal_length(value: int) -> int:
    """loaderの6 nibble・10進重み長変換を再現する。"""

    return sum(((value >> (4 * index)) & 0xF) * (10**index) for index in range(6))


def _decode_additive_dwords(data: bytes, key: int) -> bytes:
    if len(data) % 4:
        raise ValueError("encoded record is not DWORD aligned")
    output = bytearray(len(data))
    for offset in range(0, len(data), 4):
        value = struct.unpack_from("<I", data, offset)[0]
        struct.pack_into("<I", output, offset, (value + key) & 0xFFFFFFFF)
    return bytes(output)


def _valid_module_name(raw: bytes) -> str | None:
    if not 5 <= len(raw) <= MAX_NAME_BYTES or raw[-1:] != b"\0":
        return None
    value = raw[:-1]
    if not re.fullmatch(rb"[A-Za-z0-9_.-]+\.(?:dll|exe)", value, re.IGNORECASE):
        return None
    return value.decode("ascii")


def recover_scene_record(
    data: bytes,
    *,
    max_record_size: int = MAX_DECODED_RECORD,
    max_code_size: int = MAX_STOMP_CODE,
) -> tuple[dict[str, object], list[tuple[str, bytes]], dict[str, bytes | int] | None]:
    """PDB末尾の ``<length, add-key, encoded DWORDs>`` を復元する。

    offsetを固定せず、file末尾へ厳密一致するheaderだけを候補にする。復号後は
    NUL終端module名、descriptor、entry/copy範囲、x86 function prologueを全て
    検証する。key本体はreportへ出さずhashだけを返す。
    """

    base_report: dict[str, object] = {
        "schema_version": 1,
        "executed": False,
        "cpu_emulated": False,
        "network_contacted": False,
    }
    if (
        not 0 < max_record_size <= MAX_DECODED_RECORD
        or not 0 < max_code_size <= MAX_STOMP_CODE
    ):
        raise ValueError("recovery limits exceed the fixed safety ceiling")
    if not 16 <= len(data) <= MAX_PDB_SIZE:
        return (
            {**base_report, "status": "not_candidate", "reason": "input_size"},
            [],
            None,
        )

    cheap_candidates: list[tuple[int, int, int, int, int, str]] = []
    for offset in range(0, len(data) - 8, 4):
        declared, key = struct.unpack_from("<II", data, offset)
        if (
            declared < 32
            or declared > max_record_size
            or declared % 4
            or offset + 8 + declared != len(data)
        ):
            continue
        encoded = data[offset + 8 :]
        first_dword = (struct.unpack_from("<I", encoded, 0)[0] + key) & 0xFFFFFFFF
        first_plain = struct.pack("<I", first_dword)
        name_length = first_plain[0]
        if not 5 <= name_length <= min(MAX_NAME_BYTES, declared - 13):
            continue
        preview_size = min(declared, ((name_length + 15) // 4) * 4)
        preview = _decode_additive_dwords(encoded[:preview_size], key)
        module_name = _valid_module_name(preview[1:name_length])
        if module_name is None:
            continue
        descriptor_offset = name_length
        if descriptor_offset + 12 > len(preview):
            continue
        reserved, entry_offset, copy_size = struct.unpack_from(
            "<III", preview, descriptor_offset
        )
        code_offset = descriptor_offset + 12
        code_end = code_offset + copy_size
        if (
            reserved != 0
            or not 0 < copy_size <= max_code_size
            or entry_offset >= copy_size
            or code_end > declared
        ):
            continue
        prologue_offset = code_offset & ~3
        prologue_block = _decode_additive_dwords(
            encoded[prologue_offset : prologue_offset + 8], key
        )
        prologue_index = code_offset - prologue_offset
        if prologue_block[prologue_index : prologue_index + 3] != b"\x55\x8b\xec":
            continue
        cheap_candidates.append(
            (offset, key, code_offset, entry_offset, copy_size, module_name)
        )
        if len(cheap_candidates) > MAX_SCENE_HEADER_CANDIDATES:
            return (
                {
                    **base_report,
                    "status": "header_candidate_limit_blocked",
                    "max_header_candidates": MAX_SCENE_HEADER_CANDIDATES,
                },
                [],
                None,
            )

    candidates: list[tuple[int, bytes, int, int, int, str]] = []
    for (
        offset,
        key,
        code_offset,
        entry_offset,
        copy_size,
        module_name,
    ) in cheap_candidates:
        decoded = _decode_additive_dwords(data[offset + 8 :], key)
        candidates.append(
            (offset, decoded, code_offset, entry_offset, copy_size, module_name)
        )

    if len(candidates) != 1:
        return (
            {
                **base_report,
                "status": "ambiguous" if candidates else "not_found",
                "candidate_count": len(candidates),
            },
            [],
            None,
        )

    offset, decoded, code_offset, entry_offset, copy_size, module_name = candidates[0]
    encoded_key = data[offset + 4 : offset + 8]
    code = decoded[code_offset : code_offset + copy_size]
    context_offset = code_offset + copy_size
    profile: dict[str, bytes | int] | None = None
    profile_status = "not_present"
    if context_offset + 0xC4 <= len(decoded):
        wildcard_prefix = decoded[context_offset + 0x9C : context_offset + 0xA0]
        marker_suffix = decoded[context_offset + 0xC0 : context_offset + 0xC4]
        sentinel = decoded[context_offset + 0xB0 : context_offset + 0xB4]
        if wildcard_prefix == bytes((0x3F,)) * 4 and re.fullmatch(
            rb"[A-Z]{4}", marker_suffix
        ):
            profile = {
                "wildcard_prefix": wildcard_prefix,
                "marker_suffix": marker_suffix,
                "sentinel": sentinel,
            }
            profile_status = "validated"

    report = {
        **base_report,
        "status": "record_recovered",
        "source_offset": offset,
        "decoded_size": len(decoded),
        "decoded_sha256": _sha256(decoded),
        "key_sha256": _sha256(encoded_key),
        "module_name": module_name,
        "descriptor_offset": descriptor_offset,
        "code_offset": code_offset,
        "entry_offset": entry_offset,
        "copy_size": copy_size,
        "code_sha256": _sha256(code),
        "context_trailer_size": len(decoded) - context_offset,
        "volume_profile_status": profile_status,
        "volume_marker_mask": (
            "?" * 8 + bytes(profile["marker_suffix"]).hex()
            if profile is not None
            else None
        ),
        "volume_sentinel_sha256": (
            _sha256(bytes(profile["sentinel"])) if profile is not None else None
        ),
    }
    return report, [("inno-scene-record", decoded), ("inno-stomp-code", code)], profile


def recover_segmented_volume(
    data: bytes,
    profile: Mapping[str, bytes | int],
    *,
    max_output_size: int = MAX_SEGMENT_OUTPUT,
    max_segments: int = MAX_SEGMENTS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """wildcard chunk markerで分割されたvolumeをloader通りに再構築する。"""

    base_report: dict[str, object] = {
        "schema_version": 1,
        "executed": False,
        "cpu_emulated": False,
        "network_contacted": False,
    }
    if (
        not 0 < max_output_size <= MAX_SEGMENT_OUTPUT
        or not 0 < max_segments <= MAX_SEGMENTS
    ):
        raise ValueError("recovery limits exceed the fixed safety ceiling")
    if not 32 <= len(data) <= MAX_VOLUME_SIZE:
        return {**base_report, "status": "not_candidate", "reason": "input_size"}, []
    try:
        wildcard_prefix = bytes(profile["wildcard_prefix"])
        marker_suffix = bytes(profile["marker_suffix"])
        sentinel = bytes(profile["sentinel"])
    except (KeyError, TypeError, ValueError):
        return {**base_report, "status": "invalid_profile"}, []
    if len(wildcard_prefix) != 4 or len(marker_suffix) != 4 or len(sentinel) != 4:
        return {**base_report, "status": "invalid_profile"}, []

    records: list[int] = []
    cursor = 0
    while len(records) <= max_segments:
        suffix_offset = data.find(marker_suffix, cursor)
        if suffix_offset < 0:
            break
        if suffix_offset < 4:
            cursor = suffix_offset + 1
            continue
        marker_offset = suffix_offset - 4
        if all(
            expected == 0x3F or expected == observed
            for expected, observed in zip(
                wildcard_prefix, data[marker_offset:suffix_offset], strict=True
            )
        ):
            records.append(suffix_offset + 4)
        cursor = suffix_offset + 1
    if len(records) > max_segments:
        return {**base_report, "status": "segment_limit_blocked"}, []

    sentinel_value = struct.unpack("<I", sentinel)[0]
    starts = [
        offset
        for offset in records
        if offset + 20 <= len(data)
        and struct.unpack_from("<I", data, offset)[0] == sentinel_value
    ]
    if len(starts) != 1:
        return {
            **base_report,
            "status": "sentinel_ambiguous" if starts else "sentinel_not_found",
            "marker_count": len(records),
            "sentinel_count": len(starts),
        }, []
    first_index = records.index(starts[0])
    first = starts[0]
    # first recordは ``sentinel, segment-key, copy-prefix, xor-key,
    # xor-length, ...``。loaderはrecord+8から連結し、record+12のkeyで
    # 連結buffer+16をrecord+16の長さだけXORする。
    key = struct.unpack_from("<I", data, first + 12)[0]
    declared_body = struct.unpack_from("<I", data, first + 16)[0]
    allocation_size = declared_body + 16
    if declared_body == 0 or allocation_size > max_output_size:
        return {
            **base_report,
            "status": "output_size_blocked",
            "marker_count": len(records),
            "sentinel_count": len(starts),
            "declared_body_size": declared_body,
            "allocation_size": allocation_size,
            "max_output_size": max_output_size,
        }, []

    output = bytearray()
    used = 0
    final_segment_clipped = False
    final_declared_segment_length: int | None = None
    for record_index in range(first_index, len(records)):
        record = records[record_index]
        next_marker_offset = (
            records[record_index + 1] - 8
            if record_index + 1 < len(records)
            else len(data)
        )
        if record + 8 > next_marker_offset:
            return {
                **base_report,
                "status": "segment_boundary_violation",
                "marker_count": len(records),
                "segments_used": used,
                "record_offset": record,
            }, []
        encoded_length = struct.unpack_from("<I", data, record)[0]
        segment_length = _nibble_decimal_length(encoded_length)
        source_offset = record + 8
        available = next_marker_offset - source_offset
        remaining = allocation_size - len(output)
        if segment_length <= 0:
            break
        take = min(segment_length, remaining)
        if take > available:
            return {
                **base_report,
                "status": "segment_boundary_violation",
                "marker_count": len(records),
                "segments_used": used,
                "record_offset": record,
                "declared_segment_length": segment_length,
                "available_before_next_marker": max(0, available),
                "required_for_allocation": take,
            }, []
        if remaining < segment_length:
            final_segment_clipped = True
            final_declared_segment_length = segment_length
        output.extend(data[source_offset : source_offset + take])
        used += 1
        if len(output) == allocation_size:
            break
    if len(output) != allocation_size:
        return {
            **base_report,
            "status": "truncated_segment_stream",
            "marker_count": len(records),
            "segments_used": used,
            "declared_output_size": allocation_size,
            "recovered_size": len(output),
        }, []

    rounded_body = declared_body - (declared_body % 4)
    for offset in range(16, 16 + rounded_body, 4):
        value = struct.unpack_from("<I", output, offset)[0]
        struct.pack_into("<I", output, offset, value ^ key)
    recovered = bytes(output)
    source_size = struct.unpack_from("<I", recovered, 8)[0]
    destination_size = struct.unpack_from("<I", recovered, 12)[0]
    lznt1_bounds_valid = (
        0 < source_size <= len(recovered) - 16
        and 0 < destination_size <= max_output_size
    )
    report = {
        **base_report,
        "status": (
            "segmented_buffer_recovered"
            if lznt1_bounds_valid
            else "segmented_buffer_recovered_lznt1_blocked"
        ),
        "marker_count": len(records),
        "sentinel_count": len(starts),
        "segments_used": used,
        "declared_body_size": declared_body,
        "allocation_size": allocation_size,
        "final_segment_clipped_to_allocation": final_segment_clipped,
        "final_declared_segment_length": final_declared_segment_length,
        "recovered_size": len(recovered),
        "recovered_sha256": _sha256(recovered),
        "key_sha256": _sha256(data[first + 12 : first + 16]),
        "lznt1_source_size": source_size,
        "lznt1_destination_size": destination_size,
        "lznt1_bounds_valid": lznt1_bounds_valid,
        "next_action": (
            "bounded_lznt1_decompression"
            if lznt1_bounds_valid
            else "manual_size_field_mapping_review"
        ),
    }
    return report, [("inno-volume-segmented-buffer", recovered)]


def _pe_summary(data: bytes) -> dict[str, object]:
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        return {"status": "parse_failed", "error_type": type(exc).__name__}
    imports: list[dict[str, object]] = []
    import_descriptors = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    for descriptor in import_descriptors[:MAX_IMPORT_DESCRIPTORS]:
        library = descriptor.dll.decode("ascii", errors="replace")
        symbols = []
        for item in descriptor.imports[:MAX_IMPORT_SYMBOLS_PER_DESCRIPTOR]:
            symbols.append(
                {
                    "name": item.name.decode("ascii", errors="replace")
                    if item.name
                    else None,
                    "ordinal": item.ordinal,
                }
            )
        imports.append(
            {
                "library": library,
                "symbol_count": len(symbols),
                "contains_ordinal_1": any(
                    symbol.get("ordinal") == 1 for symbol in symbols
                ),
                "symbols": symbols,
                "symbols_truncated": len(descriptor.imports)
                > MAX_IMPORT_SYMBOLS_PER_DESCRIPTOR,
            }
        )
    entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    entry = pe.get_data(entry_rva, 8)
    entry_jump_rva = None
    if len(entry) >= 5 and entry[0] == 0xE9:
        entry_jump_rva = (
            entry_rva + 5 + struct.unpack_from("<i", entry, 1)[0]
        ) & 0xFFFFFFFF
    optional_header = pe.OPTIONAL_HEADER
    directory_count = getattr(optional_header, "NumberOfRvaAndSizes", 0)
    directories = getattr(optional_header, "DATA_DIRECTORY", ())
    certificate_directory = None
    if (
        type(directory_count) is int
        and directory_count > 4
        and isinstance(directories, (list, tuple))
        and len(directories) > 4
    ):
        certificate_directory = directories[4]
    return {
        "status": "parsed",
        "machine": int(pe.FILE_HEADER.Machine),
        "entry_rva": entry_rva,
        "entry_bytes": entry.hex(),
        "entry_rel32_jump_rva": entry_jump_rva,
        "imports": imports,
        "import_descriptors_truncated": len(import_descriptors)
        > MAX_IMPORT_DESCRIPTORS,
        "certificate_table_present": bool(
            certificate_directory is not None
            and getattr(certificate_directory, "VirtualAddress", 0)
            and getattr(certificate_directory, "Size", 0)
        ),
    }


def recover_inno_sideload_bundle(
    members: Mapping[str, bytes],
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """Inno抽出memberを関連付け、PDB/volume層を有界復元する。"""

    base_report: dict[str, object] = {
        "schema_version": 1,
        "executed": False,
        "cpu_emulated": False,
        "network_contacted": False,
    }
    if not 1 <= len(members) <= MAX_BUNDLE_MEMBERS:
        return {**base_report, "status": "member_limit_blocked"}, []
    normalized: dict[str, bytes] = {}
    total = 0
    try:
        for raw_name, raw_blob in members.items():
            if not isinstance(raw_name, str) or not isinstance(raw_blob, bytes):
                return {**base_report, "status": "invalid_member"}, []
            name = _safe_name(raw_name)
            blob = raw_blob
            if len(blob) > MAX_MEMBER_SIZE:
                return {
                    **base_report,
                    "status": "member_size_blocked",
                    "member": name,
                }, []
            total += len(blob)
            if total > MAX_BUNDLE_SIZE:
                return {**base_report, "status": "bundle_size_blocked"}, []
            basename = PurePosixPath(name).name.casefold()
            if basename in normalized:
                return {
                    **base_report,
                    "status": "ambiguous_basename",
                    "member": basename,
                }, []
            normalized[basename] = blob
    except (TypeError, ValueError):
        return {**base_report, "status": "invalid_member"}, []

    host = normalized.get("processormeta.exe")
    vislib = normalized.get("vislib.dll")
    volume = normalized.get("volume-ext.dll")
    pdb_candidates = [
        (name, blob) for name, blob in normalized.items() if name.endswith(".pdb")
    ]
    if host is None or vislib is None or len(pdb_candidates) != 1:
        return {
            **base_report,
            "status": "not_candidate",
            "required_members_present": {
                "host": host is not None,
                "vislib": vislib is not None,
                "unique_pdb": len(pdb_candidates) == 1,
                "volume": volume is not None,
            },
        }, []

    host_pe = _pe_summary(host)
    vislib_pe = _pe_summary(vislib)
    ordinal_one = any(
        str(item.get("library", "")).casefold() == "vislib.dll"
        and item.get("contains_ordinal_1") is True
        for item in host_pe.get("imports", [])
        if isinstance(item, dict)
    )
    vislib_strings = {
        "scene_pdb_utf16": "sceneprime29.pdb".encode("utf-16le") in vislib,
        "volume_sidecar_ascii": b"volume-ext.dll" in vislib,
        "kernel32_utf16": "kernel32".encode("utf-16le") in vislib,
    }
    pdb_report, artifacts, profile = recover_scene_record(pdb_candidates[0][1])
    volume_report: dict[str, object] = {"status": "not_attempted_no_valid_profile"}
    if volume is not None and profile is not None:
        volume_report, volume_artifacts = recover_segmented_volume(volume, profile)
        artifacts.extend(volume_artifacts)
    status = (
        "module_stomp_chain_recovered"
        if (
            ordinal_one
            and pdb_report.get("status") == "record_recovered"
            and vislib_strings["scene_pdb_utf16"]
            and vislib_strings["volume_sidecar_ascii"]
            and vislib_pe.get("entry_rel32_jump_rva") is not None
        )
        else "candidate_partial"
    )
    report = {
        **base_report,
        "status": status,
        "member_count": len(normalized),
        "host": host_pe,
        "vislib": vislib_pe,
        "host_imports_vislib_ordinal_1": ordinal_one,
        "vislib_loader_strings": vislib_strings,
        "scene_record": pdb_report,
        "volume": volume_report,
        "process_model": {
            "host_process_candidate": "ProcessorMeta.exe",
            "launch_confirmed": False,
            "subsequent_payload_execution": "same_process_module_stomp_candidate",
        },
    }
    return report, artifacts


def recover_scene_record_artifacts(
    data: bytes, name: str
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """single-file fixed-pointからPDB record復元を呼ぶ互換entry。"""

    if PurePosixPath(name.replace("\\", "/")).suffix.casefold() != ".pdb":
        return {"status": "not_candidate", "executed": False}, []
    report, artifacts, _ = recover_scene_record(data)
    return report, artifacts
