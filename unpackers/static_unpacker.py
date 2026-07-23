#!/usr/bin/env python3
"""検体を実行せず、上限付きで静的展開とアーティファクト復元を行う。"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from unpackers.path_safety import safe_member_name as validate_member_name

import dnfile
import pefile
import pyzipper

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from unpackers.asar_unpacker import is_asar, recover_asar
from unpackers.javascript_dropper_unpacker import recover_javascript_dropper
from unpackers.javascript_obfuscator import (
    decode_script_text,
    deobfuscate_plain_string_array,
    deobfuscate_string_array,
)
from unpackers.nsis_unpacker import recover_nsis_scripted_layers
from unpackers.container_recovery import (
    recover_inflated_pe,
    recover_macho_slices,
    recover_xz,
)
from unpackers.donut_unpacker import recover_donut_payloads
from unpackers.donut_wrapper_unpacker import recover_xor32_donut_wrapper
from unpackers.managed_il_triage import (
    _contain_parser_diagnostics,
    analyze_managed_pe,
)
from unpackers.static_control_flow import analyze_pe_control_flow

MAX_ARTIFACT = 256 * 1024 * 1024
ENTROPY_FULL_LIMIT = 8 * 1024 * 1024
ENTROPY_SAMPLE_WINDOW = 1 * 1024 * 1024
MAX_EXTRACTED_TOTAL = 768 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 512
MAX_RETAINED_MEMBERS = 128
MAX_COMPRESSION_RATIO = 200.0
ARCHIVE_READ_CHUNK_SIZE = 1024 * 1024
MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
MAX_PNG_CHUNKS = 4096
SCRIPT_SUFFIXES = {
    ".js",
    ".nsi",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".hta",
    ".osascript",
    ".applescript",
    ".vba",
    ".bat",
    ".cmd",
    ".sh",
}
RECOVERY_SUFFIXES = SCRIPT_SUFFIXES | {
    ".exe",
    ".dll",
    ".sys",
    ".bin",
    ".dat",
    ".json",
    ".ini",
    ".cfg",
    ".conf",
    ".a3x",
    ".sum",
    ".asar",
    ".zip",
    ".7z",
    ".cab",
}


def sha256_bytes(data: bytes) -> str:
    """バイト列の小文字SHA-256ダイジェストを返す。"""
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    """上限付きで決定的に算出し、小数4桁へ丸めたShannonエントロピーを返す。"""
    if not data:
        return 0.0
    sample = data
    if len(data) > ENTROPY_FULL_LIMIT:
        middle = max(0, (len(data) - ENTROPY_SAMPLE_WINDOW) // 2)
        sample = (
            data[:ENTROPY_SAMPLE_WINDOW]
            + data[middle : middle + ENTROPY_SAMPLE_WINDOW]
            + data[-ENTROPY_SAMPLE_WINDOW:]
        )
    counts = [0] * 256
    for value in sample:
        counts[value] += 1
    total = len(sample)
    return round(
        -sum(
            (count / total) * math.log2(count / total)
            for count in counts
            if count
        ),
        4,
    )


def detect_format(data: bytes, name: str = "sample") -> str:
    """静的復元パイプラインが対応する形式を識別する。"""
    suffix = Path(name).suffix.lower()
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(PNG_MAGIC):
        return "png"
    if is_asar(data):
        return "asar"
    if data[:4] in MACHO_MAGICS:
        # CAFEBABE is shared by Java class files and universal Mach-O.  Treat
        # it as Mach-O only when the bounded architecture table is plausible.
        if data[:4] in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
            endian = ">" if data[:4] == b"\xca\xfe\xba\xbe" else "<"
            if len(data) < 8:
                return "data"
            architecture_count = struct.unpack_from(endian + "I", data, 4)[0]
            if not 1 <= architecture_count <= 32 or 8 + architecture_count * 20 > len(data):
                return "java-class" if data[:4] == b"\xca\xfe\xba\xbe" else "data"
        return "macho"
    if data.startswith(b"7z\xbc\xaf'\x1c"):
        return "7z"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"ER\x02\x00"):
        return "apple-disk-image"
    if data.startswith(b"MSCF"):
        return "cab"
    if data.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "rar"
    if suffix == ".a3x" or "autoit-a3x" in name.lower():
        return "autoit-a3x"
    if zipfile.is_zipfile(io.BytesIO(data)):
        return "zip"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if suffix in SCRIPT_SUFFIXES or data[:256].lstrip().lower().startswith(
        (b"function ", b"var ", b"$", b"on error", b"tell application", b"#!/bin/")
    ):
        return "script"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")) or data[:512].count(b"\x00") >= 64:
        text_probe = decode_script_text(data[:4096]).lstrip().lower()
        if text_probe.startswith(
            ("//", "/*", "function ", "var ", "let ", "const ", "@echo", "set ")
        ):
            return "script"
    return "data"


def recover_png_concealed_data(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """PNGのIDAT内で画像zlib終端後に連結されたデータを上限付きで復元する。"""

    if not data.startswith(PNG_MAGIC):
        return {"status": "not_png"}, []
    offset = len(PNG_MAGIC)
    chunk_count = 0
    width = height = None
    idat = bytearray()
    png_end_offset = None
    while offset + 12 <= len(data):
        if chunk_count >= MAX_PNG_CHUNKS:
            return {"status": "chunk_limit_blocked", "chunk_count": chunk_count}, []
        length = int.from_bytes(data[offset : offset + 4], "big")
        chunk_type = data[offset + 4 : offset + 8]
        payload_start = offset + 8
        payload_end = payload_start + length
        crc_end = payload_end + 4
        if length > MAX_ARTIFACT or crc_end > len(data):
            return {"status": "invalid_chunk_bounds", "chunk_count": chunk_count}, []
        payload = data[payload_start:payload_end]
        expected_crc = int.from_bytes(data[payload_end:crc_end], "big")
        actual_crc = zlib.crc32(chunk_type + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            return {
                "status": "crc_mismatch",
                "chunk_count": chunk_count,
                "chunk_type": chunk_type.decode("ascii", errors="replace"),
            }, []
        chunk_count += 1
        if chunk_type == b"IHDR":
            if length != 13:
                return {"status": "invalid_ihdr_length"}, []
            width, height = struct.unpack(">II", payload[:8])
        elif chunk_type == b"IDAT":
            if len(idat) + length > MAX_ARTIFACT:
                return {"status": "idat_size_blocked", "chunk_count": chunk_count}, []
            idat.extend(payload)
        elif chunk_type == b"IEND":
            png_end_offset = crc_end
            break
        offset = crc_end
    if png_end_offset is None or width is None or height is None or not idat:
        return {"status": "incomplete_png", "chunk_count": chunk_count}, []

    inflater = zlib.decompressobj()
    try:
        pixels = inflater.decompress(bytes(idat), MAX_ARTIFACT + 1)
        if len(pixels) > MAX_ARTIFACT or not inflater.eof:
            return {
                "status": "decompressed_size_blocked",
                "chunk_count": chunk_count,
            }, []
        pixels += inflater.flush()
    except zlib.error as exc:
        return {
            "status": "invalid_zlib_stream",
            "chunk_count": chunk_count,
            "error": type(exc).__name__,
        }, []
    if len(pixels) > MAX_ARTIFACT:
        return {"status": "decompressed_size_blocked", "chunk_count": chunk_count}, []

    concealed = inflater.unused_data
    report = {
        "status": "concealed_data_recovered" if concealed else "valid_png_no_concealed_data",
        "width": width,
        "height": height,
        "chunk_count": chunk_count,
        "png_end_offset": png_end_offset,
        "trailing_after_iend": len(data) - png_end_offset,
        "idat_size": len(idat),
        "zlib_stream_size": len(idat) - len(concealed),
        "decompressed_image_size": len(pixels),
        "concealed_size": len(concealed),
        "concealed_sha256": sha256_bytes(concealed) if concealed else None,
        "concealed_entropy": entropy(concealed) if concealed else None,
        "concealed_prefix_hex": concealed[:16].hex(),
        "concealed_content_in_report": False,
    }
    artifacts = [("png-idat-zlib-unused-data", concealed)] if concealed else []
    return report, artifacts


def pe_resource_children(
    blob: bytes,
) -> tuple[str, list[tuple[str, bytes]], dict[str, object] | None]:
    """PEリソースを直接検査し、次層として意味がある内容だけを返す。"""

    resource_format = detect_format(blob, "resource.bin")
    if resource_format == "png":
        png_report, concealed = recover_png_concealed_data(blob)
        return resource_format, concealed, png_report

    artifacts: list[tuple[str, bytes]] = []
    if resource_format != "data":
        artifacts.append((f"pe-resource-{resource_format}", blob))
    artifacts.extend(carve_embedded_pes(blob))
    return resource_format, artifacts, None


def repetitive_padding(data: bytes, max_period: int = 32) -> dict[str, object] | None:
    """短いバイトパターンの反復だけで構成されたバッファ全体を識別する。"""
    if len(data) < 4096:
        return None
    for period in range(1, min(max_period, len(data)) + 1):
        pattern = data[:period]
        if pattern * (len(data) // period) + pattern[: len(data) % period] == data:
            return {
                "period": period,
                "pattern_hex": pattern.hex(),
                "repetitions": len(data) // period,
                "trailing_bytes": len(data) % period,
            }
    return None


def safe_member_name(name: str) -> str:
    """アーカイブのパストラバーサル、絶対パス、ドライブ指定メンバー名を拒否する。"""
    return validate_member_name(name, "archive")


def valid_pe_extent(data: bytes, offset: int = 0) -> int | None:
    """*offset*にあるPEの上限付きファイル範囲を返し、無効なら``None``を返す。"""
    if offset < 0 or offset + 0x40 > len(data) or data[offset : offset + 2] != b"MZ":
        return None
    try:
        image = pefile.PE(data=data[offset:], fast_load=True)
        if not 1 <= image.FILE_HEADER.NumberOfSections <= 96:
            return None
        extent = int(image.OPTIONAL_HEADER.SizeOfHeaders)
        for section in image.sections:
            extent = max(extent, int(section.PointerToRawData + section.SizeOfRawData))
        security = image.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if security.VirtualAddress and security.Size:
            extent = max(extent, int(security.VirtualAddress + security.Size))
        if extent <= 0 or offset + extent > len(data) or extent > MAX_ARTIFACT:
            return None
        return extent
    except (AttributeError, IndexError, pefile.PEFormatError, ValueError):
        return None


def carve_embedded_pes(data: bytes, limit: int = 16) -> list[tuple[str, bytes]]:
    """スタブを実行せず、先頭以外にある検証済みPEイメージを切り出す。"""
    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    cursor = 1
    while len(artifacts) < limit:
        offset = data.find(b"MZ", cursor)
        if offset < 0:
            break
        extent = valid_pe_extent(data, offset)
        if extent:
            blob = data[offset : offset + extent]
            digest = sha256_bytes(blob)
            if digest not in seen:
                artifacts.append(("embedded-pe", blob))
                seen.add(digest)
            cursor = offset + extent
        else:
            cursor = offset + 2
    return artifacts


def pe_summary(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """PEのパッキング証拠を分類し、埋め込みアーティファクトを上限付きで復元する。"""
    pe = pefile.PE(data=data, fast_load=False)
    sections = []
    for section in pe.sections:
        sections.append(
            {
                "name": section.Name.rstrip(b"\0").decode(errors="replace"),
                "raw_size": section.SizeOfRawData,
                "virtual_size": section.Misc_VirtualSize,
                "entropy": entropy(section.get_data()),
                "characteristics": hex(section.Characteristics),
            }
        )
    import_entries = list(getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
    imports = sum(len(entry.imports) for entry in import_entries)
    import_libraries = sorted(
        {
            entry.dll.decode("ascii", errors="replace").lower()
            for entry in import_entries
            if getattr(entry, "dll", None)
        }
    )
    overlay_offset = pe.get_overlay_data_start_offset()
    image_end = overlay_offset if overlay_offset is not None else len(data)
    marker_probe = data[: min(image_end, 32 * 1024 * 1024)].lower()
    markers = sorted(
        marker.decode()
        for marker in (
            b"UPX!",
            b"MPRESS1",
            b"MPRESS2",
            b"Themida",
            b"VMProtect",
            b"Nullsoft",
        )
        if marker.lower() in marker_probe
    )
    artifacts: list[tuple[str, bytes]] = []
    overlay = data[overlay_offset:] if overlay_offset is not None else b""
    overlay_format = detect_format(overlay, "overlay.bin") if overlay else "data"
    overlay_padding = repetitive_padding(overlay) if overlay else None
    if overlay and overlay_format != "data" and overlay_padding is None:
        artifacts.append((f"pe-overlay-{overlay_format}", overlay))
    artifacts.extend(carve_embedded_pes(overlay))
    resource_count = 0
    opaque_resources = 0
    archive_resources = 0
    png_resources_inspected = 0
    png_resources_with_concealed_data = 0
    invalid_png_resources = 0
    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for type_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            for name_entry in getattr(type_entry.directory, "entries", []):
                for lang_entry in getattr(name_entry.directory, "entries", []):
                    resource_count += 1
                    item = lang_entry.data.struct
                    blob = pe.get_data(item.OffsetToData, item.Size)
                    if not 0 < len(blob) <= MAX_ARTIFACT:
                        continue
                    resource_format, children, png_report = pe_resource_children(blob)
                    archive_resources += int(resource_format in {"7z", "cab", "zip"})
                    if png_report is not None:
                        png_resources_inspected += 1
                        png_status = png_report["status"]
                        if png_status == "concealed_data_recovered":
                            png_resources_with_concealed_data += 1
                        elif png_status != "valid_png_no_concealed_data":
                            invalid_png_resources += 1
                    artifacts.extend(children)
                    if (
                        resource_format == "data"
                        and not children
                        and len(blob) >= 4096
                        and entropy(blob) >= 7.2
                        and opaque_resources < 32
                    ):
                        artifacts.append(("pe-resource-opaque", blob))
                        opaque_resources += 1
    high_entropy = [
        item["name"]
        for item in sections
        if item["entropy"] >= 7.2 and item["raw_size"] >= 4096
    ]
    is_dotnet = bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
    lowered = data[: min(len(data), 16 * 1024 * 1024)].lower()
    is_go = b"go build id" in lowered or b"runtime.main" in lowered
    section_names = {item["name"].lower() for item in sections}
    entrypoint_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entrypoint_section = next(
        (
            item["name"]
            for item, raw_section in zip(sections, pe.sections, strict=True)
            if raw_section.VirtualAddress
            <= entrypoint_rva
            < raw_section.VirtualAddress
            + max(raw_section.Misc_VirtualSize, raw_section.SizeOfRawData)
        ),
        None,
    )
    zero_raw_virtual_sections = [
        item["name"]
        for item in sections
        if item["raw_size"] == 0 and item["virtual_size"] >= 4096
    ]
    strong_section_marker = any(
        token in name
        for name in section_names
        for token in ("upx", "mpress", "vmp", "themida")
    )
    strong_string_markers = [
        marker for marker in markers if marker in {"Themida", "VMProtect"}
    ]
    code_entropy = [
        item["name"]
        for item in sections
        if item["entropy"] >= 7.2
        and item["raw_size"] >= 4096
        and item["name"].lower() not in {".rsrc", ".reloc"}
    ]
    containerized = "Nullsoft" in markers or archive_resources > 0
    virtualized_shape = (
        imports <= 2
        and len(zero_raw_virtual_sections) >= 4
        and bool(code_entropy)
        and entrypoint_section in code_entropy
    )
    common_system_libraries = {
        "advapi32.dll",
        "comctl32.dll",
        "gdi32.dll",
        "kernel32.dll",
        "ntdll.dll",
        "ole32.dll",
        "shell32.dll",
        "user32.dll",
        "wininet.dll",
        "winhttp.dll",
        "ws2_32.dll",
    }
    single_non_system_import_library = (
        len(import_libraries) == 1
        and import_libraries[0] not in common_system_libraries
        and not import_libraries[0].startswith(("api-ms-win-", "ext-ms-win-"))
    )
    encrypted_sideload_host_shape = (
        not is_dotnet
        and not is_go
        and entrypoint_section in code_entropy
        and imports >= 32
        and single_non_system_import_library
    )
    if containerized:
        classification = "self_extracting_container"
    elif is_dotnet and code_entropy:
        classification = "managed_loader_or_obfuscated"
    elif virtualized_shape:
        classification = "virtualized_or_packed"
    elif strong_section_marker or strong_string_markers:
        classification = "packed_or_protected"
    elif encrypted_sideload_host_shape:
        classification = "suspected_encrypted_sideload_host"
    elif not is_dotnet and not is_go and code_entropy and imports <= 8:
        classification = "suspected_packed"
    else:
        classification = "not_packed"
    packed = classification in {
        "packed_or_protected",
        "suspected_packed",
        "virtualized_or_packed",
        "suspected_encrypted_sideload_host",
    }
    control_flow = None
    if packed or classification == "managed_loader_or_obfuscated" or len(data) > 32 * 1024 * 1024:
        control_flow = analyze_pe_control_flow(data)
        # The full block list is useful in a private analyst workspace but is
        # too large for recursive unpack reports.  Metrics retain every count
        # and address needed to route a hard case to a deeper tool.
        control_flow.pop("blocks", None)
        control_context = control_flow.get("static_context")
        if isinstance(control_context, dict):
            control_context.pop("sections", None)
            control_context.pop("import_names", None)
    managed_il = None
    if is_dotnet:
        managed_il = analyze_managed_pe(data)
        # Preserve counts, marker provenance, resource hashes, dispatcher
        # candidates, and the method plan while avoiding tens of thousands of
        # per-token rows in recursive public reports.  Analysts can invoke the
        # dedicated CLI for the private full inventory.
        managed_il.pop("types", None)
        managed_il.pop("methods", None)
        malformed = managed_il.get("malformed_method_bodies")
        if isinstance(malformed, list) and len(malformed) > 128:
            managed_il["malformed_method_bodies"] = malformed[:128]
            managed_il["malformed_method_bodies_truncated"] = True
    return (
        {
            "machine": hex(pe.FILE_HEADER.Machine),
            "is_dotnet": is_dotnet,
            "is_go": is_go,
            "imports": imports,
            "import_libraries": import_libraries,
            "sections": sections,
            "high_entropy_sections": high_entropy,
            "code_entropy_sections": code_entropy,
            "packer_markers": markers,
            "classification": classification,
            "containerized": containerized,
            "entrypoint_section": entrypoint_section,
            "zero_raw_virtual_sections": zero_raw_virtual_sections,
            "virtualized_shape": virtualized_shape,
            "encrypted_sideload_host_shape": encrypted_sideload_host_shape,
            "packing_suspected": packed,
            "overlay_size": len(overlay),
            "overlay_format": overlay_format,
            "overlay_repetitive_padding": overlay_padding,
            "resource_count": resource_count,
            "opaque_resources_recovered": opaque_resources,
            "archive_resources_recovered": archive_resources,
            "png_resources_inspected": png_resources_inspected,
            "png_resources_with_concealed_data": png_resources_with_concealed_data,
            "invalid_png_resources": invalid_png_resources,
            "control_flow_triage": control_flow,
            "managed_il_triage": managed_il,
        },
        artifacts,
    )


@_contain_parser_diagnostics
def recover_dotnet_resources(
    data: bytes,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """.NET manifestリソースを棚卸しし、不透明な符号化ペイロード素材を保持する。"""
    try:
        image = dnfile.dnPE(data=data)
    except Exception as exc:  # dnfile raises several parser-specific exceptions
        return {"status": "parse_failed", "error": type(exc).__name__}, []
    resources = getattr(getattr(image, "net", None), "resources", []) or []
    inventory, artifacts = [], []
    for resource in resources[:MAX_ARCHIVE_MEMBERS]:
        name = str(getattr(resource, "name", "unnamed.resources"))
        size = int(getattr(resource, "size", 0) or 0)
        rva = int(getattr(resource, "rva", 0) or 0)
        if not 0 < size <= MAX_ARTIFACT or not rva:
            inventory.append(
                {"name": name, "size": size, "status": "size_or_rva_blocked"}
            )
            continue
        blob = image.get_data(rva, size)
        if not blob:
            inventory.append({"name": name, "size": size, "status": "empty"})
            continue
        resource_set = getattr(resource, "data", None)
        entries = []
        for entry in (getattr(resource_set, "entries", []) or [])[:MAX_ARCHIVE_MEMBERS]:
            entries.append(
                {
                    "name": str(getattr(entry, "name", "")),
                    "type": str(getattr(entry, "type_name", "")),
                }
            )
        kind = detect_format(blob, name)
        item = {
            "name": name,
            "size": len(blob),
            "sha256": sha256_bytes(blob),
            "entropy": entropy(blob),
            "format": kind,
            "entries": entries,
            "status": "extracted",
        }
        inventory.append(item)
        if kind != "data":
            artifacts.append((f"dotnet-resource-{kind}", blob))
        artifacts.extend(carve_embedded_pes(blob))
        if kind == "data" and len(blob) >= 4096 and entropy(blob) >= 7.0:
            artifacts.append(("dotnet-resource-opaque", blob))
        bitmap_report, bitmap_artifacts = recover_dotnet_bitmap_payloads(resource_set)
        if bitmap_report["status"] != "no_bitmap_entries":
            item["bitmap_payloads"] = bitmap_report
            artifacts.extend(bitmap_artifacts)
    return {
        "status": "resources_recovered" if inventory else "no_manifest_resources",
        "count": len(inventory),
        "inventory": inventory,
    }, artifacts


def _resource_entry_bounds(resource_set: object, index: int) -> tuple[int, int]:
    """ResourceSetエントリ1件の上限付きシリアライズデータ範囲を返す。"""
    entries = list(getattr(resource_set, "entries", []) or [])
    raw = getattr(resource_set, "_data", b"")
    header = getattr(resource_set, "struct", None)
    base = int(getattr(header, "DataSectionOffset", 0) or 0)
    start = base + int(getattr(entries[index].struct, "DataOffset", 0) or 0)
    offsets = sorted(
        base + int(getattr(entry.struct, "DataOffset", 0) or 0) for entry in entries
    )
    later = [offset for offset in offsets if offset > start]
    end = min(later) if later else len(raw)
    if not (0 <= start < end <= len(raw)):
        raise ValueError("invalid ResourceSet entry bounds")
    return start, end


def _decode_bmp_rgb_columns(data: bytes) -> bytes:
    """埋め込みBMPに対するBitmap.GetPixelの列優先RGB抽出を再現する。"""
    if len(data) < 54 or data[:2] != b"BM":
        raise ValueError("not a BMP")
    declared_size = struct.unpack_from("<I", data, 2)[0]
    pixel_offset = struct.unpack_from("<I", data, 10)[0]
    dib_size = struct.unpack_from("<I", data, 14)[0]
    width, height = struct.unpack_from("<ii", data, 18)
    planes, bits = struct.unpack_from("<HH", data, 26)
    compression = struct.unpack_from("<I", data, 30)[0]
    if (
        declared_size > len(data)
        or dib_size < 40
        or not 0 < width <= 16384
        or not 0 < abs(height) <= 16384
        or planes != 1
        or bits not in {24, 32}
        or compression != 0
    ):
        raise ValueError("unsupported or malformed BMP")
    bytes_per_pixel = bits // 8
    stride = ((width * bits + 31) // 32) * 4
    if pixel_offset + stride * abs(height) > declared_size:
        raise ValueError("truncated BMP pixels")
    output = bytearray()
    for x in range(width):
        for y in range(abs(height)):
            stored_y = abs(height) - 1 - y if height > 0 else y
            offset = pixel_offset + stored_y * stride + x * bytes_per_pixel
            blue, green, red = data[offset : offset + 3]
            output.extend((red, green, blue))
    return bytes(output)


def recover_dotnet_bitmap_payloads(
    resource_set: object,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """シリアライズ済み.NET BitmapリソースのRGB画素に隠されたPEストリームを復元する。"""
    entries = list(getattr(resource_set, "entries", []) or [])
    raw = getattr(resource_set, "_data", b"")
    bitmap_entries = [
        (index, entry)
        for index, entry in enumerate(entries)
        if "System.Drawing.Bitmap" in str(getattr(entry, "type_name", ""))
    ]
    if not bitmap_entries:
        return {"status": "no_bitmap_entries", "entries": []}, []
    inventory, artifacts = [], []
    for index, entry in bitmap_entries:
        item = {"name": str(getattr(entry, "name", "unnamed"))}
        try:
            start, end = _resource_entry_bounds(resource_set, index)
        except ValueError as exc:
            item.update(status="invalid_bounds", error=str(exc))
            inventory.append(item)
            continue
        bmp_offset = raw.find(b"BM", start, min(end, start + 4096))
        if bmp_offset < 0 or bmp_offset + 6 > end:
            item["status"] = "unsupported_bitmap_serialization"
            inventory.append(item)
            continue
        size = struct.unpack_from("<I", raw, bmp_offset + 2)[0]
        try:
            rgb = _decode_bmp_rgb_columns(raw[bmp_offset : min(end, bmp_offset + size)])
        except ValueError as exc:
            item.update(status="unsupported_bitmap", error=str(exc))
            inventory.append(item)
            continue
        extent = valid_pe_extent(rgb, 0) if rgb.startswith(b"MZ") else None
        item.update(
            status="pe_recovered" if extent else "rgb_recovered_no_pe",
            bitmap_size=size,
            rgb_size=len(rgb),
            rgb_sha256=sha256_bytes(rgb),
        )
        if extent:
            payload = rgb[:extent]
            item.update(payload_size=extent, payload_sha256=sha256_bytes(payload))
            artifacts.append(("dotnet-bitmap-rgb-pe", payload))
        inventory.append(item)
    status = "pe_recovered" if artifacts else "bitmap_entries_processed"
    return {"status": status, "entries": inventory}, artifacts


def macho_summary(data: bytes) -> dict:
    """上限付きでMach-Oまたはユニバーサルバイナリのヘッダーメタデータを解析する。"""
    magic = data[:4]
    if magic not in MACHO_MAGICS:
        raise ValueError("not a Mach-O image")
    if magic in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        endian = ">" if magic == b"\xca\xfe\xba\xbe" else "<"
        return {
            "kind": "universal",
            "architectures": struct.unpack_from(endian + "I", data, 4)[0],
        }
    endian = "<" if magic == b"\xcf\xfa\xed\xfe" else ">"
    if len(data) < 32:
        raise ValueError("truncated Mach-O header")
    cpu_type, cpu_subtype, file_type, commands, command_size, flags = (
        struct.unpack_from(endian + "IIIIII", data, 4)
    )
    return {
        "kind": "macho64",
        "cpu_type": hex(cpu_type),
        "cpu_subtype": hex(cpu_subtype),
        "file_type": file_type,
        "load_commands": commands,
        "load_command_bytes": command_size,
        "flags": hex(flags),
    }


def _encoded_blob_kind(blob: bytes) -> str | None:
    """復号バイト列が構造上有用な場合だけ、対応種別を返す。"""
    kind = detect_format(blob)
    if kind == "pe" and valid_pe_extent(blob) is None:
        return None
    return kind if kind != "data" else None


def recover_encoded_blobs(data: bytes) -> list[tuple[str, bytes]]:
    """スクリプトから構造上有意なBase64ブロブを上限付きで復元する。

    コマンドファイルはcertutil -decodeの前に、多数のecho行で1つのペイロードを
    出力することがある。これらの断片はリダイレクト先ごとに再構築する。
    無作為な高エントロピー引数は個別に保持しない。
    """
    text = decode_script_text(data)
    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    emitted_chunks: set[str] = set()
    streams: dict[str, list[str]] = {}
    echo_pattern = re.compile(
        r"(?im)^[ \t]*@?echo[ \t]+([A-Za-z0-9+/]{4,}={0,2})"
        r"[ \t]*(>>|>)[ \t]*([^\r\n]+?)[ \t]*\r?$"
    )
    for match in echo_pattern.finditer(text):
        chunk, operator, target = match.groups()
        target = target.strip().lower()
        emitted_chunks.add(chunk)
        if operator == ">" or target not in streams:
            streams[target] = []
        streams[target].append(chunk)
    for chunks in streams.values():
        encoded = "".join(chunks)
        if len(encoded) > (MAX_ARTIFACT * 4 // 3) + 4:
            continue
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        kind = _encoded_blob_kind(blob)
        digest = sha256_bytes(blob)
        if 64 <= len(blob) <= MAX_ARTIFACT and kind and digest not in seen:
            seen.add(digest)
            artifacts.append((f"base64-echo-reassembled-{kind}", blob))
    for match in re.finditer(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{128,}={0,2}(?![A-Za-z0-9+/])", text
    ):
        encoded = match.group()
        if encoded in emitted_chunks:
            continue
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            continue
        kind = _encoded_blob_kind(blob)
        digest = sha256_bytes(blob)
        if 64 <= len(blob) <= MAX_ARTIFACT and kind and digest not in seen:
            seen.add(digest)
            artifacts.append((f"base64-{kind}", blob))
    return artifacts[:128]


class _ZipQuotaExceeded(ValueError):
    """部分的に復元したZIPアーティファクトをすべて破棄する内部シグナル。"""

    def __init__(self, status: str, name: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.name = name
        self.detail = detail


def _read_standard_zip_member_capped(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    *,
    name: str,
    max_member_size: int,
    remaining_total: int,
    max_compression_ratio: float,
    chunk_size: int,
) -> bytes:
    """ZIPメンバー1件を上限付きの断片で読み、偽装メタデータを拒否する。"""

    declared_size = int(info.file_size)
    compressed_size = int(info.compress_size)
    if compressed_size < 0:
        raise _ZipQuotaExceeded(
            "malformed_metadata", name, "negative compressed size"
        )
    ratio_output_limit = int(compressed_size * max_compression_ratio)
    output_limit = min(
        declared_size,
        max_member_size,
        remaining_total,
        ratio_output_limit,
    )
    output_size = 0
    chunks: list[bytes] = []
    with archive.open(info, "r") as handle:
        while True:
            read_size = min(chunk_size, output_limit - output_size + 1)
            chunk = handle.read(max(1, read_size))
            if not chunk:
                break
            output_size += len(chunk)
            if output_size > declared_size:
                raise _ZipQuotaExceeded(
                    "size_mismatch",
                    name,
                    f"declared {declared_size} bytes but output exceeded it",
                )
            if output_size > max_member_size:
                raise _ZipQuotaExceeded(
                    "size_blocked", name, f"member exceeded {max_member_size} bytes"
                )
            if output_size > remaining_total:
                raise _ZipQuotaExceeded(
                    "total_size_blocked",
                    name,
                    "archive exceeded cumulative extracted-byte limit",
                )
            if output_size > ratio_output_limit:
                raise _ZipQuotaExceeded(
                    "ratio_blocked",
                    name,
                    f"member exceeded compression ratio {max_compression_ratio:g}",
                )
            chunks.append(chunk)
    if output_size != declared_size:
        raise _ZipQuotaExceeded(
            "size_mismatch",
            name,
            f"declared {declared_size} bytes but produced {output_size}",
        )
    return b"".join(chunks)


def recover_zip(
    data: bytes,
    *,
    max_members: int = MAX_ARCHIVE_MEMBERS,
    max_member_size: int = MAX_ARTIFACT,
    max_total_size: int = MAX_EXTRACTED_TOTAL,
    max_compression_ratio: float = MAX_COMPRESSION_RATIO,
    read_chunk_size: int = ARCHIVE_READ_CHUNK_SIZE,
) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """メンバー数、総バイト数、圧縮率の上限内でZIPを棚卸しする。"""

    for value, label in (
        (max_members, "max_members"),
        (max_member_size, "max_member_size"),
        (max_total_size, "max_total_size"),
        (max_compression_ratio, "max_compression_ratio"),
        (read_chunk_size, "read_chunk_size"),
    ):
        if isinstance(value, bool) or value <= 0:
            raise ValueError(f"{label} must be positive")

    inventory: list[dict] = []
    artifacts: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        if len(infos) > max_members:
            return [
                {
                    "name": "__archive__",
                    "status": "member_limit_applied",
                    "member_limit": max_members,
                    "total_members": len(infos),
                    "selected_members": 0,
                }
            ], []

        prepared: list[tuple[zipfile.ZipInfo, str]] = []
        declared_total = 0
        for info in infos:
            name = safe_member_name(info.filename)
            declared_size = int(info.file_size)
            compressed_size = int(info.compress_size)
            if declared_size < 0 or compressed_size < 0:
                return [
                    {
                        "name": name,
                        "status": "malformed_metadata",
                        "size": declared_size,
                        "compressed_size": compressed_size,
                    }
                ], []
            if declared_size > max_member_size:
                return [
                    {
                        "name": name,
                        "status": "size_blocked",
                        "size": declared_size,
                        "member_size_limit": max_member_size,
                    }
                ], []
            declared_total += declared_size
            if declared_total > max_total_size:
                return [
                    {
                        "name": "__archive__",
                        "status": "total_size_blocked",
                        "declared_total_size": declared_total,
                        "total_size_limit": max_total_size,
                    }
                ], []
            ratio_output_limit = int(compressed_size * max_compression_ratio)
            if declared_size > ratio_output_limit:
                return [
                    {
                        "name": name,
                        "status": "ratio_blocked",
                        "size": declared_size,
                        "compressed_size": compressed_size,
                        "compression_ratio_limit": max_compression_ratio,
                    }
                ], []
            prepared.append((info, name))

        extracted_total = 0
        for info, name in prepared:
            try:
                blob = _read_standard_zip_member_capped(
                    archive,
                    info,
                    name=name,
                    max_member_size=max_member_size,
                    remaining_total=max_total_size - extracted_total,
                    max_compression_ratio=max_compression_ratio,
                    chunk_size=read_chunk_size,
                )
            except RuntimeError:
                inventory.append(
                    {"name": name, "size": info.file_size, "status": "encrypted"}
                )
                continue
            except _ZipQuotaExceeded as exc:
                return [
                    {
                        "name": exc.name,
                        "status": exc.status,
                        "detail": exc.detail,
                    }
                ], []
            extracted_total += len(blob)
            kind = detect_format(blob, name)
            inventory.append(
                {
                    "name": name,
                    "size": len(blob),
                    "sha256": sha256_bytes(blob),
                    "format": kind,
                }
            )
            if kind != "data":
                artifacts.append((f"zip-{kind}", blob))
    return inventory, artifacts


def run_upx(
    data: bytes, executable: Path, timeout: float = 120.0
) -> tuple[dict, bytes | None]:
    """データ変換としてUPX展開を呼び出し、出力PEを検証する。"""
    if not executable.is_file():
        return {"status": "unavailable", "path": str(executable)}, None
    with tempfile.TemporaryDirectory(prefix="asa-upx-") as temp:
        source, output = Path(temp) / "input.bin", Path(temp) / "unpacked.bin"
        source.write_bytes(data)
        completed = subprocess.run(
            [str(executable), "-d", "-o", str(output), str(source)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode or not output.is_file():
            return {
                "status": "not_upx_or_failed",
                "exit_code": completed.returncode,
            }, None
        blob = output.read_bytes()
        if not blob.startswith(b"MZ"):
            return {"status": "invalid_output", "exit_code": completed.returncode}, None
        return {
            "status": "recovered",
            "size": len(blob),
            "sha256": sha256_bytes(blob),
        }, blob


def decode_autoit_xor_literals(script: bytes) -> list[str]:
    """逆コンパイル済みAutoItソース内の反復鍵XOR文字列呼び出しを復号する。"""
    text = script.decode("utf-8", errors="ignore")
    pattern = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*\(\"0x([0-9A-Fa-f]+)\",\s*\"([^\"]+)\"\)"
    )
    decoded, seen = [], set()
    for match in pattern.finditer(text):
        if len(decoded) >= 20000 or len(match.group(1)) > 2 * 1024 * 1024:
            continue
        raw, key = bytes.fromhex(match.group(1)), match.group(2).encode()
        if not key:
            continue
        value = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(raw))
        rendered = value.decode("latin1")
        printable = sum(character.isprintable() for character in rendered)
        if rendered and printable / len(rendered) >= 0.8 and rendered not in seen:
            decoded.append(rendered)
            seen.add(rendered)
    return decoded


def recover_autoit_rc4_lznt1(
    script: bytes,
) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """AutoItのRC4・LZNT1ローダー式からPEペイロードを復元する。"""
    from Cryptodome.Cipher import ARC4
    from refinery.units.compression.lznt1 import lznt1

    text = script.decode("utf-8", errors="ignore")
    pattern = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*\(Binary\(\$([A-Za-z_][A-Za-z0-9_]*)\),\s*"
        r"Binary\([A-Za-z_][A-Za-z0-9_]*\(\"0x([0-9A-Fa-f]+)\",\s*\"([^\"]+)\"\)\)\)"
    )
    reports, artifacts, seen = [], [], set()
    for match in pattern.finditer(text):
        variable, key_hex, key_text = match.groups()
        key_raw, xor_key = bytes.fromhex(key_hex), key_text.encode()
        if not xor_key:
            continue
        key = bytes(
            byte ^ xor_key[index % len(xor_key)] for index, byte in enumerate(key_raw)
        )
        segment_pattern = re.compile(
            rf"\${re.escape(variable)}\s*=\s*(?:\${re.escape(variable)}\s*&\s*)?"
            r"\"(?:0x)?([0-9A-Fa-f]+)\""
        )
        segments = segment_pattern.findall(text)
        total_hex = sum(len(segment) for segment in segments)
        if not segments or total_hex % 2 or total_hex // 2 > MAX_ARTIFACT:
            continue
        ciphertext = bytes.fromhex("".join(segments))
        candidate_id = (sha256_bytes(ciphertext), sha256_bytes(key))
        if candidate_id in seen:
            continue
        seen.add(candidate_id)
        try:
            compressed = ARC4.new(key).decrypt(ciphertext)
            payload = bytes(lznt1()(compressed))
        except Exception as exc:
            reports.append(
                {
                    "variable": variable,
                    "status": "decode_failed",
                    "error": type(exc).__name__,
                }
            )
            continue
        if not payload.startswith(b"MZ") or valid_pe_extent(payload, 0) is None:
            reports.append(
                {
                    "variable": variable,
                    "status": "decoded_non_pe",
                    "size": len(payload),
                    "sha256": sha256_bytes(payload),
                }
            )
            continue
        reports.append(
            {
                "variable": variable,
                "status": "pe_recovered",
                "segments": len(segments),
                "ciphertext_size": len(ciphertext),
                "ciphertext_sha256": sha256_bytes(ciphertext),
                "rc4_key": key.decode("ascii", errors="replace"),
                "compressed_sha256": sha256_bytes(compressed),
                "payload_size": len(payload),
                "payload_sha256": sha256_bytes(payload),
            }
        )
        artifacts.append(("autoit-rc4-lznt1-pe", payload))
    return reports, artifacts


def recover_autoit_script(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """AutoIt A3Xを逆コンパイルし、XOR・RC4・LZNT1層を静的に復元する。"""
    try:
        from refinery.units.formats.a3xs import a3xs

        script = bytes(a3xs()(data))
    except Exception as exc:  # refinery exposes multiple format/parser failures
        return {"status": "decompile_failed", "error": type(exc).__name__}, []
    if not script or len(script) > MAX_ARTIFACT:
        return {"status": "invalid_or_oversized_output", "size": len(script)}, []
    decoded_strings = decode_autoit_xor_literals(script)
    behavior_tokens = (
        "http",
        ".dll",
        "process",
        "virtualalloc",
        "writeprocessmemory",
        "createthread",
        "ntwritevirtualmemory",
        "rtl decompress",
        "socket",
        "powershell",
    )
    behavior_strings = [
        value
        for value in decoded_strings
        if len(value) <= 512
        and any(token in value.lower() for token in behavior_tokens)
    ][:256]
    payloads, recovered = recover_autoit_rc4_lznt1(script)
    return (
        {
            "status": "decompiled",
            "size": len(script),
            "sha256": sha256_bytes(script),
            "decoded_xor_strings": len(decoded_strings),
            "behavior_strings": behavior_strings,
            "payloads": payloads,
            "sample_executed": False,
        },
        [("autoit-decompiled-script", script), *recovered],
    )


def run_die(
    data: bytes,
    executable: Path,
    name: str = "sample.bin",
    timeout: float = 120.0,
) -> dict:
    """Detect It Easyを静的分類器として実行し、JSON証拠を解析する。"""
    if not executable.is_file():
        return {"status": "unavailable", "path": str(executable)}
    with tempfile.TemporaryDirectory(prefix="asa-die-") as temp:
        suffix = Path(name).suffix or ".bin"
        source = Path(temp) / f"sample{suffix}"
        source.write_bytes(data)
        try:
            completed = subprocess.run(
                [str(executable), "-j", "-d", "-u", str(source)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timeout"}
        if completed.returncode:
            return {"status": "failed", "exit_code": completed.returncode}
        try:
            document = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return {"status": "invalid_json", "exit_code": completed.returncode}
        values = []
        for detection in document.get("detects", []):
            for value in detection.get("values", []):
                if value.get("string"):
                    values.append(value["string"])
        return {
            "status": "detected",
            "values": values,
            "raw": document,
            "sample_executed": False,
        }


def sevenzip_inventory(data: bytes, executable: Path, password: str = "") -> dict:
    """アーカイブ候補の識別と一覧化だけに7-Zipを使用する。"""
    if not executable.is_file():
        return {"status": "unavailable", "path": str(executable)}
    with tempfile.TemporaryDirectory(prefix="asa-7z-list-") as temp:
        source = Path(temp) / "input.bin"
        source.write_bytes(data)
        command = [str(executable), "l", "-slt", "-sccUTF-8"]
        if password:
            command.append(f"-p{password}")
        command.extend(["--", str(source)])
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
        paths, types, declared_sizes = [], [], []
        for line in completed.stdout.splitlines():
            if line.startswith("Path = "):
                value = line[7:]
                if value != str(source):
                    paths.append(value)
            elif line.startswith("Type = "):
                types.append(line[7:])
            elif line.startswith("Size = ") and line[7:].strip().isdigit():
                declared_sizes.append(int(line[7:].strip()))
        return {
            "status": "listed"
            if completed.returncode == 0
            else "encrypted_or_unsupported",
            "exit_code": completed.returncode,
            "archive_types": sorted(set(types)),
            "members": paths[:MAX_ARCHIVE_MEMBERS],
            "total_members": len(paths),
            "declared_total_size": sum(declared_sizes),
            "password_attempted": bool(password),
            # Safe public alias retained by report sanitizers that intentionally
            # remove every field whose name contains "password".
            "archive_unlock_attempted": bool(password),
        }


def reassemble_split_parts(
    files: dict[str, bytes],
) -> tuple[list[dict], list[tuple[str, bytes]]]:
    """オフセットと長さを検証してからJadoo形式の分割ファイルを再構築する。"""
    reports: list[dict] = []
    artifacts: list[tuple[str, bytes]] = []
    by_basename: dict[str, list[tuple[str, bytes]]] = {}
    for name, blob in files.items():
        by_basename.setdefault(PurePosixPath(name).name, []).append((name, blob))
    for manifest_name, manifest_blob in files.items():
        if not manifest_name.lower().endswith("_info.json"):
            continue
        try:
            manifest = json.loads(manifest_blob.decode("utf-8"))
            parts = manifest["parts"]
            expected_size = int(manifest["file_size"])
        except (
            KeyError,
            TypeError,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ):
            reports.append({"manifest": manifest_name, "status": "invalid_manifest"})
            continue
        if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_ARCHIVE_MEMBERS:
            reports.append({"manifest": manifest_name, "status": "invalid_part_count"})
            continue
        if not 0 < expected_size <= MAX_ARTIFACT:
            reports.append({"manifest": manifest_name, "status": "size_blocked"})
            continue
        chunks, cursor, failure = [], 0, None
        for part in sorted(parts, key=lambda item: int(item.get("start", -1))):
            try:
                basename = PurePosixPath(str(part["original_name"])).name
                expected_part_size = int(part["size"])
                start, end = int(part["start"]), int(part["end"])
            except (KeyError, TypeError, ValueError):
                failure = "invalid_part_metadata"
                break
            candidates = by_basename.get(basename, [])
            if len(candidates) != 1:
                failure = "missing_or_ambiguous_part"
                break
            blob = candidates[0][1]
            if start != cursor or end != start + expected_part_size - 1:
                failure = "non_contiguous_offsets"
                break
            if len(blob) != expected_part_size:
                failure = "part_size_mismatch"
                break
            chunks.append(blob)
            cursor += len(blob)
        if failure or cursor != expected_size:
            reports.append(
                {
                    "manifest": manifest_name,
                    "status": failure or "final_size_mismatch",
                    "expected_size": expected_size,
                    "observed_size": cursor,
                }
            )
            continue
        rebuilt = b"".join(chunks)
        output_name = str(manifest.get("file_name", "reassembled.bin"))
        output_kind = detect_format(rebuilt, output_name)
        reports.append(
            {
                "manifest": manifest_name,
                "status": "reassembled",
                "output_name": output_name,
                "format": output_kind,
                "size": len(rebuilt),
                "sha256": sha256_bytes(rebuilt),
            }
        )
        artifacts.append((f"split-reassembled-{output_kind}", rebuilt))
    return reports, artifacts


def sevenzip_extract(
    data: bytes,
    executable: Path,
    name: str = "input.bin",
    password: str = "",
) -> tuple[dict, list[tuple[str, bytes]]]:
    """認識済みコンテナをパス、件数、バイト数の上限付きで展開する。"""
    # Supplying an unrelated archive password to a PE/NSIS image makes 7-Zip
    # omit its synthetic [NSIS].nsi decompilation stream. Probe without a
    # password first and keep that mode for NSIS; other archive types retain
    # the caller-provided password for encrypted RAR/7z/ZIP cases.
    unkeyed_listing = sevenzip_inventory(data, executable, "")
    unkeyed_types = {
        str(value).lower() for value in unkeyed_listing.get("archive_types", [])
    }
    effective_password = "" if "nsis" in unkeyed_types else password
    listing = (
        unkeyed_listing
        if not effective_password
        else sevenzip_inventory(data, executable, effective_password)
    )
    if listing["status"] == "unavailable":
        return listing, []
    extractable_types = {
        "7z",
        "apm",
        "cab",
        "dmg",
        "hfs",
        "mub",
        "nsis",
        "rar",
        "zip",
    }
    archive_types = {value.lower() for value in listing.get("archive_types", [])}
    supported_archive = archive_types.intersection(extractable_types) or any(
        value.startswith("rar") for value in archive_types
    )
    if not supported_archive:
        return {**listing, "status": "not_archive_container"}, []
    if listing.get("total_members", 0) > MAX_ARCHIVE_MEMBERS:
        return {**listing, "status": "member_limit_blocked"}, []
    if listing.get("declared_total_size", 0) > MAX_EXTRACTED_TOTAL:
        return {**listing, "status": "declared_size_blocked"}, []
    with tempfile.TemporaryDirectory(prefix="asa-7z-extract-") as temp:
        root = Path(temp)
        suffix = Path(name).suffix or ".bin"
        source, output = root / f"input{suffix}", root / "out"
        source.write_bytes(data)
        command = [str(executable), "x", "-y", "-bd", "-bb0", "-sccUTF-8"]
        if effective_password:
            command.append(f"-p{effective_password}")
        command.extend([f"-o{output}", "--", str(source)])
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=180,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {**listing, "status": "extract_timeout"}, []
        inventory, candidates = [], []
        extracted_total = 0
        output_resolved = output.resolve()
        for entry in sorted(output.rglob("*")) if output.is_dir() else []:
            if not entry.is_file() or entry.is_symlink():
                continue
            resolved = entry.resolve()
            try:
                resolved.relative_to(output_resolved)
            except ValueError:
                inventory.append({"name": str(entry), "status": "path_blocked"})
                continue
            attributes = getattr(entry.stat(), "st_file_attributes", 0)
            if attributes & 0x400:
                inventory.append({"name": str(entry), "status": "reparse_blocked"})
                continue
            relative = entry.relative_to(output).as_posix()
            try:
                safe_member_name(relative)
            except ValueError:
                inventory.append({"name": relative, "status": "path_blocked"})
                continue
            size = entry.stat().st_size
            extracted_total += size
            if size > MAX_ARTIFACT:
                inventory.append(
                    {"name": relative, "size": size, "status": "size_blocked"}
                )
                continue
            if extracted_total > MAX_EXTRACTED_TOTAL:
                inventory.append(
                    {"name": relative, "size": size, "status": "total_size_blocked"}
                )
                continue
            blob = entry.read_bytes()
            kind = detect_format(blob, relative)
            item = {
                "name": relative,
                "size": len(blob),
                "sha256": sha256_bytes(blob),
                "format": kind,
                "status": "extracted",
            }
            inventory.append(item)
            suffix = entry.suffix.lower()
            keep = kind != "data" or suffix in RECOVERY_SUFFIXES
            keep = keep or ".part-" in entry.name.lower()
            keep = keep or (not suffix and len(blob) <= 16 * 1024 * 1024)
            if keep:
                priority = 0 if kind != "data" else 1
                candidates.append((priority, relative, blob, kind))
        candidates.sort(key=lambda item: (item[0], item[1].lower()))
        selected = candidates[:MAX_RETAINED_MEMBERS]
        file_map = {name: blob for _, name, blob, _ in selected}
        split_reports, split_artifacts = reassemble_split_parts(file_map)
        nsis_report, nsis_artifacts = ({"status": "not_nsis"}, [])
        if "nsis" in archive_types:
            nsis_report, nsis_artifacts = recover_nsis_scripted_layers(file_map)
        artifacts = [(f"7z-{kind}", blob) for _, _, blob, kind in selected]
        artifacts.extend(split_artifacts)
        artifacts.extend(nsis_artifacts)
        status = "extracted" if completed.returncode == 0 else "partially_extracted"
        return (
            {
                **listing,
                "status": status,
                "extract_exit_code": completed.returncode,
                "inventory": inventory[:MAX_ARCHIVE_MEMBERS],
                "extracted_total_size": extracted_total,
                "retained_members": len(selected),
                "split_reassembly": split_reports,
                "nsis_script_recovery": nsis_report,
            },
            artifacts,
        )


def unpack_bytes(
    data: bytes,
    name: str = "sample",
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    force_container_probe: bool = False,
    archive_password: str = "",
) -> tuple[dict, list[tuple[str, bytes]]]:
    """上限付き静的復元を実行し、メタデータとアーティファクトを返す。

    forceフラグは、汎用コンテナ判定に合致しない既知NSISキャリアなど、
    レビュー済みインベントリの手掛かりに使用する。入力は実行せず、
    設定済みアーカイブパーサーによる検査だけを許可する。
    """
    kind = detect_format(data, name)
    report = {
        "schema_version": 2,
        "name": name,
        "sha256": sha256_bytes(data),
        "size": len(data),
        "entropy": entropy(data),
        "format": kind,
        "entropy_sampled": len(data) > ENTROPY_FULL_LIMIT,
        "executed": False,
        "network_contacted": False,
    }
    artifacts: list[tuple[str, bytes]] = []
    static_data = data
    if kind == "pe":
        report["inflated_pe"], recovered_blob = recover_inflated_pe(data)
        if recovered_blob:
            static_data = recovered_blob
            artifacts.append(("pe-inflated-gap-removed", recovered_blob))
    if diec and kind in {"pe", "macho"}:
        report["die"] = run_die(static_data, diec, name)
    if kind == "pe":
        try:
            report["pe"], recovered = pe_summary(static_data)
        except pefile.PEFormatError as exc:
            report["pe"] = {
                "status": "parse_failed",
                "error": str(exc),
                "classification": "corrupt_or_truncated",
                "packing_suspected": False,
            }
            report["unpack_status"] = "corrupt_or_truncated"
            return report, []
        artifacts.extend(recovered)
        report["donut_wrapper"], recovered = recover_xor32_donut_wrapper(static_data)
        artifacts.extend(recovered)
        if report["pe"]["is_dotnet"]:
            report["dotnet_resources"], recovered = recover_dotnet_resources(static_data)
            artifacts.extend(recovered)
        section_names = {item["name"].lower() for item in report["pe"]["sections"]}
        likely_upx = "UPX!" in report["pe"]["packer_markers"] or any(
            "upx" in value for value in section_names
        )
        if upx and likely_upx:
            report["upx"], blob = run_upx(static_data, upx)
            if blob:
                artifacts.append(("upx", blob))
        elif upx:
            report["upx"] = {"status": "skipped_no_upx_evidence"}
        if sevenzip and (
            report["pe"]["containerized"] or force_container_probe
        ):
            report["sevenzip"], recovered = sevenzip_extract(
                static_data, sevenzip, name, archive_password
            )
            artifacts.extend(recovered)
            report["sevenzip"]["forced_by_reviewed_hint"] = bool(
                force_container_probe and not report["pe"]["containerized"]
            )
    elif kind == "macho":
        report["macho"] = macho_summary(data)
        report["macho_slices"], recovered = recover_macho_slices(data)
        artifacts.extend(recovered)
    elif kind == "png":
        report["png"], recovered = recover_png_concealed_data(data)
        artifacts.extend(recovered)
    elif kind == "xz":
        report["xz"], recovered_blob = recover_xz(data)
        if recovered_blob:
            artifacts.append(("xz-decompressed", recovered_blob))
    elif kind == "zip":
        try:
            report["zip"], recovered = recover_zip(data)
            artifacts.extend(recovered)
            if any(
                item.get("status")
                in {
                    "member_limit_applied",
                    "size_blocked",
                    "total_size_blocked",
                    "ratio_blocked",
                    "malformed_metadata",
                    "size_mismatch",
                }
                for item in report["zip"]
            ):
                report["unpack_status"] = "bounded_limit"
                report["recovered"] = []
                return report, []
        except (ValueError, zipfile.BadZipFile) as exc:
            report["zip_error"] = str(exc)
            report["unpack_status"] = "bounded_limit"
    elif kind in {"7z", "apple-disk-image", "cab", "rar"} and sevenzip:
        report["sevenzip"], recovered = sevenzip_extract(
            data, sevenzip, name, archive_password
        )
        artifacts.extend(recovered)
    elif kind == "autoit-a3x":
        report["autoit"], recovered = recover_autoit_script(data)
        artifacts.extend(recovered)
    elif kind == "asar":
        report["asar"], recovered = recover_asar(data)
        artifacts.extend(recovered)
    elif kind == "script":
        artifacts.extend(recover_encoded_blobs(data))
        report["javascript_dropper"], recovered = recover_javascript_dropper(data)
        artifacts.extend(recovered)
        report["javascript_string_array"], transformed = deobfuscate_string_array(data)
        if transformed:
            artifacts.append(("javascript-string-array-deobfuscated", transformed))
        report["javascript_plain_string_array"], transformed = deobfuscate_plain_string_array(data)
        if transformed:
            artifacts.append(
                ("javascript-plain-string-array-deobfuscated", transformed)
            )
    if len(static_data) <= 32 * 1024 * 1024:
        report["donut"], recovered = recover_donut_payloads(static_data)
        artifacts.extend(recovered)
    artifacts.extend(carve_embedded_pes(static_data))
    deduplicated: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for artifact_kind, blob in artifacts:
        digest = sha256_bytes(blob)
        if digest == report["sha256"] or digest in seen:
            continue
        seen.add(digest)
        deduplicated.append((artifact_kind, blob))
    report["recovered"] = [
        {"kind": artifact_kind, "size": len(blob), "sha256": sha256_bytes(blob)}
        for artifact_kind, blob in deduplicated
    ]
    report.setdefault(
        "unpack_status",
        "artifacts_recovered" if deduplicated else "no_artifact_recovered",
    )
    return report, deduplicated


def write_artifacts(
    path: Path, artifacts: list[tuple[str, bytes]], password: str = "infected"
) -> None:
    """復元バイト列をAES暗号化した隔離アーカイブにだけ保存する。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with pyzipper.AESZipFile(
        path, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
    ) as archive:
        archive.setpassword(password.encode())
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        for kind, blob in artifacts:
            archive.writestr(f"{kind}/{sha256_bytes(blob)}.quarantine.bin", blob)


def build_parser() -> argparse.ArgumentParser:
    """静的展開器のコマンドラインパーサーを構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--artifact-zip", type=Path)
    parser.add_argument("--upx", type=Path)
    parser.add_argument("--sevenzip", type=Path)
    parser.add_argument("--diec", type=Path)
    parser.add_argument("--force-container-probe", action="store_true")
    parser.add_argument("--archive-password", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    """生アーティファクト1件を解析し、必要に応じて復元層をアーカイブする。"""
    args = build_parser().parse_args(argv)
    if args.input.resolve() == args.output.resolve():
        raise ValueError("input and output paths must differ")
    report, artifacts = unpack_bytes(
        args.input.read_bytes(),
        args.input.name,
        args.upx,
        args.sevenzip,
        args.diec,
        args.force_container_probe,
        args.archive_password,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if args.artifact_zip and artifacts:
        write_artifacts(args.artifact_zip, artifacts)
    print(json.dumps({"output": str(args.output), "recovered": len(artifacts)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
