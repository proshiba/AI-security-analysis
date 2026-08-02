#!/usr/bin/env python3
"""ZIP・MSI・CAB・PE提出物を実行せず、メモリ内で有界に再帰調査する。"""
from __future__ import annotations
import argparse
import io
import json
import math
import re
import zipfile
from pathlib import Path
import cabarchive
import olefile
import pefile
from analyze_iso9660 import SECTOR, analyze_iso_image, is_iso9660
from malware_io import read_aes_zip_members, read_zip_members, safety_metadata, sha256_bytes, sha256_file, validate_member_name, write_json

NETWORK = re.compile(rb"(?:https?://[^\x00-\x20\"'<>]{4,300}|(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?::\d{1,5})?)", re.I)

MAX_NESTED_MEMBER_SIZE = 64 * 1024 * 1024
MAX_NESTED_MEMBERS = 256
MAX_NESTED_TOTAL_SIZE = 256 * 1024 * 1024
MAX_NESTED_COMPRESSION_RATIO = 100.0


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return round(-sum((count / len(data)) * math.log2(count / len(data)) for count in counts if count), 4)

def network_strings(data: bytes) -> list[dict]:
    found = [{"offset": match.start(), "value": match.group().decode("latin-1", errors="replace").rstrip(".,;)")} for match in NETWORK.finditer(data)]
    for match in NETWORK.finditer(data[::2]):
        found.append({"offset": match.start() * 2, "value": match.group().decode("latin-1", errors="replace"), "encoding": "utf-16-le-even"})
    return list({item["value"].lower(): item for item in found}.values())[:500]

def pe_info(data: bytes) -> dict:
    pe = pefile.PE(data=data, fast_load=False)
    imports = {entry.dll.decode(errors="replace"): [item.name.decode(errors="replace") if item.name else f"ordinal:{item.ordinal}" for item in entry.imports] for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])}
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        exports = [symbol.name.decode(errors="replace") if symbol.name else f"ordinal:{symbol.ordinal}" for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols]
    overlay = pe.get_overlay() or b""
    security = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    certificate = None
    if security.VirtualAddress and security.Size and security.VirtualAddress + security.Size <= len(data):
        blob = data[security.VirtualAddress:security.VirtualAddress + security.Size]
        certificate = {"size": len(blob), "sha256": sha256_bytes(blob)}
    return {
        "machine": hex(pe.FILE_HEADER.Machine), "timestamp": pe.FILE_HEADER.TimeDateStamp,
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "imphash": pe.get_imphash(),
        "sections": [{"name": section.Name.rstrip(b"\0").decode(errors="replace"), "raw_size": section.SizeOfRawData, "virtual_size": section.Misc_VirtualSize, "entropy": round(section.get_entropy(), 4)} for section in pe.sections],
        "imports": imports, "exports": exports,
        "overlay": {"size": len(overlay), "sha256": sha256_bytes(overlay) if overlay else None, "entropy": entropy(overlay)},
        "authenticode_blob": certificate, "network_strings": network_strings(data),
    }

def analyze_zip(data: bytes, depth: int) -> list[dict]:
    """内包ZIPを有界に読み込み、検証済みメンバーだけを再帰解析する。"""

    members = read_zip_members(
        data,
        max_member_size=MAX_NESTED_MEMBER_SIZE,
        max_members=MAX_NESTED_MEMBERS,
        max_total_size=MAX_NESTED_TOTAL_SIZE,
        max_compression_ratio=MAX_NESTED_COMPRESSION_RATIO,
    )
    return [analyze_blob(member.name, member.data, depth) for member in members]

def analyze_cab(data: bytes, depth: int) -> list[dict]:
    archive = cabarchive.CabArchive(data)
    return [analyze_blob(validate_member_name(name), item.buf, depth) for name, item in archive.items()]

def analyze_ole(data: bytes, depth: int) -> dict:
    ole = olefile.OleFileIO(io.BytesIO(data))
    streams = []
    for path in ole.listdir(streams=True, storages=False):
        blob = ole.openstream(path).read()
        kind = "cab" if blob.startswith(b"MSCF") else ("pe" if blob.startswith(b"MZ") else "data")
        item = {"name": "/".join(path), "size": len(blob), "sha256": sha256_bytes(blob), "type": kind}
        if kind == "cab" and depth < 4:
            try:
                item["members"] = analyze_cab(blob, depth + 1)
            except Exception as exc:
                item["parse_error"] = f"{type(exc).__name__}: {exc}"
        elif kind == "pe":
            item["pe"] = pe_info(blob)
        streams.append(item)
    return {"stream_count": len(streams), "streams": streams}


def _enrich_iso_entries(entries: list[dict], image: bytes, depth: int) -> None:
    """ISO entryへ同じ再帰解析結果を追加する。検体bytesは保存しない。"""
    for item in entries:
        if item.get("directory"):
            _enrich_iso_entries(item.get("children", []), image, depth)
            continue
        start = int(item["extent_lba"]) * SECTOR
        size = int(item["size"])
        if start < 0 or size < 0 or start + size > len(image):
            item["analysis_error"] = "ISO entry points outside the image"
            continue
        item["analysis"] = analyze_blob(item["path"], image[start:start + size], depth)


def analyze_blob(name: str, data: bytes, depth: int = 0) -> dict:
    result = {"name": name, "size": len(data), "sha256": sha256_bytes(data), "magic": data[:16].hex(), "entropy": entropy(data)}
    if data.startswith(b"MZ"):
        result["type"] = "pe"
        try:
            result["pe"] = pe_info(data)
        except Exception as exc:
            result["pe_error"] = f"{type(exc).__name__}: {exc}"
        if depth < 4 and zipfile.is_zipfile(io.BytesIO(data)):
            result["appended_zip"] = analyze_zip(data, depth + 1)
    elif data.startswith(bytes.fromhex("d0cf11e0a1b11ae1")):
        result.update(type="ole_msi", ole=analyze_ole(data, depth + 1))
    elif depth < 4 and zipfile.is_zipfile(io.BytesIO(data)):
        result.update(type="zip", zip=analyze_zip(data, depth + 1))
    elif data.startswith(b"MSCF"):
        result.update(type="cab", cab=analyze_cab(data, depth + 1))
    elif depth < 4 and is_iso9660(data):
        try:
            iso = analyze_iso_image(data)
            _enrich_iso_entries(iso["files"], data, depth + 1)
            result.update(type="iso9660", iso=iso)
        except Exception as exc:
            result.update(type="iso9660", iso_error=f"{type(exc).__name__}: {exc}")
    else:
        result.update(type="data", network_strings=network_strings(data))
    return result

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    members = [analyze_blob(member.name, member.data) for member in read_aes_zip_members(args.outer_zip, password=args.password)]
    result = {"schema_version": 2, "outer_zip": str(args.outer_zip), "outer_sha256": sha256_file(args.outer_zip), "members": members, **safety_metadata()}
    write_json(args.output, result)
    print(json.dumps({"output": str(args.output), "member_count": len(members), "types": [member["type"] for member in members]}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
