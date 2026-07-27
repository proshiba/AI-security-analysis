#!/usr/bin/env python3
from __future__ import annotations
import argparse
import struct
from pathlib import Path
from malware_io import read_single_aes_zip_member, safety_metadata, sha256_bytes, validate_member_name, write_json

SECTOR = 2048


def is_iso9660(image: bytes) -> bool:
    """ISO9660 primary volume descriptorを境界内で確認する。"""
    return (
        len(image) >= 17 * SECTOR
        and image[16 * SECTOR] == 1
        and image[16 * SECTOR + 1 : 16 * SECTOR + 6] == b"CD001"
        and image[16 * SECTOR + 6] == 1
    )


def records(image: bytes, extent: int, size: int, prefix: str = "", depth: int = 0) -> list[dict]:
    if depth > 32:
        raise ValueError("ISO directory depth exceeds safety limit")
    data = image[extent * SECTOR:extent * SECTOR + size]
    output, position = [], 0
    while position < len(data):
        length = data[position]
        if length == 0:
            position = ((position // SECTOR) + 1) * SECTOR
            continue
        record = data[position:position + length]
        if len(record) < 34:
            break
        lba = struct.unpack_from("<I", record, 2)[0]
        byte_count = struct.unpack_from("<I", record, 10)[0]
        flags, name_length = record[25], record[32]
        name = record[33:33 + name_length].decode("latin-1", errors="replace")
        position += length
        if name in ("\x00", "\x01"):
            continue
        name = name.split(";")[0]
        path = validate_member_name(f"{prefix}/{name}".lstrip("/"))
        item = {"path": path, "extent_lba": lba, "size": byte_count, "directory": bool(flags & 2)}
        if item["directory"]:
            item["children"] = records(image, lba, byte_count, path, depth + 1)
        else:
            blob = image[lba * SECTOR:lba * SECTOR + byte_count]
            item.update(sha256=sha256_bytes(blob), magic=blob[:16].hex(), mz_offsets=[index for index in range(len(blob)) if blob.startswith(b"MZ", index)][:20])
        output.append(item)
    return output


def analyze_iso_image(image: bytes) -> dict:
    """raw ISO/IMGをmountせず、全directory entryを棚卸しする。"""
    if not is_iso9660(image):
        raise ValueError("not an ISO9660 primary volume descriptor")
    pvd = image[16 * SECTOR:17 * SECTOR]
    root_length = pvd[156]
    if root_length < 34 or 156 + root_length > len(pvd):
        raise ValueError("invalid ISO9660 root directory record")
    root = pvd[156:156 + root_length]
    extent = struct.unpack_from("<I", root, 2)[0]
    size = struct.unpack_from("<I", root, 10)[0]
    if extent <= 0 or size <= 0 or extent * SECTOR + size > len(image):
        raise ValueError("ISO9660 root directory points outside the image")
    return {
        "volume_identifier": pvd[40:72].decode("ascii", errors="replace").strip(),
        "files": records(image, extent, size),
        "mounted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory an ISO9660 submission without mounting it.")
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()
    member = read_single_aes_zip_member(args.outer_zip, password=args.password)
    image = member.data
    result = {
        "schema_version": 2,
        "member": member.name,
        "sha256": member.sha256,
        **analyze_iso_image(image),
        **safety_metadata(),
    }
    write_json(args.output, result)
    print({"volume": result["volume_identifier"], "entries": len(result["files"])})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
