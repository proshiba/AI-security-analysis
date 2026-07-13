#!/usr/bin/env python3
from __future__ import annotations
import argparse
import struct
from pathlib import Path
from malware_io import read_single_aes_zip_member, safety_metadata, sha256_bytes, validate_member_name, write_json

SECTOR = 2048

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

def main() -> int:
    parser = argparse.ArgumentParser(description="Inventory an ISO9660 submission without mounting it.")
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()
    member = read_single_aes_zip_member(args.outer_zip, password=args.password)
    image = member.data
    pvd = image[16 * SECTOR:17 * SECTOR]
    if len(pvd) != SECTOR or pvd[1:6] != b"CD001":
        raise ValueError("not an ISO9660 primary volume descriptor")
    root = pvd[156:156 + pvd[156]]
    extent = struct.unpack_from("<I", root, 2)[0]
    size = struct.unpack_from("<I", root, 10)[0]
    result = {"schema_version": 2, "member": member.name, "sha256": member.sha256, "volume_identifier": pvd[40:72].decode("ascii", errors="replace").strip(), "files": records(image, extent, size), "mounted": False, **safety_metadata()}
    write_json(args.output, result)
    print({"volume": result["volume_identifier"], "entries": len(result["files"])})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
