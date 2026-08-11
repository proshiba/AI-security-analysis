#!/usr/bin/env python3
from __future__ import annotations

import argparse
import struct
from pathlib import Path

from malware_io import (
    read_single_aes_zip_member,
    safety_metadata,
    sha256_bytes,
    validate_member_name,
    write_json,
)

SECTOR = 2048
MAX_ISO_DIRECTORY_DEPTH = 32
MAX_ISO_ENTRIES = 4096
MAX_ISO_MEMBER_SIZE = 256 * 1024 * 1024
MAX_ISO_TOTAL_SIZE = 768 * 1024 * 1024


class ISO9660LimitError(ValueError):
    """ISO9660解析が安全上限へ達した理由と公開可能な値を保持する。"""

    def __init__(self, status: str, message: str, **details: int) -> None:
        super().__init__(message)
        self.status = status
        self.details = details


def is_iso9660(image: bytes) -> bool:
    """ISO9660 primary volume descriptorを境界内で確認する。"""
    return (
        len(image) >= 17 * SECTOR
        and image[16 * SECTOR] == 1
        and image[16 * SECTOR + 1 : 16 * SECTOR + 6] == b"CD001"
        and image[16 * SECTOR + 6] == 1
    )


def _positive_limit(value: int, label: str) -> int:
    """ISO9660解析上限が正の整数であることを確認する。"""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _extent_bounds(image: bytes, extent: int, size: int, label: str) -> tuple[int, int]:
    """ISO9660 extentをoverflowさせず、image境界内へ限定する。"""
    if extent < 0 or size < 0:
        raise ValueError(f"{label} has a negative extent or size")
    start, end = extent * SECTOR, extent * SECTOR + size
    if start > len(image) or end > len(image):
        raise ValueError(f"{label} points outside the image")
    return start, end


def _records(
    image: bytes,
    extent: int,
    size: int,
    prefix: str,
    depth: int,
    *,
    max_entries: int,
    max_directory_depth: int,
    max_member_size: int,
    max_total_size: int,
    state: dict,
    active_directories: set[tuple[int, int]],
) -> list[dict]:
    if depth > max_directory_depth:
        raise ISO9660LimitError(
            "directory_depth_blocked",
            "ISO directory depth exceeds safety limit",
            max_directory_depth=max_directory_depth,
        )
    directory_key = (extent, size)
    if directory_key in active_directories:
        raise ValueError("ISO directory cycle detected")
    start, end = _extent_bounds(image, extent, size, "ISO directory")
    data = image[start:end]
    output, position = [], 0
    active_directories.add(directory_key)
    try:
        while position < len(data):
            length = data[position]
            if length == 0:
                position = ((position // SECTOR) + 1) * SECTOR
                continue
            if length < 34 or position + length > len(data):
                raise ValueError("invalid ISO9660 directory record length")
            record = data[position : position + length]
            flags, name_length = record[25], record[32]
            if name_length == 0 or 33 + name_length > len(record):
                raise ValueError("invalid ISO9660 directory record name length")
            lba = struct.unpack_from("<I", record, 2)[0]
            byte_count = struct.unpack_from("<I", record, 10)[0]
            name = record[33 : 33 + name_length].decode("latin-1", errors="replace")
            position += length
            if name in ("\x00", "\x01"):
                continue
            name = name.split(";")[0]
            path = validate_member_name(f"{prefix}/{name}".lstrip("/"))
            state["entry_count"] += 1
            if state["entry_count"] > max_entries:
                raise ISO9660LimitError(
                    "member_limit_blocked",
                    "ISO entry count exceeds safety limit",
                    max_members=max_entries,
                )
            member_start, member_end = _extent_bounds(image, lba, byte_count, f"ISO member {path}")
            item = {
                "path": path,
                "extent_lba": lba,
                "size": byte_count,
                "directory": bool(flags & 2),
            }
            if item["directory"]:
                item["children"] = _records(
                    image,
                    lba,
                    byte_count,
                    path,
                    depth + 1,
                    max_entries=max_entries,
                    max_directory_depth=max_directory_depth,
                    max_member_size=max_member_size,
                    max_total_size=max_total_size,
                    state=state,
                    active_directories=active_directories,
                )
            else:
                if byte_count > max_member_size:
                    raise ISO9660LimitError(
                        "member_size_blocked",
                        "ISO member size exceeds safety limit",
                        max_member_size=max_member_size,
                    )
                state["total_file_size"] += byte_count
                if state["total_file_size"] > max_total_size:
                    raise ISO9660LimitError(
                        "total_size_blocked",
                        "ISO member total size exceeds safety limit",
                        declared_total_size=state["total_file_size"],
                        max_total_size=max_total_size,
                    )
                blob = image[member_start:member_end]
                item.update(
                    sha256=sha256_bytes(blob),
                    magic=blob[:16].hex(),
                    mz_offsets=[index for index in range(len(blob)) if blob.startswith(b"MZ", index)][:20],
                )
            output.append(item)
    finally:
        active_directories.remove(directory_key)
    return output


def records(
    image: bytes,
    extent: int,
    size: int,
    prefix: str = "",
    depth: int = 0,
    *,
    max_entries: int = MAX_ISO_ENTRIES,
    max_directory_depth: int = MAX_ISO_DIRECTORY_DEPTH,
    max_member_size: int = MAX_ISO_MEMBER_SIZE,
    max_total_size: int = MAX_ISO_TOTAL_SIZE,
) -> list[dict]:
    """ISO9660 directoryを境界・件数・深さ上限付きで棚卸しする。"""
    max_entries = _positive_limit(max_entries, "max_entries")
    max_directory_depth = _positive_limit(max_directory_depth, "max_directory_depth")
    max_member_size = _positive_limit(max_member_size, "max_member_size")
    max_total_size = _positive_limit(max_total_size, "max_total_size")
    return _records(
        image,
        extent,
        size,
        prefix,
        depth,
        max_entries=max_entries,
        max_directory_depth=max_directory_depth,
        max_member_size=max_member_size,
        max_total_size=max_total_size,
        state={"entry_count": 0, "total_file_size": 0},
        active_directories=set(),
    )


def analyze_iso_image(
    image: bytes,
    *,
    max_entries: int = MAX_ISO_ENTRIES,
    max_directory_depth: int = MAX_ISO_DIRECTORY_DEPTH,
    max_member_size: int = MAX_ISO_MEMBER_SIZE,
    max_total_size: int = MAX_ISO_TOTAL_SIZE,
) -> dict:
    """raw ISO/IMGをmountせず、全directory entryを棚卸しする。"""
    max_entries = _positive_limit(max_entries, "max_entries")
    max_directory_depth = _positive_limit(max_directory_depth, "max_directory_depth")
    max_member_size = _positive_limit(max_member_size, "max_member_size")
    max_total_size = _positive_limit(max_total_size, "max_total_size")
    if not is_iso9660(image):
        raise ValueError("not an ISO9660 primary volume descriptor")
    pvd = image[16 * SECTOR : 17 * SECTOR]
    root_length = pvd[156]
    if root_length < 34 or 156 + root_length > len(pvd):
        raise ValueError("invalid ISO9660 root directory record")
    root = pvd[156 : 156 + root_length]
    extent = struct.unpack_from("<I", root, 2)[0]
    size = struct.unpack_from("<I", root, 10)[0]
    if extent <= 0 or size <= 0 or extent * SECTOR + size > len(image):
        raise ValueError("ISO9660 root directory points outside the image")
    return {
        "volume_identifier": pvd[40:72].decode("ascii", errors="replace").strip(),
        "files": records(
            image,
            extent,
            size,
            max_entries=max_entries,
            max_directory_depth=max_directory_depth,
            max_member_size=max_member_size,
            max_total_size=max_total_size,
        ),
        "mounted": False,
    }


def _file_entries(entries: list[dict]) -> list[dict]:
    """棚卸し済みtreeから通常fileを決定的な順序で列挙する。"""
    output: list[dict] = []
    for item in entries:
        if item.get("directory"):
            output.extend(_file_entries(item.get("children", [])))
        else:
            output.append(item)
    return output


def validate_iso9660_members(
    image: bytes,
    *,
    max_members: int,
    max_member_size: int,
    max_total_size: int,
) -> dict:
    """ISO9660全memberの境界と復元上限を成果物化前に検証する。"""
    max_members = _positive_limit(max_members, "max_members")
    max_member_size = _positive_limit(max_member_size, "max_member_size")
    max_total_size = _positive_limit(max_total_size, "max_total_size")
    try:
        inventory = analyze_iso_image(
            image,
            max_entries=max_members,
            max_member_size=max_member_size,
            max_total_size=max_total_size,
        )
    except ISO9660LimitError as exc:
        return {
            "status": exc.status,
            "error": f"{type(exc).__name__}: {exc}",
            "mounted": False,
            **exc.details,
        }
    except (ValueError, struct.error) as exc:
        return {
            "status": "invalid_iso9660",
            "error": f"{type(exc).__name__}: {exc}",
            "mounted": False,
        }

    files = _file_entries(inventory["files"])
    if len(files) > max_members:
        return {
            **inventory,
            "status": "member_limit_blocked",
            "member_count": len(files),
            "max_members": max_members,
        }
    oversized = [item["path"] for item in files if int(item["size"]) > max_member_size]
    if oversized:
        return {
            **inventory,
            "status": "member_size_blocked",
            "member_count": len(files),
            "max_member_size": max_member_size,
            "blocked_members": oversized[:max_members],
        }
    total_size = sum(int(item["size"]) for item in files)
    if total_size > max_total_size:
        return {
            **inventory,
            "status": "total_size_blocked",
            "member_count": len(files),
            "declared_total_size": total_size,
            "max_total_size": max_total_size,
        }
    return {
        **inventory,
        "status": "validated",
        "member_count": len(files),
        "declared_total_size": total_size,
    }


def recover_iso9660_members(
    image: bytes,
    *,
    max_members: int,
    max_member_size: int,
    max_total_size: int,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """検証済みISO9660 memberを上限内で静的レイヤーとして復元する。

    directory recordが破損している場合や、件数・単体size・総sizeのいずれかが
    上限を超える場合は部分復元せず、呼び出し元がfail-closedに扱える結果を返す。
    """
    inventory = validate_iso9660_members(
        image,
        max_members=max_members,
        max_member_size=max_member_size,
        max_total_size=max_total_size,
    )
    if inventory["status"] != "validated":
        return inventory, []
    files = _file_entries(inventory["files"])
    total_size = int(inventory["declared_total_size"])
    artifacts: list[tuple[str, bytes]] = []
    for item in files:
        size = int(item["size"])
        start, end = _extent_bounds(
            image,
            int(item["extent_lba"]),
            size,
            f"ISO member {item['path']}",
        )
        if size:
            artifacts.append((str(item["path"]), image[start:end]))
    return {
        **inventory,
        "status": "artifacts_recovered" if artifacts else "no_artifact_recovered",
        "member_count": len(files),
        "extracted_total_size": total_size,
    }, artifacts


def main() -> int:
    parser = argparse.ArgumentParser(description="ISO9660提出物をmountせず、安全上限付きで棚卸しする。")
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
