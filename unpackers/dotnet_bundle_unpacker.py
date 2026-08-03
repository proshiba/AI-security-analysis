#!/usr/bin/env python3
""".NET単一ファイルbundleを実行せずに検証・展開する。"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct
import zlib

from unpackers.path_safety import safe_member_name


BUNDLE_SIGNATURE = bytes.fromhex(
    "8b1202b96a612038727b930214d7a032"
    "13f5b9e6efae3318ee3b2dce24b36aae"
)
SUPPORTED_MAJOR_VERSIONS = {2, 6}
FILE_TYPES = {
    0: "unknown",
    1: "assembly",
    2: "native_binary",
    3: "deps_json",
    4: "runtime_config_json",
    5: "symbols",
}


class DotnetBundleError(ValueError):
    """bundleが不正、未対応、または安全上の上限を超えたことを示す。"""


@dataclass(frozen=True)
class BundleEntry:
    """検証済みbundle manifest entry。"""

    offset: int
    size: int
    compressed_size: int
    file_type: int
    relative_path: str


def _read_exact(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise DotnetBundleError("bundleの読取範囲がファイル境界を超えています")
    return data[offset : offset + size], offset + size


def _read_u32(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 4)
    return struct.unpack("<I", raw)[0], offset


def _read_i32(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 4)
    return struct.unpack("<i", raw)[0], offset


def _read_i64(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 8)
    return struct.unpack("<q", raw)[0], offset


def _read_u64(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_exact(data, offset, 8)
    return struct.unpack("<Q", raw)[0], offset


def _read_binary_writer_string(
    data: bytes, offset: int, *, max_length: int = 4096
) -> tuple[str, int]:
    """BinaryWriter互換の7-bit長UTF-8文字列を境界付きで読む。"""

    length = 0
    shift = 0
    for _ in range(5):
        raw, offset = _read_exact(data, offset, 1)
        value = raw[0]
        length |= (value & 0x7F) << shift
        if value & 0x80 == 0:
            break
        shift += 7
    else:
        raise DotnetBundleError("文字列長の7-bit encodingが不正です")
    if length <= 0 or length > max_length:
        raise DotnetBundleError("bundle内の文字列長が許容範囲外です")
    raw, offset = _read_exact(data, offset, length)
    try:
        return raw.decode("utf-8"), offset
    except UnicodeDecodeError as exc:
        raise DotnetBundleError("bundle内のパスがUTF-8ではありません") from exc


def locate_bundle_header(data: bytes) -> tuple[int, int]:
    """apphost markerからmanifest offsetとmarker位置を返す。"""

    marker_offset = data.find(BUNDLE_SIGNATURE)
    if marker_offset < 8:
        raise DotnetBundleError(".NET bundle markerがありません")
    if data.find(BUNDLE_SIGNATURE, marker_offset + 1) >= 0:
        raise DotnetBundleError(".NET bundle markerが複数あり一意に選べません")
    header_offset = struct.unpack_from("<q", data, marker_offset - 8)[0]
    if header_offset <= 0 or header_offset >= len(data):
        raise DotnetBundleError("bundle header offsetがファイル境界外です")
    return header_offset, marker_offset


def parse_bundle(
    data: bytes,
    *,
    max_entries: int = 512,
    max_entry_size: int = 256 * 1024 * 1024,
    max_total_size: int = 768 * 1024 * 1024,
) -> tuple[dict[str, object], list[BundleEntry]]:
    """公式manifest形式を検証し、メタデータとentryを返す。"""

    header_offset, marker_offset = locate_bundle_header(data)
    cursor = header_offset
    major, cursor = _read_u32(data, cursor)
    minor, cursor = _read_u32(data, cursor)
    count, cursor = _read_i32(data, cursor)
    if major not in SUPPORTED_MAJOR_VERSIONS or minor != 0:
        raise DotnetBundleError(f"未対応のbundle versionです: {major}.{minor}")
    if count <= 0 or count > max_entries:
        raise DotnetBundleError("bundle entry数が許容範囲外です")
    bundle_id, cursor = _read_binary_writer_string(data, cursor, max_length=1024)

    deps_offset = deps_size = runtime_offset = runtime_size = flags = 0
    if major >= 2:
        deps_offset, cursor = _read_i64(data, cursor)
        deps_size, cursor = _read_i64(data, cursor)
        runtime_offset, cursor = _read_i64(data, cursor)
        runtime_size, cursor = _read_i64(data, cursor)
        flags, cursor = _read_u64(data, cursor)

    entries: list[BundleEntry] = []
    total_size = 0
    for _ in range(count):
        entry_offset, cursor = _read_i64(data, cursor)
        size, cursor = _read_i64(data, cursor)
        compressed_size = 0
        if major >= 6:
            compressed_size, cursor = _read_i64(data, cursor)
        raw_type, cursor = _read_exact(data, cursor, 1)
        file_type = raw_type[0]
        relative_path, cursor = _read_binary_writer_string(data, cursor)
        try:
            relative_path = safe_member_name(relative_path, "dotnet-bundle")
        except ValueError as exc:
            raise DotnetBundleError("bundle entryのパスが安全ではありません") from exc
        stored_size = compressed_size or size
        if (
            entry_offset <= 0
            or size < 0
            or compressed_size < 0
            or size > max_entry_size
            or stored_size > max_entry_size
            or entry_offset + stored_size > len(data)
            or file_type not in FILE_TYPES
        ):
            raise DotnetBundleError(
                f"bundle entryの範囲または型が不正です: {relative_path}"
            )
        total_size += size
        if total_size > max_total_size:
            raise DotnetBundleError("bundle展開後の合計サイズが上限を超えます")
        entries.append(
            BundleEntry(
                offset=entry_offset,
                size=size,
                compressed_size=compressed_size,
                file_type=file_type,
                relative_path=relative_path,
            )
        )

    return {
        "status": "parsed",
        "version": f"{major}.{minor}",
        "header_offset": header_offset,
        "marker_offset": marker_offset,
        "manifest_end_offset": cursor,
        "bundle_id": bundle_id,
        "entry_count": len(entries),
        "declared_total_size": total_size,
        "deps_json": {"offset": deps_offset, "size": deps_size},
        "runtime_config_json": {"offset": runtime_offset, "size": runtime_size},
        "flags": flags,
        "netcoreapp3_compat_mode": bool(flags & 1),
        "executed": False,
        "network_contacted": False,
    }, entries


def recover_dotnet_bundle(
    data: bytes,
    *,
    max_entries: int = 512,
    max_entry_size: int = 256 * 1024 * 1024,
    max_total_size: int = 768 * 1024 * 1024,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """bundleを安全に展開し、台帳と解析対象artifactを返す。"""

    if BUNDLE_SIGNATURE not in data:
        return {"status": "not_dotnet_bundle"}, []
    try:
        report, entries = parse_bundle(
            data,
            max_entries=max_entries,
            max_entry_size=max_entry_size,
            max_total_size=max_total_size,
        )
    except DotnetBundleError as exc:
        return {
            "status": "parse_failed",
            "error": str(exc),
            "executed": False,
            "network_contacted": False,
        }, []

    inventory: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    for entry in entries:
        stored_size = entry.compressed_size or entry.size
        stored = data[entry.offset : entry.offset + stored_size]
        try:
            blob = zlib.decompress(stored, wbits=-zlib.MAX_WBITS) if entry.compressed_size else stored
        except zlib.error as exc:
            inventory.append(
                {
                    "name": entry.relative_path,
                    "status": "decompression_failed",
                    "error": type(exc).__name__,
                }
            )
            continue
        if len(blob) != entry.size:
            inventory.append(
                {
                    "name": entry.relative_path,
                    "status": "size_mismatch_blocked",
                    "declared_size": entry.size,
                    "actual_size": len(blob),
                }
            )
            continue
        digest = hashlib.sha256(blob).hexdigest()
        inventory.append(
            {
                "name": entry.relative_path,
                "status": "recovered",
                "type": FILE_TYPES[entry.file_type],
                "offset": entry.offset,
                "size": entry.size,
                "compressed_size": entry.compressed_size,
                "sha256": digest,
            }
        )
        artifacts.append((f"dotnet-bundle-{FILE_TYPES[entry.file_type]}", blob))

    report["inventory"] = inventory
    report["recovered_count"] = len(artifacts)
    report["status"] = (
        "recovered" if len(artifacts) == len(entries) else "partially_recovered"
    )
    return report, artifacts
