"""Node SEAのPE resourceからJavaScriptとassetを実行せずに復元する。"""

from __future__ import annotations

import hashlib
import re
import struct

import pefile

from unpackers.path_safety import safe_member_name

MAGIC = bytes.fromhex("20da4301")
RESOURCE_NAME = "NODE_SEA_BLOB"
MAX_RESOURCE_SIZE = 64 * 1024 * 1024
MAX_ASSETS = 64
MAX_RESOURCE_ENTRIES = 256


class NodeSeaError(ValueError):
    """境界または構造検証の失敗。入力由来の値は例外へ含めない。"""


def _read_u64(blob: bytes, offset: int) -> tuple[int, int]:
    if offset + 8 > len(blob):
        raise NodeSeaError("truncated_length")
    return struct.unpack_from("<Q", blob, offset)[0], offset + 8


def _read_member(blob: bytes, offset: int, *, size_limit: int) -> tuple[bytes, int]:
    length, offset = _read_u64(blob, offset)
    if length > size_limit or offset + length > len(blob):
        raise NodeSeaError("member_out_of_bounds")
    return blob[offset : offset + length], offset + length


def _read_name(blob: bytes, offset: int) -> tuple[str, int]:
    raw, offset = _read_member(blob, offset, size_limit=4096)
    try:
        name = safe_member_name(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise NodeSeaError("unsafe_or_invalid_name") from exc
    return name, offset


def _artifact_name(prefix: str, index: int, name: str) -> str:
    leaf = name.rsplit("/", 1)[-1]
    leaf = re.sub(r"[^A-Za-z0-9._-]", "_", leaf)[:100]
    return f"node-sea-{prefix}-{index:02d}-{leaf}"


def parse_node_sea_blob(
    blob: bytes,
    *,
    max_member_size: int = MAX_RESOURCE_SIZE,
    max_total_size: int = MAX_RESOURCE_SIZE,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """観測したSEA v1構造を厳密に読み、完全な場合だけ層を返す。"""
    report: dict = {
        "status": "parse_failed",
        "format": "node_sea_observed_v1",
        "executed": False,
        "network_contacted": False,
    }
    try:
        if len(blob) < 18 or len(blob) > min(MAX_RESOURCE_SIZE, max_total_size):
            raise NodeSeaError("resource_size_out_of_bounds")
        if blob[:4] != MAGIC:
            raise NodeSeaError("magic_mismatch")
        flags = struct.unpack_from("<I", blob, 4)[0]
        has_code = blob[8]
        if has_code != 1:
            raise NodeSeaError("unsupported_code_layout")
        offset = 9
        main_name, offset = _read_name(blob, offset)
        main, offset = _read_member(
            blob, offset, size_limit=min(max_member_size, max_total_size)
        )
        count, offset = _read_u64(blob, offset)
        if count > MAX_ASSETS:
            raise NodeSeaError("asset_count_limit")
        assets: list[tuple[str, bytes]] = []
        members = [
            {
                "name": main_name,
                "size": len(main),
                "sha256": hashlib.sha256(main).hexdigest(),
                "role": "main",
            }
        ]
        total = len(main)
        for index in range(count):
            asset_name, offset = _read_name(blob, offset)
            asset, offset = _read_member(
                blob, offset, size_limit=min(max_member_size, max_total_size)
            )
            total += len(asset)
            if total > max_total_size:
                raise NodeSeaError("aggregate_size_limit")
            assets.append((_artifact_name("asset", index, asset_name), asset))
            members.append(
                {
                    "name": asset_name,
                    "size": len(asset),
                    "sha256": hashlib.sha256(asset).hexdigest(),
                    "role": "asset",
                }
            )
        if offset != len(blob):
            raise NodeSeaError("trailing_bytes")
        report.update(
            {
                "status": "recovered",
                "flags": flags,
                "resource_sha256": hashlib.sha256(blob).hexdigest(),
                "resource_size": len(blob),
                "members": members,
                "candidate_only": True,
                "family_attribution_allowed": False,
                "c2_confirmation_allowed": False,
            }
        )
        return report, [(_artifact_name("main", 0, main_name), main), *assets]
    except (NodeSeaError, struct.error) as exc:
        report["reason"] = str(exc)
        return report, []


def recover_node_sea_pe(
    data: bytes,
    *,
    max_member_size: int = MAX_RESOURCE_SIZE,
    max_total_size: int = MAX_RESOURCE_SIZE,
) -> tuple[dict, list[tuple[str, bytes]]]:
    """一意なRCDATA/NODE_SEA_BLOBのみをresource RVA境界内で復元する。"""
    absent = {"status": "not_detected", "executed": False, "network_contacted": False}
    if b"NODE_SEA_BLOB" not in data or not data.startswith(b"MZ"):
        return absent, []
    try:
        image = pefile.PE(data=data, fast_load=True)
        image.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        root = image.DIRECTORY_ENTRY_RESOURCE
        candidates: list[bytes] = []
        seen = 0
        for type_entry in root.entries:
            if getattr(type_entry, "id", None) != 10:
                continue
            for name_entry in type_entry.directory.entries:
                if str(getattr(name_entry, "name", "")) != RESOURCE_NAME:
                    continue
                for language_entry in name_entry.directory.entries:
                    seen += 1
                    if seen > MAX_RESOURCE_ENTRIES:
                        raise NodeSeaError("resource_entry_limit")
                    record = language_entry.data.struct
                    size = int(record.Size)
                    rva = int(record.OffsetToData)
                    if size <= 0 or size > min(MAX_RESOURCE_SIZE, max_total_size):
                        raise NodeSeaError("resource_size_out_of_bounds")
                    raw_offset = image.get_offset_from_rva(rva)
                    if raw_offset < 0 or raw_offset + size > len(data):
                        raise NodeSeaError("resource_rva_out_of_bounds")
                    candidate = data[raw_offset : raw_offset + size]
                    if candidate[:4] != MAGIC:
                        raise NodeSeaError("magic_mismatch")
                    candidates.append(candidate)
        if len(candidates) != 1:
            return (
                absent
                if not candidates
                else {
                    "status": "ambiguous_resource",
                    "resource_count": len(candidates),
                    "executed": False,
                    "network_contacted": False,
                }
            ), []
        return parse_node_sea_blob(
            candidates[0],
            max_member_size=max_member_size,
            max_total_size=max_total_size,
        )
    except (
        AttributeError,
        IndexError,
        KeyError,
        NodeSeaError,
        pefile.PEFormatError,
        TypeError,
        ValueError,
    ) as exc:
        return {
            "status": "parse_failed",
            "reason": str(exc)
            if isinstance(exc, NodeSeaError)
            else "invalid_pe_resource",
            "executed": False,
            "network_contacted": False,
        }, []
