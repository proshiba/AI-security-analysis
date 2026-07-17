"""Bounded Electron ASAR recovery without running Node.js or packaged code."""

from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import struct

from unpackers.path_safety import safe_member_name

MAX_HEADER = 16 * 1024 * 1024
MAX_MEMBER = 256 * 1024 * 1024
MAX_MEMBERS = 4096
MAX_TOTAL = 512 * 1024 * 1024
RETAIN_SUFFIXES = {".js", ".cjs", ".mjs", ".json", ".node", ".dll", ".exe", ".bin", ".dat"}


def safe_asar_name(name: str) -> str:
    """Normalize one ASAR path and reject traversal or absolute names."""
    return safe_member_name(name, "ASAR")


def asar_header(data: bytes) -> tuple[dict, int]:
    """Parse and return a validated Chromium-pickle ASAR header and data offset."""
    if len(data) < 16:
        raise ValueError("truncated ASAR header")
    word0, word1, pickle_size, json_size = struct.unpack_from("<IIII", data)
    if word0 != 4 or word1 != pickle_size + 4 or pickle_size != json_size + 4:
        raise ValueError("invalid ASAR pickle lengths")
    if not 2 <= json_size <= MAX_HEADER or 16 + json_size > len(data):
        raise ValueError("ASAR JSON header exceeds bounds")
    try:
        header = json.loads(data[16 : 16 + json_size].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid ASAR JSON header") from exc
    if not isinstance(header, dict) or not isinstance(header.get("files"), dict):
        raise ValueError("ASAR header has no files tree")
    return header, 12 + pickle_size


def is_asar(data: bytes) -> bool:
    """Return whether bytes contain a structurally valid bounded ASAR header."""
    try:
        asar_header(data)
        return True
    except ValueError:
        return False


def _walk_files(tree: dict, prefix: str = ""):
    """Yield flattened ASAR file nodes from a nested files tree."""
    for name, node in sorted(tree.items()):
        path = safe_asar_name(f"{prefix}/{name}".lstrip("/"))
        if not isinstance(node, dict):
            continue
        children = node.get("files")
        if isinstance(children, dict):
            yield from _walk_files(children, path)
        else:
            yield path, node


def recover_asar(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """Inventory an ASAR and return bounded script/config/native artifacts."""
    header, data_offset = asar_header(data)
    inventory: list[dict] = []
    artifacts: list[tuple[str, bytes]] = []
    total = 0
    for index, (name, node) in enumerate(_walk_files(header["files"])):
        if index >= MAX_MEMBERS:
            inventory.append({"status": "member_limit_reached"})
            break
        if node.get("unpacked"):
            inventory.append({"name": name, "status": "external_unpacked_member"})
            continue
        try:
            size = int(node.get("size", -1))
            offset = int(node.get("offset", -1))
        except (TypeError, ValueError):
            inventory.append({"name": name, "status": "invalid_offset_or_size"})
            continue
        start, end = data_offset + offset, data_offset + offset + size
        if not 0 <= size <= MAX_MEMBER or not data_offset <= start <= end <= len(data):
            inventory.append({"name": name, "size": size, "status": "bounds_blocked"})
            continue
        total += size
        if total > MAX_TOTAL:
            inventory.append({"name": name, "size": size, "status": "total_size_blocked"})
            continue
        blob = data[start:end]
        digest = hashlib.sha256(blob).hexdigest()
        expected = str((node.get("integrity") or {}).get("hash") or "").lower()
        integrity = "verified" if expected == digest else ("mismatch" if expected else "not_provided")
        item = {"name": name, "size": size, "sha256": digest, "integrity": integrity, "status": "extracted"}
        inventory.append(item)
        suffix = PurePosixPath(name).suffix.lower()
        if suffix in RETAIN_SUFFIXES and integrity != "mismatch":
            kind = "asar-script" if suffix in {".js", ".cjs", ".mjs", ".json"} else "asar-native"
            artifacts.append((kind, blob))
    return {
        "status": "extracted",
        "data_offset": data_offset,
        "member_count": sum(item.get("status") == "extracted" for item in inventory),
        "inventory": inventory,
    }, artifacts
