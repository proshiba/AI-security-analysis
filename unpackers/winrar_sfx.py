"""WinRAR SFXを実行せずに識別し、後段抽出計画を検証する。

PE overlayの先頭だけを調べる方式では、SFX設定領域の後ろにあるRAR署名を
見落とす。このmoduleはPEの実体末尾から有界走査し、RAR4/RAR5のmain header
checksumまで検証する。7-Zipの``-slt``出力を利用する場合も、member件数、
宣言size、安全なpath、利用可能なCRC、SFXの``Setup=``対象を抽出前に照合する。

本moduleはarchiveを展開せず、検体を実行せず、外部通信もしない。返す候補は
container routeに限られ、malware family、C2、終端payloadの根拠にはならない。
"""

from __future__ import annotations

import hashlib
import re
import struct
import unicodedata
import zlib
from collections.abc import Mapping

from unpackers.path_safety import safe_member_name

RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"

MAX_INPUT_SIZE = 128 * 1024 * 1024
# 受理した既定入力は末尾まで走査し、一意なRAR main headerを証明する。
# callerがより小さい値を明示した場合だけ、従来どおりincompleteとしてfail closedにする。
MAX_SCAN_BYTES = MAX_INPUT_SIZE
MAX_RAR_HEADER_SIZE = 1024 * 1024
MAX_LISTING_TEXT = 16 * 1024 * 1024
MAX_MEMBER_RECORDS = 4096
MAX_MEMBER_SIZE = 128 * 1024 * 1024
MAX_TOTAL_SIZE = 256 * 1024 * 1024
MAX_SELECTED_MEMBERS = 128
MAX_SELECTED_TOTAL_SIZE = 192 * 1024 * 1024
MAX_MEMBER_PATH_LENGTH = 512

_WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}

_EXECUTABLE_SUFFIXES = {
    ".exe",
    ".dll",
    ".sys",
    ".scr",
    ".cpl",
    ".ocx",
    ".com",
    ".msi",
}
_SCRIPT_SUFFIXES = {
    ".bat",
    ".cmd",
    ".hta",
    ".js",
    ".jse",
    ".ps1",
    ".psm1",
    ".py",
    ".vbe",
    ".vbs",
    ".wsf",
    ".wsh",
}
_CONFIG_OR_PAYLOAD_SUFFIXES = {
    ".bin",
    ".cfg",
    ".conf",
    ".config",
    ".dat",
    ".ini",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
}
_NESTED_CONTAINER_SUFFIXES = {".7z", ".cab", ".img", ".iso", ".rar", ".zip"}


def _decode_vint(data: bytes, offset: int) -> tuple[int, int] | None:
    """RAR5の最大10 byte可変長整数を境界内で復号する。"""

    value = 0
    shift = 0
    for index in range(10):
        position = offset + index
        if position >= len(data):
            return None
        current = data[position]
        value |= (current & 0x7F) << shift
        if not current & 0x80:
            return value, position + 1
        shift += 7
    return None


def _pe_payload_end(data: bytes) -> int | None:
    """PE sectionとcertificate tableを含むfile実体末尾を返す。"""

    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset + 24 > len(data):
        return None
    if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    if section_count > 96:
        return None
    optional_offset = pe_offset + 24
    section_table = optional_offset + optional_size
    section_table_end = section_table + section_count * 40
    if section_table_end > len(data):
        return None
    payload_end = section_table_end
    for index in range(section_count):
        entry = section_table + index * 40
        raw_size = struct.unpack_from("<I", data, entry + 16)[0]
        raw_offset = struct.unpack_from("<I", data, entry + 20)[0]
        if raw_offset > len(data) or raw_size > len(data) - raw_offset:
            return None
        payload_end = max(payload_end, raw_offset + raw_size)

    if optional_size >= 2:
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        directory_offset = 96 if magic == 0x10B else 112 if magic == 0x20B else None
        count_offset = 92 if magic == 0x10B else 108 if magic == 0x20B else None
        if (
            directory_offset is not None
            and count_offset is not None
            and count_offset + 4 <= optional_size
        ):
            directory_count = struct.unpack_from(
                "<I", data, optional_offset + count_offset
            )[0]
            security_entry = optional_offset + directory_offset + 4 * 8
            if directory_count > 4 and security_entry + 8 <= section_table:
                certificate_offset, certificate_size = struct.unpack_from(
                    "<II", data, security_entry
                )
                if certificate_size:
                    if (
                        certificate_offset > len(data)
                        or certificate_size > len(data) - certificate_offset
                    ):
                        return None
                    payload_end = max(
                        payload_end, certificate_offset + certificate_size
                    )
    return payload_end


def _validate_rar5_main_header(data: bytes, offset: int) -> dict[str, object] | None:
    """RAR5署名直後のmain headerとCRC32を検証する。"""

    protected_start = offset + len(RAR5_MAGIC) + 4
    if protected_start > len(data):
        return None
    expected_crc = struct.unpack_from("<I", data, offset + len(RAR5_MAGIC))[0]
    decoded_size = _decode_vint(data, protected_start)
    if decoded_size is None:
        return None
    header_size, body_start = decoded_size
    if not 2 <= header_size <= MAX_RAR_HEADER_SIZE:
        return None
    header_end = body_start + header_size
    if header_end > len(data):
        return None
    if zlib.crc32(data[protected_start:header_end]) & 0xFFFFFFFF != expected_crc:
        return None
    decoded_type = _decode_vint(data, body_start)
    if decoded_type is None:
        return None
    header_type, after_type = decoded_type
    decoded_flags = _decode_vint(data, after_type)
    if decoded_flags is None or header_type != 1:
        return None
    header_flags, _ = decoded_flags
    return {
        "format": "rar5",
        "header_end": header_end,
        "header_size": header_size,
        "header_type": header_type,
        "header_flags": header_flags,
        "header_crc_verified": True,
    }


def _validate_rar4_main_header(data: bytes, offset: int) -> dict[str, object] | None:
    """RAR4以前のmain headerと16-bit header CRCを検証する。"""

    header_start = offset + len(RAR4_MAGIC)
    if header_start + 7 > len(data):
        return None
    expected_crc, header_type, header_flags, header_size = struct.unpack_from(
        "<HBHH", data, header_start
    )
    if not 7 <= header_size <= MAX_RAR_HEADER_SIZE:
        return None
    header_end = header_start + header_size
    if header_end > len(data) or header_type != 0x73:
        return None
    observed_crc = zlib.crc32(data[header_start + 2 : header_end]) & 0xFFFF
    if observed_crc != expected_crc:
        return None
    return {
        "format": "rar4",
        "header_end": header_end,
        "header_size": header_size,
        "header_type": header_type,
        "header_flags": header_flags,
        "header_crc_verified": True,
    }


def assess_winrar_sfx(
    data: bytes,
    *,
    overlay_start: int | None = None,
    max_input_size: int = MAX_INPUT_SIZE,
    max_scan_bytes: int = MAX_SCAN_BYTES,
) -> dict[str, object]:
    """PE overlay内の有効なRAR main headerを有界走査する。"""

    base = {
        "schema_version": 1,
        "candidate": False,
        "sample_executed": False,
        "network_contacted": False,
        "external_process_started": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
    }
    if (
        isinstance(max_input_size, bool)
        or isinstance(max_scan_bytes, bool)
        or max_input_size <= 0
        or max_scan_bytes <= 0
    ):
        raise ValueError("scan limitは正の整数で指定してください")
    if not isinstance(data, bytes):
        raise TypeError("dataはbytesで指定してください")
    if len(data) > max_input_size:
        return {**base, "status": "input_size_blocked", "input_size": len(data)}
    if overlay_start is None:
        overlay_start = _pe_payload_end(data)
    if overlay_start is None:
        return {**base, "status": "not_pe"}
    if (
        isinstance(overlay_start, bool)
        or not isinstance(overlay_start, int)
        or not 0 <= overlay_start <= len(data)
    ):
        return {**base, "status": "invalid_overlay_boundary"}

    scan_end = min(len(data), overlay_start + max_scan_bytes)
    scan_complete = scan_end == len(data)
    candidates: list[dict[str, object]] = []
    malformed_signature_count = 0
    for magic, validator in (
        (RAR5_MAGIC, _validate_rar5_main_header),
        (RAR4_MAGIC, _validate_rar4_main_header),
    ):
        cursor = overlay_start
        while True:
            offset = data.find(magic, cursor, scan_end)
            if offset < 0:
                break
            validated = validator(data, offset)
            if validated is None or int(validated["header_end"]) > scan_end:
                malformed_signature_count += 1
            else:
                candidates.append({**validated, "archive_offset": offset})
            cursor = offset + 1

    if not scan_complete:
        return {
            **base,
            "status": "scan_limit_reached",
            "scan_complete": False,
            "scanned_bytes": scan_end - overlay_start,
            "valid_header_count_within_scan": len(candidates),
            "malformed_signature_count": malformed_signature_count,
        }
    if not candidates:
        return {
            **base,
            "status": "not_candidate",
            "scan_complete": True,
            "scanned_bytes": scan_end - overlay_start,
            "malformed_signature_count": malformed_signature_count,
        }
    if len(candidates) != 1:
        return {
            **base,
            "status": "ambiguous_valid_headers",
            "scan_complete": True,
            "scanned_bytes": scan_end - overlay_start,
            "valid_header_count": len(candidates),
            "malformed_signature_count": malformed_signature_count,
        }
    candidate = candidates[0]
    return {
        **base,
        "status": "validated_sfx_container",
        "candidate": True,
        "scan_complete": True,
        "scanned_bytes": scan_end - overlay_start,
        "archive_format": candidate["format"],
        "archive_offset": candidate["archive_offset"],
        "overlay_prefix_size": int(candidate["archive_offset"]) - overlay_start,
        "main_header_size": candidate["header_size"],
        "main_header_type": candidate["header_type"],
        "main_header_flags": candidate["header_flags"],
        "header_crc_verified": candidate["header_crc_verified"],
        "valid_header_count": 1,
        "malformed_signature_count": malformed_signature_count,
        "route": "bounded_external_archive_inventory_required",
    }


def _parse_nonnegative_integer(value: object) -> int | None:
    text = str(value or "").strip()
    if not text.isdigit():
        return None
    number = int(text)
    return number if number >= 0 else None


def _safe_windows_member_name(name: str) -> str:
    """Windows展開先でdevice名やADSへ変化するpathも拒否する。"""

    normalized = unicodedata.normalize("NFKC", safe_member_name(name, "rar"))
    if len(normalized) > MAX_MEMBER_PATH_LENGTH:
        raise ValueError("unsafe_archive_member_path")
    for component in normalized.split("/"):
        if ":" in component or component.endswith((".", " ")):
            raise ValueError("unsafe_archive_member_path")
        stem = component.split(".", 1)[0].casefold()
        if stem in _WINDOWS_RESERVED_NAMES:
            raise ValueError("unsafe_archive_member_path")
    return normalized


def parse_sevenzip_rar_listing(text: str) -> dict[str, object]:
    """7-Zip ``l -slt``のRAR descriptorとmember表を厳格に分離する。"""

    if not isinstance(text, str):
        raise TypeError("listingはstrで指定してください")
    if len(text.encode("utf-8", errors="replace")) > MAX_LISTING_TEXT:
        return {"status": "listing_size_blocked", "records": []}
    lines = text.splitlines()
    boundaries = [
        index for index, line in enumerate(lines) if line.strip() == "----------"
    ]
    if len(boundaries) != 1:
        return {
            "status": "member_listing_boundary_ambiguous",
            "boundary_count": len(boundaries),
            "records": [],
        }
    boundary = boundaries[0]
    descriptor_lines = lines[:boundary]
    member_lines = lines[boundary + 1 :]
    archive_types = [
        line[7:].strip() for line in descriptor_lines if line.startswith("Type = ")
    ]
    if len(archive_types) != 1 or not archive_types[0].casefold().startswith("rar"):
        return {"status": "not_rar_listing", "records": []}
    setup_targets = [
        match.group(1).strip()
        for line in descriptor_lines
        if (match := re.fullmatch(r"\s*Setup=(.+?)\s*", line, flags=re.IGNORECASE))
    ]

    records: list[dict[str, object]] = []
    current: dict[str, object] | None = None

    def finish() -> None:
        nonlocal current
        if current is not None:
            records.append(current)
        current = None

    field_names = {
        "Folder": "folder",
        "Size": "size",
        "Packed Size": "packed_size",
        "Attributes": "attributes",
        "Alternate Stream": "alternate_stream",
        "Encrypted": "encrypted",
        "CRC": "crc",
        "Checksum": "checksum",
        "Symbolic Link": "symbolic_link",
        "Hard Link": "hard_link",
        "Copy Link": "copy_link",
        "Characteristics": "characteristics",
    }
    for line in member_lines:
        if line.startswith("Path = "):
            finish()
            current = {"name": line[7:]}
            if len(records) >= MAX_MEMBER_RECORDS:
                return {
                    "status": "member_record_limit_blocked",
                    "archive_type": archive_types[0],
                    "records": [],
                }
            continue
        if current is None or " = " not in line:
            continue
        label, value = line.split(" = ", 1)
        key = field_names.get(label)
        if key is not None:
            current[key] = value.strip()
    finish()
    return {
        "status": "parsed",
        "archive_type": archive_types[0],
        "record_count": len(records),
        "setup_targets": setup_targets,
        "records": records,
    }


def _member_priority(name: str, setup_targets: set[str]) -> int | None:
    lowered = name.casefold()
    suffix = (
        "." + lowered.rsplit(".", 1)[1] if "." in lowered.rsplit("/", 1)[-1] else ""
    )
    if lowered in setup_targets:
        return 0
    if suffix in _EXECUTABLE_SUFFIXES:
        return 1
    if suffix in _SCRIPT_SUFFIXES:
        return 2
    if suffix in _CONFIG_OR_PAYLOAD_SUFFIXES:
        return 3
    if suffix in _NESTED_CONTAINER_SUFFIXES:
        return 4
    return None


def build_rar_sfx_extraction_plan(
    listing: Mapping[str, object],
    *,
    max_members: int = MAX_MEMBER_RECORDS,
    max_member_size: int = MAX_MEMBER_SIZE,
    max_total_size: int = MAX_TOTAL_SIZE,
    max_selected_members: int = MAX_SELECTED_MEMBERS,
    max_selected_total_size: int = MAX_SELECTED_TOTAL_SIZE,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """完全なRAR inventoryから明示的なcode/config抽出対象を選ぶ。"""

    limits = (
        max_members,
        max_member_size,
        max_total_size,
        max_selected_members,
        max_selected_total_size,
    )
    if any(isinstance(value, bool) or value <= 0 for value in limits):
        raise ValueError("plan limitは正の整数で指定してください")
    if listing.get("status") != "parsed":
        return {"status": "listing_not_complete"}, []
    records = listing.get("records")
    if not isinstance(records, list) or len(records) > max_members:
        return {"status": "member_count_blocked"}, []

    normalized: list[dict[str, object]] = []
    by_key: dict[str, dict[str, object]] = {}
    declared_total_size = 0
    for source in records:
        if not isinstance(source, Mapping) or not isinstance(source.get("name"), str):
            return {"status": "member_record_invalid"}, []
        try:
            name = _safe_windows_member_name(str(source["name"]))
        except ValueError:
            return {"status": "unsafe_member_path_blocked"}, []
        key = name.casefold()
        if key in by_key:
            return {"status": "conflicting_member_path_blocked"}, []
        folder = str(source.get("folder") or "-") == "+"
        size = _parse_nonnegative_integer(source.get("size"))
        if size is None or size > max_member_size:
            return {"status": "member_size_blocked"}, []
        declared_total_size += size
        if declared_total_size > max_total_size:
            return {"status": "declared_total_size_blocked"}, []
        if str(source.get("alternate_stream") or "-") == "+":
            return {"status": "alternate_stream_blocked"}, []
        if source.get("symbolic_link") or source.get("hard_link"):
            return {"status": "filesystem_link_blocked"}, []
        crc = str(source.get("crc") or "").strip().casefold()
        if crc and not re.fullmatch(r"[0-9a-f]{8}", crc):
            return {"status": "member_crc_invalid"}, []
        checksum = str(source.get("checksum") or "").strip().casefold()
        if checksum and not re.fullmatch(r"[0-9a-f]{64}", checksum):
            return {"status": "member_checksum_invalid"}, []
        item = {
            "name": name,
            "size": size,
            "folder": folder,
            "crc32": crc or None,
            "archive_checksum": checksum or None,
            "copy_link": str(source.get("copy_link") or "").strip() or None,
        }
        normalized.append(item)
        by_key[key] = item

    setup_targets: set[str] = set()
    for raw_target in listing.get("setup_targets") or []:
        if not isinstance(raw_target, str):
            return {"status": "setup_target_invalid"}, []
        try:
            setup_targets.add(_safe_windows_member_name(raw_target).casefold())
        except ValueError:
            return {"status": "setup_target_invalid"}, []
    if setup_targets - set(by_key):
        return {"status": "setup_target_missing"}, []

    aliases: dict[str, str] = {}
    for item in normalized:
        copy_link = item["copy_link"]
        if copy_link is None:
            continue
        try:
            target = _safe_windows_member_name(str(copy_link)).casefold()
        except ValueError:
            return {"status": "copy_link_target_invalid"}, []
        target_item = by_key.get(target)
        if target_item is None or target_item.get("copy_link") is not None:
            return {"status": "copy_link_target_missing"}, []
        if item["size"] != target_item["size"]:
            return {"status": "copy_link_size_mismatch"}, []
        aliases[str(item["name"]).casefold()] = str(target_item["name"]).casefold()

    effective_setup_targets = {aliases.get(target, target) for target in setup_targets}
    candidates: list[tuple[int, str, dict[str, object]]] = []
    for item in normalized:
        if item["folder"] or item["copy_link"] is not None:
            continue
        priority = _member_priority(str(item["name"]), effective_setup_targets)
        if priority is not None:
            candidates.append((priority, str(item["name"]).casefold(), item))
    candidates.sort(key=lambda candidate: (candidate[0], candidate[1]))

    selected: list[dict[str, object]] = []
    selected_total_size = 0
    for priority, _key, item in candidates:
        if len(selected) >= max_selected_members:
            break
        size = int(item["size"])
        if selected_total_size + size > max_selected_total_size:
            continue
        selected.append({**item, "priority": priority})
        selected_total_size += size

    selected_keys = {str(item["name"]).casefold() for item in selected}
    if not effective_setup_targets.issubset(selected_keys):
        return {"status": "setup_target_selection_blocked"}, []
    return {
        "status": "planned",
        "archive_inventory_complete": True,
        "member_count": len(normalized),
        "declared_total_size": declared_total_size,
        "safe_path_count": len(normalized),
        "copy_link_alias_count": len(aliases),
        "setup_target_count": len(setup_targets),
        "selected_member_count": len(selected),
        "selected_total_size": selected_total_size,
        "selection_complete": len(selected) == len(candidates),
        "crc_available_count": sum(bool(item["crc32"]) for item in normalized),
        "archive_checksum_available_count": sum(
            bool(item["archive_checksum"]) for item in normalized
        ),
        "archive_checksum_requires_external_parser_verification": True,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
    }, selected


def verify_rar_sfx_extraction(
    plan: list[dict[str, object]],
    extracted: Mapping[str, bytes],
    *,
    external_archive_integrity_verified: bool,
) -> dict[str, object]:
    """明示選択した抽出物をpath、size、CRCで再検証する。"""

    if external_archive_integrity_verified is not True:
        return {"status": "external_archive_integrity_unverified"}
    expected: dict[str, dict[str, object]] = {}
    for item in plan:
        if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
            return {"status": "plan_invalid"}
        try:
            key = _safe_windows_member_name(str(item["name"])).casefold()
        except ValueError:
            return {"status": "plan_invalid"}
        if key in expected:
            return {"status": "plan_invalid"}
        expected[key] = dict(item)

    observed: dict[str, tuple[str, bytes]] = {}
    for name, blob in extracted.items():
        if not isinstance(name, str) or not isinstance(blob, bytes):
            return {"status": "extracted_member_invalid"}
        try:
            key = _safe_windows_member_name(name).casefold()
        except ValueError:
            return {"status": "extracted_member_path_blocked"}
        if key in observed:
            return {"status": "extracted_member_path_conflict"}
        observed[key] = (name, blob)
    if set(observed) != set(expected):
        return {
            "status": "extracted_member_set_mismatch",
            "expected_member_count": len(expected),
            "observed_member_count": len(observed),
        }

    verified: list[dict[str, object]] = []
    for key in sorted(expected):
        item = expected[key]
        name, blob = observed[key]
        if len(blob) != item.get("size"):
            return {"status": "extracted_member_size_mismatch"}
        crc = item.get("crc32")
        if crc is not None and f"{zlib.crc32(blob) & 0xFFFFFFFF:08x}" != crc:
            return {"status": "extracted_member_crc_mismatch"}
        verified.append(
            {
                "name": name,
                "size": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(),
                "crc32_verified": crc is not None,
                "external_archive_integrity_verified": True,
            }
        )
    return {
        "status": "verified",
        "verified_member_count": len(verified),
        "verified_total_size": sum(int(item["size"]) for item in verified),
        "members": verified,
        "sample_executed": False,
        "network_contacted": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
    }


__all__ = [
    "assess_winrar_sfx",
    "build_rar_sfx_extraction_plan",
    "parse_sevenzip_rar_listing",
    "verify_rar_sfx_extraction",
]
