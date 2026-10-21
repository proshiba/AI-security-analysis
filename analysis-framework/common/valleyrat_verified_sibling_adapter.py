#!/usr/bin/env python3
"""完全検証済み7-Zip同居memberをValleyRAT strict bundleへ正規化する。"""

from __future__ import annotations

import hashlib
import io
import re
import unicodedata
import zipfile
import zlib
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from extractors.valleyrat.zip_sideload_shellcode import (
    VerifiedSiblingMember,
    recover_verified_sibling_shellcode,
)

MAXIMUM_FULL_INVENTORY_MEMBERS = 128
MAXIMUM_MATERIALIZED_MEMBERS = 128
MAXIMUM_MEMBER_SIZE = 64 * 1024 * 1024
MAXIMUM_TOTAL_SIZE = 256 * 1024 * 1024
MAXIMUM_PATH_CHARACTERS = 1024
MAXIMUM_PATH_COMPONENT_CHARACTERS = 255
SUPPORTED_ARCHIVE_TYPES = frozenset({"Rar", "Rar5"})
FORMAT_LABEL_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
CRC32_RE = re.compile(r"[0-9a-fA-F]{8}")
WINDOWS_RESERVED_BASENAMES = frozenset(
    {
        "aux",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)


@dataclass(frozen=True)
class VerifiedSiblingBundleLayer:
    """strict proof成立後だけ生成するインメモリ正規化ZIPレイヤー。"""

    data: bytes
    parent_sha256: str
    bundle_sha256: str
    terminal_sha256: str
    host_sha256: str
    loader_sha256: str
    carrier_sha256: str
    full_inventory_count: int
    full_inventory_size: int
    materialized_member_count: int
    materialized_member_size: int
    distinct_artifact_count: int
    crc32_verified_member_count: int

    def public(self) -> dict[str, Any]:
        """member名・raw設定・network値を除いたprovenanceを返す。"""

        return {
            "schema_version": 1,
            "status": "strict_lineage_recovered",
            "profile": "verified_rar_sibling_bundle_to_vvas_terminal",
            "parent_sha256": self.parent_sha256,
            "normalized_bundle_sha256": self.bundle_sha256,
            "terminal_sha256": self.terminal_sha256,
            "component_sha256": {
                "host": self.host_sha256,
                "loader": self.loader_sha256,
                "carrier": self.carrier_sha256,
            },
            "inventory": {
                "full_member_count": self.full_inventory_count,
                "full_total_size": self.full_inventory_size,
                "materialized_member_count": self.materialized_member_count,
                "materialized_total_size": self.materialized_member_size,
                "normalized_member_count": self.full_inventory_count,
                "normalized_total_size": self.full_inventory_size,
                "distinct_artifact_count": self.distinct_artifact_count,
                "verified_duplicate_alias_count": (self.full_inventory_count - self.distinct_artifact_count),
                "source_deduplicated_alias_count": (self.full_inventory_count - self.materialized_member_count),
                "crc32_verified_member_count": self.crc32_verified_member_count,
                "all_paths_validated": True,
                "all_inventory_identity_records_validated": True,
                "all_materialized_hashes_recomputed": True,
                "all_materialized_identities_joined": True,
                "all_inventory_rows_reconstructed": True,
                "materialized_identity_set_equals_inventory_identity_set": True,
                "archive_inventory_complete": True,
            },
            "proof": {
                "sibling_import_export_edge": True,
                "carrier_read_transform_sink_lineage": True,
                "terminal_vvas_structure": True,
                "normalized_bundle_is_analysis_container": True,
                "collection_complete": True,
                "collection_complete_semantics": (
                    "every_full_inventory_row_is_present_in_the_normalized_collection;_"
                    "a_source_alias_may_be_reconstructed_only_from_an_exact_sha256_and_size_duplicate"
                ),
            },
            "evidence_boundary": {
                "adapter_confirms_family": False,
                "adapter_confirms_c2": False,
                "downstream_strict_detector_required": True,
                "sample_executed": False,
                "network_contacted": False,
                "raw_member_names_included": False,
                "raw_payload_included": False,
                "raw_config_included": False,
                "raw_network_values_included": False,
            },
        }


@dataclass(frozen=True)
class _InventoryMember:
    """7-Zip inventoryの検証済み1行。"""

    path: str
    size: int
    sha256: str
    format: str
    recovery_priority: int | None
    crc32: str | None


def _normalized_member_path(value: object) -> str | None:
    """archive pathを有界相対POSIX pathへ正規化する。"""

    if not isinstance(value, str) or not value or len(value) > MAXIMUM_PATH_CHARACTERS:
        return None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        return None
    rendered = unicodedata.normalize("NFKC", value).replace("\\", "/")
    if rendered.startswith("/") or rendered.endswith("/"):
        return None
    parts = rendered.split("/")
    if not parts:
        return None
    if any(
        part in {"", ".", ".."}
        or len(part) > MAXIMUM_PATH_COMPONENT_CHARACTERS
        or ":" in part
        or part.rstrip(" .") != part
        or part.partition(".")[0].casefold() in WINDOWS_RESERVED_BASENAMES
        for part in parts
    ):
        return None
    path = PurePosixPath(*parts)
    if path.is_absolute() or not path.parts:
        return None
    normalized = path.as_posix()
    if len(normalized) > MAXIMUM_PATH_CHARACTERS:
        return None
    return normalized


def _nonnegative_integer(value: object, *, maximum: int) -> int | None:
    """boolを除外して有界非負整数だけを返す。"""

    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        return None
    return value


def _inventory_member(item: object) -> _InventoryMember | None:
    """inventory 1行を型・path・identityまで検証する。"""

    if not isinstance(item, dict) or item.get("status") != "extracted":
        return None
    path = _normalized_member_path(item.get("name"))
    size = _nonnegative_integer(item.get("size"), maximum=MAXIMUM_MEMBER_SIZE)
    digest = item.get("sha256")
    format_label = item.get("format")
    if (
        path is None
        or size is None
        or not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest) is None
        or not isinstance(format_label, str)
        or FORMAT_LABEL_RE.fullmatch(format_label) is None
    ):
        return None
    priority: int | None = None
    if "recovery_priority" in item:
        priority = _nonnegative_integer(item.get("recovery_priority"), maximum=1_000_000)
        if priority is None:
            return None
    crc_values = [item.get(key) for key in ("crc", "crc32") if key in item]
    if len(crc_values) > 1 and crc_values[0] != crc_values[1]:
        return None
    crc32: str | None = None
    if crc_values:
        raw_crc = crc_values[0]
        if not isinstance(raw_crc, str) or CRC32_RE.fullmatch(raw_crc) is None:
            return None
        crc32 = raw_crc.lower()
    return _InventoryMember(path, size, digest, format_label, priority, crc32)


def _artifact_identity_map(
    artifacts: Sequence[tuple[str, bytes]],
) -> dict[tuple[str, str], bytes] | None:
    """全artifactを検証し、同一bytes aliasだけをkind・SHA-256で畳む。"""

    if not isinstance(artifacts, (list, tuple)) or not 1 <= len(artifacts) <= MAXIMUM_MATERIALIZED_MEMBERS:
        return None
    identities: dict[tuple[str, str], bytes] = {}
    total_size = 0
    for artifact in artifacts:
        if not isinstance(artifact, tuple) or len(artifact) != 2:
            return None
        kind, data = artifact
        if (
            not isinstance(kind, str)
            or FORMAT_LABEL_RE.fullmatch(kind) is None
            or not isinstance(data, bytes)
            or len(data) > MAXIMUM_MEMBER_SIZE
        ):
            return None
        total_size += len(data)
        if total_size > MAXIMUM_TOTAL_SIZE:
            return None
        identity = (kind, hashlib.sha256(data).hexdigest())
        existing = identities.get(identity)
        if existing is not None and existing != data:
            return None
        identities[identity] = data
    return identities


def _deterministic_zip(members: Sequence[VerifiedSiblingMember]) -> bytes | None:
    """検証済みmemberだけを名前順の無圧縮ZIPへ正規化する。"""

    output = io.BytesIO()
    try:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
            for member in sorted(members, key=lambda item: item.path.casefold()):
                info = zipfile.ZipInfo(member.path, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o600 << 16
                info.flag_bits = 0
                archive.writestr(info, member.data)
    except (OSError, RuntimeError, ValueError, zipfile.LargeZipFile):
        return None
    result = output.getvalue()
    if not result or len(result) > MAXIMUM_TOTAL_SIZE:
        return None
    return result


def recover_verified_sibling_bundle_layer(
    *,
    parent_data: bytes,
    parent_sha256: str,
    report: dict[str, Any],
    artifacts: Sequence[tuple[str, bytes]],
) -> VerifiedSiblingBundleLayer | None:
    """7-Zip reportの完全join後だけstrict sibling bundleをqueue用ZIPへする。

    7-Zipが全inventoryを安全に列挙・展開したことを先に確認する。保持対象は
    inventoryの決定的な優先順、hintのordinal／kind／hash、全artifactの
    kind／hash／sizeを全件結合する。どれか1つでも曖昧なら何も返さない。
    """

    if (
        not isinstance(parent_data, bytes)
        or not isinstance(parent_sha256, str)
        or SHA256_RE.fullmatch(parent_sha256) is None
        or hashlib.sha256(parent_data).hexdigest() != parent_sha256
        or not isinstance(report, dict)
        or report.get("format") != "pe"
        or report.get("sha256") != parent_sha256
        or report.get("size") != len(parent_data)
        or report.get("executed") is not False
        or report.get("network_contacted") is not False
    ):
        return None
    sevenzip = report.get("sevenzip")
    pe = report.get("pe")
    winrar_sfx = pe.get("winrar_sfx") if isinstance(pe, dict) else None
    if (
        not isinstance(sevenzip, dict)
        or not isinstance(winrar_sfx, dict)
        or winrar_sfx.get("status") != "validated_sfx_container"
        or winrar_sfx.get("candidate") is not True
        or winrar_sfx.get("scan_complete") is not True
        or winrar_sfx.get("header_crc_verified") is not True
        or winrar_sfx.get("family_attribution_allowed") is not False
        or winrar_sfx.get("c2_confirmation_allowed") is not False
        or winrar_sfx.get("terminal_promotion_eligible") is not False
    ):
        return None
    archive_types = sevenzip.get("archive_types")
    if (
        sevenzip.get("status") != "extracted"
        or sevenzip.get("exit_code") != 0
        or sevenzip.get("extract_exit_code") != 0
        or not isinstance(archive_types, list)
        or not archive_types
        or any(item not in SUPPORTED_ARCHIVE_TYPES for item in archive_types)
        or sevenzip.get("member_layout_ambiguous") is not False
        or sevenzip.get("member_listing_boundary_observed") is not True
        or sevenzip.get("member_record_limit_exceeded") is not False
        or sevenzip.get("unsafe_member_count") != 0
    ):
        return None
    safe = sevenzip.get("safe_member_continuation")
    selective = sevenzip.get("selective_extraction")
    all_member_retention = sevenzip.get("all_bounded_member_retention")
    if (
        not isinstance(safe, dict)
        or safe.get("archive_inventory_complete") is not True
        or safe.get("blocked_member_count") != 0
        or not isinstance(selective, dict)
        or selective.get("enabled") is not False
        or selective.get("reason") != "not_required"
        or selective.get("selected_members") != []
        or selective.get("selected_total_size") != 0
        or not isinstance(all_member_retention, dict)
        or all_member_retention.get("enabled") is not True
        or all_member_retention.get("complete") is not True
    ):
        return None
    inventory_raw = sevenzip.get("inventory")
    member_paths_raw = sevenzip.get("members")
    if (
        not isinstance(inventory_raw, list)
        or not 2 <= len(inventory_raw) <= MAXIMUM_FULL_INVENTORY_MEMBERS
        or not isinstance(member_paths_raw, list)
        or len(member_paths_raw) != len(inventory_raw)
    ):
        return None
    inventory: list[_InventoryMember] = []
    for item in inventory_raw:
        parsed = _inventory_member(item)
        if parsed is None:
            return None
        inventory.append(parsed)
    inventory_paths = [item.path for item in inventory]
    member_paths = [_normalized_member_path(item) for item in member_paths_raw]
    inventory_keys = {item.casefold() for item in inventory_paths}
    member_keys = [str(item).casefold() for item in member_paths if item is not None]
    if (
        any(item is None for item in member_paths)
        or len(inventory_keys) != len(inventory_paths)
        or len(set(member_keys)) != len(member_keys)
        or set(member_keys) != inventory_keys
    ):
        return None
    full_count = len(inventory)
    full_size = sum(item.size for item in inventory)
    declared_count = _nonnegative_integer(sevenzip.get("total_members"), maximum=MAXIMUM_FULL_INVENTORY_MEMBERS)
    declared_size = _nonnegative_integer(sevenzip.get("declared_total_size"), maximum=MAXIMUM_TOTAL_SIZE)
    if (
        declared_count != full_count
        or selective.get("full_inventory_count") != full_count
        or safe.get("explicit_safe_member_count") != full_count
        or declared_size != full_size
        or sevenzip.get("extracted_total_size") != full_size
        or all_member_retention.get("full_inventory_count") != full_count
    ):
        return None
    selected = sorted(
        (item for item in inventory if item.recovery_priority is not None),
        key=lambda item: (item.recovery_priority, item.path.lower()),
    )
    retained_count = _nonnegative_integer(sevenzip.get("retained_members"), maximum=MAXIMUM_MATERIALIZED_MEMBERS)
    if (
        retained_count != len(selected)
        or retained_count != full_count
        or all_member_retention.get("retained_member_count") != full_count
        or not 2 <= len(selected) <= MAXIMUM_MATERIALIZED_MEMBERS
    ):
        return None
    hint_envelope = report.get("artifact_name_hints")
    if hint_envelope != sevenzip.get("artifact_name_hints") or not isinstance(hint_envelope, dict):
        return None
    hints = hint_envelope.get("items")
    if (
        hint_envelope.get("schema_version") != 1
        or hint_envelope.get("complete") is not True
        or not isinstance(hints, list)
        or len(hints) != len(selected)
    ):
        return None
    identities = _artifact_identity_map(artifacts)
    if identities is None:
        return None
    selected_basenames = [PurePosixPath(item.path).name for item in selected]
    if len({item.casefold() for item in selected_basenames}) != len(selected_basenames):
        return None
    verified_members: list[VerifiedSiblingMember] = []
    referenced_identities: set[tuple[str, str]] = set()
    inventory_identity_counts: Counter[tuple[str, str]] = Counter()
    materialized_identity_counts: Counter[tuple[str, str]] = Counter(
        (kind, hashlib.sha256(data).hexdigest()) for kind, data in artifacts
    )
    crc32_verified = 0
    for ordinal, (item, hint) in enumerate(zip(selected, hints, strict=True)):
        if not isinstance(hint, dict) or hint.get("artifact_index") != ordinal:
            return None
        expected_kind = f"7z-{item.format}"
        if hint.get("artifact_kind") != expected_kind or hint.get("sha256") != item.sha256:
            return None
        hint_basename = _normalized_member_path(hint.get("member_basename"))
        if hint_basename != PurePosixPath(item.path).name:
            return None
        identity = (expected_kind, item.sha256)
        data = identities.get(identity)
        if data is None or len(data) != item.size or hashlib.sha256(data).hexdigest() != item.sha256:
            return None
        if item.crc32 is not None:
            if f"{zlib.crc32(data) & 0xFFFFFFFF:08x}" != item.crc32:
                return None
            crc32_verified += 1
        inventory_identity_counts[identity] += 1
        referenced_identities.add(identity)
        verified_members.append(
            VerifiedSiblingMember(
                path=item.path,
                data=data,
                size=item.size,
                sha256=item.sha256,
            )
        )
    if referenced_identities != set(identities):
        return None
    # unpack_bytesの最終段は同一bytesをSHA-256で重複排除するため、full inventory
    # のalias数よりmaterialized artifact数が少なくなり得る。省略を許すのは、
    # 同一kind・SHA-256・sizeのinventory rowが別にあり、その実bytesが少なくとも
    # 1件materializeされている場合だけとする。unique rowの欠落、余分なartifact、
    # inventoryより多いmaterializationはいずれもfail closedにする。
    if any(
        materialized_identity_counts.get(identity, 0) < 1 or materialized_identity_counts[identity] > inventory_count
        for identity, inventory_count in inventory_identity_counts.items()
    ):
        return None
    materialized_size = sum(len(data) for _kind, data in artifacts)
    strict = recover_verified_sibling_shellcode(
        parent_data=parent_data,
        expected_parent_sha256=parent_sha256,
        members=tuple(verified_members),
        declared_member_count=full_count,
        declared_total_size=full_size,
        collection_complete=True,
    )
    if strict is None:
        return None
    bundle = _deterministic_zip(verified_members)
    if bundle is None:
        return None
    return VerifiedSiblingBundleLayer(
        data=bundle,
        parent_sha256=parent_sha256,
        bundle_sha256=hashlib.sha256(bundle).hexdigest(),
        terminal_sha256=strict.terminal_sha256,
        host_sha256=strict.host_sha256,
        loader_sha256=strict.loader_sha256,
        carrier_sha256=strict.carrier_sha256,
        full_inventory_count=full_count,
        full_inventory_size=full_size,
        materialized_member_count=len(artifacts),
        materialized_member_size=materialized_size,
        distinct_artifact_count=len(identities),
        crc32_verified_member_count=crc32_verified,
    )
