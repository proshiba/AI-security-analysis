#!/usr/bin/env python3
"""検証済みNSIS同居memberをValleyRAT多段抽出器へ配送する。"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from extractors.valleyrat.nsis_rc4_sidecar import (
    NsisRc4SidecarLineage,
    analyze_nsis_rc4_sidecar_bundle,
)

MAXIMUM_MATERIALIZED_MEMBERS = 64
MAXIMUM_MATERIALIZED_TOTAL_SIZE = 512 * 1024 * 1024
MAXIMUM_PATH_CHARACTERS = 1024
MAXIMUM_PATH_COMPONENT_CHARACTERS = 255
FORMAT_LABEL_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class VerifiedNsisRc4SidecarLayer:
    """strict chain成立後だけqueueへ渡す終端PEレイヤー。"""

    data: bytes
    parent_sha256: str
    terminal_sha256: str
    inventory_member_count: int
    inventory_total_size: int
    omitted_member_count: int
    observation: dict[str, object]

    def public(self) -> dict[str, Any]:
        """raw member名・key・設定・network値を除いたprovenanceを返す。"""

        terminal = self.observation.get("terminal")
        endpoint_count = (
            terminal.get("endpoint_count") if isinstance(terminal, dict) else None
        )
        return {
            "schema_version": 1,
            "status": "strict_lineage_recovered",
            "profile": "verified_nsis_xor_zipcrypto_rc4_to_vvas_terminal",
            "parent_sha256": self.parent_sha256,
            "terminal_sha256": self.terminal_sha256,
            "inventory": {
                "materialized_member_count": self.inventory_member_count,
                "materialized_total_size": self.inventory_total_size,
                "omitted_low_value_member_count": self.omitted_member_count,
                "all_materialized_hashes_recomputed": True,
                "all_materialized_identities_joined": True,
                "archive_inventory_complete": True,
            },
            "proof": {
                "code_referenced_repeating_xor_pe": True,
                "zipcrypto_all_member_crc_validation": True,
                "code_referenced_unique_rc4_ksa_prga": True,
                "terminal_vvas_structure_and_socket_lineage": True,
                "terminal_endpoint_count": endpoint_count,
            },
            "evidence_boundary": {
                "adapter_confirms_family": True,
                "adapter_confirms_c2_count": True,
                "raw_member_names_included": False,
                "raw_key_included": False,
                "raw_password_included": False,
                "raw_config_included": False,
                "raw_payload_included": False,
                "raw_network_values_included": False,
                "sample_executed": False,
                "network_contacted": False,
            },
        }


def _safe_member_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > MAXIMUM_PATH_CHARACTERS:
        return None
    rendered = value.replace("\\", "/")
    path = PurePosixPath(rendered)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        return None
    if any(
        part in {"", ".", ".."}
        or len(part) > MAXIMUM_PATH_COMPONENT_CHARACTERS
        or ":" in part
        or part.rstrip(" .") != part
        for part in path.parts
    ):
        return None
    return path.as_posix()


def _nonnegative_integer(value: object, *, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        return None
    return value


def _expected_artifact_kind(index: int, member: dict[str, object]) -> str | None:
    name = _safe_member_path(member.get("name"))
    format_label = member.get("format")
    if (
        name is None
        or not isinstance(format_label, str)
        or FORMAT_LABEL_RE.fullmatch(format_label) is None
    ):
        return None
    if PurePosixPath(name.casefold()).name == "[nsis].nsi":
        return "nsis-install-script.nsi"
    suffix = PurePosixPath(name.casefold()).suffix
    safe_suffix = suffix if re.fullmatch(r"\.[a-z0-9]{1,16}", suffix) else ""
    return f"nsis-member-{index:03d}-{format_label}{safe_suffix}"


def _verified_component_mapping(
    inventory: list[object],
    artifacts: Sequence[tuple[str, bytes]],
) -> tuple[dict[str, bytes], int] | None:
    if not 1 <= len(inventory) <= MAXIMUM_MATERIALIZED_MEMBERS:
        return None
    by_kind: dict[str, list[bytes]] = {}
    for artifact in artifacts:
        if (
            not isinstance(artifact, tuple)
            or len(artifact) != 2
            or not isinstance(artifact[0], str)
            or not isinstance(artifact[1], bytes)
        ):
            return None
        by_kind.setdefault(artifact[0], []).append(artifact[1])

    components: dict[str, bytes] = {}
    total_size = 0
    for index, raw_member in enumerate(inventory):
        if not isinstance(raw_member, dict):
            return None
        name = _safe_member_path(raw_member.get("output_name"))
        source_name = _safe_member_path(raw_member.get("name"))
        size = _nonnegative_integer(
            raw_member.get("size"), maximum=MAXIMUM_MATERIALIZED_TOTAL_SIZE
        )
        digest = raw_member.get("sha256")
        kind = _expected_artifact_kind(index, raw_member)
        if (
            name is None
            or source_name is None
            or size is None
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or kind is None
        ):
            return None
        matches = by_kind.get(kind, [])
        if len(matches) != 1:
            return None
        data = matches[0]
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            return None
        folded = name.casefold()
        if folded in {item.casefold() for item in components}:
            return None
        components[name] = data
        total_size += len(data)
        if total_size > MAXIMUM_MATERIALIZED_TOTAL_SIZE:
            return None
    return components, total_size


def recover_verified_nsis_rc4_sidecar_layer(
    *,
    parent_data: bytes,
    parent_sha256: str,
    report: dict[str, Any],
    artifacts: Sequence[tuple[str, bytes]],
) -> VerifiedNsisRc4SidecarLayer | None:
    """完全照合したNSIS選択memberから終端PEを自動queue用に返す。"""

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
    if not isinstance(sevenzip, dict):
        return None
    tool = sevenzip.get("tool")
    envelope = sevenzip.get("container_envelope")
    selection = sevenzip.get("selective_extraction")
    ratio = sevenzip.get("ratio_validation")
    inventory = sevenzip.get("inventory")
    if (
        sevenzip.get("status") not in {"extracted", "selectively_extracted"}
        or sevenzip.get("candidate") is not True
        or sevenzip.get("executed") is not False
        or sevenzip.get("sample_executed") is not False
        or sevenzip.get("network_contacted") is not False
        or sevenzip.get("external_parser_started") is not True
        or sevenzip.get("inventory_complete") is not True
        or sevenzip.get("archive_test_complete") is not True
        or sevenzip.get("extraction_complete") is not True
        or sevenzip.get("archive_types") != ["Nsis"]
        or not isinstance(tool, dict)
        or tool.get("available") is not True
        or tool.get("version_supported") is not True
        or tool.get("identity_unchanged") is not True
        or not isinstance(envelope, dict)
        or envelope.get("container_layout_validated") is not True
        or not isinstance(selection, dict)
        or not isinstance(ratio, dict)
        or ratio.get("complete") is not True
        or ratio.get("blocked_member_count") != 0
        or not isinstance(inventory, list)
    ):
        return None
    retained = _nonnegative_integer(
        sevenzip.get("retained_members"), maximum=MAXIMUM_MATERIALIZED_MEMBERS
    )
    selected = _nonnegative_integer(
        selection.get("selected_member_count"), maximum=MAXIMUM_MATERIALIZED_MEMBERS
    )
    omitted = _nonnegative_integer(
        selection.get("omitted_member_count"), maximum=1_000_000
    )
    declared_members = _nonnegative_integer(
        sevenzip.get("total_members"), maximum=1_000_000
    )
    if (
        retained is None
        or selected is None
        or omitted is None
        or declared_members is None
        or retained != selected
        or retained != len(inventory)
        or retained + omitted != declared_members
    ):
        return None
    verified = _verified_component_mapping(inventory, artifacts)
    if verified is None:
        return None
    components, total_size = verified
    if sevenzip.get("extracted_total_size") != total_size:
        return None
    lineage = analyze_nsis_rc4_sidecar_bundle(components)
    if not isinstance(lineage, NsisRc4SidecarLineage):
        return None
    observation = lineage.observation
    if not (
        observation.get("status")
        == "validated_nsis_xor_zipcrypto_rc4_to_vvas_terminal"
        and observation.get("supports_family_attribution") is True
        and observation.get("terminal_family_confirmed") is True
        and observation.get("terminal_network_lineage_proven") is True
        and observation.get("sample_executed") is False
        and observation.get("network_contacted") is False
    ):
        return None
    terminal = lineage.terminal_component
    if not terminal.startswith(b"MZ"):
        return None
    return VerifiedNsisRc4SidecarLayer(
        data=terminal,
        parent_sha256=parent_sha256,
        terminal_sha256=hashlib.sha256(terminal).hexdigest(),
        inventory_member_count=retained,
        inventory_total_size=total_size,
        omitted_member_count=omitted,
        observation=observation,
    )


__all__ = [
    "VerifiedNsisRc4SidecarLayer",
    "recover_verified_nsis_rc4_sidecar_layer",
]
