#!/usr/bin/env python3
"""静的レイヤーからpackaging／container構造だけを安全に集約する。"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping
from typing import Any

SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"[0-9a-f]{64}")
SAFE_LAYER_FORMATS = frozenset(
    {
        "7z",
        "apple-disk-image",
        "asar",
        "autoit-a3x",
        "cab",
        "data",
        "elf",
        "java-class",
        "macho",
        "ole",
        "pdf",
        "pe",
        "png",
        "rar",
        "script",
        "xz",
        "zip",
    }
)
PACKED_CLASSIFICATIONS = frozenset(
    {
        "packed_or_protected",
        "suspected_packed",
        "suspected_encrypted_sideload_host",
        "virtualized_or_packed",
    }
)
STRONG_PACKER_MARKERS = frozenset({"mpress1", "mpress2", "themida", "vmprotect"})
CLASSIC_UPX_SECTION_NAMES = frozenset({"upx", "upx0", "upx1", "upx2"})
MIN_CLASSIC_UPX_SECTION_SIZE = 4096
MIN_CLASSIC_UPX_PACKED_ENTROPY = 7.2
ARCHIVE_COMPLETE_STATUSES = frozenset({"extracted"})
ARCHIVE_SELECTIVE_STATUSES = frozenset({"selectively_extracted"})
ARCHIVE_PARTIAL_STATUSES = frozenset(
    {
        "actual_member_limit_blocked",
        "declared_size_blocked",
        "extract_timeout",
        "member_and_total_size_limit_blocked",
        "member_limit_blocked",
        "partially_extracted",
        "temporary_quota_blocked",
        "timeout",
        "tool_failed",
        "tool_integrity_failed",
        "tool_output_limit",
        "unsafe_tool_output",
    }
)
SAFE_ARCHIVE_MEMBER_STATUSES = frozenset({"extracted", "empty_file"})
INNO_SELECTION_LIMIT_REASONS = frozenset(
    {
        "command_length_limit",
        "low_value_members_omitted",
        "member_count_limit",
        "member_size_limit",
        "total_size_limit",
    }
)
SAFE_AGGREGATION_STATUSES = frozenset(
    {
        "candidates_recorded",
        "candidates_with_blockers",
        "candidates_with_invalid_steps",
        "complete_no_candidates",
        "not_run_assessment_only",
        "source_report_invalid",
        "source_report_unavailable",
    }
)


def _mapping(value: object) -> Mapping[str, Any] | None:
    return value if isinstance(value, Mapping) else None


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _safe_layer(value: object) -> dict[str, Any] | None:
    layer = _mapping(value)
    if layer is None:
        return None
    digest = layer.get("sha256")
    depth = _non_negative_int(layer.get("depth"))
    size = _non_negative_int(layer.get("size"))
    layer_format = layer.get("format")
    if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None or depth is None or size is None:
        return None
    return {
        "sha256": digest,
        "depth": depth,
        "size": size,
        "format": (layer_format if isinstance(layer_format, str) and layer_format in SAFE_LAYER_FORMATS else "unknown"),
    }


def _safe_count(mapping: Mapping[str, Any] | None, key: str) -> int | None:
    return _non_negative_int(mapping.get(key)) if mapping is not None else None


def _status(mapping: Mapping[str, Any] | None) -> str | None:
    value = mapping.get("status") if mapping is not None else None
    return value.casefold() if isinstance(value, str) else None


def _safe_entropy(value: object) -> float | None:
    """PE section entropyを有限な0..8の数値だけに制限する。"""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    numeric = float(value)
    return numeric if 0.0 <= numeric <= 8.0 else None


def _classic_upx_section_name(value: object) -> str | None:
    """古典的UPX section名だけを正規化し、部分一致を避ける。"""

    if not isinstance(value, str):
        return None
    normalized = value.casefold().removeprefix(".")
    return normalized if normalized in CLASSIC_UPX_SECTION_NAMES else None


def _safe_commitment(value: object, role: str) -> dict[str, Any] | None:
    commitment = _mapping(value)
    if commitment is None:
        return None
    algorithm = commitment.get("algorithm")
    digest = commitment.get("sha256")
    record_count = _non_negative_int(commitment.get("record_count"))
    if (
        not isinstance(algorithm, str)
        or algorithm.casefold() != "sha256"
        or not isinstance(digest, str)
        or SHA256_RE.fullmatch(digest.casefold()) is None
        or record_count is None
    ):
        return None
    return {
        "role": role,
        "algorithm": "sha256",
        "record_count": record_count,
        "sha256": digest.casefold(),
    }


def _fixed_count_fields(*mappings: tuple[Mapping[str, Any] | None, tuple[str, ...]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for source, names in mappings:
        for name in names:
            value = _safe_count(source, name)
            if value is not None:
                counts[name] = value
    return dict(sorted(counts.items()))


def _evidence(
    *,
    kind: str,
    source_layer: Mapping[str, Any],
    signals: set[str],
    counts: Mapping[str, int],
    source_commitments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    safe_signals = sorted(signals)
    safe_counts = dict(sorted(counts.items()))
    safe_commitments = sorted(
        source_commitments or [],
        key=lambda item: (item["role"], item["sha256"]),
    )
    core: dict[str, Any] = {
        "signals": safe_signals,
        "signal_count": len(safe_signals),
        "counts": safe_counts,
        "source_commitments": safe_commitments,
    }
    canonical = json.dumps(
        {
            "kind": kind,
            "source_layer": dict(source_layer),
            **core,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    core["commitment"] = {
        "algorithm": "sha256",
        "canonicalization": "canonical_json_utf8_structural_candidate_evidence_v1",
        "record_count": len(safe_signals) + len(safe_counts) + len(safe_commitments),
        "sha256": hashlib.sha256(canonical).hexdigest(),
    }
    return core


def _candidate_id(kind: str, source_layer: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        {
            "kind": kind,
            "source_layer_depth": source_layer["depth"],
            "source_layer_sha256": source_layer["sha256"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return f"sc-v1-{hashlib.sha256(canonical).hexdigest()}"


def _make_candidate(
    *,
    kind: str,
    source_layer: Mapping[str, Any],
    confidence: str,
    structural_status: str,
    extraction_status: str,
    accepted_child_count: int,
    reported_artifact_count: int,
    source_limit_event_count: int,
    signals: set[str],
    counts: Mapping[str, int],
    blockers: set[str],
    source_commitments: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if source_limit_event_count:
        blockers.add("source_layer_recovery_limit_observed")
    return {
        "id": _candidate_id(kind, source_layer),
        "kind": kind,
        "source_layer": dict(source_layer),
        "confidence": confidence,
        "status": structural_status,
        "extraction": {
            "status": extraction_status,
            "accepted_child_count": accepted_child_count,
            "reported_artifact_count": reported_artifact_count,
            "source_limit_event_count": source_limit_event_count,
        },
        "evidence": _evidence(
            kind=kind,
            source_layer=source_layer,
            signals=signals,
            counts=counts,
            source_commitments=source_commitments,
        ),
        "blockers": sorted(blockers),
        "maliciousness": "not_determined_from_packaging",
        "family_attribution_allowed": False,
        "executed_sample": False,
        "network_contacted": False,
    }


def _reported_artifact_count(report: Mapping[str, Any]) -> int:
    recovered = report.get("recovered")
    return len(recovered) if isinstance(recovered, list) else 0


def _accepted_child_count(step: Mapping[str, Any]) -> int:
    accepted = step.get("accepted_children")
    return len(accepted) if isinstance(accepted, list) else 0


def _source_limit_event_counts(layer_report: Mapping[str, Any]) -> Counter[str]:
    counts: Counter[str] = Counter()
    events = layer_report.get("limit_events")
    if not isinstance(events, list):
        return counts
    for event in events:
        item = _mapping(event)
        parent = item.get("parent_sha256") if item is not None else None
        if isinstance(parent, str) and SHA256_RE.fullmatch(parent):
            counts[parent] += 1
    return counts


def _contains_dynamic_evidence(value: object) -> bool:
    """sample実行／network由来の真値や過大・深過ぎる構造を拒否する。"""

    pending: list[tuple[object, int]] = [(value, 0)]
    seen: set[int] = set()
    visited = 0
    while pending:
        current, depth = pending.pop()
        if depth > 32:
            return True
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            visited += 1
            if visited > 10_000:
                return True
            for key, item in current.items():
                if (
                    isinstance(key, str)
                    and key.casefold()
                    in {
                        "executed",
                        "executed_sample",
                        "network_contacted",
                        "sample_executed",
                    }
                    and item is True
                ):
                    return True
                if isinstance(item, (Mapping, list)):
                    pending.append((item, depth + 1))
        elif isinstance(current, list):
            identity = id(current)
            if identity in seen:
                continue
            seen.add(identity)
            visited += 1
            if visited > 10_000:
                return True
            pending.extend((item, depth + 1) for item in current)
    return False


def _pyinstaller_mapping(report: Mapping[str, Any]) -> Mapping[str, Any] | None:
    candidates = [report]
    for key in ("pyinstaller", "pyinstaller_archive", "pyinstaller_carchive", "carchive"):
        nested = _mapping(report.get(key))
        if nested is not None:
            candidates.append(nested)
    for candidate in candidates:
        classification = _mapping(candidate.get("classification"))
        archive = _mapping(candidate.get("archive"))
        packaging = classification.get("packaging") if classification is not None else None
        archive_format = archive.get("format") if archive is not None else None
        direct_format = candidate.get("format")
        if any(
            isinstance(value, str) and value.casefold() == "pyinstaller carchive"
            for value in (packaging, archive_format, direct_format)
        ):
            return candidate
    return None


def _pyinstaller_candidate(
    *,
    report: Mapping[str, Any],
    source_layer: Mapping[str, Any],
    accepted_child_count: int,
    reported_artifact_count: int,
    source_limit_event_count: int,
) -> dict[str, Any] | None:
    pyinstaller = _pyinstaller_mapping(report)
    if pyinstaller is None:
        return None
    classification = _mapping(pyinstaller.get("classification"))
    archive = _mapping(pyinstaller.get("archive"))
    selection = _mapping(pyinstaller.get("selection"))
    content = _mapping(pyinstaller.get("content_validation"))
    signals = {"pyinstaller_carchive_structure"}
    if classification is not None:
        signals.add("packaging_classification")
    if archive is not None:
        signals.add("bounded_archive_inventory")
        if archive.get("reader") == "bounded_memory_carchive":
            signals.add("bounded_memory_reader")
    if content is not None and content.get("full_content_validation") is True:
        signals.add("full_content_validation")
    counts = _fixed_count_fields(
        (
            archive,
            ("entry_count", "option_count", "toc_record_count", "total_compressed_size", "total_uncompressed_size"),
        ),
        (selection, ("candidate_count", "retained_count", "omitted_entry_count", "non_candidate_count")),
        (content, ("validated_entry_count", "total_entry_count", "discarded_after_validation_count")),
    )
    commitments = []
    inventory_commitment = _safe_commitment(
        archive.get("inventory_commitment") if archive is not None else None,
        "pyinstaller_inventory",
    )
    content_commitment = _safe_commitment(
        content.get("content_commitment") if content is not None else None,
        "pyinstaller_content",
    )
    if inventory_commitment is not None:
        commitments.append(inventory_commitment)
        signals.add("inventory_commitment")
    if content_commitment is not None:
        commitments.append(content_commitment)
        signals.add("content_commitment")
    retained_count = counts.get("retained_count", accepted_child_count)
    candidate_count = counts.get("candidate_count", retained_count)
    unretained_candidate_count = max(candidate_count - retained_count, 0)
    counts["unretained_candidate_count"] = unretained_candidate_count
    if retained_count > 0 and unretained_candidate_count == 0:
        extraction_status = "recovered"
    elif retained_count > 0 or accepted_child_count > 0:
        extraction_status = "selective_recovery"
    elif counts.get("entry_count", counts.get("toc_record_count", 0)) > 0:
        extraction_status = "inventory_only"
    else:
        extraction_status = "not_recovered"
    blockers: set[str] = set()
    full_validation = content.get("full_content_validation") if content is not None else None
    if full_validation is not True:
        blockers.add(
            "pyinstaller_content_validation_incomplete"
            if full_validation is False
            else "pyinstaller_content_validation_not_reported"
        )
    if unretained_candidate_count:
        blockers.add("pyinstaller_priority_entries_not_retained")
    upstream_blockers = pyinstaller.get("blockers")
    selection_blockers = selection.get("blockers") if selection is not None else None
    reported_blocker_count = sum(
        len(value) for value in (upstream_blockers, selection_blockers) if isinstance(value, list)
    )
    if reported_blocker_count:
        counts["reported_blocker_count"] = reported_blocker_count
        blockers.add("pyinstaller_parser_reported_blockers")
    if extraction_status in {"inventory_only", "not_recovered"}:
        blockers.add("pyinstaller_payloads_not_recovered")
    return _make_candidate(
        kind="pyinstaller_carchive",
        source_layer=source_layer,
        confidence="high",
        structural_status="structure_confirmed",
        extraction_status=extraction_status,
        accepted_child_count=accepted_child_count,
        reported_artifact_count=reported_artifact_count,
        source_limit_event_count=source_limit_event_count,
        signals=signals,
        counts=counts,
        blockers=blockers,
        source_commitments=commitments,
    )


def _archive_types(sevenzip: Mapping[str, Any] | None) -> set[str]:
    values = sevenzip.get("archive_types") if sevenzip is not None else None
    if not isinstance(values, list):
        return set()
    return {value.strip().casefold() for value in values[:1024] if isinstance(value, str) and len(value) <= 128}


def _archive_extraction(
    sevenzip: Mapping[str, Any] | None,
) -> tuple[str, dict[str, int], set[str]]:
    counts = _fixed_count_fields(
        (
            sevenzip,
            (
                "total_members",
                "retained_members",
                "declared_total_size",
                "extracted_total_size",
            ),
        )
    )
    inventory = sevenzip.get("inventory") if sevenzip is not None else None
    blocked_inventory_count = 0
    if isinstance(inventory, list):
        for entry in inventory:
            item = _mapping(entry)
            status = _status(item)
            if status is not None and status not in SAFE_ARCHIVE_MEMBER_STATUSES:
                blocked_inventory_count += 1
        counts["published_inventory_count"] = len(inventory)
    if blocked_inventory_count:
        counts["blocked_inventory_count"] = blocked_inventory_count
    blockers: set[str] = set()
    status = _status(sevenzip)
    total_members = counts.get("total_members")
    retained_members = counts.get("retained_members")
    incomplete_retention = (
        total_members is not None and retained_members is not None and retained_members < total_members
    )
    if status in ARCHIVE_COMPLETE_STATUSES and not incomplete_retention and not blocked_inventory_count:
        extraction_status = "recovered"
    elif status in ARCHIVE_COMPLETE_STATUSES | ARCHIVE_SELECTIVE_STATUSES:
        extraction_status = "selective_recovery" if incomplete_retention or blocked_inventory_count else "recovered"
    elif status in ARCHIVE_PARTIAL_STATUSES:
        extraction_status = "recovery_incomplete"
    elif sevenzip is None:
        extraction_status = "not_attempted"
    else:
        extraction_status = "not_recovered"
    if incomplete_retention:
        blockers.add("archive_inventory_not_fully_retained")
    if blocked_inventory_count:
        blockers.add("archive_inventory_contains_blocked_entries")
    if extraction_status == "not_attempted":
        blockers.add("archive_extractor_not_run")
    elif extraction_status in {"not_recovered", "recovery_incomplete"}:
        blockers.add("archive_extraction_incomplete")
    return extraction_status, dict(sorted(counts.items())), blockers


def _inno_extraction(
    inno: Mapping[str, Any] | None,
) -> tuple[str, dict[str, int], set[str]] | None:
    """開始済みinnounpの権威的な状態だけをfail-closedで集約する。"""

    if inno is None or inno.get("external_parser_started") is not True:
        return None

    inventory = _mapping(inno.get("inventory"))
    selection = _mapping(inno.get("selection"))
    script = _mapping(inno.get("install_script"))
    tool = _mapping(inno.get("tool"))
    counts = _fixed_count_fields(
        (
            inventory,
            (
                "member_count",
                "declared_total_size",
                "invalid_member_count",
                "duplicate_member_count",
            ),
        ),
        (
            selection,
            (
                "selected_member_count",
                "selected_declared_size",
                "omitted_member_count",
                "launch_target_match_count",
            ),
        ),
    )
    recovered_members = inno.get("recovered_members")
    if isinstance(recovered_members, list):
        counts["recovered_member_count"] = len(recovered_members)

    status = _status(inno)
    base_valid = (
        inno.get("schema_version") == 1
        and inno.get("candidate") is True
        and inno.get("executed") is False
        and inno.get("sample_executed") is False
        and inno.get("network_contacted") is False
        and inno.get("terminal_promotion_eligible") is False
        and inno.get("archive_unlock_attempted") is False
        and status is not None
        and tool is not None
        and tool.get("configured") is True
        and tool.get("available") is True
    )
    if not base_valid:
        return (
            "recovery_incomplete",
            dict(sorted(counts.items())),
            {"archive_extraction_incomplete", "inno_extraction_report_invalid"},
        )

    trusted_statuses = {
        "artifacts_recovered",
        "bounded_selection_recovered",
        "encrypted_payload_blocked",
    }
    if status not in trusted_statuses:
        return (
            "recovery_incomplete",
            dict(sorted(counts.items())),
            {"archive_extraction_incomplete"},
        )

    tool_digest = tool.get("sha256")
    tool_size = _non_negative_int(tool.get("size"))
    tool_version = tool.get("version")
    member_count = _safe_count(inventory, "member_count")
    declared_total_size = _safe_count(inventory, "declared_total_size")
    invalid_member_count = _safe_count(inventory, "invalid_member_count")
    duplicate_member_count = _safe_count(inventory, "duplicate_member_count")
    selected_member_count = _safe_count(selection, "selected_member_count")
    selected_declared_size = _safe_count(selection, "selected_declared_size")
    omitted_member_count = _safe_count(selection, "omitted_member_count")
    launch_target_match_count = _safe_count(selection, "launch_target_match_count")
    complete_archive = (
        selection.get("complete_archive_extraction")
        if selection is not None
        else None
    )
    limit_reasons = selection.get("limit_reasons") if selection is not None else None
    structural_contract_valid = (
        tool.get("identity_unchanged") is True
        and isinstance(tool_digest, str)
        and SHA256_RE.fullmatch(tool_digest) is not None
        and tool_size is not None
        and tool_size > 0
        and isinstance(tool_version, str)
        and 0 < len(tool_version) <= 128
        and inventory is not None
        and inventory.get("status") == "listed"
        and inventory.get("tool_version") == tool_version
        and inno.get("inventory_complete") is True
        and inventory.get("inventory_complete") is True
        and member_count is not None
        and member_count > 0
        and declared_total_size is not None
        and invalid_member_count == 0
        and duplicate_member_count == 0
        and selection is not None
        and selected_member_count is not None
        and selected_declared_size is not None
        and omitted_member_count is not None
        and launch_target_match_count is not None
        and isinstance(complete_archive, bool)
        and isinstance(limit_reasons, list)
        and all(
            isinstance(reason, str) and reason in INNO_SELECTION_LIMIT_REASONS
            for reason in limit_reasons
        )
        and limit_reasons == sorted(set(limit_reasons))
        and selected_member_count + omitted_member_count == member_count
        and selected_declared_size <= declared_total_size
        and launch_target_match_count <= selected_member_count
        and script is not None
        and script.get("status") == "recovered_and_parsed"
        and script.get("decompiler_provenance_verified") is True
    )
    if not structural_contract_valid:
        return (
            "recovery_incomplete",
            dict(sorted(counts.items())),
            {"archive_extraction_incomplete", "inno_extraction_report_invalid"},
        )

    script_size = _safe_count(script, "size")
    script_digest = script.get("sha256")
    payload_encrypted = script.get("payload_encrypted")
    launch_target_count = _safe_count(script, "launch_target_count")
    dynamic_launch_target_count = _safe_count(script, "dynamic_launch_target_count")
    invalid_launch_target_count = _safe_count(script, "invalid_launch_target_count")
    launch_targets = script.get("launch_targets")
    script_contract_valid = (
        script_size is not None
        and script_size > 0
        and isinstance(script_digest, str)
        and SHA256_RE.fullmatch(script_digest) is not None
        and isinstance(payload_encrypted, bool)
        and launch_target_count is not None
        and dynamic_launch_target_count == 0
        and invalid_launch_target_count == 0
        and isinstance(launch_targets, list)
        and launch_target_count == len(launch_targets)
        and all(
            isinstance(target, str) and 0 < len(target) <= 1024
            for target in launch_targets
        )
        and len({target.casefold() for target in launch_targets})
        == len(launch_targets)
        and launch_target_match_count <= launch_target_count
    )
    if not script_contract_valid:
        return (
            "recovery_incomplete",
            dict(sorted(counts.items())),
            {"archive_extraction_incomplete", "inno_extraction_report_invalid"},
        )

    if status == "encrypted_payload_blocked":
        encrypted_contract_valid = (
            inno.get("extraction_complete") is False
            and payload_encrypted is True
            and script_size <= selected_declared_size
            and (recovered_members is None or recovered_members == [])
            and (
                (
                    complete_archive is False
                    and omitted_member_count > 0
                    and limit_reasons
                    and selected_member_count < member_count
                )
                or (
                    complete_archive is True
                    and omitted_member_count == 0
                    and limit_reasons == []
                    and selected_member_count == member_count
                    and selected_declared_size == declared_total_size
                )
            )
        )
        if encrypted_contract_valid:
            return (
                "recovery_incomplete",
                dict(sorted(counts.items())),
                {"archive_extraction_incomplete", "inno_encrypted_payload_blocked"},
            )
        return (
            "recovery_incomplete",
            dict(sorted(counts.items())),
            {"archive_extraction_incomplete", "inno_extraction_report_invalid"},
        )

    recovered_contract_valid = (
        inno.get("extraction_complete") is True
        and payload_encrypted is False
        and isinstance(recovered_members, list)
        and selected_member_count > 0
        and len(recovered_members) == selected_member_count - 1
    )
    recovered_total_size = script_size
    recovered_names: list[str] = []
    recovered_launch_target_count = 0
    if recovered_contract_valid:
        for member in recovered_members:
            item = _mapping(member)
            if item is None:
                recovered_contract_valid = False
                break
            name = item.get("name")
            size = _safe_count(item, "size")
            digest = item.get("sha256")
            member_format = item.get("format")
            launch_target = item.get("launch_target")
            try:
                encoded_name_size = (
                    len(name.encode("utf-8")) if isinstance(name, str) else None
                )
            except UnicodeEncodeError:
                encoded_name_size = None
            if (
                not isinstance(name, str)
                or not name
                or encoded_name_size is None
                or encoded_name_size > 4096
                or name != name.replace("\\", "/")
                or name.startswith("/")
                or re.match(r"^[A-Za-z]:", name) is not None
                or any(part in {"", ".", ".."} for part in name.split("/"))
                or size is None
                or not isinstance(digest, str)
                or SHA256_RE.fullmatch(digest) is None
                or not isinstance(member_format, str)
                or not member_format
                or len(member_format) > 128
                or not isinstance(launch_target, bool)
            ):
                recovered_contract_valid = False
                break
            recovered_names.append(name)
            recovered_total_size += size
            recovered_launch_target_count += int(launch_target)
    if (
        not recovered_contract_valid
        or len({name.casefold() for name in recovered_names}) != len(recovered_names)
        or recovered_total_size != selected_declared_size
        or recovered_launch_target_count != launch_target_match_count
    ):
        return (
            "recovery_incomplete",
            dict(sorted(counts.items())),
            {"archive_extraction_incomplete", "inno_extraction_report_invalid"},
        )

    if status == "artifacts_recovered":
        complete_contract_valid = (
            complete_archive is True
            and omitted_member_count == 0
            and limit_reasons == []
            and selected_member_count == member_count
            and selected_declared_size == declared_total_size
        )
        if complete_contract_valid:
            return "recovered", dict(sorted(counts.items())), set()
    elif (
        complete_archive is False
        and omitted_member_count > 0
        and limit_reasons
        and selected_member_count < member_count
    ):
        return (
            "selective_recovery",
            dict(sorted(counts.items())),
            {"archive_inventory_not_fully_retained"},
        )
    return (
        "recovery_incomplete",
        dict(sorted(counts.items())),
        {"archive_extraction_incomplete", "inno_extraction_report_invalid"},
    )


def _installer_candidates(
    *,
    report: Mapping[str, Any],
    source_layer: Mapping[str, Any],
    accepted_child_count: int,
    reported_artifact_count: int,
    source_limit_event_count: int,
) -> list[dict[str, Any]]:
    pe = _mapping(report.get("pe"))
    sevenzip = _mapping(report.get("sevenzip"))
    inno = _mapping(report.get("inno"))
    types = _archive_types(sevenzip)
    marker_values = pe.get("packer_markers") if pe is not None else None
    markers = {
        value.casefold()
        for value in (marker_values if isinstance(marker_values, list) else [])
        if isinstance(value, str)
    }
    nsis_type = any("nsis" in value or "nullsoft" in value for value in types)
    inno_type = any("inno" in value for value in types)
    nsis_marker = "nullsoft" in markers
    inno_marker = "inno setup" in markers
    candidates = []
    extraction_status, archive_counts, archive_blockers = _archive_extraction(sevenzip)
    inno_extraction = _inno_extraction(inno)
    if nsis_type or nsis_marker:
        signals = set()
        if nsis_type:
            signals.add("sevenzip_nsis_archive_type")
        if nsis_marker:
            signals.add("nullsoft_pe_marker")
        candidates.append(
            _make_candidate(
                kind="nsis_installer",
                source_layer=source_layer,
                confidence="high" if nsis_type else "medium",
                structural_status="structure_confirmed" if nsis_type else "structure_suspected",
                extraction_status=extraction_status,
                accepted_child_count=accepted_child_count,
                reported_artifact_count=reported_artifact_count,
                source_limit_event_count=source_limit_event_count,
                signals=signals,
                counts=archive_counts,
                blockers=set(archive_blockers),
            )
        )
    if inno_type or inno_marker or inno_extraction is not None:
        signals = set()
        if inno_type:
            signals.add("sevenzip_inno_archive_type")
        if inno_marker:
            signals.add("inno_setup_pe_marker")
        if inno_extraction is not None:
            signals.add("innounp_authoritative_state")
            inno_extraction_status, inno_counts, inno_blockers = inno_extraction
        else:
            inno_extraction_status, inno_counts, inno_blockers = (
                extraction_status,
                archive_counts,
                archive_blockers,
            )
        candidates.append(
            _make_candidate(
                kind="inno_setup_installer",
                source_layer=source_layer,
                confidence=(
                    "high" if inno_type or inno_extraction is not None else "medium"
                ),
                structural_status=(
                    "structure_confirmed"
                    if inno_type or inno_extraction is not None
                    else "structure_suspected"
                ),
                extraction_status=inno_extraction_status,
                accepted_child_count=accepted_child_count,
                reported_artifact_count=reported_artifact_count,
                source_limit_event_count=source_limit_event_count,
                signals=signals,
                counts=inno_counts,
                blockers=set(inno_blockers),
            )
        )
    if (
        not nsis_type
        and not nsis_marker
        and not inno_type
        and not inno_marker
        and pe is not None
        and pe.get("containerized") is True
    ):
        archive_resource_count = _safe_count(pe, "archive_resources_recovered") or 0
        signals = {"pe_self_extracting_container_classification"}
        if archive_resource_count:
            signals.add("embedded_archive_resource")
        generic_counts = dict(archive_counts)
        generic_counts["archive_resource_count"] = archive_resource_count
        candidates.append(
            _make_candidate(
                kind="self_extracting_pe_container",
                source_layer=source_layer,
                confidence="high" if archive_resource_count else "medium",
                structural_status="structure_confirmed" if archive_resource_count else "structure_suspected",
                extraction_status=extraction_status,
                accepted_child_count=accepted_child_count,
                reported_artifact_count=reported_artifact_count,
                source_limit_event_count=source_limit_event_count,
                signals=signals,
                counts=generic_counts,
                blockers=set(archive_blockers),
            )
        )
    return candidates


def _classic_upx_evidence(
    pe: Mapping[str, Any],
    markers: set[str],
) -> tuple[bool, set[str], dict[str, int]]:
    """名前だけを信用せず、古典的UPXの展開先・stub構造を検証する。"""

    raw_sections = pe.get("sections")
    sections = raw_sections if isinstance(raw_sections, list) else []
    named_labels: set[str] = set()
    zero_raw_virtual_count = 0
    high_entropy_count = 0
    entrypoint_high_entropy_count = 0
    entrypoint = pe.get("entrypoint_section")
    safe_entrypoint = entrypoint.casefold() if isinstance(entrypoint, str) else None
    for raw_section in sections:
        section = _mapping(raw_section)
        if section is None:
            continue
        name = section.get("name")
        normalized_name = _classic_upx_section_name(name)
        if normalized_name is not None:
            named_labels.add(normalized_name)
        raw_size = _non_negative_int(section.get("raw_size"))
        virtual_size = _non_negative_int(section.get("virtual_size"))
        section_entropy = _safe_entropy(section.get("entropy"))
        if (
            raw_size == 0
            and virtual_size is not None
            and virtual_size >= MIN_CLASSIC_UPX_SECTION_SIZE
        ):
            zero_raw_virtual_count += 1
        high_entropy = (
            raw_size is not None
            and raw_size >= MIN_CLASSIC_UPX_SECTION_SIZE
            and section_entropy is not None
            and section_entropy >= MIN_CLASSIC_UPX_PACKED_ENTROPY
        )
        if high_entropy:
            high_entropy_count += 1
            if isinstance(name, str) and name.casefold() == safe_entrypoint:
                entrypoint_high_entropy_count += 1

    exact_marker = "upx!" in markers
    label_corroborated = exact_marker or len(named_labels) >= 2
    structure_confirmed = bool(
        label_corroborated
        and zero_raw_virtual_count
        and high_entropy_count
        and entrypoint_high_entropy_count
    )
    signals: set[str] = set()
    if exact_marker:
        signals.add("upx_exact_marker")
    if named_labels:
        signals.add("upx_named_section")
    if len(named_labels) >= 2:
        signals.add("upx_named_section_pair")
    if zero_raw_virtual_count:
        signals.add("upx_zero_raw_virtual_unpack_target")
    if high_entropy_count:
        signals.add("upx_high_entropy_packed_section")
    if entrypoint_high_entropy_count:
        signals.add("upx_entrypoint_in_packed_section")
    counts = {
        "upx_entrypoint_packed_section_count": entrypoint_high_entropy_count,
        "upx_high_entropy_section_count": high_entropy_count,
        "upx_section_count": len(named_labels),
        "upx_zero_raw_virtual_section_count": zero_raw_virtual_count,
    }
    return structure_confirmed, signals, counts


def _upx_and_packed_candidates(
    *,
    report: Mapping[str, Any],
    source_layer: Mapping[str, Any],
    accepted_child_count: int,
    reported_artifact_count: int,
    source_limit_event_count: int,
) -> list[dict[str, Any]]:
    pe = _mapping(report.get("pe"))
    if pe is None:
        return []
    marker_values = pe.get("packer_markers")
    markers = {
        value.casefold()
        for value in (marker_values if isinstance(marker_values, list) else [])
        if isinstance(value, str)
    }
    upx_structure, upx_signals, upx_counts = _classic_upx_evidence(pe, markers)
    upx = _mapping(report.get("upx"))
    upx_status = _status(upx)
    upx_detected = upx_status == "recovered" or upx_structure
    candidates: list[dict[str, Any]] = []
    if upx_detected:
        signals = set(upx_signals)
        if upx_status == "recovered":
            signals.add("trusted_upx_static_recovery")
            extraction_status = "recovered"
            blockers: set[str] = set()
        elif upx is None:
            extraction_status = "not_attempted"
            blockers = {"upx_static_recovery_not_run"}
        else:
            extraction_status = "not_recovered"
            blockers = {"upx_static_recovery_incomplete"}
        candidates.append(
            _make_candidate(
                kind="upx_packed",
                source_layer=source_layer,
                confidence="high",
                structural_status="structure_confirmed",
                extraction_status=extraction_status,
                accepted_child_count=accepted_child_count,
                reported_artifact_count=reported_artifact_count,
                source_limit_event_count=source_limit_event_count,
                signals=signals,
                counts=upx_counts,
                blockers=blockers,
            )
        )
        return candidates
    classification = pe.get("classification")
    packing_suspected = pe.get("packing_suspected") is True
    if (not isinstance(classification, str) or classification not in PACKED_CLASSIFICATIONS) and not packing_suspected:
        return candidates
    exact_markers = markers.intersection(STRONG_PACKER_MARKERS)
    reported_high_entropy = pe.get("high_entropy_sections")
    reported_code_entropy = pe.get("code_entropy_sections")
    independent_packing_evidence = bool(
        exact_markers
        or upx_counts["upx_high_entropy_section_count"]
        or (
            isinstance(reported_high_entropy, list)
            and any(isinstance(value, str) for value in reported_high_entropy)
        )
        or (
            isinstance(reported_code_entropy, list)
            and any(isinstance(value, str) for value in reported_code_entropy)
        )
        or pe.get("virtualized_shape") is True
        or pe.get("encrypted_sideload_host_shape") is True
    )
    if (
        upx_counts["upx_section_count"]
        and classification == "packed_or_protected"
        and not independent_packing_evidence
    ):
        # static_unpackerの旧reportではUPX風section名だけでこの分類に
        # なり得た。独立構造証拠がなければrequired blockerへ昇格しない。
        return candidates
    signals = {"pe_packing_heuristic"}
    if isinstance(classification, str) and classification in PACKED_CLASSIFICATIONS:
        signals.add("pe_packing_classification")
    if exact_markers:
        signals.add("recognized_packer_marker")
    extraction_status = "selective_recovery" if accepted_child_count else "not_recovered"
    blockers = set() if accepted_child_count else {"packed_layer_not_recovered"}
    high_entropy_sections = pe.get("high_entropy_sections")
    code_entropy_sections = pe.get("code_entropy_sections")
    counts = {
        "high_entropy_section_count": (len(high_entropy_sections) if isinstance(high_entropy_sections, list) else 0),
        "code_entropy_section_count": (len(code_entropy_sections) if isinstance(code_entropy_sections, list) else 0),
        "recognized_packer_marker_count": len(exact_markers),
    }
    return [
        _make_candidate(
            kind="packed_or_protected_pe",
            source_layer=source_layer,
            confidence="high" if exact_markers else "medium",
            structural_status="structure_confirmed" if exact_markers else "structure_suspected",
            extraction_status=extraction_status,
            accepted_child_count=accepted_child_count,
            reported_artifact_count=reported_artifact_count,
            source_limit_event_count=source_limit_event_count,
            signals=signals,
            counts=counts,
            blockers=blockers,
        )
    ]


def _dotnet_resource_candidate(
    *,
    report: Mapping[str, Any],
    source_layer: Mapping[str, Any],
    accepted_child_count: int,
    reported_artifact_count: int,
    source_limit_event_count: int,
) -> dict[str, Any] | None:
    pe = _mapping(report.get("pe"))
    resources = _mapping(report.get("dotnet_resources"))
    if pe is None or resources is None or pe.get("is_dotnet") is not True:
        return None
    resource_count = _safe_count(resources, "count")
    inventory = resources.get("inventory")
    inventory_count = len(inventory) if isinstance(inventory, list) else 0
    if not resource_count and not inventory_count:
        return None
    signals = {"dotnet_pe", "manifest_resource_inventory"}
    counts = {"resource_count": resource_count or inventory_count}
    blockers: set[str] = set()
    blocked_count = 0
    non_data_resource_count = 0
    if isinstance(inventory, list):
        counts["published_inventory_count"] = len(inventory)
        for raw_item in inventory:
            item = _mapping(raw_item)
            item_status = _status(item)
            if item_status is not None and item_status != "extracted":
                blocked_count += 1
            item_format = item.get("format") if item is not None else None
            if isinstance(item_format, str) and item_format in SAFE_LAYER_FORMATS and item_format != "data":
                non_data_resource_count += 1
    counts["non_data_resource_count"] = non_data_resource_count
    if blocked_count:
        counts["blocked_resource_count"] = blocked_count
        blockers.add("dotnet_resource_inventory_contains_blocked_entries")
    if accepted_child_count:
        extraction_status = "recovered"
        signals.add("resource_child_layer_recovered")
    elif _status(resources) == "resources_recovered":
        extraction_status = "metadata_recovered"
    else:
        extraction_status = "recovery_incomplete"
        blockers.add("dotnet_resource_recovery_incomplete")
    return _make_candidate(
        kind="dotnet_resource_container",
        source_layer=source_layer,
        confidence="high",
        structural_status="structure_confirmed",
        extraction_status=extraction_status,
        accepted_child_count=accepted_child_count,
        reported_artifact_count=reported_artifact_count,
        source_limit_event_count=source_limit_event_count,
        signals=signals,
        counts=counts,
        blockers=blockers,
    )


def _embedded_pe_fanout_candidate(
    *,
    report: Mapping[str, Any],
    source_layer: Mapping[str, Any],
    accepted_child_count: int,
    reported_artifact_count: int,
    source_limit_event_count: int,
) -> dict[str, Any] | None:
    """byte carveだけの多層PE fanoutを非帰属のroute候補として保持する。"""

    pe = _mapping(report.get("pe"))
    scans = [
        scan
        for scan in (
            _mapping(report.get("embedded_pe_scan")),
            _mapping(pe.get("overlay_embedded_pe_scan")) if pe is not None else None,
        )
        if scan is not None
    ]
    discovered = sum(
        _safe_count(scan, "recovered_candidate_count") or 0 for scan in scans
    )
    if discovered < 4:
        return None
    unique_artifacts = sum(
        _safe_count(scan, "unique_artifact_count") or 0 for scan in scans
    )
    duplicate_digests = sum(
        _safe_count(scan, "duplicate_digest_count") or 0 for scan in scans
    )
    complete_scan_count = sum(_status(scan) == "complete" for scan in scans)
    incomplete_scan_count = len(scans) - complete_scan_count
    signals = {
        "bounded_embedded_pe_extent_validation",
        "multi_child_pe_fanout",
        "byte_carve_without_selection_lineage",
    }
    if pe is not None and _safe_count(pe, "overlay_size"):
        signals.add("pe_overlay_fanout")
    counts = {
        "discovered_candidate_count": discovered,
        "unique_artifact_count": unique_artifacts,
        "duplicate_digest_count": duplicate_digests,
        "complete_scan_count": complete_scan_count,
        "incomplete_scan_count": incomplete_scan_count,
    }
    skipped_opaque = (
        _safe_count(pe, "opaque_resources_skipped_without_local_decoder")
        if pe is not None
        else None
    )
    if skipped_opaque is not None:
        counts["opaque_resources_skipped_without_local_decoder"] = skipped_opaque
    blockers = {"embedded_pe_byte_carve_has_no_launch_or_decoder_lineage"}
    if incomplete_scan_count:
        blockers.add("embedded_pe_fanout_scan_incomplete")
    return _make_candidate(
        kind="embedded_pe_fanout",
        source_layer=source_layer,
        confidence="high",
        structural_status="structure_confirmed",
        extraction_status=(
            "recovered"
            if accepted_child_count and not incomplete_scan_count
            else "selective_recovery"
            if accepted_child_count
            else "inventory_only"
        ),
        accepted_child_count=accepted_child_count,
        reported_artifact_count=reported_artifact_count,
        source_limit_event_count=source_limit_event_count,
        signals=signals,
        counts=counts,
        blockers=blockers,
    )


def _candidate_rank(candidate: Mapping[str, Any]) -> tuple[Any, ...]:
    confidence_rank = {"high": 2, "medium": 1}.get(candidate.get("confidence"), 0)
    extraction = _mapping(candidate.get("extraction")) or {}
    extraction_rank = {
        "recovered": 4,
        "metadata_recovered": 3,
        "selective_recovery": 2,
        "inventory_only": 1,
    }.get(extraction.get("status"), 0)
    evidence = _mapping(candidate.get("evidence")) or {}
    signal_count = _non_negative_int(evidence.get("signal_count")) or 0
    blockers = candidate.get("blockers")
    blocker_count = len(blockers) if isinstance(blockers, list) else 0
    canonical = json.dumps(candidate, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return confidence_rank, extraction_rank, signal_count, -blocker_count, canonical


def _deduplicate(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        candidate_id = candidate["id"]
        previous = selected.get(candidate_id)
        if previous is None or _candidate_rank(candidate) > _candidate_rank(previous):
            selected[candidate_id] = candidate
    return sorted(
        selected.values(),
        key=lambda item: (
            item["source_layer"]["depth"],
            item["source_layer"]["sha256"],
            item["kind"],
            item["id"],
        ),
    )


def build_structural_candidates(
    layer_report: Mapping[str, Any],
    *,
    assessment_only: bool = False,
) -> dict[str, Any]:
    """静的reportからファミリー非依存の構造候補を決定的に生成する。

    出力はraw bytes、名前、path、address、secretを含めず、構造だけでは
    悪性・ファミリー帰属を許可しない。候補は ``static-layers.json`` の
    ``steps`` 外へ格納し、既存の復元失敗走査へ候補statusを混入させない。
    """

    base: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "not_run_assessment_only" if assessment_only else "source_report_unavailable",
        "candidate_count": 0,
        "kind_counts": {},
        "candidates": [],
        "invalid_step_count": 0,
        "maliciousness": "not_determined_from_packaging",
        "family_attribution_allowed": False,
        "executed_sample": False,
        "network_contacted": False,
    }
    if assessment_only:
        return base
    steps = layer_report.get("steps") if isinstance(layer_report, Mapping) else None
    if not isinstance(steps, list):
        return base
    limit_counts = _source_limit_event_counts(layer_report)
    candidates: list[dict[str, Any]] = []
    invalid_step_count = 0
    for raw_step in steps:
        step = _mapping(raw_step)
        source_layer = _safe_layer(step.get("input_layer") if step is not None else None)
        report = _mapping(step.get("report") if step is not None else None)
        if (
            step is None
            or step.get("status") != "succeeded"
            or source_layer is None
            or report is None
            or report.get("sanitization_failed") is True
        ):
            invalid_step_count += 1
            continue
        report_digest = report.get("sha256")
        if isinstance(report_digest, str) and report_digest != source_layer["sha256"]:
            invalid_step_count += 1
            continue
        if _contains_dynamic_evidence(report):
            invalid_step_count += 1
            continue
        accepted_child_count = _accepted_child_count(step)
        reported_artifact_count = _reported_artifact_count(report)
        source_limit_event_count = limit_counts[source_layer["sha256"]]
        pyinstaller = _pyinstaller_candidate(
            report=report,
            source_layer=source_layer,
            accepted_child_count=accepted_child_count,
            reported_artifact_count=reported_artifact_count,
            source_limit_event_count=source_limit_event_count,
        )
        if pyinstaller is not None:
            candidates.append(pyinstaller)
        candidates.extend(
            _installer_candidates(
                report=report,
                source_layer=source_layer,
                accepted_child_count=accepted_child_count,
                reported_artifact_count=reported_artifact_count,
                source_limit_event_count=source_limit_event_count,
            )
        )
        candidates.extend(
            _upx_and_packed_candidates(
                report=report,
                source_layer=source_layer,
                accepted_child_count=accepted_child_count,
                reported_artifact_count=reported_artifact_count,
                source_limit_event_count=source_limit_event_count,
            )
        )
        dotnet = _dotnet_resource_candidate(
            report=report,
            source_layer=source_layer,
            accepted_child_count=accepted_child_count,
            reported_artifact_count=reported_artifact_count,
            source_limit_event_count=source_limit_event_count,
        )
        if dotnet is not None:
            candidates.append(dotnet)
        embedded_fanout = _embedded_pe_fanout_candidate(
            report=report,
            source_layer=source_layer,
            accepted_child_count=accepted_child_count,
            reported_artifact_count=reported_artifact_count,
            source_limit_event_count=source_limit_event_count,
        )
        if embedded_fanout is not None:
            candidates.append(embedded_fanout)
    candidates = _deduplicate(candidates)
    kind_counts = Counter(item["kind"] for item in candidates)
    base.update(
        {
            "status": (
                "candidates_with_invalid_steps"
                if invalid_step_count and candidates
                else "source_report_invalid"
                if invalid_step_count
                else "candidates_with_blockers"
                if any(item["blockers"] for item in candidates)
                else "candidates_recorded"
                if candidates
                else "complete_no_candidates"
            ),
            "candidate_count": len(candidates),
            "kind_counts": dict(sorted(kind_counts.items())),
            "candidates": candidates,
            "invalid_step_count": invalid_step_count,
        }
    )
    return base


def structural_candidate_summary(candidate_report: Mapping[str, Any]) -> dict[str, Any]:
    """report.json向けにartifact、件数、statusだけを返す。"""

    status = candidate_report.get("status")
    count = _non_negative_int(candidate_report.get("candidate_count"))
    return {
        "artifact": "static-layers.json",
        "candidate_count": count or 0,
        "status": (
            status if isinstance(status, str) and status in SAFE_AGGREGATION_STATUSES else "source_report_unavailable"
        ),
    }
