#!/usr/bin/env python3
"""公開collectionから未完了静的解析の決定的なfollow-up計画を生成する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

import analysis_contract
import c2_analysis_contract
import remediation_registry

SCHEMA_VERSION = 1
MAX_CASES = 256
MAX_SOURCE_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_SOURCE_DISCOVERY_ENTRIES = 10_000
MAX_SOURCE_DISCOVERY_DEPTH = 8
MAX_PLAN_BYTES = 8 * 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COLLECTION_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
FAMILY_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
COMPLETE_TERMINAL_STATUSES = {
    "recovered",
    "no_additional_payload_verified",
    "terminal_managed_client_and_config_recovered",
}
FOLLOWUP_ACTION_ORDER = {
    "resume_workflow": 5,
    "repair_generic_triage": 10,
    "reanalyze_static_pipeline": 10,
    "expand_static_layer_budget": 20,
    "repair_static_layer_pipeline": 20,
    "recover_terminal_payload_statically": 30,
    "terminal_payload_static_recovery": 30,
    "continue_terminal_static_recovery": 30,
    "strengthen_family_resolution": 40,
    "family_attribution_review": 40,
    "implement_family_handler": 45,
    "strengthen_family_handler_evidence": 45,
    "recover_configuration_statically": 50,
    "configuration_and_c2_static_recovery": 50,
    "recover_network_configuration_statically": 55,
    "confirm_c2_protocol_statically": 60,
    "offline_protocol_evidence_review": 60,
    "perform_representative_function_static_review": 70,
    "representative_function_static_review": 70,
    "repair_publication": 80,
    "complete_case_or_enable_reviewed_partial_staging": 80,
}


class FollowupPlanError(RuntimeError):
    """安全に計画を構築できない場合の公開可能な例外。"""


def _io_path(path: Path) -> Path:
    """Windowsでは長path対応prefixを付け、公開値には使用しない。"""

    value = os.path.abspath(os.fspath(path))
    if os.name != "nt" or value.startswith("\\\\?\\"):
        return Path(value)
    if value.startswith("\\\\"):
        return Path(f"\\\\?\\UNC\\{value.lstrip(chr(92))}")
    return Path(f"\\\\?\\{value}")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256_value(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _digest(value: Any, *, locator: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise FollowupPlanError(f"SHA-256が不正です: {locator}")
    return value


def _safe_relative(value: Any, *, locator: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise FollowupPlanError(f"repository相対pathが不正です: {locator}")
    if "\\" in value or "\x00" in value or value.startswith(("/", "//")):
        raise FollowupPlanError(f"repository相対pathが不正です: {locator}")
    parts = value.split("/")
    if any(
        not part
        or part in {".", ".."}
        or ":" in part
        or part.endswith((" ", "."))
        or any(ord(character) < 32 for character in part)
        for part in parts
    ):
        raise FollowupPlanError(f"repository相対pathが不正です: {locator}")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or parsed.parts != tuple(parts):
        raise FollowupPlanError(f"repository相対pathが正規化されていません: {locator}")
    return parsed.as_posix()


def _regular_file(path: Path, *, maximum_bytes: int) -> None:
    io_path = _io_path(path)
    try:
        information = io_path.lstat()
    except OSError as exc:
        raise FollowupPlanError(f"必要fileを安全に確認できません: {path.name}") from exc
    if (
        stat.S_ISLNK(information.st_mode)
        or bool(getattr(information, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        or not stat.S_ISREG(information.st_mode)
        or information.st_nlink != 1
        or information.st_size > maximum_bytes
    ):
        raise FollowupPlanError(f"通常fileの安全境界を満たしません: {path.name}")


def _is_reparse(path: Path, information: os.stat_result) -> bool:
    del path
    return stat.S_ISLNK(information.st_mode) or bool(
        getattr(information, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _index_source_archives(
    input_root: Path,
    digests: Iterable[str],
) -> dict[str, tuple[str, Path | None]]:
    """linkを辿らない単一走査で対象archiveの一意性を索引化する。"""

    requested = set(digests)
    matches: defaultdict[str, list[Path]] = defaultdict(list)
    pending = [(input_root, 0)]
    observed = 0
    while pending:
        directory, depth = pending.pop()
        try:
            with os.scandir(_io_path(directory)) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name.casefold())
        except OSError as exc:
            raise FollowupPlanError("input rootを安全に列挙できません") from exc
        for entry in entries:
            observed += 1
            if observed > MAX_SOURCE_DISCOVERY_ENTRIES:
                raise FollowupPlanError("input rootの探索件数が上限を超えました")
            path = Path(entry.path)
            try:
                information = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise FollowupPlanError("input root entryを安全に確認できません") from exc
            if _is_reparse(path, information):
                raise FollowupPlanError("input rootにreparse pointがあります")
            if stat.S_ISDIR(information.st_mode):
                if depth >= MAX_SOURCE_DISCOVERY_DEPTH:
                    raise FollowupPlanError("input rootの探索深度が上限を超えました")
                pending.append((path, depth + 1))
                continue
            if not stat.S_ISREG(information.st_mode):
                raise FollowupPlanError("input rootに通常file／directory以外があります")
            name = entry.name.casefold()
            if name.endswith(".zip") and name[:-4] in requested:
                matches[name[:-4]].append(path)
    result: dict[str, tuple[str, Path | None]] = {}
    for digest in sorted(requested):
        candidates = matches.get(digest, [])
        if not candidates:
            result[digest] = ("absent", None)
        elif len(candidates) == 1:
            result[digest] = ("candidate", candidates[0])
        else:
            result[digest] = ("duplicate", None)
    return result


def _snapshot_sha256(path: Path, *, maximum_bytes: int) -> tuple[str, int]:
    """単一handleをchunk読取し、読取前後のidentity・size・mtimeを固定する。"""

    _regular_file(path, maximum_bytes=maximum_bytes)
    try:
        io_path = _io_path(path)
        before_path = io_path.lstat()
        digest = hashlib.sha256()
        with io_path.open("rb") as handle:
            before_handle = os.fstat(handle.fileno())
            total = 0
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_bytes:
                    raise FollowupPlanError("source archiveがsize上限を超えました")
                digest.update(chunk)
            after_handle = os.fstat(handle.fileno())
        after_path = io_path.lstat()
    except OSError as exc:
        raise FollowupPlanError("source archiveを安全にhash化できません") from exc
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        total != before_handle.st_size
        or any(getattr(before_handle, key) != getattr(after_handle, key) for key in stable_fields)
        or any(getattr(before_path, key) != getattr(after_path, key) for key in stable_fields)
    ):
        raise FollowupPlanError("source archiveが読取中に変更されました")
    return digest.hexdigest(), total


def _load_object(path: Path) -> dict[str, Any]:
    try:
        return analysis_contract.load_json_object_strict(path)
    except (OSError, TypeError, ValueError) as exc:
        raise FollowupPlanError(f"JSONを安全に読めません: {path.name}") from exc


def _resolve_repository_file(repository: Path, relative: str) -> Path:
    normalized = _safe_relative(relative, locator="case_path")
    lexical = repository.joinpath(*normalized.split("/"))
    analysis_contract.ensure_no_reparse_components(lexical)
    try:
        resolved = lexical.resolve(strict=True)
        resolved.relative_to(repository)
    except (OSError, ValueError) as exc:
        raise FollowupPlanError("case pathがrepository境界外または不在です") from exc
    if not resolved.is_dir():
        raise FollowupPlanError("case pathがdirectoryではありません")
    return resolved


def _phase_map(c2: Mapping[str, Any]) -> tuple[dict[str, Mapping[str, Any]], bool]:
    """boundedなphase索引と、planner固有の構造妥当性を返す。"""

    values = c2.get("phase_evidence")
    if not isinstance(values, list) or len(values) > 64:
        return {}, False
    result: dict[str, Mapping[str, Any]] = {}
    valid = True
    for item in values:
        if not isinstance(item, Mapping) or not isinstance(item.get("phase"), str):
            valid = False
            continue
        phase = item["phase"]
        if phase in result:
            valid = False
            continue
        result[phase] = item
    return result, valid


def _invalid_c2_validation(c2: Mapping[str, Any]) -> dict[str, Any]:
    """validatorへ安全に渡せないC2文書をcase単位のmanual判定へ変換する。"""

    c2_result = c2.get("c2")
    outcome = c2_result.get("outcome") if isinstance(c2_result, Mapping) else None
    if outcome not in {"confirmed", "no_c2_capability_verified", "unresolved"}:
        outcome = "invalid"
    return {
        "complete": False,
        "daily_ready": False,
        "deferred": False,
        "outcome": outcome,
        "finding_count": 1,
        "daily_blocking_finding_count": 1,
    }


def _validate_c2_contract(
    c2: Mapping[str, Any],
    digest: str,
    repository: Path,
) -> dict[str, Any]:
    """反復上限を先に確認し、正式validatorの例外もmanualへ閉じる。"""

    phases = c2.get("phase_evidence")
    if not isinstance(phases, list) or len(phases) > 64:
        return _invalid_c2_validation(c2)
    try:
        return c2_analysis_contract.validate_contract(
            c2,
            digest,
            repository=repository,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return _invalid_c2_validation(c2)


def _blocked(phases: Mapping[str, Mapping[str, Any]], phase: str) -> bool:
    item = phases.get(phase)
    return isinstance(item, Mapping) and item.get("status") == "blocked"


def _derive_blockers(
    report: Mapping[str, Any],
    c2: Mapping[str, Any],
    publication: Mapping[str, Any],
    c2_validation: Mapping[str, Any],
) -> list[str]:
    state = report.get("case_state")
    if not isinstance(state, Mapping):
        raise FollowupPlanError("report.case_stateがありません")
    raw = state.get("blockers")
    if not isinstance(raw, list) or len(raw) > 128 or any(not isinstance(item, str) for item in raw):
        raise FollowupPlanError("report.case_state.blockersが不正です")
    blockers = {item for item in raw if item}
    phases, phases_valid = _phase_map(c2)
    if not phases_valid:
        blockers.add("c2_contract_invalid")
    terminal = c2.get("terminal_payload")
    if not isinstance(terminal, Mapping):
        terminal = {}
        blockers.add("c2_contract_invalid")
    terminal_complete = terminal.get("reached") is True and terminal.get("status") in COMPLETE_TERMINAL_STATUSES
    if not terminal_complete:
        blockers.add("terminal_payload_not_recovered")

    terminal_family = str(terminal.get("family") or "").strip().casefold()
    attribution = publication.get("family_attribution")
    attribution_status = (
        str(attribution.get("status") or "").casefold()
        if isinstance(attribution, Mapping)
        else str(publication.get("family_attribution_status") or "").casefold()
    )
    if terminal_family in {"", "unknown", "unclassified"} or attribution_status in {
        "",
        "unresolved",
        "provider_reported_not_statically_confirmed",
    }:
        blockers.add("terminal_family_unresolved")
    if _blocked(phases, "embedded_layer_recovery") and terminal_complete:
        blockers.add("static_layer_incomplete")
    if _blocked(phases, "family_config_extraction"):
        blockers.add("static_c2_config_unresolved")
    if _blocked(phases, "c2_endpoint_extraction"):
        blockers.add("final_c2_endpoint_unresolved")
    if _blocked(phases, "c2_protocol_analysis"):
        blockers.add("c2_protocol_confirmation_pending")

    # deferred unresolvedは日次成果物として妥当でも、検体解析の完了ではない。
    # 正式C2契約が未完ならreport/publicationの状態にかかわらずfollow-upへ残す。
    if c2_validation.get("complete") is not True:
        blockers.add("c2_analysis_unresolved")
    if c2_validation.get("daily_ready") is not True:
        blockers.add("c2_contract_invalid")

    if state.get("status") != "complete" or publication.get("publication_stage") != "complete":
        blockers.add("publication_incomplete")
    return sorted(blockers)


def _source_status(
    input_root: Path | None,
    digest: str,
    acquisition: Mapping[str, Any],
    *,
    archive_index: Mapping[str, tuple[str, Path | None]] | None,
) -> dict[str, Any]:
    if input_root is None:
        return {"status": "not_checked", "verified": False}
    if archive_index is None:
        raise FollowupPlanError("source archive indexがありません")
    state, candidate = archive_index.get(digest, ("absent", None))
    if state == "duplicate":
        return {"status": "unsafe_or_invalid", "verified": False}
    if state != "candidate" or candidate is None:
        return {"status": "absent", "verified": False}
    try:
        expected_size = acquisition.get("zip_size")
        expected_sha256 = acquisition.get("zip_sha256")
        if type(expected_size) is not int or expected_size <= 0:
            raise FollowupPlanError("manifest.zip_sizeが不正です")
        expected_sha256 = _digest(expected_sha256, locator="manifest.zip_sha256")
        observed, observed_size = _snapshot_sha256(
            candidate,
            maximum_bytes=MAX_SOURCE_ARCHIVE_BYTES,
        )
        if observed_size != expected_size:
            return {"status": "size_mismatch", "verified": False}
        if observed != expected_sha256:
            return {"status": "sha256_mismatch", "verified": False}
        return {
            "status": "verified",
            "verified": True,
            "archive_sha256": observed,
            "archive_size": observed_size,
        }
    except (OSError, FollowupPlanError, ValueError):
        return {"status": "unsafe_or_invalid", "verified": False}


def _actions(blockers: Iterable[str]) -> tuple[list[dict[str, Any]], list[str]]:
    by_action: dict[str, dict[str, Any]] = {}
    unknown: list[str] = []
    for blocker in sorted(set(blockers)):
        policy = remediation_registry.planner_policy_for_blocker(blocker)
        if policy is None:
            unknown.append(blocker)
            continue
        record = by_action.setdefault(
            policy.action_id,
            {
                "action_id": policy.action_id,
                "target_phase": policy.target_phase,
                "same_workflow_retryable": policy.retryable,
                "dispatch_mode": (
                    "resume_current_workflow"
                    if policy.retryable
                    else "start_successor_static_workflow_after_evidence_change"
                ),
                "requires_changed_evidence": not policy.retryable,
                "changed_evidence": sorted(set(policy.changed_evidence)),
                "reason_codes": [],
                "policy_priority": policy.priority,
            },
        )
        record["reason_codes"].append(blocker)
        record["reason_codes"] = sorted(set(record["reason_codes"]))
        record["changed_evidence"] = sorted(set(record["changed_evidence"]) | set(policy.changed_evidence))
        record["policy_priority"] = min(record["policy_priority"], policy.priority)
    values = sorted(
        by_action.values(),
        key=lambda item: (
            FOLLOWUP_ACTION_ORDER.get(item["action_id"], 65),
            item["policy_priority"],
            item["action_id"],
        ),
    )
    for index, item in enumerate(values, start=1):
        item["sequence"] = index
    return values, unknown


def _validate_manifest_sets(
    manifest: Mapping[str, Any], publication: Mapping[str, Any]
) -> tuple[list[str], dict[str, Mapping[str, Any]], dict[str, Mapping[str, Any]]]:
    cases = manifest.get("cases")
    acquisition = manifest.get("acquisition_items")
    published = publication.get("cases")
    if (
        not isinstance(cases, list)
        or not isinstance(acquisition, list)
        or not isinstance(published, list)
        or not 1 <= len(cases) <= MAX_CASES
        or len(cases) != len(acquisition)
        or len(cases) != len(published)
    ):
        raise FollowupPlanError("collectionのcase集合または件数が不正です")
    manifest_hashes = []
    for index, item in enumerate(cases):
        case_id = item.get("case_id") if isinstance(item, Mapping) else None
        digest = case_id.removeprefix("sha256:") if isinstance(case_id, str) else None
        manifest_hashes.append(_digest(digest, locator=f"cases[{index}]"))
    if manifest_hashes != sorted(set(manifest_hashes)):
        raise FollowupPlanError("manifest.casesはSHA-256昇順の一意集合ではありません")

    acquisition_by_hash: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(acquisition):
        if not isinstance(item, Mapping):
            raise FollowupPlanError("acquisition_itemsに不正な要素があります")
        digest = _digest(item.get("sha256"), locator=f"acquisition_items[{index}]")
        if digest in acquisition_by_hash:
            raise FollowupPlanError("acquisition_itemsが重複しています")
        acquisition_by_hash[digest] = item

    publication_by_hash: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(published):
        if not isinstance(item, Mapping):
            raise FollowupPlanError("publication-summary casesに不正な要素があります")
        digest = _digest(item.get("sha256"), locator=f"publication cases[{index}]")
        if digest in publication_by_hash:
            raise FollowupPlanError("publication-summary casesが重複しています")
        publication_by_hash[digest] = item
    expected = set(manifest_hashes)
    if set(acquisition_by_hash) != expected or set(publication_by_hash) != expected:
        raise FollowupPlanError("manifest・acquisition・publicationのcase集合が一致しません")
    return manifest_hashes, acquisition_by_hash, publication_by_hash


def build_plan(
    repository: Path,
    collection: Path,
    *,
    input_root: Path | None = None,
    selected_sha256: Iterable[str] = (),
) -> dict[str, Any]:
    """検体を実行せず、collection成果物だけから静的follow-up計画を構築する。"""

    try:
        root = repository.resolve(strict=True)
        collection_root = collection.resolve(strict=True)
        collection_relative = collection_root.relative_to(root).as_posix()
    except (OSError, ValueError) as exc:
        raise FollowupPlanError("collectionがrepository配下の実directoryではありません") from exc
    analysis_contract.ensure_no_reparse_components(root)
    analysis_contract.ensure_no_reparse_components(collection_root)
    if not root.is_dir() or not collection_root.is_dir():
        raise FollowupPlanError("repositoryまたはcollectionがdirectoryではありません")

    effective_input: Path | None = None
    if input_root is not None:
        try:
            effective_input = input_root.resolve(strict=True)
            effective_input.relative_to(root)
        except ValueError:
            pass
        except OSError as exc:
            raise FollowupPlanError("input rootを安全に解決できません") from exc
        else:
            raise FollowupPlanError("input rootはrepository外に分離してください")
        analysis_contract.ensure_no_reparse_components(effective_input)
        if not effective_input.is_dir():
            raise FollowupPlanError("input rootがdirectoryではありません")

    manifest = _load_object(collection_root / "manifest.json")
    publication = _load_object(collection_root / "publication-summary.json")
    collection_id = manifest.get("collection_id")
    if (
        not isinstance(collection_id, str)
        or COLLECTION_ID_RE.fullmatch(collection_id) is None
        or collection_id != collection_root.name
    ):
        raise FollowupPlanError("manifest.collection_idがdirectory名と一致しません")
    hashes, acquisition_by_hash, publication_by_hash = _validate_manifest_sets(manifest, publication)
    requested = sorted({_digest(value, locator="--sha256") for value in selected_sha256})
    unknown_requested = sorted(set(requested) - set(hashes))
    if unknown_requested:
        raise FollowupPlanError("指定SHA-256がcollectionに存在しません")
    selected = requested or hashes

    planned_cases: list[dict[str, Any]] = []
    skipped_complete = 0
    source_index: dict[str, tuple[str, Path | None]] | None = None
    for digest in selected:
        published = publication_by_hash[digest]
        family = published.get("family")
        if not isinstance(family, str) or FAMILY_ID_RE.fullmatch(family) is None:
            raise FollowupPlanError("publication family IDが不正です")
        case_relative = _safe_relative(published.get("case_path"), locator=digest)
        case_root = _resolve_repository_file(root, case_relative)
        if case_root.name != digest:
            raise FollowupPlanError("case directory名がSHA-256と一致しません")
        report = _load_object(case_root / "report.json")
        c2 = _load_object(case_root / "c2-analysis.json")
        sample = report.get("sample")
        if (
            not isinstance(sample, Mapping)
            or sample.get("sha256") != digest
            or c2.get("sha256") != digest
            or report.get("executed_sample") is not False
            or report.get("network_contacted") is not False
        ):
            raise FollowupPlanError("caseのidentityまたは安全flagが不正です")
        # sealの無いlegacy reportを自動計画へ通すと、case成果物の差替えを検出
        # できない。存在時だけ検証する互換経路は設けず、常に完全検証する。
        if not isinstance(report.get("artifact_sha256"), Mapping):
            raise FollowupPlanError("caseのartifact sealがありません")
        integrity_errors = analysis_contract.case_integrity_errors(
            case_root,
            report,
            expected_digest=digest,
            require_resumable=False,
        )
        if integrity_errors:
            raise FollowupPlanError("caseのsealまたは成果物hash整合性が不正です")
        c2_validation = _validate_c2_contract(c2, digest, root)
        blockers = _derive_blockers(report, c2, published, c2_validation)
        actions, unknown_blockers = _actions(blockers)
        if not blockers:
            skipped_complete += 1
            continue
        if effective_input is not None and source_index is None:
            source_index = _index_source_archives(effective_input, selected)
        source = _source_status(
            effective_input,
            digest,
            acquisition_by_hash[digest],
            archive_index=source_index,
        )
        c2_contract_invalid = c2_validation.get("daily_ready") is not True or "c2_contract_invalid" in blockers
        c2_daily_ready = not c2_contract_invalid
        source_verified = source.get("verified") is True
        same_workflow_retryable = any(action.get("same_workflow_retryable") is True for action in actions)
        if unknown_blockers or c2_contract_invalid:
            decision = "manual_review_required"
        elif not source_verified:
            decision = "source_verification_required"
        elif not same_workflow_retryable:
            # 登録済みactionがすべて新しい証拠を要求する場合、取得元archiveを
            # 再確認できただけでは証拠が変化したことにならない。同じworkflowを
            # 自動再実行せず、successorへ渡す証拠fingerprintの更新を待つ。
            decision = "changed_evidence_required"
        else:
            decision = "followup_required"
        automatic_dispatch_allowed = (
            decision == "followup_required"
            and source_verified
            and same_workflow_retryable
            and not unknown_blockers
            and not c2_contract_invalid
        )
        planned_cases.append(
            {
                "sha256": digest,
                "family": family,
                "family_attribution_status": str(published.get("family_attribution_status") or "unresolved"),
                "case_path": case_relative,
                "case_state": str((report.get("case_state") or {}).get("status") or "invalid"),
                "deep_analysis_status": str(
                    (
                        c2.get("deep_analysis", {}).get("status")
                        if isinstance(c2.get("deep_analysis"), Mapping)
                        else "missing"
                    )
                    or "missing"
                ),
                "source": source,
                "decision": decision,
                "automatic_dispatch_allowed": automatic_dispatch_allowed,
                "c2_contract": {
                    "complete": c2_validation.get("complete") is True and c2_daily_ready,
                    "daily_ready": c2_daily_ready,
                    "deferred": c2_validation.get("deferred") is True and c2_daily_ready,
                    "outcome": str(c2_validation.get("outcome") or "invalid"),
                    "finding_count": int(c2_validation.get("finding_count") or 0),
                    "daily_blocking_finding_count": int(c2_validation.get("daily_blocking_finding_count") or 0),
                },
                "blocker_codes": blockers,
                "unknown_blocker_codes": unknown_blockers,
                "minimum_next_action": actions[0]["action_id"] if actions else "manual_review_required",
                "actions": actions,
            }
        )

    counts = Counter(item["decision"] for item in planned_cases)
    source_counts = Counter(item["source"]["status"] for item in planned_cases)
    plan = {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_id,
        "collection_path": collection_relative,
        "selection": {
            "mode": "explicit_sha256" if requested else "all_collection_cases",
            "requested_case_count": len(selected),
            "planned_case_count": len(planned_cases),
            "skipped_complete_count": skipped_complete,
        },
        "summary": {
            "decision_counts": dict(sorted(counts.items())),
            "source_status_counts": dict(sorted(source_counts.items())),
        },
        "execution_policy": {
            "sample_execution_allowed": False,
            "cpu_emulation_allowed": False,
            "network_contact_allowed": False,
            "automatic_scope": "bounded_static_analysis_only",
            "success_condition": (
                "終端artifact、family、config、C2/protocolを静的根拠で閉じ、case整合性検証後に再公開する"
            ),
        },
        "cases": planned_cases,
    }
    plan["plan_sha256"] = _sha256_value(plan)
    return plan


def render_markdown(plan: Mapping[str, Any]) -> str:
    """機械可読計画を簡潔な日本語の確認表へ描画する。"""

    selection = plan["selection"]
    lines = [
        "# 未完了静的解析follow-up計画",
        "",
        "## 概要",
        "",
        f"- collection: `{plan['collection_id']}`",
        f"- 対象: `{selection['requested_case_count']}`件",
        f"- follow-up必要: `{selection['planned_case_count']}`件",
        f"- 完了として除外: `{selection['skipped_complete_count']}`件",
        f"- 計画SHA-256: `{plan['plan_sha256']}`",
        "- 検体実行: `false`",
        "- CPU emulation: `false`",
        "- 外部接続: `false`",
        "",
        "## ケース別の最小手順",
        "",
        "| SHA-256 | 現在の分類 | source | decision | 最初の静的手順 | blocker数 |",
        "|---|---|---|---|---|---:|",
    ]
    for case in plan["cases"]:
        lines.append(
            f"| `{case['sha256']}` | `{case['family']}` | "
            f"`{case['source']['status']}` | `{case['decision']}` | "
            f"`{case['minimum_next_action']}` | "
            f"{len(case['blocker_codes'])} |"
        )
    lines.extend(
        [
            "",
            (
                "順序付きの全action、必要な更新証拠、機械可読blockerは"
                "[STATIC-FOLLOWUP-PLAN.json](STATIC-FOLLOWUP-PLAN.json)を参照してください。"
            ),
            "未登録blockerが1つでもあるケースは自動実行せず`manual_review_required`で停止します。",
            "登録済みactionがすべて新しい証拠を要求する場合も、同じworkflowを再実行せず`changed_evidence_required`で停止します。",
            "",
        ]
    )
    return "\n".join(lines)


def _atomic_write(path: Path, content: bytes) -> None:
    """reparse・競合差替えを拒否し、同一directory内からatomic replaceする。"""

    analysis_contract.ensure_no_reparse_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    previous: tuple[int, int, int, int, int] | None = None
    try:
        information = path.lstat()
    except FileNotFoundError:
        pass
    else:
        if _is_reparse(path, information) or not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
            raise FollowupPlanError("計画出力先が通常fileではありません")
        previous = tuple(getattr(information, field) for field in fields)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            current = path.lstat()
        except FileNotFoundError:
            if previous is not None:
                raise FollowupPlanError("計画出力先が書込み前に変更されました")
        else:
            identity = tuple(getattr(current, field) for field in fields)
            if (
                previous is None
                or identity != previous
                or _is_reparse(path, current)
                or not stat.S_ISREG(current.st_mode)
                or current.st_nlink != 1
            ):
                raise FollowupPlanError("計画出力先が書込み前に変更されました")
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def _read_existing_output(path: Path) -> bytes | None:
    """既存計画を単一handleへ固定し、上限内で競合なく読む。"""

    try:
        information = path.lstat()
    except FileNotFoundError:
        return None
    if (
        _is_reparse(path, information)
        or not stat.S_ISREG(information.st_mode)
        or information.st_nlink != 1
        or information.st_size > MAX_PLAN_BYTES
    ):
        raise FollowupPlanError("既存計画が通常fileの安全境界を満たしません")
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    try:
        with path.open("rb") as handle:
            before = os.fstat(handle.fileno())
            content = handle.read(MAX_PLAN_BYTES + 1)
            after = os.fstat(handle.fileno())
        final = path.lstat()
    except OSError as exc:
        raise FollowupPlanError("既存計画を安全に読めません") from exc
    if (
        len(content) > MAX_PLAN_BYTES
        or len(content) != before.st_size
        or any(getattr(before, field) != getattr(after, field) for field in fields)
        or any(getattr(information, field) != getattr(final, field) for field in fields)
    ):
        raise FollowupPlanError("既存計画が読取中に変更されました")
    return content


def sync_plan(
    repository: Path,
    collection: Path,
    *,
    input_root: Path | None = None,
    selected_sha256: Iterable[str] = (),
    write: bool = False,
) -> dict[str, Any]:
    """期待するJSON/Markdownとの差分を返し、指定時だけ原子的に更新する。"""

    plan = build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=selected_sha256,
    )
    outputs = {
        "STATIC-FOLLOWUP-PLAN.json": json.dumps(
            plan, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False
        ).encode("utf-8")
        + b"\n",
        "STATIC-FOLLOWUP-PLAN.md": render_markdown(plan).encode("utf-8"),
    }
    mismatches = []
    for name, expected in outputs.items():
        path = collection / name
        current = _read_existing_output(path)
        if current == expected:
            continue
        mismatches.append(name)
        if write:
            _atomic_write(path, expected)
            if _read_existing_output(path) != expected:
                raise FollowupPlanError("計画出力の書込み後検証に失敗しました")
    return {
        "collection_id": plan["collection_id"],
        "plan_sha256": plan["plan_sha256"],
        "planned_case_count": plan["selection"]["planned_case_count"],
        "mismatches": mismatches,
        "write_performed": bool(write and mismatches),
    }


def build_parser() -> argparse.ArgumentParser:
    """collection再解析計画CLIの引数parserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument(
        "--input-root",
        type=Path,
        help="repository外の<sha256>.zip配置root。存在・size・archive SHA-256だけを検証します",
    )
    parser.add_argument("--sha256", action="append", default=[], help="対象を指定SHA-256へ限定します")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="計画JSON/Markdownをcollectionへ書きます")
    mode.add_argument("--check", action="store_true", help="既存計画が不一致なら終了コード1にします")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数から計画を生成し、check時は差分を終了codeへ反映する。"""

    args = build_parser().parse_args(argv)
    result = sync_plan(
        args.repository.resolve(),
        args.collection.resolve(),
        input_root=args.input_root,
        selected_sha256=args.sha256,
        write=args.write,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if args.check and result["mismatches"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
