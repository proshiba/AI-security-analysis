#!/usr/bin/env python3
"""自動解析cycleのprivate成果物を、完了済みの単一caseへ分離する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import uuid
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

import archive_analysis_datastore as archive
import stage_case_analysis_datastore as base
import terminal_payload_acquisition

SCHEMA_VERSION = "analysis-datastore-cycle-case-staging/v1"
SUMMARY_SCHEMA_VERSION = "analysis-datastore-cycle-case-summary/v1"
FOLLOW_ON_SCHEMA_VERSION = "analysis-datastore-cycle-case-follow-on/v1"
TERMINAL_SCHEMA_VERSION = "analysis-datastore-cycle-case-terminal/v1"
SOURCE_SIDECAR_SCHEMA_VERSION = "analysis-datastore-cycle-case-source-sidecars/v1"
MAX_FOLLOW_ON_EDGES = 128
MAX_FOLLOW_ON_PAYLOAD_SIZE = 128 * 1024 * 1024
MAX_FOLLOW_ON_TOTAL_BYTES = 256 * 1024 * 1024
COMPLETE_EDGE_STATUSES = frozenset({"child_complete", "shared_sha256_reused_complete"})
ALLOWED_SOURCE_SIDECARS = frozenset({"exclusion-set.json", "family-hints.json", "manifest.json"})
REQUIRED_RUN_FILES = frozenset(
    {
        "follow-on-analysis.json",
        "summary.json",
        "terminal-payload-acquisition.json",
    }
)
REJECTED_STATUS_PARTS = (
    "abort",
    "error",
    "fail",
    "incomplete",
    "partial",
    "pending",
    "timeout",
)


class CycleCaseStagingError(RuntimeError):
    """cycle caseを安全なarchive入力へ分離できない場合の例外。"""


def _fail(message: str) -> None:
    raise CycleCaseStagingError(message)


def _sha256(value: Any, *, label: str) -> str:
    try:
        return base._validate_sha256(value, label=label)
    except base.CaseStagingError as exc:
        raise CycleCaseStagingError(str(exc)) from exc


def _read_json(path: Path, *, label: str) -> tuple[dict[str, Any], str]:
    try:
        return base._read_json(path, label=label)
    except base.CaseStagingError as exc:
        raise CycleCaseStagingError(str(exc)) from exc


def _validate_directory(path: Path, *, label: str) -> Path:
    try:
        return base._validate_existing_directory(path, label=label)
    except base.CaseStagingError as exc:
        raise CycleCaseStagingError(str(exc)) from exc


def _status_rejected(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    lowered = value.casefold()
    return any(part in lowered for part in REJECTED_STATUS_PARTS)


def _require_false(document: Mapping[str, Any], field: str, *, label: str) -> None:
    if document.get(field) is not False:
        _fail(f"{label}.{field}はfalseである必要があります")


def _list_root_entries(root: Path, *, label: str) -> dict[str, os.stat_result]:
    entries: dict[str, os.stat_result] = {}
    try:
        with os.scandir(root) as iterator:
            raw_entries = list(iterator)
    except OSError as exc:
        raise CycleCaseStagingError(f"{label}を列挙できません") from exc
    if len(raw_entries) > base.MAX_CASES + 32:
        _fail(f"{label}のentry件数が上限を超えました")
    for entry in raw_entries:
        if entry.name.casefold() in entries:
            _fail(f"{label}に大小文字非依存の重複entryがあります")
        path = Path(entry.path)
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise CycleCaseStagingError(f"{label} entryを確認できません") from exc
        if entry.is_symlink() or base._is_reparse(metadata):
            _fail(f"{label}にreparse pointは使用できません")
        entries[entry.name.casefold()] = metadata
    return entries


def _validate_source_root(
    source_root: Path,
) -> tuple[dict[str, Any], str, dict[str, Path], dict[str, Path]]:
    manifest_path = source_root / "manifest.json"
    manifest, manifest_sha256 = _read_json(
        manifest_path,
        label="MalwareBazaar source manifest",
    )
    selected_raw = manifest.get("selected_hashes")
    items_raw = manifest.get("items")
    metadata_raw = manifest.get("selected_metadata")
    if (
        manifest.get("schema_version") != 1
        or manifest.get("complete") is not True
        or manifest.get("archives_remain_encrypted") is not True
        or manifest.get("samples_executed") is not False
        or not isinstance(selected_raw, list)
        or not isinstance(items_raw, list)
        or not isinstance(metadata_raw, list)
        or not 1 <= len(selected_raw) <= base.MAX_CASES
        or len(items_raw) != len(selected_raw)
        or len(metadata_raw) != len(selected_raw)
    ):
        _fail("MalwareBazaar source manifestが完全・非実行契約を満たしません")
    selected = [_sha256(value, label="selected_hashes item") for value in selected_raw]
    if len(set(selected)) != len(selected):
        _fail("selected_hashesに重複があります")
    selected_set = set(selected)
    item_map: dict[str, Mapping[str, Any]] = {}
    metadata_set: set[str] = set()
    for raw in items_raw:
        if not isinstance(raw, Mapping):
            _fail("source manifest itemがobjectではありません")
        digest = _sha256(raw.get("sha256"), label="source manifest item.sha256")
        if digest in item_map:
            _fail("source manifest itemに重複があります")
        item_map[digest] = raw
    for raw in metadata_raw:
        if not isinstance(raw, Mapping):
            _fail("selected_metadata itemがobjectではありません")
        digest = _sha256(
            raw.get("sha256_hash"),
            label="selected_metadata.sha256_hash",
        )
        if digest in metadata_set:
            _fail("selected_metadataに重複があります")
        metadata_set.add(digest)
    if set(item_map) != selected_set or metadata_set != selected_set:
        _fail("source manifestのcase集合が一致しません")

    entries = _list_root_entries(source_root, label="source root")
    source_cases: dict[str, Path] = {}
    sidecars: dict[str, Path] = {}
    for name, metadata in entries.items():
        if name in ALLOWED_SOURCE_SIDECARS:
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                _fail("source sidecarは独立した通常fileである必要があります")
            sidecars[name] = (source_root / name).resolve(strict=True)
            if name != "manifest.json":
                _read_json(source_root / name, label=f"source sidecar {name}")
            continue
        if base.SHA256_RE.fullmatch(name) is None or not stat.S_ISDIR(metadata.st_mode):
            _fail("source rootに未束縛entryがあります")
        source_cases[name] = (source_root / name).resolve(strict=True)
    if set(source_cases) != selected_set:
        _fail("source directoryとselected_hashesのcase集合が一致しません")

    for digest, directory in source_cases.items():
        expected = directory / f"{digest}.zip"
        try:
            files = base._walk_files(directory, role="source")
        except base.CaseStagingError as exc:
            raise CycleCaseStagingError(str(exc)) from exc
        if len(files) != 1 or files[0][1].as_posix() != expected.name:
            _fail("source case directoryに未束縛entryがあります")
        try:
            archive_sha256, archive_size, _identity = archive._hash_source_snapshot(expected)
        except archive.DatastoreError as exc:
            raise CycleCaseStagingError("source archiveを安全に照合できません") from exc
        item = item_map[digest]
        metadata = item.get("metadata")
        if (
            item.get("zip_sha256") != archive_sha256
            or item.get("zip_size") != archive_size
            or not isinstance(metadata, Mapping)
            or metadata.get("sha256_hash") != digest
        ):
            _fail("source archiveとmanifestのsize／SHA-256が一致しません")
    return (
        manifest,
        manifest_sha256,
        dict(sorted(source_cases.items())),
        dict(sorted(sidecars.items())),
    )


def _summary_entry_map(
    values: Any,
    *,
    label: str,
) -> dict[str, Mapping[str, Any]]:
    if not isinstance(values, list):
        _fail(f"{label}はlistである必要があります")
    result: dict[str, Mapping[str, Any]] = {}
    for raw in values:
        if not isinstance(raw, Mapping):
            _fail(f"{label} itemがobjectではありません")
        digest = _sha256(raw.get("sha256"), label=f"{label}.sha256")
        if digest in result:
            _fail(f"{label}に重複があります")
        result[digest] = raw
    return result


def _validate_case_complete(directory: Path, *, digest: str) -> dict[str, Any]:
    try:
        base._validate_one_shot_report_identity(directory, digest=digest)
    except base.CaseStagingError as exc:
        raise CycleCaseStagingError(str(exc)) from exc
    report, _report_sha256 = _read_json(
        directory / "report.json",
        label="case report",
    )
    state = report.get("case_state")
    if (
        not isinstance(state, Mapping)
        or state.get("status") != "complete"
        or state.get("complete") is not True
        or state.get("blockers") not in ([], None)
    ):
        _fail("partialまたは未完了のcaseはstagingできません")
    _require_false(report, "executed_sample", label="case report")
    _require_false(report, "network_contacted", label="case report")
    if report.get("ai_used") not in (False, None):
        _fail("AI利用済みcaseはcycle自動解析stagingへ含められません")
    return report


def _normalize_edge(raw: Mapping[str, Any]) -> dict[str, Any]:
    parent = _sha256(raw.get("parent_sha256"), label="follow-on edge parent")
    child = _sha256(raw.get("child_sha256"), label="follow-on edge child")
    relative_value = raw.get("path")
    if not isinstance(relative_value, str) or not relative_value:
        _fail("follow-on edge pathが不正です")
    relative = PurePosixPath(relative_value)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or ":" in relative_value
        or "\\" in relative_value
    ):
        _fail("follow-on edge pathが安全な相対pathではありません")
    size = raw.get("size")
    depth = raw.get("depth")
    if (
        type(size) is not int
        or not 0 <= size <= MAX_FOLLOW_ON_PAYLOAD_SIZE
        or type(depth) is not int
        or not 1 <= depth <= 5
    ):
        _fail("follow-on edgeのsizeまたはdepthが不正です")
    status = raw.get("status")
    if status not in COMPLETE_EDGE_STATUSES:
        _fail("未完了のfollow-on edgeはstagingできません")
    for field in ("kind", "role"):
        value = raw.get(field)
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 128
            or any(ord(character) < 32 for character in value)
        ):
            _fail(f"follow-on edgeの{field}が不正です")
    return {
        "child_sha256": child,
        "depth": depth,
        "kind": raw.get("kind"),
        "parent_sha256": parent,
        "path": relative.as_posix(),
        "role": raw.get("role"),
        "size": size,
        "status": status,
    }


def _reachable_by_root(
    roots: set[str],
    edges: Sequence[Mapping[str, Any]],
) -> dict[str, set[str]]:
    children: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        children[str(edge["parent_sha256"])].append(str(edge["child_sha256"]))
    colors: dict[str, int] = {}

    def visit(node: str) -> None:
        state = colors.get(node, 0)
        if state == 1:
            _fail("follow-on edgeにcycleがあります")
        if state == 2:
            return
        colors[node] = 1
        for child in children.get(node, []):
            visit(child)
        colors[node] = 2

    for node in sorted({*roots, *children}):
        visit(node)

    reachable: dict[str, set[str]] = {}
    owners: dict[str, set[str]] = defaultdict(set)
    for root in sorted(roots):
        observed = {root}
        queue = deque([root])
        while queue:
            parent = queue.popleft()
            for child in children.get(parent, []):
                if child in observed:
                    continue
                observed.add(child)
                queue.append(child)
        descendants = observed - {root}
        reachable[root] = descendants
        for child in descendants:
            owners[child].add(root)
    if any(len(values) != 1 for values in owners.values()):
        _fail("複数rootが共有するderived caseは単一case stagingへ混在できません")
    return reachable


def _validate_edge_payload(
    *,
    run_root: Path,
    edge: Mapping[str, Any],
) -> Path:
    """edgeを親case内の通常fileへ束縛し、sizeとSHA-256を再照合する。"""

    parent = str(edge["parent_sha256"])
    parent_root = (run_root / "cases" / parent).resolve(strict=True)
    relative = PurePosixPath(str(edge["path"]))
    candidate = parent_root.joinpath(*relative.parts)
    current = archive._extended_length_path(parent_root)
    try:
        for index, part in enumerate(relative.parts):
            current /= part
            metadata = current.lstat()
            if current.is_symlink() or base._is_reparse(metadata):
                _fail("follow-on edge payload pathにreparse pointは使用できません")
            if index < len(relative.parts) - 1 and not stat.S_ISDIR(metadata.st_mode):
                _fail("follow-on edge payloadの中間pathがdirectoryではありません")
    except OSError as exc:
        raise CycleCaseStagingError("follow-on edge payloadを親caseへ安全に束縛できません") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or current.is_symlink()
        or base._is_reparse(metadata)
    ):
        _fail("follow-on edge payloadは親case内の独立した通常fileである必要があります")
    try:
        digest, size, _identity = archive._hash_source_snapshot(candidate)
    except archive.DatastoreError as exc:
        raise CycleCaseStagingError("follow-on edge payloadを単一handleで照合できません") from exc
    if digest != edge["child_sha256"] or size != edge["size"]:
        _fail("follow-on edge payloadのsizeまたはSHA-256が一致しません")
    return candidate


def _validate_run_root(
    run_root: Path,
    *,
    selected: set[str],
) -> dict[str, Any]:
    entries = _list_root_entries(run_root, label="cycle run root")
    expected_names = {"cases", *REQUIRED_RUN_FILES}
    if set(entries) != expected_names:
        _fail("cycle run rootにABORTED markerまたは未束縛entryがあります")
    if not stat.S_ISDIR(entries["cases"].st_mode):
        _fail("cycle run casesはdirectoryである必要があります")
    for name in REQUIRED_RUN_FILES:
        metadata = entries[name]
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            _fail("cycle runの共通成果物は独立した通常fileである必要があります")

    summary, summary_sha256 = _read_json(
        run_root / "summary.json",
        label="cycle summary",
    )
    follow_on, follow_on_sha256 = _read_json(
        run_root / "follow-on-analysis.json",
        label="cycle follow-on analysis",
    )
    terminal, terminal_sha256 = _read_json(
        run_root / "terminal-payload-acquisition.json",
        label="cycle terminal acquisition",
    )
    for label, document in (
        ("cycle summary", summary),
        ("cycle follow-on analysis", follow_on),
        ("cycle terminal acquisition", terminal),
    ):
        _require_false(document, "executed_sample", label=label)
        _require_false(document, "network_contacted", label=label)
        if document.get("ai_used") not in (False, None):
            _fail(f"{label}.ai_usedはfalseまたは未設定である必要があります")
        if _status_rejected(document.get("status")):
            _fail(f"{label}がpartial、ABORTEDまたは失敗状態です")
    if follow_on.get("status") not in {"complete", "no_retained_payloads"}:
        _fail("cycle follow-on analysisが完了状態ではありません")
    if terminal.get("status") not in {"verified", "not_recovered"}:
        _fail("cycle terminal acquisitionが完了状態ではありません")

    cases = _summary_entry_map(summary.get("cases"), label="summary.cases")
    derived = _summary_entry_map(
        summary.get("derived_cases", []),
        label="summary.derived_cases",
    )
    if set(cases) != selected:
        _fail("sourceとcycle summaryのroot case集合が一致しません")
    for digest, entry in cases.items():
        if entry.get("case_state") != "complete" or _status_rejected(entry.get("automation_state")):
            _fail("cycle summaryにpartialまたは未完了root caseがあります")
        report_value = entry.get("report")
        expected_report = f"cases/{digest}/report.json"
        if report_value != expected_report:
            _fail("cycle summaryのreport相対pathがcaseへ束縛されていません")
    for digest, entry in derived.items():
        if (
            entry.get("case_state") != "complete"
            or entry.get("report") != f"cases/{digest}/report.json"
            or _status_rejected(entry.get("automation_state"))
            or entry.get("ai_used") not in (False, None)
        ):
            _fail("cycle summaryにpartialまたは未完了derived caseがあります")

    counts = summary.get("counts")
    if not isinstance(counts, Mapping):
        _fail("cycle summary countsがobjectではありません")
    if (
        counts.get("input_files") != len(selected)
        or counts.get("analyzed") != len(selected)
        or counts.get("complete") != len(selected)
        or counts.get("partial") != 0
        or counts.get("failed") != 0
        or counts.get("errors") != 0
    ):
        _fail("cycle summaryが全root case完了契約を満たしません")

    raw_edges = follow_on.get("edges")
    if not isinstance(raw_edges, list) or len(raw_edges) > MAX_FOLLOW_ON_EDGES:
        _fail("follow-on edgesがlistではありません")
    edges = [_normalize_edge(raw) for raw in raw_edges if isinstance(raw, Mapping)]
    if len(edges) != len(raw_edges):
        _fail("follow-on edge itemがobjectではありません")
    edge_identities = {
        (
            edge["parent_sha256"],
            edge["child_sha256"],
            edge["path"],
            edge["role"],
            edge["kind"],
            edge["size"],
            edge["status"],
        )
        for edge in edges
    }
    if len(edge_identities) != len(edges):
        _fail("follow-on edgeに重複があります")
    derived_set = set(derived)
    edge_children = {str(edge["child_sha256"]) for edge in edges}
    if edge_children != derived_set:
        _fail("follow-on edgeとderived case集合が一致しません")
    allowed = selected | derived_set
    if any(str(edge["parent_sha256"]) not in allowed or str(edge["child_sha256"]) not in derived_set for edge in edges):
        _fail("follow-on edgeが検証済みcase集合の外を参照しています")
    if follow_on.get("errors") not in ([], None):
        _fail("follow-on analysisにerrorがあります")
    if follow_on.get("omitted_metadata") not in ([], None) or follow_on.get("omitted_metadata_commitments") not in (
        [],
        None,
    ):
        _fail("follow-on analysisに省略またはcommitmentがあります")
    reachable = _reachable_by_root(selected, edges)
    observed_descendants = set().union(*reachable.values()) if reachable else set()
    if observed_descendants != derived_set:
        _fail("rootから到達できないderived caseがあります")

    root_states = {digest: "complete" for digest in selected}
    try:
        expected_terminal = terminal_payload_acquisition.build_terminal_payload_acquisition(
            follow_on,
            root_case_states=root_states,
        )
    except terminal_payload_acquisition.TerminalPayloadAcquisitionError as exc:
        raise CycleCaseStagingError("follow-on graphを既存の終端payload契約で検証できません") from exc
    if terminal != expected_terminal:
        _fail("terminal acquisitionがfollow-on graphの決定的生成結果と一致しません")

    follow_on_reference = summary.get("follow_on_analysis")
    terminal_reference = summary.get("terminal_payload_acquisition")
    if not isinstance(follow_on_reference, Mapping) or (
        follow_on_reference.get("artifact") != "follow-on-analysis.json"
        or follow_on_reference.get("sha256") != follow_on_sha256
        or follow_on_reference.get("status") != follow_on.get("status")
        or follow_on_reference.get("node_count") != len(follow_on.get("nodes") or [])
        or follow_on_reference.get("edge_count") != len(edges)
        or follow_on_reference.get("error_count") != 0
    ):
        _fail("cycle summaryのfollow-on参照が実体と一致しません")
    if not isinstance(terminal_reference, Mapping) or (
        terminal_reference.get("artifact") != "terminal-payload-acquisition.json"
        or terminal_reference.get("sha256") != terminal_sha256
        or terminal_reference.get("status") != terminal.get("status")
        or terminal_reference.get("frontier_count") != len(terminal.get("frontier") or [])
        or terminal_reference.get("selected_count") != len(terminal.get("selected_sha256") or [])
        or terminal_reference.get("pending_count") != len(terminal.get("pending_sha256") or [])
    ):
        _fail("cycle summaryのterminal payload参照が実体と一致しません")

    case_directories = base._case_directories(
        _validate_directory(run_root / "cases", label="cycle run cases root"),
        label="cycle run cases root",
    )
    if set(case_directories) != allowed:
        _fail("cycle run cases directoryに未束縛caseがあります")
    for digest, directory in case_directories.items():
        _validate_case_complete(directory, digest=digest)

    edge_payloads: list[dict[str, Any]] = []
    unique_payloads: dict[str, int] = {}
    for edge in edges:
        payload = _validate_edge_payload(run_root=run_root, edge=edge)
        payload_key = base._source_commitment_key(payload)
        observed_size = int(edge["size"])
        prior_size = unique_payloads.setdefault(payload_key, observed_size)
        if prior_size != observed_size:
            _fail("同一follow-on payload pathのsizeが一致しません")
        edge_payloads.append({"edge": edge, "path": payload})
    if sum(unique_payloads.values()) > MAX_FOLLOW_ON_TOTAL_BYTES:
        _fail("follow-on payloadの合計sizeが上限を超えました")

    if terminal.get("pending_sha256") not in ([], None) or terminal.get("omitted_sha256") not in ([], None):
        _fail("terminal acquisitionにpendingまたはomitted payloadがあります")
    if terminal.get("blockers") not in ([], None):
        _fail("terminal acquisitionにblockerがあります")

    return {
        "case_directories": case_directories,
        "cases": cases,
        "derived": derived,
        "edges": edges,
        "edge_payloads": edge_payloads,
        "follow_on": follow_on,
        "follow_on_sha256": follow_on_sha256,
        "reachable": reachable,
        "summary": summary,
        "summary_sha256": summary_sha256,
        "terminal": terminal,
        "terminal_sha256": terminal_sha256,
    }


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _case_summary_projection(
    run: Mapping[str, Any],
    *,
    collection_id: str,
    digest: str,
) -> dict[str, Any]:
    descendants = sorted(run["reachable"][digest])
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "source_schema_version": run["summary"].get("schema_version"),
        "source_summary_sha256": run["summary_sha256"],
        "collection_id": collection_id,
        "case_sha256": digest,
        "case": dict(run["cases"][digest]),
        "derived_cases": [
            {
                "sha256": child,
                "source_entry_sha256": _canonical_sha256(run["derived"][child]),
            }
            for child in descendants
        ],
        "safety": {
            "different_root_cases_included": False,
            "sample_executed": False,
            "network_contacted": False,
            "ai_used": False,
        },
    }


def _case_follow_on_projection(
    run: Mapping[str, Any],
    *,
    collection_id: str,
    digest: str,
) -> dict[str, Any]:
    reachable = {digest, *run["reachable"][digest]}
    edges = [edge for edge in run["edges"] if edge["parent_sha256"] in reachable and edge["child_sha256"] in reachable]
    return {
        "schema_version": FOLLOW_ON_SCHEMA_VERSION,
        "source_schema_version": run["follow_on"].get("schema_version"),
        "source_follow_on_sha256": run["follow_on_sha256"],
        "collection_id": collection_id,
        "case_sha256": digest,
        "descendant_sha256": sorted(reachable - {digest}),
        "edges": edges,
        "safety": {
            "different_root_cases_included": False,
            "sample_executed": False,
            "network_contacted": False,
            "ai_used": False,
        },
    }


def _case_terminal_projection(
    run: Mapping[str, Any],
    *,
    collection_id: str,
    digest: str,
) -> dict[str, Any]:
    reachable = {digest, *run["reachable"][digest]}
    frontier: list[dict[str, Any]] = []
    for raw in run["terminal"].get("frontier", []):
        if not isinstance(raw, Mapping):
            _fail("terminal frontier itemがobjectではありません")
        sha = _sha256(raw.get("sha256"), label="terminal frontier sha256")
        parents = raw.get("parent_sha256")
        if not isinstance(parents, list):
            _fail("terminal frontier parent_sha256がlistではありません")
        normalized_parents = [_sha256(value, label="terminal frontier parent") for value in parents]
        if sha in reachable or any(parent in reachable for parent in normalized_parents):
            sanitized = {
                key: value
                for key, value in raw.items()
                if key
                in {
                    "case_state",
                    "depth",
                    "disposition",
                    "edge_statuses",
                    "kinds",
                    "node_state",
                    "reason",
                    "roles",
                    "sha256",
                    "size",
                }
            }
            sanitized["parent_sha256"] = normalized_parents
            frontier.append(sanitized)
    return {
        "schema_version": TERMINAL_SCHEMA_VERSION,
        "source_schema_version": run["terminal"].get("schema_version"),
        "source_terminal_sha256": run["terminal_sha256"],
        "collection_id": collection_id,
        "case_sha256": digest,
        "status": run["terminal"].get("status"),
        "method": run["terminal"].get("method"),
        "frontier": frontier,
        "selected_sha256": sorted(set(run["terminal"].get("selected_sha256", [])) & reachable),
        "pending_sha256": [],
        "omitted_sha256": [],
        "blockers": [],
        "safety": {
            "different_root_cases_included": False,
            "sample_executed": False,
            "network_contacted": False,
        },
    }


def _source_sidecar_projection(
    *,
    collection_id: str,
    digest: str,
    sidecars: Mapping[str, Path],
    commitments: Mapping[str, base.SourceCommitment],
) -> dict[str, Any]:
    """source共通sidecarをraw copyせず、file単位commitmentだけへ縮約する。"""

    projected: list[dict[str, Any]] = []
    for name, path in sorted(sidecars.items()):
        if name == "manifest.json":
            continue
        try:
            commitment = commitments[base._source_commitment_key(path)]
        except KeyError as exc:
            raise CycleCaseStagingError("source sidecarがpreflight commitmentへ含まれていません") from exc
        projected.append(
            {
                "name": name,
                "size": commitment.size,
                "sha256": commitment.sha256,
                "raw_content_included": False,
            }
        )
    return {
        "schema_version": SOURCE_SIDECAR_SCHEMA_VERSION,
        "collection_id": collection_id,
        "case_sha256": digest,
        "source_sidecars": projected,
        "safety": {
            "raw_sidecars_included": False,
            "different_root_cases_included": False,
            "sample_executed": False,
            "network_contacted": False,
        },
    }


def stage_cycle_case(
    *,
    repository: Path,
    collection_id: str,
    source_root: Path,
    run_root: Path,
    output_root: Path,
    case_sha256: str,
) -> dict[str, Any]:
    """完了済みcycleから1件だけを物理copyし、archive helperへ引き渡す。"""

    digest = _sha256(case_sha256, label="case SHA-256")
    if base.COLLECTION_RE.fullmatch(collection_id) is None:
        _fail("collection IDは小文字英数字で開始し、小文字英数字・._-だけを許可します")
    repository = _validate_directory(repository, label="repository")
    source_root = _validate_directory(source_root, label="source root")
    run_root = _validate_directory(run_root, label="cycle run root")
    inputs = (source_root, run_root)
    if any(base._is_within(item, repository) for item in inputs):
        _fail("private artifact入力をrepository内から取得できません")
    if base._is_within(source_root, run_root) or base._is_within(run_root, source_root):
        _fail("private artifact入力rootは相互に分離してください")
    try:
        output_root = base._prepare_output_root(
            output_root,
            repository=repository,
            inputs=inputs,
        )
    except base.CaseStagingError as exc:
        raise CycleCaseStagingError(str(exc)) from exc

    (
        source_manifest,
        source_manifest_sha256,
        source_cases,
        source_sidecars,
    ) = _validate_source_root(source_root)
    if digest not in source_cases:
        _fail("指定caseが検証済みsource集合にありません")
    run = _validate_run_root(run_root, selected=set(source_cases))
    source_directory = source_cases[digest]
    analysis_directory = run["case_directories"][digest]
    reachable = {digest, *run["reachable"][digest]}
    edge_copy_plan: dict[str, Path] = {}
    for record in run["edge_payloads"]:
        edge = record["edge"]
        if edge["parent_sha256"] not in reachable or edge["child_sha256"] not in reachable:
            continue
        destination = f"recovered-payloads/{edge['parent_sha256']}/{edge['path']}"
        prior = edge_copy_plan.setdefault(destination, record["path"])
        if prior != record["path"]:
            _fail("follow-on payloadのstaging相対pathが衝突しています")

    input_files: dict[str, tuple[Path, str]] = {}
    for root, role, destination in (
        (source_directory, "source", f"source/{digest}"),
        (analysis_directory, "cycle_analysis", f"cycle-analysis/{digest}"),
    ):
        try:
            files = base._walk_files(root, role=role)
        except base.CaseStagingError as exc:
            raise CycleCaseStagingError(str(exc)) from exc
        for path, relative in files:
            key = base._source_commitment_key(path)
            input_files[key] = (
                path,
                f"{destination}/{relative.as_posix()}",
            )
    for name in REQUIRED_RUN_FILES:
        path = run_root / name
        input_files[base._source_commitment_key(path)] = (
            path,
            f"derived/source-{name}",
        )
    manifest_path = source_root / "manifest.json"
    input_files[base._source_commitment_key(manifest_path)] = (
        manifest_path,
        "derived/source-manifest.json",
    )
    for name, path in source_sidecars.items():
        input_files.setdefault(
            base._source_commitment_key(path),
            (path, f"derived/source-sidecar-{name}"),
        )
    for destination, path in edge_copy_plan.items():
        input_files.setdefault(
            base._source_commitment_key(path),
            (path, destination),
        )
    try:
        commitments = {
            key: base._snapshot_source_commitment(path, relative=relative)
            for key, (path, relative) in sorted(input_files.items())
        }
    except base.CaseStagingError as exc:
        raise CycleCaseStagingError(str(exc)) from exc
    required = (
        sum(item.size for item in commitments.values())
        + sum(commitments[base._source_commitment_key(path)].size for path in edge_copy_plan.values())
        + 1024 * 1024
    )
    try:
        free = shutil.disk_usage(output_root).free
    except OSError as exc:
        raise CycleCaseStagingError("cycle case staging filesystemの空き容量を確認できません") from exc
    if free < required + base.MINIMUM_FREE_RESERVE_BYTES:
        _fail("cycle case stagingに必要な空き容量と安全余白がありません")

    target = base._datastore_target(collection_id, digest)
    final = output_root / target
    if os.path.lexists(final):
        _fail(f"既存cycle case stagingを上書きしません: {target}")
    temporary: Path | None = output_root / f".{digest[:12]}.{uuid.uuid4().hex[:12]}.staging"
    try:
        temporary.mkdir()
    except OSError as exc:
        raise CycleCaseStagingError("cycle case一時stagingを排他作成できません") from exc
    copied: list[base.CopiedFile] = []
    try:
        try:
            copied.extend(
                base._copy_tree(
                    source_directory,
                    temporary / "source" / digest,
                    staging_root=temporary,
                    role="source",
                    commitments=commitments,
                )
            )
            copied.extend(
                base._copy_tree(
                    analysis_directory,
                    temporary / "cycle-analysis" / digest,
                    staging_root=temporary,
                    role="cycle_analysis",
                    commitments=commitments,
                )
            )
            for destination, path in sorted(edge_copy_plan.items()):
                copied.append(
                    base._copy_file(
                        path,
                        temporary.joinpath(*PurePosixPath(destination).parts),
                        staging_root=temporary,
                        role="recovered_payload",
                        commitments=commitments,
                    )
                )
            for path, label in (
                (manifest_path, "source manifest"),
                (run_root / "summary.json", "cycle summary"),
                (run_root / "follow-on-analysis.json", "cycle follow-on"),
                (
                    run_root / "terminal-payload-acquisition.json",
                    "cycle terminal acquisition",
                ),
            ):
                base._assert_source_commitment(
                    path,
                    commitments=commitments,
                    role=label,
                )
            for name, path in source_sidecars.items():
                base._assert_source_commitment(
                    path,
                    commitments=commitments,
                    role=f"source sidecar {name}",
                )
        except base.CaseStagingError as exc:
            raise CycleCaseStagingError(str(exc)) from exc

        source_acquisition = base._source_case_document_from_manifest(
            source_manifest=source_manifest,
            source_manifest_sha256=source_manifest_sha256,
            collection_id=collection_id,
            case_sha256=digest,
        )
        source_acquisition["archive"]["path"] = f"source/{digest}/{digest}.zip"
        generated = (
            (
                "source-acquisition.case.json",
                source_acquisition,
                "derived_acquisition_manifest",
            ),
            (
                "source-sidecars.case.json",
                _source_sidecar_projection(
                    collection_id=collection_id,
                    digest=digest,
                    sidecars=source_sidecars,
                    commitments=commitments,
                ),
                "derived_source_sidecar_manifest",
            ),
            (
                "run-summary.case.json",
                _case_summary_projection(
                    run,
                    collection_id=collection_id,
                    digest=digest,
                ),
                "derived_cycle_summary",
            ),
            (
                "follow-on.case.json",
                _case_follow_on_projection(
                    run,
                    collection_id=collection_id,
                    digest=digest,
                ),
                "derived_follow_on_manifest",
            ),
            (
                "terminal-payload.case.json",
                _case_terminal_projection(
                    run,
                    collection_id=collection_id,
                    digest=digest,
                ),
                "derived_terminal_manifest",
            ),
        )
        for name, document, role in generated:
            try:
                copied.append(
                    base._write_generated_json(
                        temporary / "derived" / name,
                        document,
                        staging_root=temporary,
                        role=role,
                    )
                )
            except base.CaseStagingError as exc:
                raise CycleCaseStagingError(str(exc)) from exc

        records = sorted(
            (base._inventory_record(item) for item in copied),
            key=lambda item: str(item["path"]).casefold(),
        )
        roles: dict[str, dict[str, int]] = {}
        for item in records:
            role = str(item["role"])
            summary = roles.setdefault(role, {"file_count": 0, "total_size": 0})
            summary["file_count"] += 1
            summary["total_size"] += int(item["size"])
        staging_manifest = {
            "schema_version": SCHEMA_VERSION,
            "target": target,
            "collection_id": collection_id,
            "case_sha256": digest,
            "file_count_excluding_this_manifest": len(records),
            "total_size_excluding_this_manifest": sum(int(item["size"]) for item in records),
            "file_inventory_sha256": base._inventory_sha256(records),
            "files": records,
            "roles": dict(sorted(roles.items())),
            "archive_handoff": {
                "tool": "analysis-framework/common/archive_analysis_datastore.py",
                "target": target,
                "source": "<this-cycle-case-staging-directory>",
                "receipt_must_remain_outside_repository": True,
                "datastore_upload_json_created": False,
            },
            "safety": {
                "physical_copy_only": True,
                "hardlinks_allowed": False,
                "symlinks_or_junctions_allowed": False,
                "host_secret_name_scan_complete": True,
                "host_secret_content_scan_complete": True,
                "different_root_cases_included": False,
                "partial_or_aborted_input_included": False,
                "sample_executed": False,
                "network_contacted": False,
                "source_deleted": False,
            },
        }
        try:
            manifest_file = base._write_generated_json(
                temporary / "_cycle_case_staging_manifest.json",
                staging_manifest,
                staging_root=temporary,
                role="cycle_case_staging_manifest",
            )
            copied.append(manifest_file)
            base._scan_staged_case_references(temporary, case_sha256=digest)
            archive_files = archive.collect_source_files([temporary])
        except (base.CaseStagingError, archive.DatastoreError) as exc:
            raise CycleCaseStagingError("cycle case stagingを既存archive helperへ安全に渡せません") from exc
        if len(archive_files) != len(copied):
            _fail("cycle case staging inventoryとarchive inventoryが一致しません")
        os.replace(temporary, final)
        temporary = None
        try:
            final_files, source_tree_sha256, total_size = base._verify_promoted_staging(
                final,
                copied,
                case_sha256=digest,
            )
        except base.CaseStagingError as exc:
            raise CycleCaseStagingError(str(exc)) from exc
    except BaseException:
        if temporary is not None:
            try:
                base._remove_new_staging(temporary, output_root=output_root)
            except base.CaseStagingError:
                pass
        raise

    staged = {
        "case_sha256": digest,
        "target": target,
        "source_path": os.fspath(final),
        "file_count": len(final_files),
        "total_size": total_size,
        "source_tree_sha256": source_tree_sha256,
        "staging_manifest_sha256": manifest_file.sha256,
        "archive_arguments": ["--target", target, "--source", os.fspath(final)],
        "sample_executed": False,
        "network_contacted": False,
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "collection_id": collection_id,
        "case_count": 1,
        "projected_staging_bytes": required,
        "observed_free_bytes_before_staging": free,
        "preflight_secret_content_scanned_files": len(commitments),
        "cases": [staged],
        "safety": {
            "case_separated": True,
            "physical_copy_only": True,
            "partial_or_aborted_input_rejected": True,
            "preflight_secret_name_and_content_scan_complete": True,
            "sample_executed": False,
            "network_contacted": False,
            "s3_upload_performed": False,
            "receipt_created": False,
            "source_deleted": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    """cycle case staging CLIを構築する。"""

    parser = argparse.ArgumentParser(
        description=("完了済み自動解析cycleから単一caseを物理copyし、暗号化archive入力へ分離します。")
    )
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--case-sha256", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point。staging以外のupload・削除・検体実行は行わない。"""

    arguments = build_parser().parse_args(argv)
    try:
        result = stage_cycle_case(
            repository=arguments.repository,
            collection_id=arguments.collection_id,
            source_root=arguments.source_root,
            run_root=arguments.run_root,
            output_root=arguments.output_root,
            case_sha256=arguments.case_sha256,
        )
    except (CycleCaseStagingError, base.CaseStagingError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
