#!/usr/bin/env python3
"""case成果物からcollection公開集計を決定的に再投影する。

公開済みの ``report.json``、``c2-analysis.json``、``static-logic.json`` だけを読み、
``publication-summary.json`` と ``manifest.json`` の派生fieldを同期する。検体、private
成果物、外部networkには触れない。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
from collections import Counter
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path, PurePosixPath
from typing import Any

from analysis_contract import (
    MAX_JSON_OBJECT_SIZE,
    RESUMABLE_CASE_STATES,
    case_integrity_errors,
    ensure_no_reparse_components,
    load_json_object_strict,
)
from c2_analysis_contract import validate_contract as validate_c2_contract
from validate_function_analysis import COMPLETE_STATUSES
from validate_function_analysis import validate_case as validate_function_case

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_COUNT_FIELDS = {
    "discovered_functions": "discovered_function_inventory_count",
    "characteristic_functions": "characteristic_function_selected_count",
    "attempted": "decompilation_attempted_count",
    "succeeded": "decompilation_succeeded_count",
    "limited": "decompilation_limited_or_failed_count",
    "excluded": "decompilation_excluded_count",
    "unselected": "unselected_function_count",
    "ghidra_functions": "ghidra_function_inventory_count",
    "managed_methods": "managed_method_inventory_count",
    "valid_mcp_programs": "ghidra_programs_with_valid_mcp_responses",
}


class ProjectionError(ValueError):
    """公開集計を安全に再投影できない場合の例外。"""


def _json_bytes(document: Mapping[str, Any]) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def _bounded_snapshot(path: Path) -> bytes:
    ensure_no_reparse_components(path)
    with path.open("rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_JSON_OBJECT_SIZE:
            raise ProjectionError(f"JSON入力が通常fileではないか容量上限を超えています: {path}")
        data = stream.read(MAX_JSON_OBJECT_SIZE + 1)
    if len(data) > MAX_JSON_OBJECT_SIZE or len(data) != metadata.st_size:
        raise ProjectionError(f"JSON入力を安定したsnapshotとして読めません: {path}")
    return data


def _digest_from_case_id(value: object) -> str:
    if not isinstance(value, str):
        raise ProjectionError("manifestのcase_idが文字列ではありません")
    digest = value.removeprefix("sha256:").casefold()
    if not SHA256_RE.fullmatch(digest):
        raise ProjectionError(f"manifestのcase_idが不正です: {value}")
    return digest


def _requested_hashes(manifest: Mapping[str, Any]) -> list[str]:
    raw_cases = manifest.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ProjectionError("manifestに対象caseがありません")
    result: list[str] = []
    for item in raw_cases:
        if not isinstance(item, Mapping):
            raise ProjectionError("manifest.casesにobjectではない要素があります")
        result.append(_digest_from_case_id(item.get("case_id") or item.get("sha256")))
    if len(set(result)) != len(result):
        raise ProjectionError("manifestのcase SHA-256が重複しています")
    return result


def _summary_cases(summary: Mapping[str, Any], requested: list[str]) -> dict[str, dict[str, Any]]:
    raw_cases = summary.get("cases")
    if not isinstance(raw_cases, list):
        raise ProjectionError("publication-summary.casesが配列ではありません")
    indexed: dict[str, dict[str, Any]] = {}
    for item in raw_cases:
        if not isinstance(item, dict):
            raise ProjectionError("publication-summary.casesにobjectではない要素があります")
        digest = str(item.get("sha256") or "").casefold()
        if not SHA256_RE.fullmatch(digest):
            raise ProjectionError("publication-summaryに不正なSHA-256があります")
        if digest in indexed:
            raise ProjectionError(f"publication-summaryのcaseが重複しています: {digest}")
        indexed[digest] = item
    if set(indexed) != set(requested):
        missing = sorted(set(requested) - set(indexed))
        extra = sorted(set(indexed) - set(requested))
        raise ProjectionError(f"manifestとpublication-summaryのcase集合が不一致です: missing={missing}, extra={extra}")
    return indexed


def _case_directory(repository: Path, item: Mapping[str, Any], digest: str) -> Path:
    raw = item.get("case_path")
    if not isinstance(raw, str) or not raw.strip():
        raise ProjectionError(f"case_pathがありません: {digest}")
    relative = PurePosixPath(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ProjectionError(f"case_pathがrepository相対pathではありません: {digest}")
    case_dir = (repository / Path(*relative.parts)).resolve()
    malware_root = (repository / "analysis-results" / "malware").resolve()
    try:
        case_dir.relative_to(malware_root)
    except ValueError as exc:
        raise ProjectionError(f"case_pathがmalware成果物外を指しています: {digest}") from exc
    if case_dir.name.casefold() != digest or not case_dir.is_dir():
        raise ProjectionError(f"case_pathが対象SHA-256 directoryと一致しません: {digest}")
    return case_dir


def _nonnegative_int(coverage: Mapping[str, Any], name: str, digest: str) -> int:
    value = coverage.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProjectionError(f"static-logic coverageが不正です: {digest}: {name}")
    return value


def _program_keys(logic: Mapping[str, Any], digest: str) -> set[str]:
    result: set[str] = set()
    evidence = logic.get("program_evidence", [])
    if not isinstance(evidence, list):
        raise ProjectionError(f"program_evidenceが配列ではありません: {digest}")
    for index, item in enumerate(evidence):
        if not isinstance(item, Mapping):
            raise ProjectionError(f"program_evidenceにobjectではない要素があります: {digest}:{index}")
        key = str(item.get("program_id") or item.get("program_selector") or "").strip()
        if not key:
            raise ProjectionError(f"program_evidenceに識別子がありません: {digest}:{index}")
        result.add(key)
    return result


def _provider_attribution_projection(
    report: Mapping[str, Any],
    summary_item: Mapping[str, Any],
) -> dict[str, Any]:
    classification = report.get("classification")
    selected = classification.get("selected_families") if isinstance(classification, Mapping) else None
    basis = str(summary_item.get("attribution_basis") or "").strip().casefold()
    provider_basis = (
        basis.startswith("malwarebazaar_")
        or basis == "unsupported_reported_signature"
        or "provider" in basis
        or "プロバイダ" in basis
    )
    if selected == [] and provider_basis:
        return {
            "family_attribution_status": "provider_reported_not_statically_confirmed",
            "statically_confirmed_family": None,
            "family_role": "provider_reported_grouping",
        }
    return {}


def _validated_case_projection(
    repository: Path,
    case_dir: Path,
    digest: str,
    summary_item: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], set[str], dict[Path, bytes]]:
    report_path = case_dir / "report.json"
    logic_path = case_dir / "static-logic.json"
    c2_path = case_dir / "c2-analysis.json"
    snapshots = {path: _bounded_snapshot(path) for path in (report_path, logic_path, c2_path)}
    report = load_json_object_strict(report_path)
    state = report.get("case_state")
    status = str(state.get("status") if isinstance(state, Mapping) else "")
    errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        require_resumable=status in RESUMABLE_CASE_STATES,
    )
    if errors:
        raise ProjectionError(f"case整合性検証に失敗しました: {digest}: {errors}")
    blockers = state.get("blockers", []) if isinstance(state, Mapping) else []
    if not isinstance(blockers, list) or not all(isinstance(item, str) and item.strip() for item in blockers):
        raise ProjectionError(f"case_state.blockersが不正です: {digest}")
    normalized_blockers = sorted(set(blockers))

    c2_document = load_json_object_strict(c2_path)
    c2 = validate_c2_contract(c2_document, digest, repository=repository)

    logic = load_json_object_strict(logic_path)
    logic_status = str(logic.get("status") or "").strip()
    if not logic_status or str(logic.get("sha256") or "").casefold() != digest:
        raise ProjectionError(f"static-logicの状態またはSHA-256が不正です: {digest}")
    coverage = logic.get("coverage")
    if not isinstance(coverage, Mapping):
        raise ProjectionError(f"static-logic.coverageがありません: {digest}")
    for field in _COUNT_FIELDS.values():
        _nonnegative_int(coverage, field, digest)
    if logic_status in COMPLETE_STATUSES:
        validation = validate_function_case(case_dir, digest)
        if not validation.valid:
            raise ProjectionError(f"関数解析検証に失敗しました: {digest}: {validation.findings}")
    else:
        validation = None
    if status == "complete" and c2.get("complete") is not True:
        raise ProjectionError(f"complete caseのC2解析契約が未完了です: {digest}")
    if status == "complete" and (logic_status not in COMPLETE_STATUSES or validation is None):
        raise ProjectionError(f"complete caseの代表関数静的解析が未完了です: {digest}")
    for path, expected in snapshots.items():
        if _bounded_snapshot(path) != expected:
            raise ProjectionError(f"検証中にcase成果物が変更されました: {digest}: {path.name}")
    return (
        {
            "case_state": status,
            "blockers": normalized_blockers,
            "publication_complete": status == "complete" and c2.get("complete") is True and validation is not None,
            "publication_stage": "complete" if status == "complete" else "partial_followup_required",
            "c2_analysis_outcome": str(c2.get("outcome") or "unresolved"),
            "c2_analysis_complete": bool(c2.get("complete")),
            "c2_analysis_finding_count": int(c2.get("finding_count") or 0),
            "static_logic_status": logic_status,
            "function_analysis": dict(coverage),
            **_provider_attribution_projection(report, summary_item),
        },
        dict(coverage),
        _program_keys(logic, digest),
        snapshots,
    )


def build_collection_projection(repository: Path, collection_dir: Path) -> dict[str, Any]:
    """公開case成果物を検証し、manifestとsummaryの期待値を返す。"""

    repository = repository.resolve()
    collection_dir = collection_dir.resolve()
    expected_collection_root = (repository / "analysis-results" / "collections").resolve()
    try:
        collection_dir.relative_to(expected_collection_root)
    except ValueError as exc:
        raise ProjectionError("collectionはrepository内のanalysis-results/collections配下に限定されます") from exc
    manifest_path = collection_dir / "manifest.json"
    summary_path = collection_dir / "publication-summary.json"
    source_snapshots = {manifest_path: _bounded_snapshot(manifest_path), summary_path: _bounded_snapshot(summary_path)}
    manifest = load_json_object_strict(manifest_path)
    summary = load_json_object_strict(summary_path)
    requested = _requested_hashes(manifest)
    indexed = _summary_cases(summary, requested)

    manifest_expected = deepcopy(manifest)
    summary_expected = deepcopy(summary)
    expected_items = _summary_cases(summary_expected, requested)
    state_counts: Counter[str] = Counter()
    blocker_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    totals: Counter[str] = Counter()
    unique_programs: set[str] = set()
    case_snapshots: dict[Path, bytes] = {}

    for digest in requested:
        case_dir = _case_directory(repository, indexed[digest], digest)
        values, coverage, program_keys, snapshots = _validated_case_projection(
            repository,
            case_dir,
            digest,
            indexed[digest],
        )
        expected_items[digest].update({key: value for key, value in values.items() if key != "publication_complete"})
        state_counts[values["case_state"]] += 1
        blocker_counts.update(values["blockers"])
        status_counts[values["static_logic_status"]] += 1
        unique_programs.update(program_keys)
        case_snapshots.update(snapshots)
        for aggregate, field in _COUNT_FIELDS.items():
            totals[aggregate] += _nonnegative_int(coverage, field, digest)

    all_complete = bool(requested) and all(
        expected_items[digest]["case_state"] == "complete"
        and expected_items[digest]["c2_analysis_complete"] is True
        and expected_items[digest]["static_logic_status"] in COMPLETE_STATUSES
        for digest in requested
    )
    publication_stage = "complete" if all_complete else "partial_followup_required"
    common = {
        "analysis_complete": all_complete,
        "publication_stage": publication_stage,
        "case_state_counts": dict(sorted(state_counts.items())),
        "case_blocker_counts": dict(sorted(blocker_counts.items())),
    }
    manifest_expected.update({**common, "complete": all_complete})
    summary_expected.update(common)
    summary_expected["static_logic_status"] = dict(sorted(status_counts.items()))
    summary_expected["function_analysis"] = {
        "root_cases": len(requested),
        "unique_pe_programs": len(unique_programs),
        "discovered_function_inventory_count": totals["discovered_functions"],
        "characteristic_function_selected_count": totals["characteristic_functions"],
        "characteristic_function_attempted_count": totals["attempted"],
        "decompilation_succeeded_count": totals["succeeded"],
        "decompilation_limited_or_failed_count": totals["limited"],
        "decompilation_excluded_count": totals["excluded"],
        "unselected_function_count": totals["unselected"],
        "all_characteristic_functions_attempted": all(
            bool(expected_items[digest]["function_analysis"].get("all_characteristic_functions_attempted"))
            for digest in requested
        ),
        "raw_private_artifacts_retained": all(
            bool(expected_items[digest]["function_analysis"].get("raw_private_artifacts_retained"))
            for digest in requested
        ),
        "all_static_analysis_content_retained": all(
            bool(expected_items[digest]["function_analysis"].get("all_static_analysis_content_retained"))
            for digest in requested
        ),
        "ghidra_function_inventory_count": totals["ghidra_functions"],
        "managed_method_inventory_count": totals["managed_methods"],
        "ghidra_programs_with_valid_mcp_responses": totals["valid_mcp_programs"],
    }
    return {
        "manifest": manifest_expected,
        "summary": summary_expected,
        "source_snapshots": {**source_snapshots, **case_snapshots},
        "case_count": len(requested),
    }


def _atomic_write_documents(
    documents: Mapping[Path, Mapping[str, Any]],
    source_snapshots: Mapping[Path, bytes],
) -> None:
    prepared: dict[Path, Path] = {}
    replaced: list[Path] = []
    try:
        for path, document in documents.items():
            handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
            temporary_path = Path(temporary)
            prepared[path] = temporary_path
            with os.fdopen(handle, "wb") as stream:
                stream.write(_json_bytes(document))
                stream.flush()
                os.fsync(stream.fileno())
        for path, expected in source_snapshots.items():
            if _bounded_snapshot(path) != expected:
                raise ProjectionError(f"投影後に入力が変更されました: {path}")
        for path, temporary in prepared.items():
            os.replace(temporary, path)
            replaced.append(path)
        for path, document in documents.items():
            expected = _json_bytes(document)
            if _bounded_snapshot(path) != expected or load_json_object_strict(path) != document:
                raise ProjectionError(f"原子置換後のbyte／JSON再検証に失敗しました: {path}")
    except BaseException as original_error:
        rollback_errors: list[str] = []
        for path in reversed(replaced):
            original = source_snapshots[path]
            handle, temporary = tempfile.mkstemp(prefix=f".{path.name}.rollback.", suffix=".tmp", dir=path.parent)
            temporary_path = Path(temporary)
            try:
                with os.fdopen(handle, "wb") as stream:
                    stream.write(original)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_path, path)
            finally:
                temporary_path.unlink(missing_ok=True)
            try:
                if _bounded_snapshot(path) != original:
                    rollback_errors.append(os.fspath(path))
            except (OSError, ValueError):
                rollback_errors.append(os.fspath(path))
        if rollback_errors:
            raise ProjectionError(f"公開集計のrollback再検証に失敗しました: {rollback_errors}") from original_error
        raise
    finally:
        for temporary in prepared.values():
            temporary.unlink(missing_ok=True)


def synchronize_collection_projection(
    repository: Path,
    collection_dir: Path,
    *,
    write: bool = False,
    check: bool = False,
) -> dict[str, Any]:
    """collection投影を比較し、要求時は原子的に更新する。"""

    if write and check:
        raise ProjectionError("--writeと--checkは同時に指定できません")
    projection = build_collection_projection(repository, collection_dir)
    collection_dir = collection_dir.resolve()
    paths = {
        collection_dir / "manifest.json": projection["manifest"],
        collection_dir / "publication-summary.json": projection["summary"],
    }
    stale = [path.name for path, expected in paths.items() if load_json_object_strict(path) != expected]
    if write and stale:
        _atomic_write_documents(paths, projection["source_snapshots"])
    output_paths = frozenset(paths)
    snapshots_to_confirm = {
        path: data
        for path, data in projection["source_snapshots"].items()
        if not (write and stale) or path not in output_paths
    }
    for path, expected in snapshots_to_confirm.items():
        if _bounded_snapshot(path) != expected:
            raise ProjectionError(f"read-only検証の完了前に入力が変更されました: {path}")
    return {
        "status": "updated" if write and stale else "stale" if stale else "current",
        "stale_files": stale,
        "case_count": projection["case_count"],
        "write_performed": bool(write and stale),
        "check_passed": not stale or bool(write),
    }


def build_parser() -> argparse.ArgumentParser:
    """CLI parserを構築する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True, help="repository root")
    parser.add_argument("--collection", type=Path, required=True, help="collection directory")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="staleな集計を原子的に更新する")
    mode.add_argument("--check", action="store_true", help="staleなら終了code 1を返す")
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLIを実行し、check結果に応じた終了codeを返す。"""

    args = build_parser().parse_args(argv)
    try:
        result = synchronize_collection_projection(
            args.repository,
            args.collection,
            write=args.write,
            check=args.check,
        )
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if args.check and not result["check_passed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
