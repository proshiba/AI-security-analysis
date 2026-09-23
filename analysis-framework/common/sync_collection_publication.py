#!/usr/bin/env python3
"""case成果物からcollection公開集計を決定的に再投影する。

公開済みの ``report.json``、``c2-analysis.json``、``static-logic.json`` だけを読み、
``publication-summary.json``、``manifest.json``、``README.md`` の派生表示を同期する。検体、private
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
from malwarebazaar_family_labels import is_reported_name_placeholder
from validate_function_analysis import COMPLETE_STATUSES
from validate_function_analysis import validate_case as validate_function_case

SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_ATTRIBUTION_STATUSES = frozenset(
    {
        "statically_confirmed",
        "provider_reported_not_statically_confirmed",
        "unresolved",
    }
)
_SOURCE_CASE_PROJECTED_FIELDS = frozenset(
    {
        "attribution_basis",
        "blockers",
        "c2_analysis_complete",
        "c2_analysis_finding_count",
        "c2_analysis_outcome",
        "case_path",
        "case_state",
        "confirmed_static_c2_observations",
        "confirmed_static_management_observations",
        "confirmed_static_network_observations",
        "family",
        "family_attribution_status",
        "family_role",
        "file_type",
        "first_seen",
        "function_analysis",
        "handler_failures",
        "handler_successes",
        "provider_reported_family",
        "provider_reported_label",
        "publication_stage",
        "reported_signature",
        "sha256",
        "static_config_recovered",
        "static_logic_status",
        "statically_confirmed_family",
    }
)
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


def _document_bytes(document: Mapping[str, Any] | bytes) -> bytes:
    return document if isinstance(document, bytes) else _json_bytes(document)


def _readme_bytes(source: bytes, summary: Mapping[str, Any], case_count: int) -> bytes:
    """静的ロジック節だけを検証済みcase集計から再生成する。"""

    try:
        readme = source.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ProjectionError("collection READMEがUTF-8ではありません") from exc
    statuses = summary["static_logic_status"]
    coverage = summary["function_analysis"]
    if sum(statuses.values()) != case_count:
        raise ProjectionError("静的ロジック件数と対象case数が一致しません")
    completed = sum(count for status, count in statuses.items() if status in COMPLETE_STATUSES)
    pending = case_count - completed
    if pending < 0:
        raise ProjectionError("静的ロジック件数が対象case数を超えています")
    lines = [
        "## 静的ロジック状態",
        "",
        f"- 代表関数解析完了case: `{completed}`",
    ]
    if pending:
        lines.append(f"- 代表関数解析保留case: `{pending}`")
    lines.extend(
        [
            f"- Ghidra／CILプログラム: `{coverage['unique_pe_programs']}`件の固有PE",
            f"- 発見関数／メソッドinventory: `{coverage['discovered_function_inventory_count']}`",
            f"- 代表関数: `{coverage['characteristic_function_selected_count']}`",
            f"- 選定外関数: `{coverage['unselected_function_count']}`",
            f"- Ghidra関数: `{coverage['ghidra_function_inventory_count']}`",
            f"- managedメソッド: `{coverage['managed_method_inventory_count']}`",
            f"- MCP成功証跡付きプログラム: `{coverage['ghidra_programs_with_valid_mcp_responses']}`",
            f"- 逆コンパイル／CIL解析試行: `{coverage['characteristic_function_attempted_count']}`",
            f"- 成功: `{coverage['decompilation_succeeded_count']}`",
            f"- 制約付き／失敗: `{coverage['decompilation_limited_or_failed_count']}`",
            "",
        ]
    )
    if pending:
        lines.append("保留caseの関数本体は未確認です。上記の関数台帳と試行件数は公開済みcaseの記録から集計しており、全件の解析完了を意味しません。")
    else:
        lines.append("全関数inventoryを保持しつつ、特徴的な代表関数を選定して解析しました。")
    lines.extend(
        [
            (
                "各caseのSTATIC-LOGIC.mdに関数解説、OVERALL-LOGIC.mdに全体処理を記録しています。"
                if not pending
                else "完了caseのSTATIC-LOGIC.mdに関数解説、OVERALL-LOGIC.mdに全体処理を記録しています。"
            ),
            "生の逆コンパイル本文とCIL命令列はリポジトリ外へ保持しています。" if not pending else "取得済みの生の逆コンパイル本文とCIL命令列はリポジトリ外へ保持しています。",
            "",
            "",
        ]
    )
    pattern = re.compile(r"(?ms)^## 静的ロジック状態\n.*?(?=^個別のPE構造)")
    replacement = "\n".join(lines)
    rendered, count = pattern.subn(lambda _match: replacement, readme)
    if count != 1:
        raise ProjectionError("collection READMEの静的ロジック節を一意に特定できません")
    return rendered.encode("utf-8")


def _decode_readme(source: bytes, label: str) -> str:
    try:
        return source.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise ProjectionError(f"{label}がUTF-8ではありません") from exc


def _attribution_counts(items: list[Mapping[str, Any]], label: str) -> Counter[str]:
    counts: Counter[str] = Counter()
    for item in items:
        status = item.get("family_attribution_status")
        if not isinstance(status, str) or status not in _ATTRIBUTION_STATUSES:
            raise ProjectionError(f"{label}のfamily_attribution_statusが不正です: {status!r}")
        counts[status] += 1
    return counts


def _root_attribution_readme_bytes(
    source: bytes,
    family_items: Mapping[str, list[Mapping[str, Any]]],
) -> bytes:
    """collection READMEの帰属集計だけを検証済みcaseから再生成する。"""

    readme = _decode_readme(source, "collection README")
    all_items = [item for items in family_items.values() for item in items]
    total_counts = _attribution_counts(all_items, "collection")
    provider_count = total_counts.get("provider_reported_not_statically_confirmed", 0)
    provider_pattern = re.compile(
        r"(?m)^- 提供元報告のみで内部静的ファミリー未確認: `\d+`$"
    )
    readme, count = provider_pattern.subn(
        f"- 提供元報告のみで内部静的ファミリー未確認: `{provider_count}`",
        readme,
    )
    if count != 1:
        raise ProjectionError("collection READMEの提供元帰属集計を一意に特定できません")

    lines = [
        "## 整理先ラベル内訳",
        "",
        "| 整理先ラベル | 件数 | 内部静的確認済み | 提供元報告のみ・内部静的未確認 | 未解決 |",
        "|---|---:|---:|---:|---:|",
    ]
    for family, items in sorted(
        family_items.items(), key=lambda value: (-len(value[1]), value[0])
    ):
        counts = _attribution_counts(items, f"source {family}")
        lines.append(
            f"| [{family}](sources/{family}/README.md) | {len(items)} | "
            f"{counts.get('statically_confirmed', 0)} | "
            f"{counts.get('provider_reported_not_statically_confirmed', 0)} | "
            f"{counts.get('unresolved', 0)} |"
        )
    lines.extend(["", ""])
    pattern = re.compile(r"(?ms)^## 整理先ラベル内訳\n.*?(?=^## 静的ロジック状態\n)")
    rendered, count = pattern.subn(lambda _match: "\n".join(lines), readme)
    if count != 1:
        raise ProjectionError("collection READMEの整理先ラベル内訳を一意に特定できません")
    return rendered.encode("utf-8")


def _source_readme_bytes(
    source: bytes,
    family: str,
    counts: Mapping[str, int],
    case_count: int,
) -> bytes:
    """source READMEの帰属件数を同じsource case集合から再生成する。"""

    readme = _decode_readme(source, f"source README ({family})")
    if len(re.findall(rf"(?m)^# {re.escape(family)} 収録ケース$", readme)) != 1:
        raise ProjectionError(f"source READMEの見出しを一意に特定できません: {family}")
    replacements = {
        r"(?m)^- 収録件数: `\d+`$": f"- 収録件数: `{case_count}`",
        r"(?m)^- 内部静的確認済み: `\d+`$": (
            f"- 内部静的確認済み: `{counts.get('statically_confirmed', 0)}`"
        ),
        r"(?m)^- 提供元報告のみ（内部静的未確認）: `\d+`$": (
            "- 提供元報告のみ（内部静的未確認）: "
            f"`{counts.get('provider_reported_not_statically_confirmed', 0)}`"
        ),
        r"(?m)^- 未解決: `\d+`$": f"- 未解決: `{counts.get('unresolved', 0)}`",
    }
    for pattern, replacement in replacements.items():
        readme, count = re.subn(pattern, replacement, readme)
        if count != 1:
            raise ProjectionError(f"source READMEの帰属集計を一意に特定できません: {family}")
    return readme.encode("utf-8")


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


def _safe_family_name(value: object) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise ProjectionError(f"source family名が不正です: {value!r}")
    if Path(value).name != value or "/" in value or "\\" in value:
        raise ProjectionError(f"source family名が単一directory名ではありません: {value!r}")
    return value


def _manifest_family_sources(
    manifest: Mapping[str, Any],
    expected_families: set[str],
) -> dict[str, PurePosixPath]:
    raw_sources = manifest.get("family_sources")
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ProjectionError("manifest.family_sourcesがありません")
    sources: dict[str, PurePosixPath] = {}
    folded: set[str] = set()
    for raw in raw_sources:
        if not isinstance(raw, Mapping):
            raise ProjectionError("manifest.family_sourcesにobjectではない要素があります")
        family = _safe_family_name(raw.get("family"))
        if family.casefold() in folded:
            raise ProjectionError(f"manifest.family_sourcesが重複しています: {family}")
        folded.add(family.casefold())
        path_value = raw.get("path")
        if not isinstance(path_value, str):
            raise ProjectionError(f"manifest.family_sources.pathが文字列ではありません: {family}")
        path = PurePosixPath(path_value)
        if path.is_absolute() or path.parts != ("sources", family):
            raise ProjectionError(f"manifest.family_sources.pathが既知layoutではありません: {family}")
        sources[family] = path
    if set(sources) != expected_families:
        raise ProjectionError(
            "manifest.family_sourcesとcaseのfamily集合が不一致です: "
            f"manifest={sorted(sources)}, cases={sorted(expected_families)}"
        )
    return sources


def _source_case_index(
    family: str,
    document: Mapping[str, Any],
    expected: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    schema_version = document.get("schema_version")
    if (
        isinstance(schema_version, bool)
        or schema_version != 1
        or document.get("family") != family
    ):
        raise ProjectionError(f"source summaryのschemaまたはfamilyが不正です: {family}")
    raw_cases = document.get("cases")
    count = document.get("count")
    if not isinstance(raw_cases, list) or isinstance(count, bool) or not isinstance(count, int):
        raise ProjectionError(f"source summaryのcasesまたはcountが不正です: {family}")
    if count != len(raw_cases):
        raise ProjectionError(
            f"source summaryのcountとcases件数が一致しません: {family}: "
            f"count={count}, cases={len(raw_cases)}"
        )
    indexed: dict[str, dict[str, Any]] = {}
    for raw in raw_cases:
        if not isinstance(raw, dict):
            raise ProjectionError(f"source summary.casesにobjectではない要素があります: {family}")
        digest = str(raw.get("sha256") or "").casefold()
        if not SHA256_RE.fullmatch(digest):
            raise ProjectionError(f"source summaryに不正なSHA-256があります: {family}")
        if digest in indexed:
            raise ProjectionError(f"source summaryのcaseが重複しています: {family}:{digest}")
        if raw.get("family") != family:
            raise ProjectionError(f"source summary caseのfamilyが不一致です: {family}:{digest}")
        indexed[digest] = raw
    if count != len(expected):
        raise ProjectionError(
            f"source summaryの件数がpublication-summaryと一致しません: {family}: "
            f"count={count}, expected={len(expected)}"
        )
    if set(indexed) != set(expected):
        raise ProjectionError(f"source summaryとpublication-summaryのcase集合が不一致です: {family}")
    for digest, raw in indexed.items():
        if raw.get("case_path") != expected[digest].get("case_path"):
            raise ProjectionError(f"source summary case_pathが不一致です: {family}:{digest}")
    aggregate = document.get("family_attribution_status")
    if not isinstance(aggregate, Mapping):
        raise ProjectionError(f"source summaryの帰属集計がobjectではありません: {family}")
    aggregate_total = 0
    for status, value in aggregate.items():
        if status not in _ATTRIBUTION_STATUSES or isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ProjectionError(f"source summaryの帰属集計が不正です: {family}:{status}")
        aggregate_total += value
    if aggregate_total != count:
        raise ProjectionError(f"source summaryの帰属集計件数が一致しません: {family}")
    return indexed


def _source_projections(
    collection_dir: Path,
    manifest: Mapping[str, Any],
    expected_items: Mapping[str, Mapping[str, Any]],
) -> tuple[
    dict[Path, Mapping[str, Any] | bytes],
    dict[Path, bytes],
    dict[str, list[Mapping[str, Any]]],
]:
    """既知のsources layoutを検証し、帰属fieldと集計の投影を返す。"""

    families: dict[str, dict[str, Mapping[str, Any]]] = {}
    folded: set[str] = set()
    for digest, item in expected_items.items():
        family = _safe_family_name(item.get("family"))
        if family.casefold() in folded and family not in families:
            raise ProjectionError(f"caseのfamily名が大文字小文字だけで競合しています: {family}")
        folded.add(family.casefold())
        families.setdefault(family, {})[digest] = item
    source_paths = _manifest_family_sources(manifest, set(families))
    sources_root = collection_dir / "sources"
    ensure_no_reparse_components(sources_root)
    if not sources_root.is_dir():
        raise ProjectionError("collection sources directoryがありません")
    actual_entries = list(sources_root.iterdir())
    if any(not entry.is_dir() for entry in actual_entries):
        raise ProjectionError("collection sources直下に未知のfileがあります")
    actual_families = {entry.name for entry in actual_entries}
    if actual_families != set(source_paths):
        raise ProjectionError(
            f"collection sourcesのdirectory集合が不一致です: actual={sorted(actual_families)}"
        )

    documents: dict[Path, Mapping[str, Any] | bytes] = {}
    snapshots: dict[Path, bytes] = {}
    projected_family_items: dict[str, list[Mapping[str, Any]]] = {}
    for family in sorted(families):
        source_dir = collection_dir / Path(*source_paths[family].parts)
        ensure_no_reparse_components(source_dir)
        entries = list(source_dir.iterdir())
        if {entry.name for entry in entries} != {"README.md", "summary.json"} or any(
            not entry.is_file() for entry in entries
        ):
            raise ProjectionError(f"source directoryが既知layoutではありません: {family}")
        summary_path = source_dir / "summary.json"
        readme_path = source_dir / "README.md"
        snapshots[summary_path] = _bounded_snapshot(summary_path)
        snapshots[readme_path] = _bounded_snapshot(readme_path)
        summary = load_json_object_strict(summary_path)
        indexed = _source_case_index(family, summary, families[family])
        expected_summary = deepcopy(summary)
        expected_index = {str(item["sha256"]).casefold(): item for item in expected_summary["cases"]}
        projected_items: list[Mapping[str, Any]] = []
        for digest in indexed:
            source_item = expected_index[digest]
            canonical_item = families[family][digest]
            for field in tuple(source_item):
                if field not in canonical_item:
                    continue
                if field in _SOURCE_CASE_PROJECTED_FIELDS:
                    source_item[field] = deepcopy(canonical_item[field])
                elif source_item[field] != canonical_item[field]:
                    raise ProjectionError(
                        f"source summaryの未知共有fieldがpublication-summaryと競合しています: "
                        f"{family}:{digest}:{field}"
                    )
            projected_items.append(source_item)
        counts = _attribution_counts(projected_items, f"source {family}")
        expected_summary["count"] = len(projected_items)
        expected_summary["family_attribution_status"] = dict(sorted(counts.items()))
        documents[summary_path] = expected_summary
        documents[readme_path] = _source_readme_bytes(
            snapshots[readme_path], family, counts, len(projected_items)
        )
        projected_family_items[family] = projected_items
    return documents, snapshots, projected_family_items


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
    if selected == [] and is_reported_name_placeholder(summary_item.get("reported_signature")):
        return {
            "attribution_basis": "no_supported_family_evidence",
            "family_attribution_status": "unresolved",
            "provider_reported_label": None,
            "provider_reported_family": None,
            "statically_confirmed_family": None,
            "family_role": "unclassified_grouping",
        }
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
    readme_path = collection_dir / "README.md"
    source_snapshots = {
        manifest_path: _bounded_snapshot(manifest_path),
        summary_path: _bounded_snapshot(summary_path),
        readme_path: _bounded_snapshot(readme_path),
    }
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
    attribution_status_counts = Counter(
        str(expected_items[digest].get("family_attribution_status") or "unresolved")
        for digest in requested
    )
    summary_expected["family_attribution_status"] = dict(sorted(attribution_status_counts.items()))
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
    source_documents, family_source_snapshots, family_items = _source_projections(
        collection_dir,
        manifest,
        expected_items,
    )
    family_counts = {family: len(items) for family, items in sorted(family_items.items())}
    if sum(family_counts.values()) != len(requested):
        raise ProjectionError("source family別件数と対象case数が一致しません")
    summary_expected["counts"] = family_counts
    root_readme = _root_attribution_readme_bytes(source_snapshots[readme_path], family_items)
    documents: dict[Path, Mapping[str, Any] | bytes] = {
        manifest_path: manifest_expected,
        summary_path: summary_expected,
        readme_path: _readme_bytes(root_readme, summary_expected, len(requested)),
        **source_documents,
    }
    return {
        "manifest": manifest_expected,
        "summary": summary_expected,
        "readme": documents[readme_path],
        "documents": documents,
        "source_snapshots": {**source_snapshots, **family_source_snapshots, **case_snapshots},
        "case_count": len(requested),
    }


def _atomic_write_documents(
    documents: Mapping[Path, Mapping[str, Any] | bytes],
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
                stream.write(_document_bytes(document))
                stream.flush()
                os.fsync(stream.fileno())
        for path, expected in source_snapshots.items():
            if _bounded_snapshot(path) != expected:
                raise ProjectionError(f"投影後に入力が変更されました: {path}")
        for path, temporary in prepared.items():
            os.replace(temporary, path)
            replaced.append(path)
        for path, document in documents.items():
            expected = _document_bytes(document)
            if _bounded_snapshot(path) != expected or (
                not isinstance(document, bytes) and load_json_object_strict(path) != document
            ):
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
    paths = projection["documents"]
    stale = [
        path.relative_to(collection_dir).as_posix()
        for path, expected in paths.items()
        if (_bounded_snapshot(path) != expected if isinstance(expected, bytes) else load_json_object_strict(path) != expected)
    ]
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
