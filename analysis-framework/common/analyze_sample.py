#!/usr/bin/env python3
"""検体の適用可否判定から静的解析までを1コマンドで実行する。"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import shutil
import sys
import zipfile
from typing import Any

import pyzipper


COMMON_ROOT = Path(__file__).resolve().parent
FRAMEWORK_ROOT = COMMON_ROOT.parent
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
CLASSIFIERS_ROOT = FRAMEWORK_ROOT / "classifiers"
DEFAULT_REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"
DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024
DEFAULT_MAX_FILES = 1_000
CONFIDENCE = {"high": 3, "medium": 2, "low": 1}
FAMILY_ALIASES = {
    "mx_go": "mx-go",
    "amos": "amosstealer",
    "atomicstealer": "amosstealer",
    "remcos": "remcosrat",
    "remus": "remusstealer",
    "lumma": "lummastealer",
    "atlas": "atlascross",
}

for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT, CLASSIFIERS_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_family_sample  # noqa: E402
import classify_sample  # noqa: E402
from analysis_contract import (  # noqa: E402
    artifact_hashes,
    build_pipeline_fingerprint,
    case_integrity_errors,
    ensure_no_reparse_components,
    ensure_tree_without_reparse,
    format_compatible,
    handler_result_quality,
    load_json_object_strict,
    normalize_sha256_digest,
    resolve_case_artifact,
    runtime_dependency_versions,
    seal_report,
)
from handler_catalog import (  # noqa: E402
    HandlerSpec,
    catalog_summary,
    clear_handler_caches,
    discover_handlers,
    execute_handler,
    load_handler,
    sanitize_public_value,
)
from extractors.profiled_family import clear_profile_cache  # noqa: E402
from profiled_family_detector import clear_known_hash_cache  # noqa: E402
from campaign_correlation import (  # noqa: E402
    extract_campaign_evidence,
    load_rules,
    match_fingerprints,
)
from case_features import build_case_profile, render_features_markdown  # noqa: E402
from static_logic import (  # noqa: E402
    build_static_logic_report,
    render_static_logic_markdown,
)
from malware_io import (  # noqa: E402
    read_single_aes_zip_member,
    read_file_capped,
    safe_output_name,
    sha256_bytes,
    write_json,
)
from unpackers.static_unpacker import detect_format, unpack_bytes  # noqa: E402
import static_layer_pipeline as static_layers  # noqa: E402

InputUnit = static_layers.InputUnit
StaticLayer = static_layers.StaticLayer
StaticLayerPolicy = static_layers.StaticLayerPolicy
MAX_STATIC_LAYERS = static_layers.MAX_STATIC_LAYERS
MAX_STATIC_DEPTH = static_layers.MAX_STATIC_DEPTH
MAX_RECOVERED_LAYER_SIZE = static_layers.MAX_RECOVERED_LAYER_SIZE
MAX_RECOVERED_TOTAL_SIZE = static_layers.MAX_RECOVERED_TOTAL_SIZE
MAX_STATIC_COMPRESSION_RATIO = static_layers.MAX_STATIC_COMPRESSION_RATIO
MAX_ARCHIVE_MEMBERS = static_layers.MAX_ARCHIVE_MEMBERS
recover_layer_pipeline = static_layers.recover_static_layers


CAMPAIGN_CORRELATION_RULES = FRAMEWORK_ROOT / "registry" / "campaign_correlation_rules.json"
CAMPAIGN_FINGERPRINTS = FRAMEWORK_ROOT / "registry" / "campaign_fingerprints.json"


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        """使用法、オプション見出し、標準help説明を日本語で返す。"""

        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このヘルプを表示して終了します")
        )


def normalize_family(value: str) -> str:
    """CLIの代表的な別名を内部ファミリーIDへ正規化する。"""

    lowered = value.strip().lower()
    return FAMILY_ALIASES.get(lowered, lowered)


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def collect_inputs(inputs: list[Path], output: Path, max_files: int) -> list[Path]:
    """ファイルとディレクトリを決定的に展開し、symlinkと出力先を除外する。"""

    if isinstance(max_files, bool) or not isinstance(max_files, int) or max_files <= 0:
        raise ValueError("max_files must be positive")
    collected: dict[str, Path] = {}
    for supplied in inputs:
        if not supplied.exists():
            raise FileNotFoundError(f"入力が見つかりません: {supplied}")
        if supplied.is_symlink():
            continue
        candidates = [supplied] if supplied.is_file() else sorted(supplied.rglob("*"))
        for candidate in candidates:
            if not candidate.is_file() or candidate.is_symlink() or _inside(candidate, output):
                continue
            resolved = candidate.resolve()
            collected[str(resolved).casefold()] = resolved
            if len(collected) > max_files:
                raise ValueError(f"入力ファイル数が上限 {max_files} を超えました")
    return [collected[key] for key in sorted(collected)]


def _zip_envelope_shape(data: bytes) -> tuple[bool, int]:
    """ZIPが暗号化済み単一メンバーの受け入れ用外装か確認する。"""

    if not zipfile.is_zipfile(io.BytesIO(data)):
        return False, 0
    try:
        with pyzipper.AESZipFile(io.BytesIO(data)) as archive:
            infos = [item for item in archive.infolist() if not item.is_dir()]
            return bool(infos and all(item.flag_bits & 1 for item in infos)), len(infos)
    except (OSError, RuntimeError, zipfile.BadZipFile):
        return False, 0


def read_input_unit(
    path: Path,
    *,
    password: str,
    archive_mode: str,
    max_file_size: int,
) -> InputUnit:
    """生ファイルまたは認証済み単一メンバーZIPをメモリ内で読み込む。"""

    if archive_mode not in {"auto", "raw", "malwarebazaar"}:
        raise ValueError(f"unsupported archive_mode: {archive_mode!r}")
    if isinstance(max_file_size, bool) or not isinstance(max_file_size, int) or max_file_size <= 0:
        raise ValueError("max_file_size must be a positive integer")
    size = path.stat().st_size
    if size > max_file_size:
        raise ValueError(f"入力サイズが上限 {max_file_size} bytes を超えました")
    outer = read_file_capped(path, max_size=max_file_size)
    outer_digest = sha256_bytes(outer)
    encrypted, member_count = _zip_envelope_shape(outer)
    unwrap = archive_mode == "malwarebazaar" or (archive_mode == "auto" and encrypted and member_count == 1)
    if not unwrap:
        return InputUnit(
            source_name=path.name,
            data=outer,
            input_kind="raw",
            outer_sha256=outer_digest,
            outer_size=len(outer),
        )
    member = read_single_aes_zip_member(
        outer,
        password=password,
        max_member_size=max_file_size,
    )
    return InputUnit(
        source_name=Path(member.name).name,
        data=member.data,
        input_kind="authenticated_single_member_zip",
        outer_sha256=outer_digest,
        outer_size=len(outer),
        member_name=member.name,
    )


def _registered_families(registry: Path) -> set[str]:
    return set(classify_sample._validated_registry(registry))


def recover_static_layers(
    unit: InputUnit,
    *,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    force_container_probe: bool = False,
    archive_password: str = "infected",
) -> tuple[list[StaticLayer], dict[str, Any]]:
    """共有パイプラインへ既存unpackerと公開値sanitizerを注入する互換入口。"""

    return recover_layer_pipeline(
        unit,
        unpacker=unpack_bytes,
        sanitizer=sanitize_public_value,
        policy=StaticLayerPolicy(),
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        force_container_probe=force_container_probe,
        archive_password=archive_password,
    )


def _handler_evidence_score(value: Any) -> int:
    """互換用に、共通証拠tierから決定的なscoreだけを返す。"""

    return int(handler_result_quality(value)["score"])


def _detector_error_for_family(classification: dict[str, Any], family: str) -> bool:
    """選択候補familyの検出器が例外終了したか返す。"""

    observations = classification.get("observations")
    if not isinstance(observations, dict):
        return False
    errors = observations.get("detector_errors")
    return isinstance(errors, dict) and family in errors


def _selected_family(
    classification: dict[str, Any],
    forced_family: str | None,
    minimum_confidence: str,
) -> tuple[str | None, str]:
    if forced_family:
        if classification.get("malware_type") != forced_family:
            return None, "explicit_family_not_selected"
        if classification.get("attribution_basis") == "explicit_user_type_unmatched":
            return None, "explicit_family_detector_unmatched"
        if _detector_error_for_family(classification, forced_family):
            return None, "explicit_family_detector_failed"
        return forced_family, "explicit_operator_selection"
    family = classification.get("malware_type")
    confidence = classification.get("malware_type_confidence", "low")
    if family == "unknown" or CONFIDENCE.get(confidence, 0) < CONFIDENCE[minimum_confidence]:
        return None, "no_unique_detection_above_threshold"
    if _detector_error_for_family(classification, str(family)):
        return None, "selected_family_detector_failed"
    return str(family), str(classification.get("attribution_basis", "detector"))


def assess_handlers(
    specs: list[HandlerSpec],
    layer_selections: list[dict[str, Any]],
    forced_family: str | None,
    registered_families: set[str] | None = None,
) -> list[dict[str, Any]]:
    """全既存解析器について、自動実行、非適用、手動確認を明示する。"""

    registered = registered_families or set()
    results = []
    for spec in specs:
        status = "not_applicable"
        reason = "different_family"
        family_layers = [item for item in layer_selections if item["selected_family"] == spec.family]
        eligible_layers = [
            item
            for item in family_layers
            if spec.campaign is None or item["classification"].get("campaign_type", "unknown") == spec.campaign
        ]
        if not spec.supported_interface:
            status, reason = "unsupported_interface", spec.reason
        elif family_layers:
            if spec.campaign and not eligible_layers:
                status, reason = "manual_review", "campaign_specific_handler_not_selected"
            elif spec.automatic:
                status = "applicable_forced" if forced_family else "applicable"
                reason = "explicit_family" if forced_family else "detector_selected_family"
            else:
                status, reason = "manual_review", spec.reason
        elif spec.family not in registered:
            status, reason = "manual_review", "family_has_no_registered_detector"
        results.append(
            {
                **spec.public(),
                "status": status,
                "applicability_reason": reason,
                "applicable_layers": [item["layer"].sha256 for item in eligible_layers],
            }
        )
    return results


def summarize_family_coverage(specs: list[HandlerSpec], registered_families: set[str]) -> list[dict[str, Any]]:
    """検出器と既存解析器の有無をファミリー単位で可視化する。"""

    families = sorted(registered_families | {item.family for item in specs})
    results = []
    for family in families:
        family_specs = [item for item in specs if item.family == family]
        automatic = [item.id for item in family_specs if item.automatic]
        manual = [item.id for item in family_specs if not item.automatic]
        if family not in registered_families:
            status = "handler_without_registered_detector"
        elif automatic:
            status = "automatic_handler_available"
        elif family_specs:
            status = "manual_or_unsupported_only"
        else:
            status = "no_handler_implemented"
        results.append(
            {
                "family": family,
                "status": status,
                "detector_registered": family in registered_families,
                "automatic_handlers": automatic,
                "manual_or_unsupported_handlers": manual,
            }
        )
    return results


def _preflight_applicable(specs: list[HandlerSpec], applicability: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """適用対象だけをimportし、依存関係または関数欠落を事前確認する。"""

    by_id = {item.id: item for item in specs}
    results = []
    for item in applicability:
        if item["status"] not in {"applicable", "applicable_forced"}:
            continue
        status = {"handler_id": item["id"], "available": True, "error": None}
        try:
            load_handler(by_id[item["id"]])
        except Exception as exc:
            status.update(
                available=False,
                error=sanitize_public_value(f"{type(exc).__name__}: {exc}"),
            )
        results.append(status)
    return results


def plan_handler_layers(
    spec: HandlerSpec,
    applicability: dict[str, Any],
    layers: list[StaticLayer],
) -> list[dict[str, Any]]:
    """family一致層とその外装祖先だけを、形式契約付きで実行順へ変換する。"""

    anchors = set(applicability.get("applicable_layers") or [])
    by_hash = {layer.sha256: layer for layer in layers}
    ancestors: set[str] = set()
    for anchor in anchors:
        current = by_hash.get(anchor)
        while current is not None and current.parent_sha256:
            ancestors.add(current.parent_sha256)
            current = by_hash.get(current.parent_sha256)
    plan = []
    for index, layer in enumerate(layers):
        if layer.sha256 in anchors:
            routing_role = "selected_family_layer"
            priority = 0
        elif layer.sha256 in ancestors:
            routing_role = "ancestor_fallback"
            priority = 1
        else:
            routing_role = "unrelated_layer"
            priority = 2
        actual_format = detect_format(layer.data, layer.name)
        plan.append(
            {
                "layer": layer,
                "layer_index": index,
                "routing_role": routing_role,
                "priority": priority,
                "actual_format": actual_format,
                "compatible": format_compatible(spec.input_formats, actual_format),
            }
        )
    return sorted(plan, key=lambda item: (item["priority"], item["layer_index"]))


def _triage_issues(value: Any, path: str = "root") -> list[str]:
    """汎用トリアージ内のparse失敗と明示的partialを再帰的に収集する。"""

    issues = []
    if isinstance(value, dict):
        coverage = value.get("analysis_coverage")
        if isinstance(coverage, dict) and coverage.get("status") not in {None, "complete"}:
            issues.append(f"{path}:coverage:{coverage.get('status')}")
        for key, item in value.items():
            lowered = str(key).casefold()
            child_path = f"{path}.{key}"
            if lowered == "parse_error" or lowered.endswith("_error"):
                issues.append(child_path)
            elif key != "analysis_coverage":
                issues.extend(_triage_issues(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            issues.extend(_triage_issues(item, f"{path}[{index}]"))
    return issues


def _run_generic_triage(layers: list[StaticLayer], case_dir: Path) -> tuple[dict[str, Any], str]:
    """全静的復元層を個別にトリアージし、部分失敗を隠さず集約する。"""

    entries = []
    for layer in layers:
        try:
            value = analyze_family_sample.analyze(
                layer.name,
                layer.data,
                case_dir / "scripts",
                persist_normalized_text=False,
                recurse_archives=False,
            )
            issues = _triage_issues(value)
            entries.append(
                {
                    "layer": layer.public(),
                    "status": "partial" if issues else "complete",
                    "issues": issues,
                    "result": sanitize_public_value(value),
                }
            )
        except Exception as exc:
            entries.append(
                {
                    "layer": layer.public(),
                    "status": "failed",
                    "issues": [f"{type(exc).__name__}: {exc}"],
                    "result": None,
                }
            )
    root = entries[0]
    document = dict(root["result"] or {})
    if root["result"] is None:
        document.update(status="failed", error=root["issues"][0])
    document["recovered_layer_triage"] = entries[1:]
    failed = sum(item["status"] == "failed" for item in entries)
    partial = sum(item["status"] == "partial" for item in entries)
    status = "failed" if failed == len(entries) else ("partial" if failed or partial else "complete")
    document["analysis_coverage"] = {
        "status": status,
        "layer_count": len(entries),
        "complete_layers": sum(item["status"] == "complete" for item in entries),
        "partial_layers": partial,
        "failed_layers": failed,
    }
    document["executed_sample"] = False
    document["network_contacted"] = False
    return document, status


INCOMPLETE_STATIC_STATUSES = frozenset(
    {
        "bounded_limit",
        "corrupt_or_truncated",
        "failed",
        "malformed_metadata",
        "member_limit_applied",
        "parse_failed",
        "partially_extracted",
        "ratio_blocked",
        "size_blocked",
        "size_mismatch",
        "total_size_blocked",
    }
)
INCOMPLETE_STATIC_STATUS_TOKENS = (
    "blocked",
    "corrupt",
    "encrypted",
    "error",
    "failed",
    "incomplete",
    "invalid",
    "limit",
    "malformed",
    "mismatch",
    "partial",
    "timeout",
    "truncated",
    "unavailable",
)


def _is_incomplete_static_status(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    normalized = value.strip().casefold()
    return normalized in INCOMPLETE_STATIC_STATUSES or any(
        token in normalized for token in INCOMPLETE_STATIC_STATUS_TOKENS
    )


def _static_layer_issues(layer_report: dict[str, Any]) -> list[str]:
    """静的復元stepの失敗、深度上限、parser上限を決定的に列挙する。"""

    issues: list[str] = []

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for raw_key, item in value.items():
                key = str(raw_key).casefold()
                child = f"{path}.{raw_key}"
                fallback = value.get("sevenzip")
                authoritative = value.get("embedded_installer_archive")
                if (
                    key == "sevenzip"
                    and isinstance(item, dict)
                    and item.get("status") == "partially_extracted"
                    and isinstance(authoritative, dict)
                    and authoritative.get("status") == "artifacts_recovered"
                    and int(authoritative.get("record_count") or 0) > 0
                ):
                    continue
                if (
                    key == "cab"
                    and isinstance(item, dict)
                    and item.get("status") == "parse_failed"
                    and isinstance(fallback, dict)
                    and fallback.get("status") == "extracted"
                    and fallback.get("extract_exit_code") == 0
                ):
                    # cabarchiveが未対応のLZXでも、境界付き7-Zip fallbackが
                    # 全memberを正常展開できた場合は未完了にしない。
                    continue
                if item == "validation_failed" and ".profiled_transforms.attempts[" in path:
                    continue
                if key == "unpack_status" and _is_incomplete_static_status(item):
                    issues.append(f"{child}:{item}")
                elif key == "status" and _is_incomplete_static_status(item):
                    issues.append(f"{child}:{item}")
                elif (key == "parse_error" or key.endswith("_error")) and (
                    item is not None and item is not False and item != ""
                ):
                    issues.append(child)
                visit(item, child)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                visit(item, f"{path}[{index}]")

    steps = layer_report.get("steps")
    if not isinstance(steps, list):
        steps = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            issues.append(f"steps[{index}]:invalid")
            continue
        step_status = step.get("status")
        if _is_incomplete_static_status(step_status):
            issues.append(f"steps[{index}]:{step_status}")
        visit(step.get("report"), f"steps[{index}].report")
        report = step.get("report")
        if isinstance(report, dict) and "sevenzip" not in report:
            if report.get("format") in {"7z", "apple-disk-image", "cab", "rar"}:
                issues.append(f"steps[{index}].report:container_extractor_unavailable")
            pe_report = report.get("pe")
            if isinstance(pe_report, dict) and pe_report.get("containerized") is True:
                issues.append(f"steps[{index}].report:pe_container_extractor_unavailable")
    return sorted(set(issues))


def _completion_state(
    *,
    assessment_only: bool,
    generic_status: str,
    layer_report: dict[str, Any],
    layer_selections: list[dict[str, Any]],
    selected_families: list[str],
    applicability: list[dict[str, Any]],
    executions: list[dict[str, Any]],
    logic_report: dict[str, Any],
) -> dict[str, Any]:
    """再開・公開判断に使うcase完了状態とblockerを一箇所で算出する。"""

    blockers = []
    if generic_status == "failed":
        blockers.append("generic_triage_failed")
    elif generic_status == "partial":
        blockers.append("generic_triage_partial")
    limit_count = int((layer_report.get("counts") or {}).get("limit_events") or 0)
    if limit_count:
        blockers.append("static_layer_limit_reached")
    static_issues = _static_layer_issues(layer_report)
    if static_issues:
        blockers.append("static_layer_incomplete")

    detector_error_set: set[str] = set()
    for selection in layer_selections:
        if not isinstance(selection, dict):
            continue
        classification = selection.get("classification")
        if not isinstance(classification, dict):
            continue
        observations = classification.get("observations")
        if not isinstance(observations, dict):
            continue
        errors = observations.get("detector_errors")
        if isinstance(errors, dict):
            detector_error_set.update(str(family) for family in errors)
    detector_errors = sorted(detector_error_set)
    if detector_errors:
        blockers.append("detector_error_present")

    execution_values = [item for item in executions if isinstance(item, dict)]
    execution_statuses = [str(item.get("status")) for item in execution_values]
    incomplete_anchor_attempts = []
    if not assessment_only:
        for status in sorted(set(execution_statuses)):
            if status in {
                "failed",
                "preflight_failed",
                "no_evidence",
                "ambiguous_evidence",
                "incompatible_input_format",
            }:
                blockers.append(f"handler_{status}")

        applicable_handlers: dict[str, set[str]] = {family: set() for family in selected_families}
        for item in applicability:
            if not isinstance(item, dict):
                continue
            family = item.get("family")
            handler_id = item.get("id")
            if (
                family in applicable_handlers
                and isinstance(handler_id, str)
                and item.get("status") in {"applicable", "applicable_forced"}
            ):
                applicable_handlers[family].add(handler_id)
        successful_handlers = {
            str(item.get("handler_id")) for item in execution_values if item.get("status") == "succeeded"
        }
        for family, handler_ids in sorted(applicable_handlers.items()):
            if not handler_ids:
                blockers.append(f"selected_family_has_no_automatic_handler:{family}")
            elif not handler_ids.intersection(successful_handlers):
                blockers.append(f"selected_family_has_no_valid_handler_evidence:{family}")

        for execution in execution_values:
            for attempt in execution.get("attempts") or []:
                if not isinstance(attempt, dict) or attempt.get("routing_role") != "selected_family_layer":
                    continue
                attempt_status = attempt.get("status")
                if attempt_status in {"failed", "skipped_incompatible_format"} or (
                    attempt_status == "succeeded" and attempt.get("evidence_status") != "sufficient"
                ):
                    incomplete_anchor_attempts.append(
                        {
                            "handler_id": execution.get("handler_id"),
                            "layer_sha256": (attempt.get("layer") or {}).get("sha256"),
                            "status": attempt_status,
                        }
                    )
        if incomplete_anchor_attempts:
            blockers.append("selected_family_layer_incomplete")
        if logic_report.get("status") == "function_analysis_required":
            blockers.append("representative_function_analysis_required")

    blockers = sorted(set(blockers))
    if assessment_only:
        status = "assessment_only_complete" if not blockers else "partial"
    elif not blockers and selected_families:
        status = "complete"
    elif not blockers:
        status = "triaged_unknown"
    elif generic_status == "failed" and "succeeded" not in execution_statuses:
        status = "failed"
    else:
        status = "partial"
    return {
        "status": status,
        "complete": status in {"complete", "triaged_unknown", "assessment_only_complete"},
        "resumable": status in {"complete", "triaged_unknown", "assessment_only_complete"},
        "blockers": blockers,
        "detector_error_families": detector_errors,
        "static_layer_issues": static_issues,
        "incomplete_selected_layer_attempts": incomplete_anchor_attempts,
    }


def _prepare_case_directory(output: Path, digest: str) -> Path:
    """再解析が確定したSHA-256 caseだけを検証後に空directoryへ初期化する。"""

    normalize_sha256_digest(digest)
    cases_root = output / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(cases_root)
    resolved_root = cases_root.resolve(strict=True)
    case_dir = cases_root / digest
    ensure_no_reparse_components(case_dir)
    if case_dir.exists():
        ensure_tree_without_reparse(case_dir)
        resolved_case = case_dir.resolve(strict=True)
        if not resolved_case.is_dir() or resolved_case.parent != resolved_root or resolved_case.name != digest:
            raise ValueError(f"安全に初期化できないcase directoryです: {digest}")
        shutil.rmtree(case_dir)
    case_dir.mkdir()
    return case_dir


def analyze_unit(
    unit: InputUnit,
    *,
    output: Path,
    registry: Path,
    specs: list[HandlerSpec],
    registered: set[str],
    forced_family: str | None,
    minimum_confidence: str,
    assessment_only: bool,
    analysis_contract: dict[str, Any],
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    force_container_probe: bool = False,
    archive_password: str = "infected",
) -> dict[str, Any]:
    """1検体を分類し、適用可能な既存静的解析器を一括実行する。"""

    digest = hashlib.sha256(unit.data).hexdigest()
    case_dir = _prepare_case_directory(output, digest)
    classifier_family = forced_family if forced_family in registered else None
    if assessment_only:
        layers = [
            StaticLayer(
                name=unit.source_name,
                data=unit.data,
                sha256=digest,
                parent_sha256=None,
                depth=0,
                transform="submission",
            )
        ]
        layer_report = {
            "schema_version": 1,
            "status": "not_run_assessment_only",
            "layers": [layers[0].public()],
            "executed_sample": False,
            "network_contacted": False,
            "recovered_content_exported": False,
        }
    else:
        layers, layer_report = recover_static_layers(
            unit,
            upx=upx,
            sevenzip=sevenzip,
            diec=diec,
            force_container_probe=force_container_probe,
            archive_password=archive_password,
        )
    write_json(case_dir / "static-layers.json", layer_report)

    layer_selections: list[dict[str, Any]] = []
    public_classifications = []
    for layer in layers:
        classification = classify_sample.classify_bytes(
            layer.data,
            Path(layer.name),
            registry,
            classifier_family,
        )
        selected_family, selection_basis = _selected_family(
            classification,
            forced_family,
            minimum_confidence,
        )
        classification["one_shot_selection"] = {
            "family": selected_family,
            "basis": selection_basis,
            "forced_family_registered": (forced_family in registered if forced_family else None),
        }
        layer_selections.append(
            {
                "layer": layer,
                "classification": classification,
                "selected_family": selected_family,
                "selection_basis": selection_basis,
            }
        )
        public_classifications.append(
            {
                "layer": layer.public(),
                "classification": sanitize_public_value(classification),
            }
        )

    root_selection = layer_selections[0]
    root_classification = sanitize_public_value(root_selection["classification"])
    selected_families = sorted(
        {item["selected_family"] for item in layer_selections if item["selected_family"] is not None}
    )
    classification_document = {
        **root_classification,
        "root": root_classification,
        "layer_classifications": public_classifications,
        "selected_families": selected_families,
    }
    applicability = assess_handlers(
        specs,
        layer_selections,
        forced_family,
        registered,
    )
    preflight = _preflight_applicable(specs, applicability)
    available = {item["handler_id"]: item for item in preflight}
    write_json(case_dir / "classification.json", classification_document)
    write_json(
        case_dir / "applicability.json",
        {
            "schema_version": 1,
            "selected_family": root_selection["selected_family"],
            "selected_families": selected_families,
            "selection_basis": root_selection["selection_basis"],
            "catalog": catalog_summary(specs),
            "family_coverage": summarize_family_coverage(specs, registered),
            "handlers": applicability,
            "preflight": preflight,
            "executed_sample": False,
            "network_contacted": False,
        },
    )

    generic_status = "not_run_assessment_only"
    if not assessment_only:
        generic, generic_status = _run_generic_triage(layers, case_dir)
        write_json(case_dir / "generic-triage.json", generic)

    executions = []
    specs_by_id = {item.id: item for item in specs}
    if not assessment_only:
        for item in applicability:
            if item["status"] not in {"applicable", "applicable_forced"}:
                continue
            handler_id = item["id"]
            if not available.get(handler_id, {}).get("available"):
                executions.append(
                    {
                        "handler_id": handler_id,
                        "status": "preflight_failed",
                        "error": available.get(handler_id, {}).get("error"),
                    }
                )
                continue
            attempts = []
            completed = []
            spec = specs_by_id[handler_id]
            plan = plan_handler_layers(spec, item, layers)
            for planned in plan:
                layer = planned["layer"]
                attempt = {
                    "layer": layer.public(),
                    "routing_role": planned["routing_role"],
                    "actual_format": planned["actual_format"],
                    "accepted_formats": list(spec.input_formats),
                }
                if planned["routing_role"] == "unrelated_layer":
                    attempts.append({**attempt, "status": "skipped_unrelated_layer"})
                    continue
                if not planned["compatible"]:
                    attempts.append({**attempt, "status": "skipped_incompatible_format"})
                    continue
                if planned["routing_role"] == "ancestor_fallback" and any(
                    value[0]["sufficient"] and value[0]["tier"] >= 4 for value in completed
                ):
                    attempts.append({**attempt, "status": "skipped_fallback_not_needed"})
                    continue
                try:
                    result = execute_handler(spec, layer.data, layer.name)
                    quality = handler_result_quality(
                        result.get("result"),
                        minimum_score=spec.minimum_evidence_score,
                    )
                    attempts.append(
                        {
                            **attempt,
                            "status": "succeeded",
                            "evidence_status": ("sufficient" if quality["sufficient"] else "insufficient"),
                            "evidence": quality,
                        }
                    )
                    completed.append(
                        (
                            quality,
                            -planned["layer_index"],
                            layer,
                            result,
                        )
                    )
                except Exception as exc:
                    attempts.append(
                        {
                            **attempt,
                            "status": "failed",
                            "error": sanitize_public_value(f"{type(exc).__name__}: {exc}"),
                        }
                    )
            if not completed:
                attempted = any(value["status"] == "failed" for value in attempts)
                executions.append(
                    {
                        "handler_id": handler_id,
                        "status": "failed" if attempted else "incompatible_input_format",
                        "error": (
                            "all_eligible_layers_failed" if attempted else "no_eligible_layer_satisfied_input_contract"
                        ),
                        "attempts": attempts,
                    }
                )
                continue
            selected_quality, _, selected_layer, selected_result = max(
                completed,
                key=lambda value: (
                    value[0]["score"],
                    value[1],
                ),
            )
            strongest = [
                value
                for value in completed
                if value[0]["score"] == selected_quality["score"] and value[0]["sufficient"]
            ]
            ambiguous_layers = sorted({value[2].sha256 for value in strongest})
            if not selected_quality["sufficient"]:
                execution_status = "no_evidence"
            elif len(ambiguous_layers) > 1:
                execution_status = "ambiguous_evidence"
            else:
                execution_status = "succeeded"
            filename = (
                safe_output_name(spec.family)
                + "-"
                + hashlib.sha256(handler_id.encode("utf-8")).hexdigest()[:16]
                + ".json"
            )
            destination = case_dir / "handlers" / filename
            write_json(
                destination,
                {
                    **selected_result,
                    "selected_layer": selected_layer.public(),
                    "selected_evidence": selected_quality,
                    "selected_evidence_score": selected_quality["score"],
                    "selection_strategy": "evidence_tier_then_score_then_root_order",
                    "ambiguous_best_layer_sha256": ambiguous_layers,
                    "attempts": attempts,
                },
            )
            executions.append(
                {
                    "handler_id": handler_id,
                    "status": execution_status,
                    "selected_layer_sha256": selected_layer.sha256,
                    "selected_evidence": selected_quality,
                    "ambiguous_best_layer_sha256": ambiguous_layers,
                    "result": f"handlers/{filename}",
                    "attempts": attempts,
                }
            )

    report = {
        "schema_version": 1,
        "sample": {
            "sha256": digest,
            "size": len(unit.data),
            "source_name": unit.source_name,
            "input_kind": unit.input_kind,
            "outer_sha256": unit.outer_sha256,
            "outer_size": unit.outer_size,
            "member_name": unit.member_name,
        },
        "classification": {
            "family": root_classification.get("malware_type"),
            "confidence": root_classification.get("malware_type_confidence"),
            "campaign": root_classification.get("campaign_type"),
            "selected_family": root_selection["selected_family"],
            "selected_families": selected_families,
            "selection_basis": root_selection["selection_basis"],
        },
        "static_layers": "static-layers.json",
        "generic_triage": generic_status,
        "analysis_contract": analysis_contract,
        "handler_executions": executions,
        "assessment_only": assessment_only,
        "executed_sample": False,
        "network_contacted": False,
        "limitations": [
            "検体と復元層は実行していません。",
            "外部ホストへの接続、C2 probe、stage取得は行っていません。",
            "unknownまたは曖昧な判定ではファミリー固有解析器を自動流用しません。",
            "手動確認対象の特殊解析器はapplicability.jsonへ理由付きで残します。",
        ],
    }
    write_json(case_dir / "report.json", report)
    logic_report = build_static_logic_report(
        sha256=digest,
        family=root_selection["selected_family"] or root_classification.get("malware_type"),
        source_name=unit.source_name,
        data=None if assessment_only else unit.data,
    )
    write_json(case_dir / "static-logic.json", logic_report)
    (case_dir / "STATIC-LOGIC.md").write_text(render_static_logic_markdown(logic_report), encoding="utf-8")
    profile = build_case_profile(case_dir)
    write_json(case_dir / "features.json", profile)
    (case_dir / "FEATURES.md").write_text(render_features_markdown(profile), encoding="utf-8")
    rules = load_rules(CAMPAIGN_CORRELATION_RULES)
    evidence = extract_campaign_evidence(case_dir, profile, rules)
    if CAMPAIGN_FINGERPRINTS.is_file():
        fingerprints = json.loads(CAMPAIGN_FINGERPRINTS.read_text(encoding="utf-8-sig"))
    else:
        fingerprints = {"schema_version": 1, "fingerprints": []}
    campaign_labels = match_fingerprints(evidence, fingerprints)
    write_json(
        case_dir / "campaign-labels.json",
        {
            "schema_version": 1,
            "sha256": digest,
            "labels": campaign_labels,
            "status": "matched" if campaign_labels else "no_strong_match",
            "rule_source": "registry/campaign_fingerprints.json",
            "executed_sample": False,
            "network_contacted": False,
            "safety": {
                "samples_opened": False,
                "samples_executed": False,
                "network_contacted": False,
            },
        },
    )
    completion = _completion_state(
        assessment_only=assessment_only,
        generic_status=generic_status,
        layer_report=layer_report,
        layer_selections=layer_selections,
        selected_families=selected_families,
        applicability=applicability,
        executions=executions,
        logic_report=logic_report,
    )
    report["knowledge_artifacts"] = {
        "features": "features.json",
        "features_markdown": "FEATURES.md",
        "campaign_labels": "campaign-labels.json",
        "static_logic": "static-logic.json",
        "static_logic_markdown": "STATIC-LOGIC.md",
    }
    report["case_state"] = completion
    artifact_paths = [
        "static-layers.json",
        "classification.json",
        "applicability.json",
        "features.json",
        "FEATURES.md",
        "campaign-labels.json",
        "static-logic.json",
        "STATIC-LOGIC.md",
    ]
    if not assessment_only:
        artifact_paths.append("generic-triage.json")
    artifact_paths.extend(item["result"] for item in executions if isinstance(item.get("result"), str))
    report["artifact_sha256"] = artifact_hashes(case_dir, artifact_paths)
    seal_report(report)
    write_json(case_dir / "report.json", report)
    return {
        "sha256": digest,
        "source_name": unit.source_name,
        "family": root_classification.get("malware_type"),
        "selected_family": root_selection["selected_family"],
        "selected_families": selected_families,
        "campaign": root_classification.get("campaign_type"),
        "handler_succeeded": sum(item["status"] == "succeeded" for item in executions),
        "handler_failed": sum(item["status"] in {"failed", "preflight_failed"} for item in executions),
        "handler_no_evidence": sum(item["status"] == "no_evidence" for item in executions),
        "handler_ambiguous": sum(item["status"] == "ambiguous_evidence" for item in executions),
        "handler_incompatible": sum(item["status"] == "incompatible_input_format" for item in executions),
        "analysis_stage_failed": generic_status == "failed",
        "analysis_stage_partial": generic_status == "partial",
        "case_state": completion["status"],
        "report": f"cases/{digest}/report.json",
    }


def _analysis_components(registry: Path, specs: list[HandlerSpec]) -> list[Path]:
    """case結果へ影響する解析コード、検出器、抽出器、規則を列挙する。"""

    components = {
        Path(__file__).resolve(),
        (COMMON_ROOT / "analysis_contract.py").resolve(),
        (COMMON_ROOT / "analyze_family_sample.py").resolve(),
        (COMMON_ROOT / "campaign_correlation.py").resolve(),
        (COMMON_ROOT / "case_features.py").resolve(),
        (COMMON_ROOT / "handler_catalog.py").resolve(),
        (COMMON_ROOT / "static_logic.py").resolve(),
        (FRAMEWORK_ROOT / "requirements.txt").resolve(),
        (CLASSIFIERS_ROOT / "classify_sample.py").resolve(),
        registry.resolve(),
        CAMPAIGN_CORRELATION_RULES.resolve(),
        CAMPAIGN_FINGERPRINTS.resolve(),
    }
    for root in (COMMON_ROOT, CLASSIFIERS_ROOT):
        if root.is_dir():
            components.update(
                path.resolve()
                for path in root.rglob("*.py")
                if "tests" not in path.parts and not path.name.startswith("test_")
            )
    for root in (
        FRAMEWORK_ROOT / "registry",
        FRAMEWORK_ROOT / "malware",
        REPOSITORY_ROOT / "extractors" / "profiles",
        REPOSITORY_ROOT / "unpackers" / "profiles",
    ):
        if not root.is_dir():
            continue
        components.update(
            path.resolve()
            for path in root.rglob("*")
            if path.is_file() and path.suffix.casefold() in {".json", ".yaml", ".yml"}
        )
    for spec in specs:
        path = (REPOSITORY_ROOT / spec.relative_path).resolve()
        if path.is_file():
            components.add(path)
    registry_value = json.loads(registry.read_text(encoding="utf-8-sig"))
    for metadata in (registry_value.get("malware_types") or {}).values():
        if not isinstance(metadata, dict) or not isinstance(metadata.get("detector"), str):
            continue
        path = (FRAMEWORK_ROOT / metadata["detector"]).resolve()
        if path.is_file():
            components.add(path)
    for root in (REPOSITORY_ROOT / "extractors", REPOSITORY_ROOT / "unpackers"):
        if not root.is_dir():
            continue
        components.update(
            path.resolve()
            for path in root.rglob("*.py")
            if "tests" not in path.parts and not path.name.startswith("test_")
        )
    return sorted(components, key=lambda path: str(path).casefold())


def _normalize_tool_path(value: Path | None, label: str) -> Path | None:
    """明示指定された外部静的toolを通常fileへ限定する。"""

    if value is None:
        return None
    try:
        resolved = value.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label}が見つかりません: {value}") from exc
    if not resolved.is_file():
        raise ValueError(f"{label}は通常fileで指定してください: {value}")
    return resolved


def _tool_identity(path: Path | None) -> dict[str, Any] | None:
    """外部toolの絶対pathを公開せず、名前・size・内容hashを契約化する。"""

    if path is None:
        return None
    data = path.read_bytes()
    return {
        "name": path.name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _static_tool_settings(upx: Path | None, sevenzip: Path | None, diec: Path | None) -> dict[str, Any]:
    return {
        "upx": _tool_identity(upx),
        "sevenzip": _tool_identity(sevenzip),
        "diec": _tool_identity(diec),
    }


def _build_analysis_contract(
    *,
    registry: Path,
    specs: list[HandlerSpec],
    archive_mode: str,
    forced_family: str | None,
    minimum_confidence: str,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    force_container_probe: bool = False,
    archive_password: str = "infected",
    assessment_only: bool,
    max_file_size: int,
) -> dict[str, Any]:
    """再開判定に必要なコード・レジストリ・設定指紋を構築する。"""

    catalog = json.dumps(
        [spec.public() for spec in specs],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    settings = {
        "archive_mode": archive_mode,
        "forced_family": forced_family,
        "minimum_confidence": minimum_confidence,
        "assessment_only": assessment_only,
        "max_file_size": max_file_size,
        "static_tools": _static_tool_settings(upx, sevenzip, diec),
        "force_container_probe": force_container_probe,
        "archive_password_fingerprint": hashlib.sha256(archive_password.encode("utf-8")).hexdigest(),
        "handler_catalog_sha256": hashlib.sha256(catalog).hexdigest(),
        "runtime": runtime_dependency_versions(),
    }
    return build_pipeline_fingerprint(
        repository_root=REPOSITORY_ROOT,
        components=_analysis_components(registry, specs),
        settings=settings,
    )


def load_resumable_case(
    output: Path,
    digest: str,
    *,
    assessment_only: bool,
    expected_contract: dict[str, Any],
    unit: InputUnit,
) -> dict[str, Any] | None:
    """同一入力・同一契約・全成果物一致の完了caseだけを再利用する。"""

    normalize_sha256_digest(digest)
    case_dir = output / "cases" / digest
    if not case_dir.exists():
        return None
    ensure_no_reparse_components(case_dir)
    try:
        report_path = resolve_case_artifact(case_dir, "report.json")
    except ValueError as exc:
        if "reparse point" in str(exc):
            raise
        return None
    try:
        report = load_json_object_strict(report_path)
    except ValueError:
        return None
    integrity_errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        expected_contract=expected_contract,
        require_resumable=True,
    )
    if any("reparse" in error for error in integrity_errors):
        raise ValueError(f"再開対象caseにreparse pointがあります: {digest} ({integrity_errors})")
    if integrity_errors:
        return None
    state = report.get("case_state")
    sample = report.get("sample")
    classification = report.get("classification")
    executions = report.get("handler_executions")
    provenance = {
        "source_name": unit.source_name,
        "input_kind": unit.input_kind,
        "outer_sha256": unit.outer_sha256,
        "member_name": unit.member_name,
    }
    if any(sample.get(key) != value for key, value in provenance.items()):
        return None
    if report.get("assessment_only") is not assessment_only:
        return None
    selected_families = classification.get("selected_families")
    source_name = sample.get("source_name")
    if not isinstance(source_name, str) or not source_name:
        return None
    statuses = [item.get("status") for item in executions if isinstance(item, dict)]
    return {
        "sha256": digest,
        "source_name": source_name,
        "family": classification.get("family"),
        "selected_family": classification.get("selected_family"),
        "selected_families": selected_families,
        "campaign": classification.get("campaign"),
        "handler_succeeded": sum(status == "succeeded" for status in statuses),
        "handler_failed": sum(status in {"failed", "preflight_failed"} for status in statuses),
        "handler_no_evidence": sum(status == "no_evidence" for status in statuses),
        "handler_ambiguous": sum(status == "ambiguous_evidence" for status in statuses),
        "handler_incompatible": sum(status == "incompatible_input_format" for status in statuses),
        "analysis_stage_failed": report.get("generic_triage") == "failed",
        "analysis_stage_partial": report.get("generic_triage") == "partial",
        "case_state": state.get("status"),
        "report": f"cases/{digest}/report.json",
        "resumed": True,
    }


def run_batch(
    inputs: list[Path],
    output: Path,
    *,
    registry: Path = DEFAULT_REGISTRY,
    password: str = "infected",
    archive_mode: str = "auto",
    forced_family: str | None = None,
    minimum_confidence: str = "medium",
    assessment_only: bool = False,
    max_files: int = DEFAULT_MAX_FILES,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    force_container_probe: bool = False,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    resume: bool = False,
) -> dict[str, Any]:
    """複数入力をSHA-256で重複排除し、失敗を検体単位に分離する。"""

    output.mkdir(parents=True, exist_ok=True)
    paths = collect_inputs(inputs, output, max_files)
    if archive_mode == "malwarebazaar":
        paths = [path for path in paths if path.suffix.casefold() == ".zip"]
    if not paths:
        raise ValueError("解析対象ファイルがありません")
    if not isinstance(password, str):
        raise TypeError("archive passwordは文字列で指定してください")
    upx = _normalize_tool_path(upx, "UPX")
    sevenzip = _normalize_tool_path(sevenzip, "7-Zip")
    diec = _normalize_tool_path(diec, "Detect It Easy CLI")

    clear_handler_caches()
    classify_sample.clear_classifier_caches()
    clear_profile_cache()
    clear_known_hash_cache()
    specs = discover_handlers()
    registered = _registered_families(registry)
    forced_family = normalize_family(forced_family) if forced_family else None
    if forced_family and forced_family not in registered:
        raise ValueError(f"未登録のファミリーです: {forced_family}")
    analysis_contract = _build_analysis_contract(
        registry=registry,
        specs=specs,
        archive_mode=archive_mode,
        forced_family=forced_family,
        minimum_confidence=minimum_confidence,
        assessment_only=assessment_only,
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        force_container_probe=force_container_probe,
        archive_password=password,
        max_file_size=max_file_size,
    )
    cases = []
    errors = []
    duplicates = []
    seen: set[str] = set()
    for path in paths:
        try:
            unit = read_input_unit(
                path,
                password=password,
                archive_mode=archive_mode,
                max_file_size=max_file_size,
            )
            digest = hashlib.sha256(unit.data).hexdigest()
            if digest in seen:
                duplicates.append({"source_name": path.name, "sha256": digest})
                continue
            seen.add(digest)
            if resume:
                resumed = load_resumable_case(
                    output,
                    digest,
                    assessment_only=assessment_only,
                    expected_contract=analysis_contract,
                    unit=unit,
                )
                if resumed is not None:
                    cases.append(resumed)
                    continue
            cases.append(
                analyze_unit(
                    unit,
                    output=output,
                    registry=registry,
                    specs=specs,
                    registered=registered,
                    forced_family=forced_family,
                    minimum_confidence=minimum_confidence,
                    upx=upx,
                    sevenzip=sevenzip,
                    diec=diec,
                    force_container_probe=force_container_probe,
                    archive_password=password,
                    assessment_only=assessment_only,
                    analysis_contract=analysis_contract,
                )
            )
        except Exception as exc:
            errors.append(
                {
                    "source_name": path.name,
                    "error": sanitize_public_value(f"{type(exc).__name__}: {exc}"),
                }
            )
    summary = {
        "schema_version": 1,
        "counts": {
            "input_files": len(paths),
            "analyzed": len(cases),
            "duplicates": len(duplicates),
            "errors": len(errors),
            "identified": sum(bool(item["selected_families"]) for item in cases),
            "unknown_or_ambiguous": sum(not item["selected_families"] for item in cases),
            "handler_successes": sum(item["handler_succeeded"] for item in cases),
            "handler_failures": sum(item["handler_failed"] for item in cases),
            "handler_no_evidence": sum(item["handler_no_evidence"] for item in cases),
            "handler_ambiguous": sum(item["handler_ambiguous"] for item in cases),
            "handler_incompatible": sum(item["handler_incompatible"] for item in cases),
            "analysis_stage_failures": sum(item["analysis_stage_failed"] for item in cases),
            "analysis_stage_partial": sum(item["analysis_stage_partial"] for item in cases),
            "complete": sum(item["case_state"] == "complete" for item in cases),
            "triaged_unknown": sum(item["case_state"] == "triaged_unknown" for item in cases),
            "partial": sum(item["case_state"] == "partial" for item in cases),
            "failed": sum(item["case_state"] == "failed" for item in cases),
            "resumed": sum(bool(item.get("resumed")) for item in cases),
        },
        "catalog": catalog_summary(specs),
        "analysis_contract": analysis_contract,
        "cases": cases,
        "duplicates": duplicates,
        "errors": errors,
        "settings": {
            "archive_mode": archive_mode,
            "forced_family": forced_family,
            "minimum_confidence": minimum_confidence,
            "assessment_only": assessment_only,
            "max_files": max_files,
            "max_file_size": max_file_size,
            "static_tools": {
                "upx": upx.name if upx else None,
                "sevenzip": sevenzip.name if sevenzip else None,
                "diec": diec.name if diec else None,
            },
            "force_container_probe": force_container_probe,
            "resume": resume,
        },
        "executed_sample": False,
        "network_contacted": False,
    }
    write_json(output / "summary.json", summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    """日本語helpを持つ一括静的解析CLIを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        help="解析するファイルまたはディレクトリ。複数回指定できます。",
    )
    parser.add_argument("--output", required=True, type=Path, help="解析結果の出力先。")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY, help="検出器レジストリ。")
    parser.add_argument("--password", default="infected", help="受け入れ用暗号化ZIPのパスワード。")
    parser.add_argument(
        "--archive-mode",
        choices=("auto", "raw", "malwarebazaar"),
        default="auto",
        help="autoは暗号化単一メンバーZIPだけをメモリ内展開します。",
    )
    parser.add_argument("--family", help="ファミリーを明示選択します。構造一致の代替証拠にはしません。")
    parser.add_argument(
        "--minimum-confidence",
        choices=("low", "medium", "high"),
        default="medium",
        help="ファミリー固有解析器を自動実行する最低確度。",
    )
    parser.add_argument(
        "--assessment-only",
        action="store_true",
        help="適用可否判定だけを行い、汎用・ファミリー固有解析器を実行しません。",
    )
    parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES, help="入力ファイル数の上限。")
    parser.add_argument(
        "--max-file-size",
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        help="外装と内包検体それぞれのbyte上限。",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="安全フラグと必須成果物を検証できた完了caseを再利用します。",
    )
    parser.add_argument(
        "--upx",
        type=Path,
        help="任意のUPX実行file。明示指定時だけ静的展開へ使用します。",
    )
    parser.add_argument(
        "--sevenzip",
        type=Path,
        help="任意の7-Zip実行file。7z/RAR/CAB/DMG/PE containerの静的展開に使用します。",
    )
    parser.add_argument(
        "--diec",
        type=Path,
        help="任意のDetect It Easy CLI実行file。PE/Mach-O識別補助に使用します。",
    )
    parser.add_argument(
        "--force-container-probe",
        action="store_true",
        help="レビュー済み手掛かりがあるPEを7-Zipで追加検査します。",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、失敗を検体単位に分離した一括解析を実行する。"""

    args = build_parser().parse_args(argv)
    summary = run_batch(
        args.input,
        args.output,
        registry=args.registry,
        password=args.password,
        archive_mode=args.archive_mode,
        forced_family=args.family,
        minimum_confidence=args.minimum_confidence,
        assessment_only=args.assessment_only,
        max_files=args.max_files,
        upx=args.upx,
        sevenzip=args.sevenzip,
        diec=args.diec,
        force_container_probe=args.force_container_probe,
        max_file_size=args.max_file_size,
        resume=args.resume,
    )
    print(json.dumps(summary["counts"], ensure_ascii=False, indent=2))
    incomplete = summary["counts"]["errors"] + summary["counts"]["partial"] + summary["counts"]["failed"]
    return 0 if incomplete == 0 else 20


if __name__ == "__main__":
    raise SystemExit(main())
