#!/usr/bin/env python3
"""検体の適用可否判定から静的解析までを1コマンドで実行する。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections import Counter, deque
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pyzipper

COMMON_ROOT = Path(__file__).resolve().parent
FRAMEWORK_ROOT = COMMON_ROOT.parent
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
CLASSIFIERS_ROOT = FRAMEWORK_ROOT / "classifiers"
DEFAULT_REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"
DEFAULT_MAX_FILE_SIZE = 512 * 1024 * 1024
DEFAULT_MAX_FILES = 1_000
MAX_FOLLOW_ON_ARTIFACTS = 64
MAX_FOLLOW_ON_EDGES = 128
MAX_FOLLOW_ON_OMITTED_METADATA = 4096
MAX_FOLLOW_ON_DEPTH = 4
MAX_FOLLOW_ON_TOTAL_BYTES = 256 * 1024 * 1024
MAX_FOLLOW_ON_PAYLOAD_SIZE = 128 * 1024 * 1024
MAX_FOLLOW_ON_WALL_SECONDS = 300.0
MAX_FOLLOW_ON_CHILD_SECONDS = 120.0
MAX_FOLLOW_ON_WORKER_REQUEST = 64 * 1024
MAX_FOLLOW_ON_WORKER_RESPONSE = 4 * 1024 * 1024
MAX_DIRECT_CLI_SECONDS = 24 * 60 * 60
MAX_DIRECT_CLI_ACTIVE_PROCESSES = 32
MAX_DIRECT_CLI_MEMORY_BYTES = 4 * 1024 * 1024 * 1024
MAX_FOLLOW_ON_WORKER_ACTIVE_PROCESSES = 8
MAX_FOLLOW_ON_WORKER_MEMORY_BYTES = 2 * 1024 * 1024 * 1024
MAX_HANDLER_ATTEMPTS_PER_CASE = 64
MAX_HANDLER_RESULT_BYTES_PER_CASE = 16 * 1024 * 1024
MAX_HANDLER_WALL_SECONDS_PER_CASE = 300.0
MAX_STATIC_TOOL_BINARY_BYTES = 128 * 1024 * 1024
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
import orchestration_outcome  # noqa: E402
import runtime_contract  # noqa: E402
import static_layer_pipeline as static_layers  # noqa: E402
from follow_on_commitment import (  # noqa: E402
    canonical_multiset_commitment,
    metadata_identity,
)
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
from campaign_correlation import (  # noqa: E402
    extract_campaign_evidence,
    load_rules,
    match_fingerprints,
)
from case_features import build_case_profile, render_features_markdown  # noqa: E402
from extractors.profiled_family import clear_profile_cache  # noqa: E402
from handler_catalog import (  # noqa: E402
    DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
    DEFAULT_MAXIMUM_ASSESSMENT_TOTAL_SIZE,
    MAX_ASSESSMENT_ATTEMPTS,
    MAX_ASSESSMENT_LAYERS,
    HandlerSpec,
    assess_candidate_handlers,
    catalog_summary,
    clear_handler_caches,
    collect_detector_evaluations,
    discover_handlers,
    execute_handler_bounded_for_assessment,
    sanitize_public_value,
    _bounded_handler_environment,
    _read_verified_artifact,
)
from malware_io import (  # noqa: E402
    read_file_capped,
    read_single_aes_zip_member,
    safe_output_name,
    sha256_bytes,
    write_json,
)
from profiled_family_detector import clear_known_hash_cache  # noqa: E402
from static_logic import (  # noqa: E402
    build_static_logic_report,
    function_analysis_is_available,
    render_static_logic_markdown,
)
from unpackers.static_unpacker import detect_format, unpack_bytes  # noqa: E402

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
DEFAULT_STRING_SCAN_LIMIT = analyze_family_sample.DEFAULT_STRING_SCAN_LIMIT
BINARY_FORMATS = frozenset({"pe", "elf", "macho"})
FAMILY_POLICY_CATEGORIES = frozenset(
    {
        "rat",
        "stealer",
        "loader",
        "downloader",
        "backdoor",
        "ransomware",
        "worm",
        "bot",
        "keylogger",
        "miner",
        "other",
    }
)


def _bounded_json_size(value: Any, *, maximum_bytes: int) -> int | None:
    """JSONを連結せず走査し、上限内ならUTF-8 byte数を返す。"""

    total = 0
    try:
        chunks = json.JSONEncoder(
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).iterencode(value)
        for chunk in chunks:
            total += len(chunk.encode("utf-8"))
            if total > maximum_bytes:
                return None
    except (RecursionError, TypeError, ValueError):
        return None
    return total


CAMPAIGN_CORRELATION_RULES = FRAMEWORK_ROOT / "registry" / "campaign_correlation_rules.json"
CAMPAIGN_FINGERPRINTS = FRAMEWORK_ROOT / "registry" / "campaign_fingerprints.json"
FAMILY_ANALYSIS_REQUIREMENTS = FRAMEWORK_ROOT / "registry" / "family_analysis_requirements.json"


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


def _positive_integer(value: str) -> int:
    """CLI引数を正の整数へ変換し、0以下と非整数を拒否する。"""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("正の整数で指定してください") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("正の整数で指定してください")
    return parsed


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
    max_static_layers: int = MAX_STATIC_LAYERS,
    archive_password: str = "infected",
) -> tuple[list[StaticLayer], dict[str, Any]]:
    """共有パイプラインへ既存unpackerと公開値sanitizerを注入する互換入口。"""

    return recover_layer_pipeline(
        unit,
        unpacker=unpack_bytes,
        sanitizer=sanitize_public_value,
        policy=StaticLayerPolicy(max_layers=max_static_layers),
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        force_container_probe=force_container_probe,
        archive_password=archive_password,
    )


def _layer_count_limit_reached(layer_report: dict[str, Any]) -> bool:
    """静的復元が層数上限へ達した場合だけ再試行対象とする。"""

    events = layer_report.get("limit_events")
    return isinstance(events, list) and any(
        isinstance(event, dict) and event.get("reason") == "layer_count_limit" for event in events
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


def _load_family_hint_manifest(
    supplied: Path | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """外部ヒントを厳格に読み、内容識別子とともに返す。"""

    if supplied is None:
        return None, None
    path = supplied.expanduser()
    manifest = classify_sample.load_family_hint_manifest(path)
    canonical = json.dumps(
        manifest,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    identity = {
        "name": path.name,
        "canonical_size": len(canonical),
        "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
    }
    return manifest, identity


def _verification_candidates(routing: dict[str, Any]) -> list[dict[str, Any]]:
    """通常の確定経路を除き、handlerで再検証できる候補だけを返す。"""

    values = routing.get("candidates")
    if not isinstance(values, list):
        return []
    return [
        item
        for item in values
        if isinstance(item, dict)
        and item.get("routing_eligible") is True
        and item.get("routing_mode") == "candidate_verification"
        and isinstance(item.get("routing_eligibility"), dict)
        and item["routing_eligibility"].get("candidate_verification") is True
    ]


def _load_family_analysis_requirements(path: Path = FAMILY_ANALYSIS_REQUIREMENTS) -> dict[str, dict[str, Any]]:
    """family別の必須成果物policyを厳格schemaで読み込む。"""

    document = load_json_object_strict(path)
    if (
        set(document) != {"schema_version", "policies"}
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
    ):
        raise ValueError("family analysis requirementsのroot schemaが不正です")
    supplied = document.get("policies")
    if not isinstance(supplied, dict) or len(supplied) > 512:
        raise ValueError("family analysis requirementsのpoliciesが不正です")
    expected = {"category", "config_required", "network_required", "terminal_payload_required"}
    policies: dict[str, dict[str, Any]] = {}
    for family, policy in supplied.items():
        if not isinstance(family, str) or classify_sample.FAMILY_ID_RE.fullmatch(family) is None:
            raise ValueError("family analysis requirementsに不正なfamilyがあります")
        if not isinstance(policy, dict) or set(policy) != expected:
            raise ValueError(f"family analysis requirementsのfieldが不正です: {family}")
        if policy.get("category") not in FAMILY_POLICY_CATEGORIES:
            raise ValueError(f"family analysis requirementsのcategoryが不正です: {family}")
        if any(type(policy.get(key)) is not bool for key in expected - {"category"}):
            raise ValueError(f"family analysis requirementsのbooleanが不正です: {family}")
        policies[family] = dict(policy)
    return dict(sorted(policies.items()))


def _requirements_policy_summary(policies: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """requirements policyのcoverageを機械可読に要約する。"""

    categories = {
        category: sum(policy.get("category") == category for policy in policies.values())
        for category in sorted(FAMILY_POLICY_CATEGORIES)
    }
    return {
        "source": "registry/family_analysis_requirements.json",
        "declared_family_count": len(policies),
        "categories": categories,
        "undeclared_family_policy": "block_complete_after_resolution",
    }


def _candidate_handler_assessment(
    *,
    routing: dict[str, Any],
    layers: list[StaticLayer],
    layer_classifications: list[dict[str, Any]],
    specs: list[HandlerSpec],
    assessment_only: bool,
    artifact_directory: Path | None,
) -> dict[str, Any]:
    """互換layerを容量・試行数の上限内で静的に候補検証する。"""

    candidates = _verification_candidates(routing)
    base = {
        "schema_version": 1,
        "candidate_count": len(candidates),
        "executed_sample": False,
        "network_contacted": False,
        "filesystem_written_by_handlers": False,
    }
    if assessment_only:
        return {**base, "status": "not_run_assessment_only", "planned_attempt_count": 0, "families": []}
    if not candidates:
        return {**base, "status": "no_candidates", "planned_attempt_count": 0, "families": []}
    candidate_families = {str(item["family"]) for item in candidates}
    candidate_specs = [spec for spec in specs if spec.automatic and spec.family in candidate_families]
    attempts_per_layer = sum(sum(spec.family == family for spec in candidate_specs) for family in candidate_families)
    if attempts_per_layer <= 0:
        return {**base, "status": "no_automatic_handler", "planned_attempt_count": 0, "families": []}

    supported_hashes = {
        digest for item in candidates for digest in item.get("layer_sha256", []) if isinstance(digest, str)
    }
    eligible: list[tuple[int, StaticLayer, str]] = []
    excluded: list[dict[str, Any]] = []
    for index, layer in enumerate(layers):
        actual_format = detect_format(layer.data, layer.name)
        if not any(format_compatible(spec.input_formats, actual_format) for spec in candidate_specs):
            excluded.append({"layer": layer.public(), "reason": "no_candidate_handler_accepts_format"})
        elif len(layer.data) > DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE:
            excluded.append({"layer": layer.public(), "reason": "candidate_layer_size_limit"})
        else:
            eligible.append((index, layer, actual_format))

    layer_limit = min(MAX_ASSESSMENT_LAYERS, MAX_ASSESSMENT_ATTEMPTS // attempts_per_layer)
    ordered = sorted(
        eligible,
        key=lambda item: (0 if item[1].sha256 in supported_hashes else 1, item[1].depth, item[0]),
    )
    selected: list[tuple[int, StaticLayer, str]] = []
    total_size = 0
    for item in ordered:
        if len(selected) >= layer_limit:
            excluded.append({"layer": item[1].public(), "reason": "candidate_attempt_limit"})
            continue
        if total_size + len(item[1].data) > DEFAULT_MAXIMUM_ASSESSMENT_TOTAL_SIZE:
            excluded.append({"layer": item[1].public(), "reason": "candidate_total_size_limit"})
            continue
        selected.append(item)
        total_size += len(item[1].data)
    if not selected:
        return {
            **base,
            "status": "no_eligible_layer_within_limits",
            "planned_attempt_count": 0,
            "families": [],
            "excluded_layers": excluded,
        }

    selected_hashes = {item[1].sha256 for item in selected}
    assessment_layers = [
        {
            "name": layer.name,
            "data": layer.data,
            "sha256": layer.sha256,
            "parent_sha256": layer.parent_sha256 if layer.parent_sha256 in selected_hashes else None,
            "depth": layer.depth,
            "transform": layer.transform,
            "format": actual_format,
        }
        for _index, layer, actual_format in selected
    ]
    result = assess_candidate_handlers(
        candidates,
        assessment_layers,
        detector_evaluations=collect_detector_evaluations(layer_classifications),
        specs=candidate_specs,
        maximum_attempts=MAX_ASSESSMENT_ATTEMPTS,
        artifact_directory=artifact_directory,
        artifact_path_prefix="p",
    )
    result["selected_layer_count"] = len(selected)
    result["selected_total_size"] = total_size
    result["excluded_layers"] = excluded
    return sanitize_public_value(result)


def _preflight_applicable(specs: list[HandlerSpec], applicability: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """親processではimportせず、layer単位の事前検査を隔離workerへ委譲する。"""

    known_ids = {item.id for item in specs}
    results = []
    for item in applicability:
        if item["status"] not in {"applicable", "applicable_forced"}:
            continue
        handler_id = item["id"]
        results.append(
            {
                "handler_id": handler_id,
                "available": handler_id in known_ids,
                "error": None if handler_id in known_ids else "handler_spec_not_found",
                "execution_boundary": "bounded_assessment_worker",
                "preflight": "deferred_to_per_layer_worker",
            }
        )
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


def _run_generic_triage(
    layers: list[StaticLayer],
    case_dir: Path,
    *,
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
) -> tuple[dict[str, Any], str]:
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
                string_scan_limit=string_scan_limit,
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
    steps = layer_report.get("steps")
    if not isinstance(steps, list):
        steps = []
    dotnet_recovered_layers = {
        str(step.get("input_layer", {}).get("sha256"))
        for step in steps
        if isinstance(step, dict)
        and isinstance(step.get("input_layer"), dict)
        and isinstance(step.get("report"), dict)
        and isinstance(step["report"].get("dotnet_bundle"), dict)
        and step["report"]["dotnet_bundle"].get("status") == "recovered"
    }

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for raw_key, item in value.items():
                key = str(raw_key).casefold()
                child = f"{path}.{raw_key}"
                fallback = value.get("sevenzip")
                authoritative = value.get("embedded_installer_archive")
                recovered = value.get("recovered")
                embedded_dotnet_recovered = isinstance(recovered, list) and any(
                    isinstance(candidate, dict)
                    and candidate.get("kind") == "embedded-pe"
                    and candidate.get("sha256") in dotnet_recovered_layers
                    for candidate in recovered
                )
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
                    key in {"cab", "dotnet_bundle"}
                    and isinstance(item, dict)
                    and item.get("status") == "parse_failed"
                    and (
                        (
                            isinstance(fallback, dict)
                            and fallback.get("status") == "extracted"
                            and fallback.get("extract_exit_code") == 0
                        )
                        or (key == "dotnet_bundle" and embedded_dotnet_recovered)
                    )
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


def _handler_static_logic_records(
    case_dir: Path,
    executions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """成功ハンドラーが公開した代表関数をcaseの標準ロジックへ集約する。"""

    records: list[dict[str, Any]] = []
    root = case_dir.resolve()
    for execution in executions:
        if execution.get("status") != "succeeded":
            continue
        relative = execution.get("result")
        if not isinstance(relative, str):
            continue
        candidate = (case_dir / relative).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if not candidate.is_file():
            continue
        artifact = load_json_object_strict(candidate)
        payload = artifact.get("result")
        functions = payload.get("representative_functions") if isinstance(payload, dict) else None
        if not isinstance(functions, list):
            continue
        records.extend(item for item in functions[:128] if isinstance(item, dict))
    return records[:512]


def _verified_outputs_from_wrapper(value: Any) -> list[dict[str, Any]]:
    """handler wrapperが生成した検証済みbinary metadataだけを返す。"""

    if not isinstance(value, dict):
        return []
    supplied = value.get("verified_binary_outputs")
    if not isinstance(supplied, list) or not supplied:
        supplied = value.get("observed_binary_outputs")
    if not isinstance(supplied, list):
        return []
    return [item for item in supplied if isinstance(item, dict)]


def _verified_output_audit_from_wrapper(value: Any) -> dict[str, Any] | None:
    """handler wrapperの保持・後続解析auditを改変せずoutcome境界へ渡す。"""

    if not isinstance(value, dict):
        return None
    supplied = value.get("verified_binary_output_audit")
    return supplied if isinstance(supplied, dict) else None


def _legacy_outcome_handler_records(
    case_dir: Path,
    executions: list[dict[str, Any]],
    specs: list[HandlerSpec],
    *,
    wrapper_overrides: Mapping[Path, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """既存handler結果をfamily付きのoutcome証拠へ正規化する。"""

    by_id = {spec.id: spec for spec in specs}
    records = []
    for execution in executions:
        handler_id = execution.get("handler_id")
        spec = by_id.get(handler_id)
        if spec is None:
            continue
        record = {
            "source": "selected_family_analysis",
            "family": spec.family,
            "handler_id": handler_id,
            "status": execution.get("status"),
            "selected_evidence": execution.get("selected_evidence"),
            "selected_layer_sha256": execution.get("selected_layer_sha256"),
        }
        relative = execution.get("result")
        if isinstance(relative, str):
            wrapper_path = resolve_case_artifact(case_dir, relative)
            wrapper = wrapper_overrides.get(wrapper_path) if wrapper_overrides is not None else None
            if wrapper is None:
                wrapper = load_json_object_strict(wrapper_path)
            record["result"] = wrapper
            verified = _verified_outputs_from_wrapper(wrapper)
            if verified:
                record["verified_binary_outputs"] = verified
            audit = _verified_output_audit_from_wrapper(wrapper)
            if audit is not None:
                record["verified_binary_output_audit"] = audit
        records.append(record)
    return records


def _candidate_outcome_handler_records(assessment: dict[str, Any]) -> list[dict[str, Any]]:
    """候補handlerの全試行をfamily付きのoutcome証拠へ正規化する。"""

    records = []
    for family_result in assessment.get("families") or []:
        if not isinstance(family_result, dict):
            continue
        family = family_result.get("family")
        for attempt in family_result.get("attempts") or []:
            if not isinstance(attempt, dict):
                continue
            supplied_source = attempt.get("source")
            source = (
                supplied_source if isinstance(supplied_source, str) and supplied_source else "candidate_verification"
            )
            records.append(
                {
                    "source": source,
                    "family": family,
                    "handler_id": attempt.get("handler_id"),
                    "status": attempt.get("status"),
                    "handler_evidence": attempt.get("handler_evidence"),
                    "detector_corroboration": attempt.get("detector_corroboration"),
                    "selected_layer_sha256": (
                        attempt.get("selected_layer_sha256") or (attempt.get("layer") or {}).get("sha256")
                    ),
                    "verified_binary_outputs": _verified_outputs_from_wrapper(attempt.get("result")),
                    "verified_binary_output_audit": _verified_output_audit_from_wrapper(attempt.get("result")),
                    "result": attempt.get("result"),
                }
            )
    return records


def _outcome_candidates(
    routing: dict[str, Any],
    layers: list[StaticLayer],
    logic_report: dict[str, Any],
    requirements_policy: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """binaryの未完了関数解析を候補familyの必須gateへ反映する。"""

    function_required = not function_analysis_is_available(logic_report) and any(
        detect_format(layer.data, layer.name) in BINARY_FORMATS for layer in layers
    )
    candidates = []
    for supplied in routing.get("candidates") or []:
        if not isinstance(supplied, dict):
            continue
        candidate = dict(supplied)
        family = candidate.get("family")
        policy = requirements_policy.get(family) if isinstance(family, str) else None
        requirements = {
            "policy_declared": policy is not None,
            "policy_category": policy.get("category") if policy is not None else None,
            "config_required": policy.get("config_required") if policy is not None else None,
            "network_required": policy.get("network_required") if policy is not None else None,
            "terminal_payload_required": (policy.get("terminal_payload_required") if policy is not None else None),
        }
        if function_required:
            requirements["function_analysis_required"] = True
        candidate["requirements"] = requirements
        candidates.append(candidate)
    return candidates


def _public_outcome_handler_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """秘密値やhandler本文を除いた証拠索引を返す。"""

    return [
        {
            key: record.get(key)
            for key in (
                "source",
                "family",
                "handler_id",
                "status",
                "selected_evidence",
                "handler_evidence",
                "detector_corroboration",
                "selected_layer_sha256",
                "verified_binary_outputs",
                "verified_binary_output_audit",
            )
        }
        for record in records
    ]


def _automation_summary_state(outcome: dict[str, Any]) -> str:
    """自動処理の結果をresolved・partial・unknownの排他的状態へ変換する。"""

    resolution = outcome.get("family_resolution")
    resolution_status = resolution.get("status") if isinstance(resolution, dict) else None
    blockers = set(outcome.get("blockers") or [])
    if outcome.get("status") == "complete" and resolution_status == "resolved":
        return "resolved"
    if resolution_status in {"unresolved", "ambiguous"} and blockers.issubset({"family_resolution"}):
        return "unknown"
    return "partial"


def _synchronize_completion_with_outcome(
    completion: dict[str, Any],
    outcome: Mapping[str, Any],
) -> None:
    """resolved familyでは厳格orchestration gateをcase stateへfail-closedで反映する。"""

    resolution = outcome.get("family_resolution")
    if not isinstance(resolution, Mapping) or resolution.get("status") != "resolved":
        return
    previous = [
        item
        for item in completion.get("blockers", [])
        if isinstance(item, str) and not item.startswith("orchestration:")
    ]
    orchestration_blockers = [
        f"orchestration:{item}" for item in outcome.get("blockers", []) if isinstance(item, str) and item
    ]
    blockers = sorted(set((*previous, *orchestration_blockers)))
    completion["blockers"] = blockers
    if blockers:
        if completion.get("status") != "failed":
            completion["status"] = "partial"
        completion["complete"] = False
        completion["resumable"] = False
    elif completion.get("status") != "failed":
        completion["status"] = "complete"
        completion["complete"] = True
        completion["resumable"] = True


def _apply_requirements_policy_gate(
    outcome: dict[str, Any],
    requirements_policy: dict[str, dict[str, Any]],
) -> None:
    """resolved familyにpolicy宣言がない場合、completeをfail-closedで拒否する。"""

    resolution = outcome.get("family_resolution")
    resolved = isinstance(resolution, dict) and resolution.get("status") == "resolved"
    resolved_family = resolution.get("family") if resolved else None
    declared = isinstance(resolved_family, str) and resolved_family in requirements_policy
    outcome["requirements_policy"] = {
        "schema_version": 1,
        "source": "registry/family_analysis_requirements.json",
        "declared_family_count": len(requirements_policy),
        "resolved_family": resolved_family,
    }
    outcome.setdefault("quality_gates", {})["requirements_policy"] = {
        "required": resolved,
        "satisfied": bool(not resolved or declared),
        "observed": declared if resolved else None,
        "status": "satisfied" if resolved and declared else ("required_missing" if resolved else "not_applicable"),
    }
    if resolved and not declared:
        blockers = set(outcome.get("blockers") or [])
        blockers.add("requirements_policy")
        outcome["blockers"] = sorted(blockers)
        outcome["status"] = "partial"
        actions = list(outcome.get("next_actions_ja") or [])
        action = "familyの必須config・通信先・最終payload policyをregistryへ宣言してください。"
        if action not in actions:
            actions.append(action)
        outcome["next_actions_ja"] = actions


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
        if selected_families and not function_analysis_is_available(logic_report):
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
        "complete": status in {"complete", "assessment_only_complete"},
        "resumable": status in {"complete", "assessment_only_complete"},
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
    family_hint_manifest: dict[str, Any] | None = None,
    family_requirements_policy: dict[str, dict[str, Any]] | None = None,
    upx: Path | None = None,
    sevenzip: Path | None = None,
    diec: Path | None = None,
    force_container_probe: bool = False,
    max_static_layers: int = MAX_STATIC_LAYERS,
    retry_max_static_layers: int | None = None,
    archive_password: str = "infected",
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
    follow_on_lineage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """1検体を分類し、適用可能な既存静的解析器を一括実行する。"""

    digest = hashlib.sha256(unit.data).hexdigest()
    requirements_policy = (
        family_requirements_policy if family_requirements_policy is not None else _load_family_analysis_requirements()
    )
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
            max_static_layers=max_static_layers,
            archive_password=archive_password,
        )
        if retry_max_static_layers is not None and _layer_count_limit_reached(layer_report):
            initial_counts = layer_report.get("counts", {})
            initial_limit_events = layer_report.get("limit_events", [])
            layers, layer_report = recover_static_layers(
                unit,
                upx=upx,
                sevenzip=sevenzip,
                diec=diec,
                force_container_probe=force_container_probe,
                max_static_layers=retry_max_static_layers,
                archive_password=archive_password,
            )
            layer_report["adaptive_retry"] = {
                "trigger": "layer_count_limit",
                "initial_max_static_layers": max_static_layers,
                "retry_max_static_layers": retry_max_static_layers,
                "initial_counts": initial_counts,
                "initial_limit_event_count": (
                    len(initial_limit_events) if isinstance(initial_limit_events, list) else None
                ),
            }
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
    family_coverage = summarize_family_coverage(specs, registered)
    routing_family_coverage = [
        item
        for item in family_coverage
        if classify_sample.FAMILY_ID_RE.fullmatch(str(item.get("family", ""))) is not None
    ]
    metadata_hints = (
        classify_sample.family_hints_for_sha256(family_hint_manifest, digest)
        if family_hint_manifest is not None
        else []
    )
    routing = classify_sample.build_family_routing_candidates(
        public_classifications,
        metadata_hints=metadata_hints,
        family_coverage=routing_family_coverage,
    )
    write_json(case_dir / "family-routing.json", routing)
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
        generic, generic_status = _run_generic_triage(
            layers,
            case_dir,
            string_scan_limit=string_scan_limit,
        )
        write_json(case_dir / "generic-triage.json", generic)

    executions = []
    recovered_payload_directory: Path | None = None
    if not assessment_only:
        resolved_case = case_dir.resolve(strict=True)
        resolved_repository = REPOSITORY_ROOT.resolve(strict=True)
        if resolved_case != resolved_repository and resolved_repository not in resolved_case.parents:
            # WindowsのMAX_PATH余裕を確保するため、hash case配下は短い固定名にする。
            recovered_payload_directory = case_dir / "p"
            ensure_no_reparse_components(recovered_payload_directory)
            recovered_payload_directory.mkdir()
            ensure_no_reparse_components(recovered_payload_directory)
    specs_by_id = {item.id: item for item in specs}
    handler_attempts_used = 0
    handler_result_bytes_used = 0
    handler_deadline = time.monotonic() + MAX_HANDLER_WALL_SECONDS_PER_CASE
    handler_budget_reason: str | None = None
    if not assessment_only:
        for item in applicability:
            if item["status"] not in {"applicable", "applicable_forced"}:
                continue
            handler_id = item["id"]
            if (
                handler_attempts_used >= MAX_HANDLER_ATTEMPTS_PER_CASE
                or time.monotonic() >= handler_deadline
                or handler_result_bytes_used >= MAX_HANDLER_RESULT_BYTES_PER_CASE
            ):
                handler_budget_reason = handler_budget_reason or "handler_case_budget_exhausted"
                executions.append(
                    {
                        "handler_id": handler_id,
                        "status": "failed",
                        "error": handler_budget_reason,
                        "attempts": [],
                    }
                )
                continue
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
            handler_truncated = False
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
                if handler_attempts_used >= MAX_HANDLER_ATTEMPTS_PER_CASE or time.monotonic() >= handler_deadline:
                    handler_budget_reason = (
                        "handler_attempt_limit"
                        if handler_attempts_used >= MAX_HANDLER_ATTEMPTS_PER_CASE
                        else "handler_wall_clock_limit"
                    )
                    attempts.append(
                        {
                            **attempt,
                            "status": "failed",
                            "error": handler_budget_reason,
                        }
                    )
                    handler_truncated = True
                    break
                handler_attempts_used += 1
                try:
                    bounded = execute_handler_bounded_for_assessment(
                        spec,
                        layer.data,
                        layer.name,
                        actual_format=planned["actual_format"],
                        maximum_input_size=DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
                        artifact_directory=recovered_payload_directory,
                        artifact_path_prefix="p",
                    )
                    worker_status = bounded.get("status")
                    worker_attempt = {
                        **attempt,
                        "execution_boundary": "bounded_assessment_worker",
                        "worker_status": worker_status,
                        "preflight": sanitize_public_value(bounded.get("preflight")),
                    }
                    if worker_status != "completed":
                        attempts.append(
                            {
                                **worker_attempt,
                                "status": "failed",
                                "error": sanitize_public_value(
                                    bounded.get("error")
                                    or (
                                        "handler_preflight_blocked"
                                        if worker_status == "preflight_blocked"
                                        else "handler_worker_incomplete"
                                    )
                                ),
                            }
                        )
                        continue
                    result = bounded.get("execution")
                    if not isinstance(result, dict):
                        attempts.append(
                            {
                                **worker_attempt,
                                "status": "failed",
                                "error": "handler_worker_invalid_execution",
                            }
                        )
                        continue
                    remaining_result_bytes = MAX_HANDLER_RESULT_BYTES_PER_CASE - handler_result_bytes_used
                    result_size = _bounded_json_size(
                        result,
                        maximum_bytes=remaining_result_bytes,
                    )
                    if result_size is None:
                        handler_budget_reason = "handler_result_bytes_limit"
                        handler_truncated = True
                        attempts.append(
                            {
                                **worker_attempt,
                                "status": "failed",
                                "error": handler_budget_reason,
                            }
                        )
                        break
                    handler_result_bytes_used += result_size
                    quality = handler_result_quality(
                        result.get("result"),
                        minimum_score=spec.minimum_evidence_score,
                    )
                    attempts.append(
                        {
                            **worker_attempt,
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
            elif len(ambiguous_layers) > 1 or handler_truncated:
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
                    "resource_budget_truncated": handler_truncated,
                    "resource_budget_reason": (handler_budget_reason if handler_truncated else None),
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
                    "resource_budget_truncated": handler_truncated,
                    "resource_budget_reason": (handler_budget_reason if handler_truncated else None),
                    "result": f"handlers/{filename}",
                    "attempts": attempts,
                }
            )

    candidate_assessment = _candidate_handler_assessment(
        routing=routing,
        layers=layers,
        layer_classifications=public_classifications,
        specs=specs,
        assessment_only=assessment_only,
        artifact_directory=recovered_payload_directory,
    )
    write_json(case_dir / "candidate-handler-assessment.json", candidate_assessment)

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
        "ai_used": False,
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
    if follow_on_lineage is not None:
        report["follow_on_lineage"] = sanitize_public_value(follow_on_lineage)
    handler_logic_records = _handler_static_logic_records(case_dir, executions)
    logic_report = build_static_logic_report(
        sha256=digest,
        family=root_selection["selected_family"] or root_classification.get("malware_type"),
        source_name=unit.source_name,
        data=None if assessment_only or handler_logic_records else unit.data,
        records=handler_logic_records,
        analysis_source=(
            "campaign_handler_representative_functions" if handler_logic_records else "one_shot_static_analysis"
        ),
    )
    write_json(case_dir / "static-logic.json", logic_report)
    (case_dir / "STATIC-LOGIC.md").write_text(render_static_logic_markdown(logic_report), encoding="utf-8")
    profile = build_case_profile(case_dir)
    write_json(case_dir / "features.json", profile)
    (case_dir / "FEATURES.md").write_text(render_features_markdown(profile), encoding="utf-8")
    rules = load_rules(CAMPAIGN_CORRELATION_RULES)
    evidence = extract_campaign_evidence(case_dir, profile, rules)
    if CAMPAIGN_FINGERPRINTS.is_file():
        fingerprints = load_json_object_strict(CAMPAIGN_FINGERPRINTS)
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
    legacy_outcome_records = _legacy_outcome_handler_records(case_dir, executions, specs)
    candidate_outcome_records = _candidate_outcome_handler_records(candidate_assessment)
    outcome_handler_records = legacy_outcome_records + candidate_outcome_records
    outcome_candidates = _outcome_candidates(
        routing,
        layers,
        logic_report,
        requirements_policy,
    )
    family_resolution = orchestration_outcome.resolve_family(
        outcome_candidates,
        outcome_handler_records,
    )
    outcome = orchestration_outcome.build_outcome(
        sample_sha256=digest,
        generic_status=generic_status,
        layer_status=(
            "not_run_assessment_only"
            if assessment_only
            else ("complete" if not _static_layer_issues(layer_report) else "partial")
        ),
        candidates=outcome_candidates,
        handler_records=outcome_handler_records,
        function_analysis_available=function_analysis_is_available(logic_report),
    )
    outcome["family_resolution"] = family_resolution
    _apply_requirements_policy_gate(outcome, requirements_policy)
    outcome["handler_evidence"] = _public_outcome_handler_records(outcome_handler_records)
    outcome["artifacts"] = {
        "routing": "family-routing.json",
        "candidate_handler_assessment": "candidate-handler-assessment.json",
    }
    write_json(case_dir / "orchestration.json", outcome)

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
    if (
        completion["status"] == "triaged_unknown"
        and outcome.get("status") == "complete"
        and family_resolution.get("status") == "resolved"
        and not outcome.get("blockers")
    ):
        completion["status"] = "complete"
        completion["complete"] = True
        completion["resumable"] = True
        completion["automation_family"] = family_resolution.get("family")
        completion["automation_promotion"] = "strong_evidence_without_legacy_blockers"
    _synchronize_completion_with_outcome(completion, outcome)
    report["knowledge_artifacts"] = {
        "features": "features.json",
        "features_markdown": "FEATURES.md",
        "campaign_labels": "campaign-labels.json",
        "static_logic": "static-logic.json",
        "static_logic_markdown": "STATIC-LOGIC.md",
    }
    report["case_state"] = completion
    report["classification"]["automation_family"] = family_resolution.get("family")
    report["classification"]["automation_status"] = family_resolution.get("status")
    report["candidate_handler_assessment"] = {
        "status": candidate_assessment.get("status"),
        "planned_attempt_count": candidate_assessment.get("planned_attempt_count", 0),
    }
    report["orchestration"] = "orchestration.json"
    report["knowledge_artifacts"].update(
        {
            "family_routing": "family-routing.json",
            "candidate_handler_assessment": "candidate-handler-assessment.json",
            "orchestration": "orchestration.json",
        }
    )
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
    artifact_paths.extend(["family-routing.json", "candidate-handler-assessment.json", "orchestration.json"])
    retained_outputs = (outcome.get("outputs") or {}).get("retained_binary_outputs")
    if isinstance(retained_outputs, list):
        retained_paths = {
            item["path"] for item in retained_outputs if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        artifact_paths.extend(path for path in sorted(retained_paths) if path not in artifact_paths)
    report["artifact_sha256"] = artifact_hashes(case_dir, artifact_paths)
    seal_report(report)
    write_json(case_dir / "report.json", report)
    return {
        "sha256": digest,
        "source_name": unit.source_name,
        "family": root_classification.get("malware_type"),
        "selected_family": root_selection["selected_family"],
        "selected_families": selected_families,
        "automation_family": family_resolution.get("family"),
        "automation_state": _automation_summary_state(outcome),
        "candidate_handler_attempts": int(candidate_assessment.get("planned_attempt_count", 0)),
        "ai_used": False,
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
        "resumed": False,
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
    for root in (COMMON_ROOT, CLASSIFIERS_ROOT, FRAMEWORK_ROOT / "malware"):
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
    registry_value = load_json_object_strict(registry)
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


def _static_tool_has_single_link(information: os.stat_result) -> bool:
    """link数を確認できない0も含め、単一link以外をfail-closedにする。"""

    return information.st_nlink == 1


def _normalize_tool_path(value: Path | None, label: str) -> Path | None:
    """明示指定された外部静的toolを通常fileへ限定する。"""

    if value is None:
        return None
    try:
        lexical = value.expanduser()
        if not lexical.is_absolute():
            lexical = Path.cwd() / lexical
        ensure_no_reparse_components(lexical)
        information = lexical.lstat()
        resolved = lexical.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"{label}が見つかりません: {value}") from exc
    if (
        not stat.S_ISREG(information.st_mode)
        or not _static_tool_has_single_link(information)
        or int(getattr(information, "st_file_attributes", 0))
        & int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
        or not 1 <= information.st_size <= MAX_STATIC_TOOL_BINARY_BYTES
    ):
        raise ValueError(f"{label}は単一link・非reparseの通常fileで指定してください: {value}")
    return resolved


def _read_static_tool_binary_once(path: Path) -> bytes:
    """tool binaryを単一handleから有界に読み、置換・hardlinkを拒否する。"""

    ensure_no_reparse_components(path)
    before_path = path.lstat()
    flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_CLOEXEC", 0))
    flags |= int(getattr(os, "O_NOINHERIT", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or not _static_tool_has_single_link(opened)
            or not _static_tool_has_single_link(before_path)
            or not _same_file_identity(opened, before_path)
            or not 1 <= opened.st_size <= MAX_STATIC_TOOL_BINARY_BYTES
        ):
            raise ValueError("static tool binary metadataが不正です")
        remaining = opened.st_size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_handle = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    after_path = path.lstat()
    if (
        len(payload) != opened.st_size
        or not _static_tool_has_single_link(after_handle)
        or not _static_tool_has_single_link(after_path)
        or not _same_file_identity(opened, after_handle)
        or not _same_file_identity(opened, after_path)
        or after_handle.st_size != opened.st_size
        or getattr(after_handle, "st_mtime_ns", None) != getattr(opened, "st_mtime_ns", None)
        or getattr(after_handle, "st_ctime_ns", None) != getattr(opened, "st_ctime_ns", None)
    ):
        raise ValueError("static tool binaryが読取り中に変更されました")
    return payload


def _tool_identity(path: Path | None) -> dict[str, Any] | None:
    """外部toolの絶対pathを公開せず、名前・size・内容hashを契約化する。"""

    if path is None:
        return None
    data = _read_static_tool_binary_once(path)
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
    max_static_layers: int = MAX_STATIC_LAYERS,
    retry_max_static_layers: int | None = None,
    archive_password: str = "infected",
    assessment_only: bool,
    max_file_size: int,
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
    family_hint_manifest_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """再開判定に必要なコード・レジストリ・設定指紋を構築する。"""

    catalog = json.dumps(
        [spec.public() for spec in specs],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    settings = {
        "archive_mode": archive_mode,
        "forced_family": forced_family,
        "minimum_confidence": minimum_confidence,
        "assessment_only": assessment_only,
        "max_file_size": max_file_size,
        "string_scan_limit": string_scan_limit,
        "family_hint_manifest": family_hint_manifest_identity,
        "static_tools": _static_tool_settings(upx, sevenzip, diec),
        "force_container_probe": force_container_probe,
        "max_static_layers": max_static_layers,
        "retry_max_static_layers": retry_max_static_layers,
        "follow_on_fixed_point": {
            "maximum_artifacts": MAX_FOLLOW_ON_ARTIFACTS,
            "maximum_edges": MAX_FOLLOW_ON_EDGES,
            "maximum_omitted_metadata": MAX_FOLLOW_ON_OMITTED_METADATA,
            "maximum_depth": MAX_FOLLOW_ON_DEPTH,
            "maximum_total_bytes": MAX_FOLLOW_ON_TOTAL_BYTES,
            "maximum_payload_size": MAX_FOLLOW_ON_PAYLOAD_SIZE,
            "maximum_wall_seconds": MAX_FOLLOW_ON_WALL_SECONDS,
            "maximum_child_seconds": MAX_FOLLOW_ON_CHILD_SECONDS,
        },
        "archive_password_fingerprint": hashlib.sha256(archive_password.encode("utf-8")).hexdigest(),
        "handler_catalog_sha256": hashlib.sha256(catalog).hexdigest(),
        "runtime": runtime_dependency_versions(),
    }
    return build_pipeline_fingerprint(
        repository_root=REPOSITORY_ROOT,
        components=_analysis_components(registry, specs),
        settings=settings,
    )


def _build_follow_on_analysis_contract(
    *,
    registry: Path,
    specs: list[HandlerSpec],
    minimum_confidence: str,
    upx: Path | None,
    sevenzip: Path | None,
    diec: Path | None,
    force_container_probe: bool,
    max_static_layers: int,
    retry_max_static_layers: int | None,
    archive_password: str,
    string_scan_limit: int,
) -> dict[str, Any]:
    """保持済みraw payloadへ実際に適用する設定だけで契約を構築する。"""

    return _build_analysis_contract(
        registry=registry,
        specs=specs,
        archive_mode="raw",
        forced_family=None,
        minimum_confidence=minimum_confidence,
        assessment_only=False,
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        force_container_probe=force_container_probe,
        max_static_layers=max_static_layers,
        retry_max_static_layers=retry_max_static_layers,
        archive_password=archive_password,
        max_file_size=MAX_FOLLOW_ON_PAYLOAD_SIZE,
        string_scan_limit=string_scan_limit,
        family_hint_manifest_identity=None,
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
    try:
        orchestration = load_json_object_strict(resolve_case_artifact(case_dir, "orchestration.json"))
        candidate_assessment = load_json_object_strict(
            resolve_case_artifact(case_dir, "candidate-handler-assessment.json")
        )
    except (TypeError, ValueError):
        return None
    if (
        isinstance(state, Mapping)
        and state.get("status") == "complete"
        and (orchestration.get("status") != "complete" or orchestration.get("blockers") != [])
    ):
        return None
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
        "automation_family": (orchestration.get("family_resolution") or {}).get("family"),
        "automation_state": _automation_summary_state(orchestration),
        "candidate_handler_attempts": int(candidate_assessment.get("planned_attempt_count", 0)),
        "ai_used": False,
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


def _follow_on_worker_root(value: Any, *, name: str) -> Path:
    """内部workerへ渡すrootを絶対・非reparse directoryへ制限する。"""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"follow-on {name}が不正です")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"follow-on {name}は絶対pathで指定してください")
    ensure_no_reparse_components(path)
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"follow-on {name}は既存directoryではありません")
    return resolved


def _same_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    """同じfile objectを示す最小identityを比較する。"""

    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def _write_private_regular_file(path: Path, payload: bytes, *, maximum_size: int) -> None:
    """owner限定modeのsingle-link通常fileを排他的に作成する。"""

    if not 0 < len(payload) <= maximum_size:
        raise ValueError("follow-on private file sizeが不正です")
    if not path.is_absolute() or path.exists() or not path.parent.is_dir():
        raise ValueError("follow-on private file pathが不正です")
    ensure_no_reparse_components(path.parent)
    parent_before = path.parent.lstat()
    if not stat.S_ISDIR(parent_before.st_mode):
        raise ValueError("follow-on private file parentがdirectoryではありません")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
        0o600,
    )
    created: os.stat_result | None = None
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        created = os.fstat(descriptor)
        path_opened = path.lstat()
        parent_opened = path.parent.lstat()
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_nlink != 1
            or not stat.S_ISREG(path_opened.st_mode)
            or path_opened.st_nlink != 1
            or not _same_file_identity(created, path_opened)
            or not _same_file_identity(parent_before, parent_opened)
            or (os.name != "nt" and stat.S_IMODE(path_opened.st_mode) & 0o077)
        ):
            raise ValueError("follow-on private fileの作成後検証に失敗しました")
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("follow-on private fileを書き切れませんでした")
            written += count
        os.fsync(descriptor)
        final_fd = os.fstat(descriptor)
        final_path = path.lstat()
        final_parent = path.parent.lstat()
        if (
            final_fd.st_size != len(payload)
            or final_fd.st_nlink != 1
            or final_path.st_nlink != 1
            or not _same_file_identity(created, final_fd)
            or not _same_file_identity(created, final_path)
            or not _same_file_identity(parent_before, final_parent)
        ):
            raise ValueError("follow-on private fileが書込み中に変更されました")
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if created is not None and path.exists():
            try:
                current = path.lstat()
                if _same_file_identity(created, current):
                    path.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    os.close(descriptor)


def _read_private_regular_file(
    path: Path,
    *,
    maximum_size: int,
    expected_size: int | None = None,
    expected_sha256: str | None = None,
) -> bytes:
    """private通常fileを単一handleで有界読取りし、置換とhardlinkを拒否する。"""

    if not path.is_absolute():
        raise ValueError("follow-on private fileは絶対pathで指定してください")
    ensure_no_reparse_components(path)
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        path_before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not stat.S_ISREG(path_before.st_mode)
            or path_before.st_nlink != 1
            or not _same_file_identity(before, path_before)
            or not 0 < before.st_size <= maximum_size
            or (expected_size is not None and before.st_size != expected_size)
            or (os.name != "nt" and stat.S_IMODE(path_before.st_mode) & 0o077)
        ):
            raise ValueError("follow-on private file metadataが不正です")
        remaining = before.st_size + 1
        chunks: list[bytes] = []
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        path_after = path.lstat()
    finally:
        os.close(descriptor)
    if (
        len(raw) != before.st_size
        or not _same_file_identity(before, after)
        or not _same_file_identity(before, path_after)
        or after.st_nlink != 1
        or path_after.st_nlink != 1
        or after.st_size != before.st_size
        or getattr(after, "st_mtime_ns", None) != getattr(before, "st_mtime_ns", None)
    ):
        raise ValueError("follow-on private fileが読取り中に変更されました")
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("follow-on private file hashが一致しません")
    return raw


def _strict_json_object_bytes(raw: bytes, *, label: str) -> dict[str, Any]:
    """重複key・非finite値・非objectを拒否してUTF-8 JSONを読む。"""

    def strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label}に重複keyがあります")
            value[key] = item
        return value

    def reject_constant(_value: str) -> None:
        raise ValueError(f"{label}に非finite数値があります")

    def parse_finite_float(raw_value: str) -> float:
        parsed = float(raw_value)
        if not math.isfinite(parsed):
            reject_constant(raw_value)
        return parsed

    def parse_bounded_int(raw_value: str) -> int:
        digits = raw_value[1:] if raw_value.startswith("-") else raw_value
        if len(digits) > 128:
            raise ValueError(f"{label}の整数桁数が上限を超えています")
        return int(raw_value)

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=strict_pairs,
            parse_int=parse_bounded_int,
            parse_float=parse_finite_float,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"{label}を解釈できません") from exc
    if not isinstance(value, dict):
        raise TypeError(f"{label}はJSON objectである必要があります")
    pending: list[tuple[Any, int]] = [(value, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > 128:
            raise ValueError(f"{label}の入れ子が深すぎます")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)
    return value


def _follow_on_worker_main(
    request_path: str,
    request_size_text: str,
    request_sha256: str,
    response_path: str,
) -> int:
    """1つの保持payloadだけを既存pipelineへ通す隔離worker entrypoint。"""

    request_file = Path(request_path)
    response_file = Path(response_path)
    if (
        not request_file.is_absolute()
        or not response_file.is_absolute()
        or response_file.exists()
        or request_file.parent != response_file.parent
        or not response_file.parent.is_dir()
    ):
        return 2
    try:
        ensure_no_reparse_components(response_file.parent)
        if not request_size_text.isascii() or not request_size_text.isdecimal():
            raise ValueError("follow-on worker request sizeが不正です")
        request_size = int(request_size_text)
        request_digest = normalize_sha256_digest(request_sha256)
        request_raw = _read_private_regular_file(
            request_file,
            maximum_size=MAX_FOLLOW_ON_WORKER_REQUEST,
            expected_size=request_size,
            expected_sha256=request_digest,
        )
        request = _strict_json_object_bytes(request_raw, label="follow-on worker request")
        expected_keys = {
            "schema_version",
            "output",
            "registry",
            "minimum_confidence",
            "upx",
            "sevenzip",
            "diec",
            "force_container_probe",
            "max_static_layers",
            "retry_max_static_layers",
            "archive_password",
            "string_scan_limit",
            "analysis_contract",
            "source_name",
            "expected_sha256",
            "depth",
            "parent_sha256",
        }
        if not isinstance(request, dict) or set(request) != expected_keys:
            raise ValueError("follow-on worker request schemaが不正です")
        output = _follow_on_worker_root(request["output"], name="output")
        repository = REPOSITORY_ROOT.resolve(strict=True)
        if output == repository or repository in output.parents:
            raise ValueError("follow-on outputをrepository配下へ作成できません")
        registry = Path(request["registry"])
        ensure_no_reparse_components(registry)
        registry = registry.resolve(strict=True)
        if repository not in registry.parents or not registry.is_file():
            raise ValueError("follow-on registryがrepository境界外です")
        expected_sha256 = normalize_sha256_digest(request["expected_sha256"])
        parent_sha256 = normalize_sha256_digest(request["parent_sha256"])
        depth = request["depth"]
        if not isinstance(depth, int) or isinstance(depth, bool) or not 1 <= depth <= MAX_FOLLOW_ON_DEPTH:
            raise ValueError("follow-on depthが不正です")
        source_name = request["source_name"]
        if (
            not isinstance(source_name, str)
            or not source_name
            or len(source_name) > 512
            or any(ord(character) < 32 or ord(character) == 127 for character in source_name)
        ):
            raise ValueError("follow-on source_nameが不正です")
        data = sys.stdin.buffer.read(MAX_FOLLOW_ON_PAYLOAD_SIZE + 1)
        if len(data) > MAX_FOLLOW_ON_PAYLOAD_SIZE:
            raise ValueError("follow-on payloadがsize上限を超えています")
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise ValueError("follow-on payload hashが一致しません")
        analysis_contract = request["analysis_contract"]
        if not isinstance(analysis_contract, dict):
            raise ValueError("follow-on analysis_contractが不正です")
        minimum_confidence = request["minimum_confidence"]
        if minimum_confidence not in CONFIDENCE:
            raise ValueError("follow-on minimum_confidenceが不正です")

        clear_handler_caches()
        classify_sample.clear_classifier_caches()
        clear_profile_cache()
        clear_known_hash_cache()
        specs = discover_handlers()
        registered = _registered_families(registry)
        upx = _normalize_tool_path(
            Path(request["upx"]) if isinstance(request["upx"], str) else None,
            "UPX",
        )
        sevenzip = _normalize_tool_path(
            Path(request["sevenzip"]) if isinstance(request["sevenzip"], str) else None,
            "7-Zip",
        )
        diec = _normalize_tool_path(
            Path(request["diec"]) if isinstance(request["diec"], str) else None,
            "Detect It Easy CLI",
        )
        child_contract = _build_follow_on_analysis_contract(
            registry=registry,
            specs=specs,
            minimum_confidence=minimum_confidence,
            upx=upx,
            sevenzip=sevenzip,
            diec=diec,
            force_container_probe=request["force_container_probe"] is True,
            max_static_layers=int(request["max_static_layers"]),
            retry_max_static_layers=request["retry_max_static_layers"],
            archive_password=str(request["archive_password"]),
            string_scan_limit=int(request["string_scan_limit"]),
        )
        if analysis_contract != child_contract:
            raise ValueError("follow-on analysis_contractが実行時設定と一致しません")
        unit = InputUnit(
            source_name=source_name,
            data=data,
            input_kind="follow_on_payload",
            outer_sha256=expected_sha256,
            outer_size=len(data),
            member_name=None,
        )
        result = analyze_unit(
            unit,
            output=output,
            registry=registry,
            specs=specs,
            registered=registered,
            forced_family=None,
            minimum_confidence=minimum_confidence,
            assessment_only=False,
            analysis_contract=child_contract,
            family_hint_manifest=None,
            family_requirements_policy=_load_family_analysis_requirements(),
            upx=upx,
            sevenzip=sevenzip,
            diec=diec,
            force_container_probe=request["force_container_probe"] is True,
            max_static_layers=int(request["max_static_layers"]),
            retry_max_static_layers=request["retry_max_static_layers"],
            archive_password=str(request["archive_password"]),
            string_scan_limit=int(request["string_scan_limit"]),
            follow_on_lineage={
                "schema_version": 1,
                "depth": depth,
                "parent_sha256": parent_sha256,
                "root_kind": "retained_terminal_or_final_payload",
            },
        )
        response: dict[str, Any] = {"ok": True, "result": result}
    except Exception as exc:  # noqa: BLE001 - worker境界では例外内容を型だけへ正規化する
        response = {
            "ok": False,
            "error": "follow_on_worker_failed",
            "error_type": type(exc).__name__,
        }
    encoded = json.dumps(
        response,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(encoded) > MAX_FOLLOW_ON_WORKER_RESPONSE:
        encoded = b'{"error":"follow_on_worker_response_limit","ok":false}'
    try:
        _write_private_regular_file(
            response_file,
            encoded,
            maximum_size=MAX_FOLLOW_ON_WORKER_RESPONSE,
        )
    except (OSError, ValueError):
        return 3
    return 0


def _execute_follow_on_child(
    *,
    payload: bytes,
    digest: str,
    parent_sha256: str,
    depth: int,
    output: Path,
    registry: Path,
    minimum_confidence: str,
    upx: Path | None,
    sevenzip: Path | None,
    diec: Path | None,
    force_container_probe: bool,
    max_static_layers: int,
    retry_max_static_layers: int | None,
    archive_password: str,
    string_scan_limit: int,
    analysis_contract: dict[str, Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    """保持payloadを隔離processの既存analyze_unitへwall-clock上限付きで渡す。"""

    request = {
        "schema_version": 1,
        "output": str(output.resolve(strict=True)),
        "registry": str(registry.resolve(strict=True)),
        "minimum_confidence": minimum_confidence,
        "upx": str(upx) if upx is not None else None,
        "sevenzip": str(sevenzip) if sevenzip is not None else None,
        "diec": str(diec) if diec is not None else None,
        "force_container_probe": force_container_probe,
        "max_static_layers": max_static_layers,
        "retry_max_static_layers": retry_max_static_layers,
        "archive_password": archive_password,
        "string_scan_limit": string_scan_limit,
        "analysis_contract": analysis_contract,
        "source_name": f"follow-on-{digest[:16]}.bin",
        "expected_sha256": digest,
        "depth": depth,
        "parent_sha256": parent_sha256,
    }
    request_raw = json.dumps(
        request,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    if len(request_raw) > MAX_FOLLOW_ON_WORKER_REQUEST:
        raise ValueError("follow-on worker requestがsize上限を超えています")
    request_digest = hashlib.sha256(request_raw).hexdigest()
    from bounded_process import run_bounded

    with tempfile.TemporaryDirectory(prefix="follow-on-analysis-") as temporary:
        temporary_root = Path(temporary).resolve(strict=True)
        ensure_no_reparse_components(temporary_root)
        request_path = temporary_root / "request.json"
        response_path = temporary_root / "response.json"
        worker_temp = temporary_root / "worker-temp"
        worker_temp.mkdir(mode=0o700)
        os.chmod(worker_temp, 0o700)
        _write_private_regular_file(
            request_path,
            request_raw,
            maximum_size=MAX_FOLLOW_ON_WORKER_REQUEST,
        )
        completed = run_bounded(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                "--follow-on-worker",
                str(request_path),
                str(len(request_raw)),
                request_digest,
                str(response_path),
            ],
            timeout=timeout_seconds,
            check=False,
            shell=False,
            env=_bounded_handler_environment(temporary_root=worker_temp),
            cwd=REPOSITORY_ROOT,
            input=payload,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=False,
            require_containment=True,
            maximum_active_processes=MAX_FOLLOW_ON_WORKER_ACTIVE_PROCESSES,
            maximum_memory_bytes=MAX_FOLLOW_ON_WORKER_MEMORY_BYTES,
        )
        if completed.returncode != 0:
            raise RuntimeError("follow-on workerが失敗しました")
        response_raw = _read_private_regular_file(
            response_path,
            maximum_size=MAX_FOLLOW_ON_WORKER_RESPONSE,
        )
        response = _strict_json_object_bytes(response_raw, label="follow-on worker response")
    if response.get("ok") is not True or not isinstance(response.get("result"), dict):
        raise RuntimeError(str(response.get("error") or "follow_on_worker_invalid_response"))
    return response["result"]


def _atomic_replace_json(path: Path, value: object) -> None:
    """case JSONを同一directory内tempからatomic replaceする。"""

    ensure_no_reparse_components(path.parent)
    encoded = _encoded_json_document(value)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".follow-on-", suffix=".json", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        ensure_no_reparse_components(temporary)
        information = temporary.stat()
        if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
            raise ValueError("follow-on atomic JSON tempが通常fileではありません")
        os.replace(temporary, path)
        ensure_no_reparse_components(path)
    finally:
        if temporary.exists():
            temporary.unlink(missing_ok=True)


def _encoded_json_document(value: object) -> bytes:
    """atomic JSON保存と事前artifact hash計算で同一のbytesを生成する。"""

    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _retained_outputs_from_wrapper(wrapper: object) -> list[dict[str, Any]]:
    """親再hash済み保持auditと一致するpayload metadataだけを返す。"""

    if not isinstance(wrapper, Mapping):
        return []
    supplied = wrapper.get("verified_binary_outputs")
    if not isinstance(supplied, Sequence) or isinstance(supplied, (str, bytes, bytearray)):
        return []
    if len(supplied) > MAX_FOLLOW_ON_ARTIFACTS:
        return []
    bounded = list(supplied)
    audit = orchestration_outcome._verified_output_audit(  # noqa: SLF001 - 同一pipelineのstrict schema
        wrapper.get("verified_binary_output_audit"),
        output_count=len(bounded),
    )
    if audit is None:
        return []
    outputs = []
    for supplied_output in bounded:
        output = orchestration_outcome._verified_binary_output(  # noqa: SLF001
            supplied_output
        )
        if output is None:
            return []
        outputs.append(output)
    return outputs


def _wrapper_follow_on_promotion_eligible(wrapper: object) -> bool:
    """全observed payloadが欠落・切捨てなく保持された監査だけを受理する。"""

    outputs = _retained_outputs_from_wrapper(wrapper)
    if not outputs or not isinstance(wrapper, Mapping):
        return False
    audit = wrapper.get("verified_binary_output_audit")
    if not isinstance(audit, Mapping):
        return False
    count = len(outputs)
    return (
        audit.get("observed_output_count") == count
        and audit.get("retained_output_count") == count
        and audit.get("truncated") is False
        and audit.get("reasons") == []
    )


def _case_wrapper_documents(
    case_dir: Path,
    report: Mapping[str, Any],
) -> tuple[list[tuple[Path, dict[str, Any]]], Path, dict[str, Any]]:
    """selected wrapper群とcandidate assessmentをcase境界内から厳格に読む。"""

    selected = []
    for execution in report.get("handler_executions") or []:
        if not isinstance(execution, Mapping) or not isinstance(execution.get("result"), str):
            continue
        path = resolve_case_artifact(case_dir, execution["result"])
        selected.append((path, load_json_object_strict(path)))
    candidate_path = resolve_case_artifact(case_dir, "candidate-handler-assessment.json")
    return selected, candidate_path, load_json_object_strict(candidate_path)


def _candidate_wrappers(candidate_assessment: Mapping[str, Any]) -> list[dict[str, Any]]:
    wrappers = []
    for family in candidate_assessment.get("families") or []:
        if not isinstance(family, Mapping):
            continue
        for attempt in family.get("attempts") or []:
            if not isinstance(attempt, Mapping):
                continue
            wrapper = attempt.get("result")
            if isinstance(wrapper, dict):
                wrappers.append(wrapper)
    return wrappers


def _follow_on_case_directory(output: Path, digest: str) -> Path:
    """follow-on caseを固定output配下の非reparse directoryへ限定する。"""

    normalized = normalize_sha256_digest(digest)
    ensure_no_reparse_components(output)
    resolved_output = output.resolve(strict=True)
    lexical = output / "cases" / normalized
    ensure_no_reparse_components(lexical)
    resolved = lexical.resolve(strict=True)
    try:
        resolved.relative_to(resolved_output)
    except ValueError as exc:
        raise ValueError("follow-on caseがoutput境界外です") from exc
    if not resolved.is_dir():
        raise ValueError("follow-on caseがdirectoryではありません")
    return resolved


def _case_retained_payloads(
    output: Path,
    digest: str,
    *,
    maximum_records: int,
    maximum_read_bytes: int,
    maximum_omitted_records: int = MAX_FOLLOW_ON_OMITTED_METADATA,
    include_omitted_metadata: bool = False,
    include_omitted_commitment: bool = False,
    deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> (
    tuple[list[dict[str, Any]], list[str], int, int]
    | tuple[list[dict[str, Any]], list[str], int, int, list[dict[str, Any]]]
    | tuple[
        list[dict[str, Any]],
        list[str],
        int,
        int,
        list[dict[str, Any]],
        dict[str, int | str] | None,
    ]
):
    """caseに保持されたpayloadを実file再検証付きでqueue recordへ変換する。"""

    for label, value in (
        ("maximum_records", maximum_records),
        ("maximum_read_bytes", maximum_read_bytes),
        ("maximum_omitted_records", maximum_omitted_records),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{label}は0以上の整数でなければなりません")
    normalize_sha256_digest(digest)
    if include_omitted_commitment and not include_omitted_metadata:
        raise ValueError("commitment出力にはomitted metadata出力が必要です")
    omitted_metadata: list[dict[str, Any]] = []
    committed_omissions: Counter[tuple[str, str, str, str, int]] = Counter()
    errors: set[str] = set()

    def result(
        records: list[dict[str, Any]],
        read_count: int,
        read_bytes: int,
    ) -> (
        tuple[list[dict[str, Any]], list[str], int, int]
        | tuple[list[dict[str, Any]], list[str], int, int, list[dict[str, Any]]]
        | tuple[
            list[dict[str, Any]],
            list[str],
            int,
            int,
            list[dict[str, Any]],
            dict[str, int | str] | None,
        ]
    ):
        base = (records, sorted(errors), read_count, read_bytes)
        if not include_omitted_metadata:
            return base
        ordered_omissions = sorted(
            omitted_metadata,
            key=lambda item: (
                item["sha256"],
                item["path"],
                item["role"],
                item["kind"],
                item["size"],
                item["reason"],
            ),
        )
        if not include_omitted_commitment:
            return (*base, ordered_omissions)
        return (
            *base,
            ordered_omissions,
            canonical_multiset_commitment(committed_omissions),
        )

    def record_omission(
        metadata: Mapping[str, Any],
        reason: str,
        *,
        error: str | None = None,
    ) -> None:
        errors.add(error or reason)
        if len(omitted_metadata) >= maximum_omitted_records:
            errors.add("verified_output_omitted_metadata_limit")
            committed_omissions[metadata_identity(metadata)] += 1
            return
        omitted_metadata.append(
            {
                "sha256": str(metadata["sha256"]),
                "size": int(metadata["size"]),
                "path": str(metadata["path"]),
                "role": str(metadata["role"]),
                "kind": str(metadata["kind"]),
                "reason": reason,
            }
        )

    case_dir = _follow_on_case_directory(output, digest)
    repository = REPOSITORY_ROOT.resolve(strict=True)
    if case_dir == repository or repository in case_dir.parents:
        errors.add("repository_output_retention_forbidden")
        return result([], 0, 0)
    report = load_json_object_strict(resolve_case_artifact(case_dir, "report.json"))
    selected, _candidate_path, candidate_assessment = _case_wrapper_documents(case_dir, report)
    wrappers = [wrapper for _path, wrapper in selected]
    wrappers.extend(_candidate_wrappers(candidate_assessment))
    metadata_records: list[dict[str, Any]] = []
    for wrapper in wrappers:
        retained_claimed = (
            isinstance(wrapper, Mapping)
            and isinstance(wrapper.get("verified_binary_output_audit"), Mapping)
            and wrapper["verified_binary_output_audit"].get("retained_for_follow_on_analysis") is True
        )
        if retained_claimed and not _wrapper_follow_on_promotion_eligible(wrapper):
            errors.add("incomplete_retention_audit")
        for metadata in _retained_outputs_from_wrapper(wrapper):
            if len(metadata_records) >= maximum_records:
                record_omission(metadata, "verified_output_edge_limit")
                continue
            metadata_records.append(metadata)

    records: list[dict[str, Any]] = []
    cache: dict[tuple[str, str, int], bytes] = {}
    read_bytes = 0
    read_count = 0
    for index, metadata in enumerate(metadata_records):
        if deadline is not None and monotonic() >= deadline:
            for remaining_metadata in metadata_records[index:]:
                record_omission(
                    remaining_metadata,
                    "verified_output_read_wall_clock_limit",
                )
            break
        child_digest = str(metadata["sha256"])
        size = int(metadata["size"])
        key = (child_digest, str(metadata["path"]), size)
        raw = cache.get(key)
        if raw is None:
            if read_bytes + size > maximum_read_bytes:
                record_omission(metadata, "verified_output_read_bytes_limit")
                continue
            try:
                path = resolve_case_artifact(case_dir, str(metadata["path"]))
                read_options: dict[str, Any] = {}
                if deadline is not None:
                    read_options = {"deadline": deadline, "monotonic": monotonic}
                raw = _read_verified_artifact(
                    path,
                    expected_size=size,
                    expected_sha256=child_digest,
                    **read_options,
                )
            except TimeoutError:
                for remaining_metadata in metadata_records[index:]:
                    record_omission(
                        remaining_metadata,
                        "verified_output_read_wall_clock_limit",
                    )
                break
            except (OSError, ValueError, RuntimeError):
                record_omission(
                    metadata,
                    "artifact_verification_failed",
                    error=f"artifact_verification_failed:{child_digest}",
                )
                continue
            cache[key] = raw
            read_bytes += len(raw)
            read_count += 1
        records.append(
            {
                "sha256": child_digest,
                "size": len(raw),
                "path": str(metadata["path"]),
                "role": str(metadata["role"]),
                "kind": str(metadata["kind"]),
                "data": raw,
            }
        )
    return result(records, read_count, read_bytes)


def _case_strict_complete(
    output: Path,
    digest: str,
    *,
    expected_contract: Mapping[str, Any],
) -> bool:
    """case integrity・resumable state・orchestration gateが全てcompleteか確認する。"""

    try:
        case_dir = _follow_on_case_directory(output, digest)
        report = load_json_object_strict(resolve_case_artifact(case_dir, "report.json"))
        if case_integrity_errors(
            case_dir,
            report,
            expected_digest=digest,
            expected_contract=expected_contract,
            require_resumable=True,
        ):
            return False
        outcome = load_json_object_strict(resolve_case_artifact(case_dir, "orchestration.json"))
    except (OSError, TypeError, ValueError):
        return False
    return (
        (report.get("case_state") or {}).get("status") == "complete"
        and outcome.get("status") == "complete"
        and outcome.get("blockers") == []
    )


def _case_result_from_disk(
    output: Path,
    digest: str,
    *,
    resumed: bool = False,
    expected_contract: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """fresh/partial子caseをsummary互換recordへ正規化する。"""

    case_dir = _follow_on_case_directory(output, digest)
    report = load_json_object_strict(resolve_case_artifact(case_dir, "report.json"))
    if expected_contract is not None and case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        expected_contract=expected_contract,
        require_resumable=False,
    ):
        raise ValueError("follow-on case integrityを検証できません")
    outcome = load_json_object_strict(resolve_case_artifact(case_dir, "orchestration.json"))
    candidate = load_json_object_strict(resolve_case_artifact(case_dir, "candidate-handler-assessment.json"))
    classification = report.get("classification") or {}
    executions = [item for item in report.get("handler_executions") or [] if isinstance(item, dict)]
    statuses = [item.get("status") for item in executions]
    case_state = (report.get("case_state") or {}).get("status")
    if case_state not in {"complete", "triaged_unknown", "partial", "failed"}:
        raise ValueError("follow-on caseがterminal stateへ到達していません")
    if case_state == "complete" and (outcome.get("status") != "complete" or outcome.get("blockers") != []):
        raise ValueError("complete caseとorchestration gateが一致しません")
    return {
        "sha256": digest,
        "source_name": (report.get("sample") or {}).get("source_name"),
        "family": classification.get("family"),
        "selected_family": classification.get("selected_family"),
        "selected_families": classification.get("selected_families") or [],
        "automation_family": (outcome.get("family_resolution") or {}).get("family"),
        "automation_state": _automation_summary_state(outcome),
        "candidate_handler_attempts": int(candidate.get("planned_attempt_count", 0)),
        "ai_used": False,
        "campaign": classification.get("campaign"),
        "handler_succeeded": sum(item == "succeeded" for item in statuses),
        "handler_failed": sum(item in {"failed", "preflight_failed"} for item in statuses),
        "handler_no_evidence": sum(item == "no_evidence" for item in statuses),
        "handler_ambiguous": sum(item == "ambiguous_evidence" for item in statuses),
        "handler_incompatible": sum(item == "incompatible_input_format" for item in statuses),
        "analysis_stage_failed": report.get("generic_triage") == "failed",
        "analysis_stage_partial": report.get("generic_triage") == "partial",
        "case_state": case_state,
        "report": f"cases/{digest}/report.json",
        "resumed": resumed,
    }


def _completed_follow_on_child_proof(
    output: Path,
    digest: str,
    *,
    analysis_contract: Mapping[str, Any],
) -> dict[str, Any]:
    """完全な子caseだけから親昇格へ使う暗号学的proofを作る。"""

    case_dir = _follow_on_case_directory(output, digest)
    report = load_json_object_strict(resolve_case_artifact(case_dir, "report.json"))
    errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        expected_contract=analysis_contract,
        require_resumable=False,
    )
    outcome = load_json_object_strict(resolve_case_artifact(case_dir, "orchestration.json"))
    semantic_sha256 = report.get("report_semantic_sha256")
    if (
        errors
        or (report.get("case_state") or {}).get("status") != "complete"
        or outcome.get("status") != "complete"
        or outcome.get("blockers") != []
        or not isinstance(semantic_sha256, str)
        or re.fullmatch(r"[0-9a-f]{64}", semantic_sha256) is None
    ):
        raise ValueError("follow-on child caseが厳格completeではありません")
    return {
        "sha256": digest,
        "analysis_contract_sha256": analysis_contract.get("sha256"),
        "report_semantic_sha256": semantic_sha256,
    }


def _case_has_follow_on_promotion(output: Path, digest: str) -> bool:
    """既存の厳格complete caseがfollow-on昇格proofを持つか返す。"""

    report = load_json_object_strict(
        resolve_case_artifact(
            _follow_on_case_directory(output, digest),
            "report.json",
        )
    )
    return isinstance(report.get("follow_on_promotion"), Mapping)


def _promote_wrapper_follow_on_audit(
    wrapper: dict[str, Any],
    *,
    proofs: Mapping[str, Mapping[str, Any]],
) -> bool:
    """wrapperの全保持payloadがcompleteの場合だけ解析完了auditへ昇格する。"""

    outputs = _retained_outputs_from_wrapper(wrapper)
    if not outputs or not _wrapper_follow_on_promotion_eligible(wrapper):
        return False
    digests = sorted({str(item["sha256"]) for item in outputs})
    if any(digest not in proofs for digest in digests):
        return False
    audit = wrapper.get("verified_binary_output_audit")
    if not isinstance(audit, dict):
        return False
    proof = {
        "schema_version": 1,
        "status": "all_retained_payloads_strict_complete",
        "children": [dict(proofs[digest]) for digest in digests],
    }
    changed = audit.get("follow_on_analysis_complete") is not True or wrapper.get("follow_on_analysis_proof") != proof
    audit["follow_on_analysis_complete"] = True
    wrapper["follow_on_analysis_proof"] = proof
    return changed


def _promote_parent_case_from_follow_on(
    output: Path,
    digest: str,
    *,
    parent_contract: Mapping[str, Any],
    child_contract: Mapping[str, Any],
    specs: list[HandlerSpec],
    complete_child_digests: set[str],
) -> bool:
    """子case証明を全て検証してから親成果物を一括commitし、再sealする。"""

    case_dir = _follow_on_case_directory(output, digest)
    report_path = resolve_case_artifact(case_dir, "report.json")
    report = copy.deepcopy(load_json_object_strict(report_path))
    integrity_errors = case_integrity_errors(
        case_dir,
        report,
        expected_digest=digest,
        expected_contract=parent_contract,
        require_resumable=False,
    )
    if integrity_errors:
        raise ValueError("parent case integrityが不正です")

    loaded_selected, candidate_path, loaded_candidate = _case_wrapper_documents(
        case_dir,
        report,
    )
    selected = [(path, copy.deepcopy(wrapper)) for path, wrapper in loaded_selected]
    candidate = copy.deepcopy(loaded_candidate)
    wrappers = [wrapper for _path, wrapper in selected]
    candidate_wrappers = _candidate_wrappers(candidate)
    all_wrappers = [*wrappers, *candidate_wrappers]
    required_digests = {
        str(item["sha256"]) for wrapper in all_wrappers for item in _retained_outputs_from_wrapper(wrapper)
    }
    eligible_digests = required_digests & complete_child_digests
    proofs = {
        child_digest: _completed_follow_on_child_proof(
            output,
            child_digest,
            analysis_contract=child_contract,
        )
        for child_digest in sorted(eligible_digests)
    }

    selected_changed: list[tuple[Path, dict[str, Any]]] = []
    for path, wrapper in selected:
        if _promote_wrapper_follow_on_audit(wrapper, proofs=proofs):
            selected_changed.append((path, wrapper))
    candidate_changed = False
    for wrapper in candidate_wrappers:
        if _promote_wrapper_follow_on_audit(wrapper, proofs=proofs):
            candidate_changed = True

    selected_overrides = {path: wrapper for path, wrapper in selected}
    records = [
        *_legacy_outcome_handler_records(
            case_dir,
            report.get("handler_executions") or [],
            specs,
            wrapper_overrides=selected_overrides,
        ),
        *_candidate_outcome_handler_records(candidate),
    ]
    outcome_path = resolve_case_artifact(case_dir, "orchestration.json")
    outcome = copy.deepcopy(load_json_object_strict(outcome_path))
    resolution = outcome.get("family_resolution")
    resolved_family = resolution.get("family") if isinstance(resolution, Mapping) else None
    candidate_outputs = orchestration_outcome.summarize_handler_outputs(
        records,
        verified_only=False,
    )
    outputs = (
        orchestration_outcome.summarize_handler_outputs(
            records,
            family_filter=resolved_family,
        )
        if isinstance(resolved_family, str)
        else orchestration_outcome.summarize_handler_outputs([])
    )
    outcome["outputs"] = outputs
    outcome["candidate_outputs"] = candidate_outputs
    gates = outcome.get("quality_gates")
    if not isinstance(gates, dict) or not isinstance(gates.get("terminal_payload"), dict):
        raise ValueError("parent orchestration gateが不正です")
    terminal_gate = gates["terminal_payload"]
    required = terminal_gate.get("required")
    satisfied = bool(outputs.get("terminal_payload_sha256"))
    terminal_gate["satisfied"] = satisfied
    terminal_gate["status"] = (
        "not_applicable"
        if required is False
        else "satisfied"
        if satisfied
        else "required_missing"
        if required is True
        else "not_declared"
    )
    old_blockers = [value for value in outcome.get("blockers") or [] if isinstance(value, str)]
    old_actions = [value for value in outcome.get("next_actions_ja") or [] if isinstance(value, str)]
    action_by_blocker = dict(zip(old_blockers, old_actions, strict=False))
    blockers = sorted(
        name for name, gate in gates.items() if isinstance(gate, Mapping) and gate.get("status") == "required_missing"
    )
    outcome["blockers"] = blockers
    outcome["next_actions_ja"] = [
        action_by_blocker.get(name, f"{name}の未解決事項を確認してください。") for name in blockers
    ]
    if blockers:
        outcome["status"] = "partial"
    elif isinstance(resolution, Mapping) and resolution.get("status") == "resolved":
        outcome["status"] = "complete"

    completion = report.get("case_state")
    if not isinstance(completion, dict):
        raise ValueError("parent case_stateが不正です")
    _synchronize_completion_with_outcome(completion, outcome)
    retained_output_digests = outputs.get("retained_terminal_payload_sha256")
    promoted_output_digests = outputs.get("terminal_payload_sha256")
    if (
        not isinstance(retained_output_digests, list)
        or not retained_output_digests
        or retained_output_digests != sorted(set(retained_output_digests))
        or promoted_output_digests != retained_output_digests
        or any(value not in proofs for value in promoted_output_digests)
    ):
        raise ValueError("resolved familyの保持payloadが親別proofと一致しません")
    report["follow_on_promotion"] = {
        "schema_version": 1,
        "status": "verified_children_linked",
        "child_analysis_contract_sha256": child_contract.get("sha256"),
        "children": [proofs[key] for key in promoted_output_digests],
    }

    planned_items = [*selected_changed]
    if candidate_changed:
        planned_items.append((candidate_path, candidate))
    planned_items.append((outcome_path, outcome))
    planned_paths = [path for path, _document in planned_items]
    if len(planned_paths) != len(set(planned_paths)) or report_path in planned_paths:
        raise ValueError("parent commit対象artifact pathが重複しています")
    planned_documents = dict(planned_items)

    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, Mapping) or not manifest:
        raise ValueError("parent artifact manifestが不正です")
    manifest_keys = list(manifest)
    if any(not isinstance(value, str) or not value for value in manifest_keys):
        raise ValueError("parent artifact manifest pathが不正です")
    manifest_paths: dict[Path, str] = {}
    for relative in manifest_keys:
        artifact_path = resolve_case_artifact(case_dir, relative)
        if artifact_path in manifest_paths:
            raise ValueError("parent artifact manifest pathが重複しています")
        manifest_paths[artifact_path] = relative
    if not set(planned_documents).issubset(manifest_paths):
        raise ValueError("parent commit対象artifactがmanifestにありません")

    prepared_manifest = artifact_hashes(case_dir, manifest_keys)
    prepared_documents = {path: _encoded_json_document(document) for path, document in planned_documents.items()}
    for path, encoded in prepared_documents.items():
        prepared_manifest[manifest_paths[path]] = hashlib.sha256(encoded).hexdigest()
    report["artifact_sha256"] = prepared_manifest
    seal_report(report)
    _encoded_json_document(report)

    # ここからがcommit phase。上記のproof、gate、manifest検証失敗では一切書かない。
    for path in sorted(planned_documents, key=lambda value: str(value).casefold()):
        _atomic_replace_json(path, planned_documents[path])
    _atomic_replace_json(report_path, report)
    return _case_strict_complete(
        output,
        digest,
        expected_contract=parent_contract,
    )


def _parent_complete_child_digests(
    parent_digest: str,
    *,
    outbound: Mapping[str, Sequence[int]],
    edges: Sequence[Mapping[str, Any]],
    depths: Mapping[str, int],
    strict_complete_digests: set[str],
) -> set[str]:
    """当該親が通常／shared edgeで到達したchild-contract完了SHAだけを返す。"""

    return {
        str(edges[index]["child_sha256"])
        for index in outbound.get(parent_digest, ())
        if edges[index].get("status") in {"queued", "shared_sha256_reference"}
        and edges[index].get("child_sha256") in strict_complete_digests
        and depths.get(str(edges[index].get("child_sha256")), 0) > 0
    }


def _run_follow_on_fixed_point(
    *,
    root_digests: Sequence[str],
    output: Path,
    registry: Path,
    specs: list[HandlerSpec],
    requirements_policy: dict[str, dict[str, Any]],
    minimum_confidence: str,
    upx: Path | None,
    sevenzip: Path | None,
    diec: Path | None,
    force_container_probe: bool,
    max_static_layers: int,
    retry_max_static_layers: int | None,
    archive_password: str,
    string_scan_limit: int,
    analysis_contract: dict[str, Any],
    root_analysis_contract: Mapping[str, Any],
    resume: bool,
    execute_child: Callable[..., dict[str, Any]] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """保持payloadをSHA-256固定点queueで同一job内の子caseへ再投入する。"""

    repository = REPOSITORY_ROOT.resolve(strict=True)
    resolved_output = output.resolve(strict=True)
    limits = {
        "maximum_artifacts": MAX_FOLLOW_ON_ARTIFACTS,
        "maximum_edges": MAX_FOLLOW_ON_EDGES,
        "maximum_omitted_metadata": MAX_FOLLOW_ON_OMITTED_METADATA,
        "maximum_depth": MAX_FOLLOW_ON_DEPTH,
        "maximum_total_bytes": MAX_FOLLOW_ON_TOTAL_BYTES,
        "maximum_payload_size": MAX_FOLLOW_ON_PAYLOAD_SIZE,
        "maximum_wall_seconds": MAX_FOLLOW_ON_WALL_SECONDS,
        "maximum_child_seconds": MAX_FOLLOW_ON_CHILD_SECONDS,
    }
    base = {
        "schema_version": 1,
        "limits": limits,
        "analysis_contract_sha256": analysis_contract.get("sha256"),
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }
    if resolved_output == repository or repository in resolved_output.parents:
        return {
            **base,
            "status": "disabled_repository_output",
            "roots": sorted(set(root_digests)),
            "nodes": [],
            "edges": [],
            "omitted_metadata": [],
            "omitted_metadata_commitments": [],
            "errors": ["repository_output_retention_forbidden"],
            "wall_clock_exhausted": False,
        }
    executor = execute_child or _execute_follow_on_child
    deadline = monotonic() + MAX_FOLLOW_ON_WALL_SECONDS
    roots = sorted({normalize_sha256_digest(item) for item in root_digests})
    queue: deque[dict[str, Any]] = deque()
    queued: set[str] = set()
    visited: set[str] = set(roots)
    strict_complete_digests: set[str] = set()
    ancestors: dict[str, frozenset[str]] = {digest: frozenset({digest}) for digest in roots}
    depths: dict[str, int] = {digest: 0 for digest in roots}
    nodes: dict[str, dict[str, Any]] = {
        digest: {
            "sha256": digest,
            "depth": 0,
            "state": "root",
        }
        for digest in roots
    }
    edges: list[dict[str, Any]] = []
    outbound: dict[str, list[int]] = {}
    inbound: dict[str, set[str]] = {}
    errors: set[str] = set()
    omitted_metadata: list[dict[str, Any]] = []
    omitted_commitments_by_parent: dict[str, dict[str, Any]] = {}
    queued_bytes = 0
    queued_artifacts = 0
    verified_read_bytes = 0
    verified_read_count = 0
    wall_clock_exhausted = False

    def discover(parent_sha256: str) -> None:
        nonlocal queued_artifacts, queued_bytes, verified_read_bytes, verified_read_count
        nonlocal wall_clock_exhausted
        parent_depth = depths[parent_sha256]
        if monotonic() >= deadline:
            errors.add(f"{parent_sha256}:wall_clock_limit_before_discovery")
            return
        try:
            scan_result = _case_retained_payloads(
                output,
                parent_sha256,
                maximum_records=max(0, MAX_FOLLOW_ON_EDGES - len(edges)),
                maximum_read_bytes=max(0, MAX_FOLLOW_ON_TOTAL_BYTES - verified_read_bytes),
                maximum_omitted_records=max(
                    0,
                    MAX_FOLLOW_ON_OMITTED_METADATA - len(omitted_metadata),
                ),
                include_omitted_metadata=True,
                include_omitted_commitment=True,
                deadline=deadline,
                monotonic=monotonic,
            )
            if not isinstance(scan_result, tuple):
                raise ValueError("保持payload scanの戻り値がtupleではありません")
            if len(scan_result) == 4:
                payloads, extraction_errors, read_count, read_bytes = scan_result
                scan_omissions: list[dict[str, Any]] = []
                scan_commitment = None
            elif len(scan_result) == 5:
                payloads, extraction_errors, read_count, read_bytes, supplied_omissions = scan_result
                if not isinstance(supplied_omissions, list):
                    raise ValueError("omitted metadataがlistではありません")
                scan_omissions = supplied_omissions
                scan_commitment = None
            elif len(scan_result) == 6:
                (
                    payloads,
                    extraction_errors,
                    read_count,
                    read_bytes,
                    supplied_omissions,
                    scan_commitment,
                ) = scan_result
                if not isinstance(supplied_omissions, list):
                    raise ValueError("omitted metadataがlistではありません")
                scan_omissions = supplied_omissions
            else:
                raise ValueError("保持payload scanの戻り値件数が不正です")
            normalized_omissions = []
            allowed_reasons = {
                "artifact_verification_failed",
                "verified_output_edge_limit",
                "verified_output_read_bytes_limit",
                "verified_output_read_wall_clock_limit",
            }
            for omission in scan_omissions:
                if (
                    not isinstance(omission, Mapping)
                    or set(omission) != {"sha256", "size", "path", "role", "kind", "reason"}
                    or omission.get("reason") not in allowed_reasons
                    or not isinstance(omission.get("size"), int)
                    or isinstance(omission.get("size"), bool)
                    or int(omission["size"]) < 0
                    or any(
                        not isinstance(omission.get(key), str) or not omission[key] for key in ("path", "role", "kind")
                    )
                ):
                    raise ValueError("omitted metadata recordが不正です")
                child_digest = normalize_sha256_digest(str(omission["sha256"]))
                normalized_omissions.append(
                    {
                        "parent_sha256": parent_sha256,
                        "sha256": child_digest,
                        "size": int(omission["size"]),
                        "path": str(omission["path"]),
                        "role": str(omission["role"]),
                        "kind": str(omission["kind"]),
                        "reason": str(omission["reason"]),
                    }
                )
            if len(omitted_metadata) + len(normalized_omissions) > MAX_FOLLOW_ON_OMITTED_METADATA:
                raise ValueError("omitted metadataが全体上限を超えました")
            omitted_metadata.extend(normalized_omissions)
            if scan_commitment is not None:
                if (
                    not isinstance(scan_commitment, Mapping)
                    or set(scan_commitment) != {"count", "sha256"}
                    or isinstance(scan_commitment.get("count"), bool)
                    or not isinstance(scan_commitment.get("count"), int)
                    or int(scan_commitment["count"]) <= 0
                    or not isinstance(scan_commitment.get("sha256"), str)
                ):
                    raise ValueError("omitted metadata commitmentが不正です")
                commitment_digest = normalize_sha256_digest(scan_commitment["sha256"])
                if parent_sha256 in omitted_commitments_by_parent:
                    raise ValueError("同一親のomitted metadata commitmentが重複しています")
                omitted_commitments_by_parent[parent_sha256] = {
                    "parent_sha256": parent_sha256,
                    "count": int(scan_commitment["count"]),
                    "sha256": commitment_digest,
                }
                if "verified_output_omitted_metadata_limit" not in extraction_errors:
                    extraction_errors.append("verified_output_omitted_metadata_limit")
            verified_read_count += read_count
            verified_read_bytes += read_bytes
        except (OSError, TypeError, ValueError) as exc:
            payloads = []
            extraction_errors = [f"case_retained_payload_scan_failed:{type(exc).__name__}"]
        if monotonic() >= deadline:
            wall_clock_exhausted = True
            extraction_errors.append("wall_clock_limit_after_discovery")
        errors.update(f"{parent_sha256}:{item}" for item in extraction_errors)
        for payload in payloads:
            child_sha256 = payload["sha256"]
            child_depth = parent_depth + 1
            edge = {
                "parent_sha256": parent_sha256,
                "child_sha256": child_sha256,
                "depth": child_depth,
                "path": payload["path"],
                "role": payload["role"],
                "kind": payload["kind"],
                "size": payload["size"],
                "status": "queued",
            }
            edge_index = len(edges)
            edges.append(edge)
            outbound.setdefault(parent_sha256, []).append(edge_index)
            inbound.setdefault(child_sha256, set()).add(parent_sha256)
            if child_sha256 in ancestors[parent_sha256]:
                edge["status"] = "cycle_excluded"
                continue
            if child_depth > MAX_FOLLOW_ON_DEPTH:
                edge["status"] = "depth_limit"
                continue
            if payload["size"] > MAX_FOLLOW_ON_PAYLOAD_SIZE:
                edge["status"] = "payload_size_limit"
                continue
            if child_sha256 in visited or child_sha256 in queued:
                edge["status"] = "shared_sha256_reference"
                continue
            if queued_artifacts + 1 > MAX_FOLLOW_ON_ARTIFACTS:
                edge["status"] = "artifact_count_limit"
                continue
            if queued_bytes + payload["size"] > MAX_FOLLOW_ON_TOTAL_BYTES:
                edge["status"] = "total_bytes_limit"
                continue
            queued.add(child_sha256)
            visited.add(child_sha256)
            queued_artifacts += 1
            queued_bytes += payload["size"]
            depths[child_sha256] = child_depth
            ancestors[child_sha256] = frozenset({*ancestors[parent_sha256], child_sha256})
            nodes[child_sha256] = {
                "sha256": child_sha256,
                "depth": child_depth,
                "size": payload["size"],
                "state": "queued",
            }
            queue.append(
                {
                    **payload,
                    "parent_sha256": parent_sha256,
                    "depth": child_depth,
                }
            )

    for root in roots:
        discover(root)

    while queue:
        item = queue.popleft()
        digest = item["sha256"]
        remaining = deadline - monotonic()
        if remaining <= 0:
            wall_clock_exhausted = True
            nodes[digest]["state"] = "wall_clock_limit"
            while queue:
                pending = queue.popleft()
                nodes[pending["sha256"]]["state"] = "wall_clock_limit"
            break
        resumed_complete = resume and _case_strict_complete(
            output,
            digest,
            expected_contract=analysis_contract,
        )
        remaining = deadline - monotonic()
        if remaining <= 0:
            wall_clock_exhausted = True
            nodes[digest]["state"] = "wall_clock_limit"
            while queue:
                pending = queue.popleft()
                nodes[pending["sha256"]]["state"] = "wall_clock_limit"
            break
        if resumed_complete:
            nodes[digest]["state"] = "resumed_complete"
            nodes[digest]["case_state"] = "complete"
            strict_complete_digests.add(digest)
            discover(digest)
            continue
        remaining = deadline - monotonic()
        if remaining <= 0:
            wall_clock_exhausted = True
            nodes[digest]["state"] = "wall_clock_limit"
            while queue:
                pending = queue.popleft()
                nodes[pending["sha256"]]["state"] = "wall_clock_limit"
            break
        timeout = min(MAX_FOLLOW_ON_CHILD_SECONDS, remaining)
        try:
            executor(
                payload=item["data"],
                digest=digest,
                parent_sha256=item["parent_sha256"],
                depth=item["depth"],
                output=output,
                registry=registry,
                minimum_confidence=minimum_confidence,
                upx=upx,
                sevenzip=sevenzip,
                diec=diec,
                force_container_probe=force_container_probe,
                max_static_layers=max_static_layers,
                retry_max_static_layers=retry_max_static_layers,
                archive_password=archive_password,
                string_scan_limit=string_scan_limit,
                analysis_contract=analysis_contract,
                timeout_seconds=timeout,
            )
            result = _case_result_from_disk(
                output,
                digest,
                expected_contract=analysis_contract,
            )
            if monotonic() >= deadline:
                wall_clock_exhausted = True
                nodes[digest]["state"] = "wall_clock_limit"
                while queue:
                    pending = queue.popleft()
                    nodes[pending["sha256"]]["state"] = "wall_clock_limit"
                break
            nodes[digest]["state"] = "analyzed"
            nodes[digest]["case_state"] = result.get("case_state")
            if result.get("case_state") == "complete":
                strict_complete_digests.add(digest)
            discover(digest)
        except subprocess.TimeoutExpired:
            nodes[digest]["state"] = "timeout"
        except Exception as exc:  # noqa: BLE001 - 子worker境界の失敗をqueue状態へ正規化する
            nodes[digest]["state"] = "failed"
            nodes[digest]["error_type"] = type(exc).__name__
            errors.add(f"{digest}:child_analysis_failed:{type(exc).__name__}")

    # rootを先に評価し、別rootと同じSHAの保持payloadを入力順序へ依存せず再利用する。
    for root_digest in roots:
        if _case_strict_complete(
            output,
            root_digest,
            expected_contract=root_analysis_contract,
        ):
            strict_complete_digests.add(root_digest)

    promoted_parents: set[str] = set()
    promotion_enabled = not omitted_commitments_by_parent
    for parent_digest in sorted(nodes, key=lambda value: (-depths[value], value)) if promotion_enabled else []:
        if depths[parent_digest] > 0 and nodes[parent_digest].get("state") not in {"analyzed", "resumed_complete"}:
            continue
        if monotonic() >= deadline:
            wall_clock_exhausted = True
            break
        expected_contract = root_analysis_contract if depths[parent_digest] == 0 else analysis_contract
        complete_child_digests = _parent_complete_child_digests(
            parent_digest,
            outbound=outbound,
            edges=edges,
            depths=depths,
            strict_complete_digests=strict_complete_digests,
        )
        if parent_digest in strict_complete_digests or _case_strict_complete(
            output,
            parent_digest,
            expected_contract=expected_contract,
        ):
            strict_complete_digests.add(parent_digest)
            if not _case_has_follow_on_promotion(output, parent_digest):
                continue
        elif not complete_child_digests:
            continue
        try:
            promoted = _promote_parent_case_from_follow_on(
                output,
                parent_digest,
                parent_contract=expected_contract,
                child_contract=analysis_contract,
                specs=specs,
                complete_child_digests=complete_child_digests,
            )
        except (OSError, TypeError, ValueError) as exc:
            errors.add(f"{parent_digest}:parent_promotion_failed:{type(exc).__name__}")
            continue
        if promoted:
            strict_complete_digests.add(parent_digest)
            promoted_parents.add(parent_digest)
            if depths[parent_digest] > 0:
                nodes[parent_digest]["case_state"] = "complete"
        if monotonic() >= deadline:
            wall_clock_exhausted = True
            break

    # 子の厳格complete証明があるedgeだけを完了として公開する。
    for edge in edges:
        if edge["status"] not in {"queued", "shared_sha256_reference"}:
            continue
        child_complete = edge["child_sha256"] in strict_complete_digests
        if edge["status"] == "shared_sha256_reference":
            edge["status"] = "shared_sha256_reused_complete" if child_complete else "shared_sha256_reused_incomplete"
        else:
            edge["status"] = "child_complete" if child_complete else "child_incomplete"
    all_children_complete = bool(edges) and all(
        edge["status"]
        in {
            "child_complete",
            "shared_sha256_reused_complete",
        }
        for edge in edges
    )
    return {
        **base,
        "status": (
            "no_retained_payloads"
            if (
                not edges
                and not omitted_metadata
                and not omitted_commitments_by_parent
                and not errors
                and not wall_clock_exhausted
            )
            else (
                "complete"
                if (
                    all_children_complete
                    and not omitted_metadata
                    and not omitted_commitments_by_parent
                    and not errors
                    and not wall_clock_exhausted
                )
                else "partial"
            )
        ),
        "roots": roots,
        "nodes": [nodes[key] for key in sorted(nodes)],
        "edges": sorted(
            edges,
            key=lambda item: (
                item["parent_sha256"],
                item["child_sha256"],
                item["path"],
            ),
        ),
        "omitted_metadata": sorted(
            omitted_metadata,
            key=lambda item: (
                item["parent_sha256"],
                item["sha256"],
                item["path"],
                item["role"],
                item["kind"],
                item["size"],
                item["reason"],
            ),
        ),
        "omitted_metadata_commitments": [
            omitted_commitments_by_parent[parent] for parent in sorted(omitted_commitments_by_parent)
        ],
        "errors": sorted(errors),
        "queued_artifact_count": queued_artifacts,
        "queued_total_bytes": queued_bytes,
        "verified_read_count": verified_read_count,
        "verified_read_bytes": verified_read_bytes,
        "parent_promotion_enabled": promotion_enabled,
        "promoted_parent_sha256": sorted(promoted_parents),
        "wall_clock_exhausted": wall_clock_exhausted,
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
    max_static_layers: int = MAX_STATIC_LAYERS,
    retry_max_static_layers: int | None = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    string_scan_limit: int = DEFAULT_STRING_SCAN_LIMIT,
    resume: bool = False,
    family_hint_manifest: Path | None = None,
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
    if isinstance(string_scan_limit, bool) or not isinstance(string_scan_limit, int) or string_scan_limit <= 0:
        raise ValueError("string_scan_limitは正の整数で指定してください")
    StaticLayerPolicy(max_layers=max_static_layers)
    if retry_max_static_layers is not None:
        StaticLayerPolicy(max_layers=retry_max_static_layers)
        if retry_max_static_layers <= max_static_layers:
            raise ValueError("retry_max_static_layersは初回上限より大きくしてください")
    upx = _normalize_tool_path(upx, "UPX")
    sevenzip = _normalize_tool_path(sevenzip, "7-Zip")
    diec = _normalize_tool_path(diec, "Detect It Easy CLI")
    family_hint_document, family_hint_identity = _load_family_hint_manifest(family_hint_manifest)
    family_requirements_policy = _load_family_analysis_requirements()

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
        max_static_layers=max_static_layers,
        retry_max_static_layers=retry_max_static_layers,
        archive_password=password,
        max_file_size=max_file_size,
        string_scan_limit=string_scan_limit,
        family_hint_manifest_identity=family_hint_identity,
    )
    follow_on_analysis_contract = _build_follow_on_analysis_contract(
        registry=registry,
        specs=specs,
        minimum_confidence=minimum_confidence,
        upx=upx,
        sevenzip=sevenzip,
        diec=diec,
        force_container_probe=force_container_probe,
        max_static_layers=max_static_layers,
        retry_max_static_layers=retry_max_static_layers,
        archive_password=password,
        string_scan_limit=string_scan_limit,
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
                    max_static_layers=max_static_layers,
                    retry_max_static_layers=retry_max_static_layers,
                    archive_password=password,
                    string_scan_limit=string_scan_limit,
                    assessment_only=assessment_only,
                    analysis_contract=analysis_contract,
                    family_hint_manifest=family_hint_document,
                    family_requirements_policy=family_requirements_policy,
                )
            )
        except Exception as exc:
            errors.append(
                {
                    "source_name": path.name,
                    "error": sanitize_public_value(f"{type(exc).__name__}: {exc}"),
                }
            )
    if assessment_only:
        follow_on = {
            "schema_version": 1,
            "status": "disabled_assessment_only",
            "roots": sorted(item["sha256"] for item in cases),
            "nodes": [],
            "edges": [],
            "omitted_metadata": [],
            "omitted_metadata_commitments": [],
            "errors": [],
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        }
    else:
        try:
            follow_on = _run_follow_on_fixed_point(
                root_digests=[item["sha256"] for item in cases],
                output=output,
                registry=registry,
                specs=specs,
                requirements_policy=family_requirements_policy,
                minimum_confidence=minimum_confidence,
                upx=upx,
                sevenzip=sevenzip,
                diec=diec,
                force_container_probe=force_container_probe,
                max_static_layers=max_static_layers,
                retry_max_static_layers=retry_max_static_layers,
                archive_password=password,
                string_scan_limit=string_scan_limit,
                analysis_contract=follow_on_analysis_contract,
                root_analysis_contract=analysis_contract,
                resume=resume,
            )
            refreshed = []
            for item in cases:
                try:
                    updated = _case_result_from_disk(
                        output,
                        item["sha256"],
                        resumed=bool(item.get("resumed")),
                        expected_contract=analysis_contract,
                    )
                except (OSError, TypeError, ValueError):
                    updated = item
                refreshed.append(updated)
            cases = refreshed
        except Exception as exc:  # noqa: BLE001 - fixed-point全体の障害をroot結果から分離する
            follow_on = {
                "schema_version": 1,
                "status": "failed",
                "roots": sorted(item["sha256"] for item in cases),
                "nodes": [],
                "edges": [],
                "omitted_metadata": [],
                "omitted_metadata_commitments": [],
                "errors": [f"fixed_point_failed:{type(exc).__name__}"],
                "executed_sample": False,
                "network_contacted": False,
                "ai_used": False,
            }
    root_digests = {item["sha256"] for item in cases}
    derived_parents: dict[str, set[str]] = {}
    for edge in follow_on.get("edges") or []:
        if (
            isinstance(edge, Mapping)
            and edge.get("status")
            in {
                "child_complete",
                "child_incomplete",
            }
            and isinstance(edge.get("child_sha256"), str)
        ):
            derived_parents.setdefault(edge["child_sha256"], set()).add(str(edge.get("parent_sha256")))
    derived_cases = []
    follow_on_errors = {str(value) for value in follow_on.get("errors") or [] if isinstance(value, str)}
    for node in follow_on.get("nodes") or []:
        if not isinstance(node, Mapping) or not isinstance(node.get("depth"), int):
            continue
        digest = node.get("sha256")
        if node["depth"] <= 0 or not isinstance(digest, str) or digest in root_digests:
            continue
        if node.get("state") not in {"analyzed", "resumed_complete"}:
            continue
        try:
            item = _case_result_from_disk(
                output,
                digest,
                resumed=node.get("state") == "resumed_complete",
                expected_contract=follow_on_analysis_contract,
            )
        except (OSError, TypeError, ValueError) as exc:
            follow_on_errors.add(f"{digest}:derived_case_omitted:{type(exc).__name__}")
            if isinstance(node, dict):
                node["state"] = "incomplete_case_omitted"
            continue
        item["case_origin"] = "derived_follow_on"
        item["follow_on_depth"] = node["depth"]
        item["parent_sha256"] = sorted(derived_parents.get(digest, set()))
        derived_cases.append(item)
    if follow_on_errors != set(follow_on.get("errors") or []):
        follow_on["errors"] = sorted(follow_on_errors)
        follow_on["status"] = "partial"
    derived_cases.sort(key=lambda item: (item["follow_on_depth"], item["sha256"]))
    derived_counts = {
        "analyzed": len(derived_cases),
        "identified": sum(bool(item["selected_families"]) for item in derived_cases),
        "unknown_or_ambiguous": sum(not item["selected_families"] for item in derived_cases),
        "complete": sum(item["case_state"] == "complete" for item in derived_cases),
        "triaged_unknown": sum(item["case_state"] == "triaged_unknown" for item in derived_cases),
        "partial": sum(item["case_state"] == "partial" for item in derived_cases),
        "failed": sum(item["case_state"] == "failed" for item in derived_cases),
        "resumed": sum(bool(item.get("resumed")) for item in derived_cases),
    }
    _atomic_replace_json(output / "follow-on-analysis.json", follow_on)
    follow_on_digest = hashlib.sha256((output / "follow-on-analysis.json").read_bytes()).hexdigest()
    summary = {
        "schema_version": 1,
        "counts": {
            "input_files": len(paths),
            "analyzed": len(cases),
            "duplicates": len(duplicates),
            "errors": len(errors),
            "identified": sum(bool(item["selected_families"]) for item in cases),
            "unknown_or_ambiguous": sum(not item["selected_families"] for item in cases),
            "automation_resolved": sum(item.get("automation_state") == "resolved" for item in cases),
            "automation_partial": sum(item.get("automation_state") == "partial" for item in cases),
            "automation_unknown": sum(item.get("automation_state") == "unknown" for item in cases),
            "candidate_handler_attempts": sum(item.get("candidate_handler_attempts", 0) for item in cases),
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
        "follow_on_analysis_contract": follow_on_analysis_contract,
        "requirements_policy": _requirements_policy_summary(family_requirements_policy),
        "follow_on_analysis": {
            "artifact": "follow-on-analysis.json",
            "sha256": follow_on_digest,
            "status": follow_on.get("status"),
            "node_count": len(follow_on.get("nodes") or []),
            "edge_count": len(follow_on.get("edges") or []),
            "error_count": len(follow_on.get("errors") or []),
        },
        "cases": cases,
        "derived_cases": derived_cases,
        "derived_counts": derived_counts,
        "duplicates": duplicates,
        "errors": errors,
        "settings": {
            "archive_mode": archive_mode,
            "forced_family": forced_family,
            "minimum_confidence": minimum_confidence,
            "assessment_only": assessment_only,
            "max_files": max_files,
            "max_file_size": max_file_size,
            "string_scan_limit": string_scan_limit,
            "family_hint_manifest": family_hint_identity,
            "static_tools": {
                "upx": upx.name if upx else None,
                "sevenzip": sevenzip.name if sevenzip else None,
                "diec": diec.name if diec else None,
            },
            "force_container_probe": force_container_probe,
            "max_static_layers": max_static_layers,
            "retry_max_static_layers": retry_max_static_layers,
            "resume": resume,
            "follow_on_fixed_point": not assessment_only,
        },
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
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
        "--family-hint-manifest",
        type=Path,
        help="root SHA-256へ完全一致する外部familyヒントのstrict JSON。ヒント単独では確定しません。",
    )
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
        "--string-scan-limit",
        type=_positive_integer,
        default=DEFAULT_STRING_SCAN_LIMIT,
        help="各静的復元層から保持する文字列候補数の上限。正の整数で指定します。",
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
        "--max-static-layers",
        type=int,
        default=MAX_STATIC_LAYERS,
        help="静的復元で保持する層数の初回上限。正の整数で指定します。",
    )
    parser.add_argument(
        "--retry-max-static-layers",
        type=int,
        help="初回に層数上限へ達した検体だけ再試行する上限。初回上限より大きく指定します。",
    )
    parser.add_argument(
        "--force-container-probe",
        action="store_true",
        help="レビュー済み手掛かりがあるPEを7-Zipで追加検査します。",
    )
    return parser


def _runtime_preflight_main() -> int:
    """隔離runtimeでhandler catalogを構築できることを短時間で検証する。"""

    try:
        runtime_contract.import_required_runtime_modules()
        clear_handler_caches()
        specs = discover_handlers()
        automatic = [spec for spec in specs if spec.automatic and spec.supported_interface]
        if not automatic or len(automatic) > 256:
            raise ValueError("automatic handler catalog件数が不正です")
        for spec in automatic:
            formats = [value for value in spec.input_formats if value != "any"]
            if not formats:
                raise ValueError(f"handler input formatが有界ではありません: {spec.id}")
    except Exception:  # noqa: BLE001 - runtime境界では詳細を外へ出さず失敗codeだけ返す
        return 2
    return 0


def _interpreter_is_isolated() -> bool:
    """現在のPythonが`-I`で起動された場合だけTrueを返す。"""

    return bool(sys.flags.isolated)


def _run_isolated_cli(argv: Sequence[str] | None) -> int:
    """通常CLIの解析本体を同じPythonの隔離processへ移し、終了codeを返す。"""

    if _interpreter_is_isolated():
        raise RuntimeError("isolated CLIを再帰起動できません")
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        from bounded_process import run_bounded

        completed = run_bounded(
            [
                sys.executable,
                "-I",
                "-B",
                str(Path(__file__).resolve()),
                *arguments,
            ],
            cwd=REPOSITORY_ROOT,
            env=_bounded_handler_environment(),
            shell=False,
            check=False,
            stdout=sys.stdout,
            stderr=sys.stderr,
            timeout=MAX_DIRECT_CLI_SECONDS,
            require_containment=True,
            maximum_active_processes=MAX_DIRECT_CLI_ACTIVE_PROCESSES,
            maximum_memory_bytes=MAX_DIRECT_CLI_MEMORY_BYTES,
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
        return 2
    return int(completed.returncode)


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、失敗を検体単位に分離した一括解析を実行する。"""

    if not _interpreter_is_isolated():
        return _run_isolated_cli(argv)
    if _runtime_preflight_main() != 0:
        return 2
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
        max_static_layers=args.max_static_layers,
        retry_max_static_layers=args.retry_max_static_layers,
        max_file_size=args.max_file_size,
        string_scan_limit=args.string_scan_limit,
        resume=args.resume,
        family_hint_manifest=args.family_hint_manifest,
    )
    print(json.dumps(summary["counts"], ensure_ascii=False, indent=2, allow_nan=False))
    counts = summary["counts"]
    incomplete = (
        counts.get("errors", 0)
        + counts.get("triaged_unknown", 0)
        + counts.get("partial", 0)
        + counts.get("failed", 0)
        + (summary.get("derived_counts") or {}).get("triaged_unknown", 0)
    )
    follow_on_status = (summary.get("follow_on_analysis") or {}).get("status")
    if follow_on_status not in {
        "complete",
        "no_retained_payloads",
        "disabled_assessment_only",
    }:
        incomplete += 1
    return 0 if incomplete == 0 else 20


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "--runtime-preflight":
        raise SystemExit(_runtime_preflight_main())
    if len(sys.argv) == 6 and sys.argv[1] == "--follow-on-worker":
        raise SystemExit(_follow_on_worker_main(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]))
    raise SystemExit(main())
