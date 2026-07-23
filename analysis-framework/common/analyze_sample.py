#!/usr/bin/env python3
"""検体の適用可否判定から静的解析までを1コマンドで実行する。"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path
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
from handler_catalog import (  # noqa: E402
    HandlerSpec,
    catalog_summary,
    discover_handlers,
    execute_handler,
    load_handler,
    sanitize_public_value,
)
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
    ArchiveValidationError,
    read_single_aes_zip_member,
    safe_output_name,
    sha256_bytes,
    write_json,
)
from unpackers.static_unpacker import unpack_bytes  # noqa: E402


MAX_STATIC_LAYERS = 32
MAX_STATIC_DEPTH = 3
MAX_RECOVERED_LAYER_SIZE = 64 * 1024 * 1024
MAX_RECOVERED_TOTAL_SIZE = 256 * 1024 * 1024
CAMPAIGN_CORRELATION_RULES = FRAMEWORK_ROOT / "registry" / "campaign_correlation_rules.json"
CAMPAIGN_FINGERPRINTS = FRAMEWORK_ROOT / "registry" / "campaign_fingerprints.json"


@dataclass(frozen=True)
class InputUnit:
    """解析対象のインメモリ検体と公開可能な入力メタデータ。"""

    source_name: str
    data: bytes
    input_kind: str
    outer_sha256: str
    outer_size: int
    member_name: str | None = None


@dataclass(frozen=True)
class StaticLayer:
    """メモリ内だけで保持する認証済み静的復元レイヤー。"""

    name: str
    data: bytes
    sha256: str
    parent_sha256: str | None
    depth: int
    transform: str

    def public(self) -> dict[str, Any]:
        """バイト列を含まないレイヤーメタデータを返す。"""

        return {
            "name": self.name,
            "sha256": self.sha256,
            "size": len(self.data),
            "parent_sha256": self.parent_sha256,
            "depth": self.depth,
            "transform": self.transform,
        }


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

    if max_files <= 0:
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

    size = path.stat().st_size
    if size > max_file_size:
        raise ValueError(f"入力サイズが上限 {max_file_size} bytes を超えました")
    outer = path.read_bytes()
    outer_digest = sha256_bytes(outer)
    encrypted, member_count = _zip_envelope_shape(outer)
    unwrap = archive_mode == "malwarebazaar" or (
        archive_mode == "auto" and encrypted and member_count == 1
    )
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
    data = json.loads(registry.read_text(encoding="utf-8-sig"))
    values = data.get("malware_types", {})
    if not isinstance(values, dict):
        raise ValueError("registry malware_types must be an object")
    return set(values)


def recover_static_layers(unit: InputUnit) -> tuple[list[StaticLayer], dict[str, Any]]:
    """既存アンパッカー群で復元層を再帰処理し、バイト列はメモリ内だけに保持する。"""

    root = StaticLayer(
        name=unit.source_name,
        data=unit.data,
        sha256=hashlib.sha256(unit.data).hexdigest(),
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    layers = [root]
    seen = {root.sha256}
    steps = []
    recovered_total = 0
    cursor = 0
    limit_events = []
    while cursor < len(layers):
        layer = layers[cursor]
        cursor += 1
        if layer.depth >= MAX_STATIC_DEPTH:
            steps.append(
                {
                    "input_layer": layer.public(),
                    "status": "skipped_depth_limit",
                }
            )
            continue
        try:
            report, artifacts = unpack_bytes(layer.data, layer.name)
            step = {
                "input_layer": layer.public(),
                "status": "succeeded",
                "report": sanitize_public_value(report),
                "accepted_children": [],
            }
        except Exception as exc:
            steps.append(
                {
                    "input_layer": layer.public(),
                    "status": "failed",
                    "error": sanitize_public_value(f"{type(exc).__name__}: {exc}"),
                }
            )
            continue
        for artifact_kind, blob in artifacts:
            if not isinstance(blob, bytes):
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "reason": "non_bytes_artifact_rejected",
                    }
                )
                continue
            digest = hashlib.sha256(blob).hexdigest()
            if digest in seen:
                continue
            if len(blob) > MAX_RECOVERED_LAYER_SIZE:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "sha256": digest,
                        "size": len(blob),
                        "reason": "layer_size_limit",
                    }
                )
                continue
            if recovered_total + len(blob) > MAX_RECOVERED_TOTAL_SIZE:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "sha256": digest,
                        "size": len(blob),
                        "reason": "recovered_total_limit",
                    }
                )
                continue
            if len(layers) >= MAX_STATIC_LAYERS:
                limit_events.append(
                    {
                        "parent_sha256": layer.sha256,
                        "kind": str(artifact_kind),
                        "sha256": digest,
                        "size": len(blob),
                        "reason": "layer_count_limit",
                    }
                )
                continue
            child = StaticLayer(
                name=f"{layer.name}::{artifact_kind}",
                data=blob,
                sha256=digest,
                parent_sha256=layer.sha256,
                depth=layer.depth + 1,
                transform=str(artifact_kind),
            )
            layers.append(child)
            seen.add(digest)
            recovered_total += len(blob)
            step["accepted_children"].append(child.public())
        steps.append(step)
    public = {
        "schema_version": 1,
        "limits": {
            "max_layers": MAX_STATIC_LAYERS,
            "max_depth": MAX_STATIC_DEPTH,
            "max_recovered_layer_size": MAX_RECOVERED_LAYER_SIZE,
            "max_recovered_total_size": MAX_RECOVERED_TOTAL_SIZE,
        },
        "counts": {
            "layers": len(layers),
            "recovered_layers": len(layers) - 1,
            "recovered_bytes": recovered_total,
            "limit_events": len(limit_events),
        },
        "layers": [item.public() for item in layers],
        "steps": steps,
        "limit_events": limit_events,
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }
    return layers, public


def _handler_evidence_score(value: Any) -> int:
    """空結果より復元設定・IOCを優先する決定的な選択scoreを返す。"""

    if not isinstance(value, dict):
        return 0
    score = 0
    for key, item in value.items():
        lowered = str(key).lower()
        if lowered in {
            "findings",
            "c2",
            "config_endpoints",
            "network_endpoints",
            "urls",
            "endpoints",
        } and isinstance(item, list):
            score += min(len(item), 100) * 10
        if lowered in {"static_config_recovered", "decoded_config_recovered"} and item is True:
            score += 1_000
        if lowered in {"family", "variant"} and str(item).lower() not in {
            "",
            "none",
            "unknown",
            "unresolved",
        }:
            score += 100
        if isinstance(item, dict):
            score += _handler_evidence_score(item)
    return score


def _selected_family(
    classification: dict[str, Any],
    forced_family: str | None,
    minimum_confidence: str,
) -> tuple[str | None, str]:
    if forced_family:
        return forced_family, "explicit_operator_selection"
    family = classification.get("malware_type")
    confidence = classification.get("malware_type_confidence", "low")
    if family == "unknown" or CONFIDENCE.get(confidence, 0) < CONFIDENCE[minimum_confidence]:
        return None, "no_unique_detection_above_threshold"
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
        family_layers = [
            item for item in layer_selections if item["selected_family"] == spec.family
        ]
        eligible_layers = [
            item
            for item in family_layers
            if spec.campaign is None
            or item["classification"].get("campaign_type", "unknown") == spec.campaign
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


def summarize_family_coverage(
    specs: list[HandlerSpec], registered_families: set[str]
) -> list[dict[str, Any]]:
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


def _preflight_applicable(
    specs: list[HandlerSpec], applicability: list[dict[str, Any]]
) -> list[dict[str, Any]]:
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
) -> dict[str, Any]:
    """1検体を分類し、適用可能な既存静的解析器を一括実行する。"""

    digest = hashlib.sha256(unit.data).hexdigest()
    case_dir = output / "cases" / digest
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
        layers, layer_report = recover_static_layers(unit)
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
            "forced_family_registered": (
                forced_family in registered if forced_family else None
            ),
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
        {
            item["selected_family"]
            for item in layer_selections
            if item["selected_family"] is not None
        }
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
        try:
            generic = analyze_family_sample.analyze(
                unit.source_name,
                unit.data,
                case_dir / "scripts",
                persist_normalized_text=False,
            )
            write_json(case_dir / "generic-triage.json", sanitize_public_value(generic))
            generic_status = "succeeded"
        except Exception as exc:
            write_json(
                case_dir / "generic-triage.json",
                {
                    "schema_version": 1,
                    "status": "failed",
                    "error": sanitize_public_value(f"{type(exc).__name__}: {exc}"),
                    "executed_sample": False,
                    "network_contacted": False,
                },
            )
            generic_status = "failed"

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
            successes = []
            for layer_index, layer in enumerate(layers):
                try:
                    result = execute_handler(specs_by_id[handler_id], layer.data, layer.name)
                    score = _handler_evidence_score(result.get("result"))
                    attempts.append(
                        {
                            "layer": layer.public(),
                            "status": "succeeded",
                            "evidence_score": score,
                        }
                    )
                    successes.append((score, -layer_index, layer, result))
                except Exception as exc:
                    attempts.append(
                        {
                            "layer": layer.public(),
                            "status": "failed",
                            "error": sanitize_public_value(
                                f"{type(exc).__name__}: {exc}"
                            ),
                        }
                    )
            if not successes:
                executions.append(
                    {
                        "handler_id": handler_id,
                        "status": "failed",
                        "error": "all_static_layers_failed",
                        "attempts": attempts,
                    }
                )
                continue
            selected_score, _, selected_layer, selected_result = max(successes)
            filename = (
                safe_output_name(specs_by_id[handler_id].family)
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
                    "selected_evidence_score": selected_score,
                    "selection_strategy": "strongest_static_evidence_then_root_order",
                    "attempts": attempts,
                },
            )
            executions.append(
                {
                    "handler_id": handler_id,
                    "status": "succeeded",
                    "selected_layer_sha256": selected_layer.sha256,
                    "result": f"handlers/{filename}",
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
    (case_dir / "STATIC-LOGIC.md").write_text(
        render_static_logic_markdown(logic_report), encoding="utf-8"
    )
    profile = build_case_profile(case_dir)
    write_json(case_dir / "features.json", profile)
    (case_dir / "FEATURES.md").write_text(
        render_features_markdown(profile), encoding="utf-8"
    )
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
    report["knowledge_artifacts"] = {
        "features": "features.json",
        "features_markdown": "FEATURES.md",
        "campaign_labels": "campaign-labels.json",
        "static_logic": "static-logic.json",
        "static_logic_markdown": "STATIC-LOGIC.md",
    }
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
        "analysis_stage_failed": generic_status == "failed",
        "report": f"cases/{digest}/report.json",
    }


def load_resumable_case(
    output: Path,
    digest: str,
    *,
    assessment_only: bool,
) -> dict[str, Any] | None:
    """検証済みの完了レポートを再開用case summaryへ復元する。"""

    case_dir = output / "cases" / digest
    report_path = case_dir / "report.json"
    if not report_path.is_file():
        return None
    if case_dir.is_symlink() or report_path.is_symlink():
        raise ValueError(f"再開対象caseにsymbolic linkがあります: {digest}")
    required = (
        "static-layers.json",
        "classification.json",
        "applicability.json",
        "features.json",
        "FEATURES.md",
        "campaign-labels.json",
        "static-logic.json",
        "STATIC-LOGIC.md",
    )
    if any(not (case_dir / name).is_file() for name in required):
        raise ValueError(f"再開対象caseの必須成果物が不足しています: {digest}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"再開対象reportを検証できません: {digest}") from exc
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError(f"再開対象reportのschemaが不正です: {digest}")
    sample = report.get("sample")
    classification = report.get("classification")
    executions = report.get("handler_executions")
    if not isinstance(sample, dict) or sample.get("sha256") != digest:
        raise ValueError(f"再開対象reportのSHA-256が不一致です: {digest}")
    if not isinstance(classification, dict) or not isinstance(executions, list):
        raise ValueError(f"再開対象reportの構造が不正です: {digest}")
    if report.get("executed_sample") is not False or report.get("network_contacted") is not False:
        raise ValueError(f"再開対象reportの安全フラグが不正です: {digest}")
    if report.get("assessment_only") is not assessment_only:
        raise ValueError(f"再開対象reportの解析モードが一致しません: {digest}")
    selected_families = classification.get("selected_families")
    if not isinstance(selected_families, list) or any(
        not isinstance(item, str) for item in selected_families
    ):
        raise ValueError(f"再開対象reportのfamily一覧が不正です: {digest}")
    source_name = sample.get("source_name")
    if not isinstance(source_name, str) or not source_name:
        raise ValueError(f"再開対象reportのsource名が不正です: {digest}")
    statuses = [
        item.get("status")
        for item in executions
        if isinstance(item, dict)
    ]
    return {
        "sha256": digest,
        "source_name": source_name,
        "family": classification.get("family"),
        "selected_family": classification.get("selected_family"),
        "selected_families": selected_families,
        "campaign": classification.get("campaign"),
        "handler_succeeded": sum(status == "succeeded" for status in statuses),
        "handler_failed": sum(
            status in {"failed", "preflight_failed"} for status in statuses
        ),
        "analysis_stage_failed": report.get("generic_triage") == "failed",
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
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    resume: bool = False,
) -> dict[str, Any]:
    """複数入力をSHA-256で重複排除し、失敗を検体単位に分離する。"""

    output.mkdir(parents=True, exist_ok=True)
    paths = collect_inputs(inputs, output, max_files)
    if archive_mode == "malwarebazaar":
        paths = [path for path in paths if path.suffix.casefold() == ".zip"]
    specs = discover_handlers()
    registered = _registered_families(registry)
    forced_family = normalize_family(forced_family) if forced_family else None
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
                    assessment_only=assessment_only,
                )
            )
        except (ArchiveValidationError, OSError, ValueError, RuntimeError) as exc:
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
            "analysis_stage_failures": sum(item["analysis_stage_failed"] for item in cases),
            "resumed": sum(bool(item.get("resumed")) for item in cases),
        },
        "catalog": catalog_summary(specs),
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
        max_file_size=args.max_file_size,
        resume=args.resume,
    )
    print(json.dumps(summary["counts"], ensure_ascii=False, indent=2))
    failed = (
        summary["counts"]["errors"]
        + summary["counts"]["handler_failures"]
        + summary["counts"]["analysis_stage_failures"]
    )
    return 0 if failed == 0 else 20


if __name__ == "__main__":
    raise SystemExit(main())
