#!/usr/bin/env python3
"""既知マルウェアのscript-only解析カバレッジを機械監査する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from analysis_contract import load_json_object_strict
from handler_catalog import (
    DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
    HandlerSpec,
    discover_handlers,
    preflight_handler_for_assessment,
)

SCHEMA_VERSION = 2
FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"
DEFAULT_REQUIREMENTS = FRAMEWORK_ROOT / "registry" / "family_analysis_requirements.json"
MAX_COVERAGE_PREFLIGHTS = 2_048
PREFLIGHT_PROBE_INPUT_SIZE = 1
FAMILY_ID = re.compile(r"^[a-z0-9_-]+$")
QUALITY_POLICY_CATEGORIES = frozenset(
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

PreflightCallable = Callable[..., dict[str, Any]]


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _registered_families(path: Path) -> set[str]:
    document = load_json_object_strict(path)
    values = document.get("malware_types")
    if not isinstance(values, dict):
        raise TypeError("registry.malware_typesはobjectで指定してください")
    if any(not isinstance(key, str) or not key for key in values):
        raise ValueError("registryのfamily名が不正です")
    return set(values)


def _normalize_quality_policies(
    supplied: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, Any]]:
    """CLIとPython APIで同じ品質policy schemaをfail-closed検証する。"""

    if not isinstance(supplied, Mapping):
        raise TypeError("quality_policiesはmappingで指定してください")
    if len(supplied) > 512:
        raise ValueError("family analysis requirementsのpoliciesが不正です")
    expected = {
        "category",
        "config_required",
        "network_required",
        "terminal_payload_required",
    }
    policies: dict[str, dict[str, Any]] = {}
    for family, policy in supplied.items():
        if not isinstance(family, str) or FAMILY_ID.fullmatch(family) is None:
            raise ValueError("family analysis requirementsに不正なfamilyがあります")
        if not isinstance(policy, Mapping) or set(policy) != expected:
            raise ValueError(
                f"family analysis requirementsのfieldが不正です: {family}"
            )
        if policy.get("category") not in QUALITY_POLICY_CATEGORIES:
            raise ValueError(
                f"family analysis requirementsのcategoryが不正です: {family}"
            )
        if any(
            type(policy.get(key)) is not bool
            for key in expected - {"category"}
        ):
            raise ValueError(
                f"family analysis requirementsのbooleanが不正です: {family}"
            )
        policies[family] = dict(policy)
    return dict(sorted(policies.items()))


def _load_quality_policies(path: Path) -> dict[str, dict[str, Any]]:
    """family別の解析完結条件を厳格schemaで読み込む。"""

    document = load_json_object_strict(path)
    if (
        set(document) != {"schema_version", "policies"}
        or type(document.get("schema_version")) is not int
        or document.get("schema_version") != 1
    ):
        raise ValueError("family analysis requirementsのroot schemaが不正です")
    supplied = document.get("policies")
    if not isinstance(supplied, dict):
        raise TypeError("family analysis requirementsのpoliciesはobjectで指定してください")
    return _normalize_quality_policies(supplied)


def _dependency_fingerprint(preflights: Sequence[dict[str, Any]]) -> str:
    """preflightが検証したsource/dependency集合を正規化して指紋化する。"""

    sources: set[str] = set()
    dependencies: set[tuple[str, str]] = set()
    for preflight in preflights:
        source_sha256 = preflight.get("source_sha256")
        if _is_sha256(source_sha256):
            sources.add(source_sha256.lower())
        audit = preflight.get("dependency_audit")
        files = audit.get("files") if isinstance(audit, dict) else None
        if not isinstance(files, list):
            continue
        for item in files:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            sha256 = item.get("sha256")
            if (
                isinstance(path, str)
                and path
                and _is_sha256(sha256)
            ):
                dependencies.add((path.replace(chr(92), "/"), sha256.lower()))
    canonical = {
        "source_sha256": sorted(sources),
        "dependencies": [
            {"path": path, "sha256": sha256}
            for path, sha256 in sorted(dependencies)
        ],
    }
    encoded = json.dumps(
        canonical,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _preflight_automatic_handler(
    spec: HandlerSpec,
    *,
    preflight: PreflightCallable,
) -> tuple[dict[str, Any], int]:
    """宣言formatごとの安全preflightを行い、handler単位へ集約する。"""

    declared_formats = sorted(set(spec.input_formats))
    if not declared_formats:
        return (
            {
                "handler_id": spec.id,
                "declared_formats": [],
                "eligible_formats": [],
                "blocked_formats": [],
                "eligible": False,
                "blockers": ["handler_has_no_declared_input_format"],
                "dependency_fingerprint_sha256": _dependency_fingerprint([]),
                "dependency_file_count": 0,
            },
            0,
        )

    format_results: list[dict[str, Any]] = []
    raw_preflights: list[dict[str, Any]] = []
    for actual_format in declared_formats:
        try:
            result = preflight(
                spec,
                actual_format=actual_format,
                input_size=PREFLIGHT_PROBE_INPUT_SIZE,
                maximum_input_size=DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
            )
        except Exception as exc:  # noqa: BLE001 - preflight失敗をfamily全体の監査停止にしない
            result = {
                "eligible": False,
                "blockers": [f"preflight_exception:{type(exc).__name__}"],
                "source_sha256": None,
                "dependency_audit": {"files": []},
                "sample_execution_allowed": False,
                "network_allowed": False,
                "filesystem_write_allowed": False,
            }
        if not isinstance(result, dict):
            result = {
                "eligible": False,
                "blockers": ["preflight_result_not_object"],
                "source_sha256": None,
                "dependency_audit": {"files": []},
                "sample_execution_allowed": False,
                "network_allowed": False,
                "filesystem_write_allowed": False,
            }
        raw_preflights.append(result)
        raw_blockers = result.get("blockers")
        blocker_values = raw_blockers if isinstance(raw_blockers, list) else []
        blockers = sorted(
            {
                str(value)
                for value in blocker_values
                if isinstance(value, str) and value
            }
        )
        safety_contract = {
            "sample_execution_allowed": result.get("sample_execution_allowed"),
            "network_allowed": result.get("network_allowed"),
            "filesystem_write_allowed": result.get("filesystem_write_allowed"),
        }
        for key, value in safety_contract.items():
            if value is not False:
                blockers.append(f"preflight_safety_contract_invalid:{key}")
        if result.get("handler_id") != spec.id:
            blockers.append("preflight_handler_id_mismatch")
        if result.get("actual_format") != actual_format:
            blockers.append("preflight_actual_format_mismatch")
        if not _is_sha256(result.get("source_sha256")):
            blockers.append("preflight_source_digest_missing_or_invalid")
        dependency_audit = result.get("dependency_audit")
        dependency_files = (
            dependency_audit.get("files")
            if isinstance(dependency_audit, dict)
            else None
        )
        if not isinstance(dependency_files, list) or not dependency_files:
            blockers.append("preflight_dependency_audit_missing_or_invalid")
        if result.get("eligible") is not True and not blockers:
            blockers.append("preflight_ineligible_without_blocker")
        eligible = result.get("eligible") is True and not blockers
        format_results.append(
            {
                "format": actual_format,
                "eligible": eligible,
                "blockers": sorted(set(blockers)),
            }
        )

    fingerprints = {
        _dependency_fingerprint([item])
        for item in raw_preflights
    }
    fingerprint = _dependency_fingerprint(raw_preflights)
    aggregate_blockers = sorted(
        {
            blocker
            for item in format_results
            for blocker in item["blockers"]
        }
    )
    if len(fingerprints) > 1:
        aggregate_blockers.append("dependency_fingerprint_changed_during_audit")
    eligible_formats = [
        item["format"] for item in format_results if item["eligible"]
    ]
    handler_eligible = bool(eligible_formats) and len(fingerprints) == 1
    dependency_paths = {
        item.get("path")
        for result in raw_preflights
        for item in (
            result.get("dependency_audit", {}).get("files", [])
            if isinstance(result.get("dependency_audit"), dict)
            else []
        )
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    return (
        {
            "handler_id": spec.id,
            "declared_formats": declared_formats,
            "eligible_formats": eligible_formats if handler_eligible else [],
            "blocked_formats": [
                item for item in format_results if not item["eligible"]
            ],
            "eligible": handler_eligible,
            "blockers": sorted(set(aggregate_blockers)) if not handler_eligible else [],
            "dependency_fingerprint_sha256": fingerprint,
            "dependency_file_count": len(dependency_paths),
        },
        len(format_results),
    )


def build_coverage(
    *,
    registered_families: set[str],
    specs: Sequence[HandlerSpec],
    quality_policies: Mapping[str, Mapping[str, Any]] | None = None,
    preflight: PreflightCallable = preflight_handler_for_assessment,
    maximum_preflights: int = MAX_COVERAGE_PREFLIGHTS,
) -> dict[str, Any]:
    """detectorとhandlerの組合せから自動化能力を決定的に集計する。"""

    if (
        not isinstance(maximum_preflights, int)
        or isinstance(maximum_preflights, bool)
        or maximum_preflights <= 0
        or maximum_preflights > MAX_COVERAGE_PREFLIGHTS
    ):
        raise ValueError(
            f"maximum_preflightsは1..{MAX_COVERAGE_PREFLIGHTS}で指定してください"
        )
    normalized_policies = _normalize_quality_policies(quality_policies or {})
    ordered_specs = sorted(
        specs,
        key=lambda item: (item.family, item.id, item.relative_path, item.callable_name),
    )
    handler_ids = [spec.id for spec in ordered_specs]
    if len(handler_ids) != len(set(handler_ids)):
        raise ValueError("handler IDが重複しているため安全preflightを開始できません")
    planned_preflights = sum(
        len(set(spec.input_formats))
        for spec in ordered_specs
        if spec.automatic
    )
    if planned_preflights > maximum_preflights:
        raise ValueError(
            "automatic handler preflight件数上限を超えています: "
            f"{planned_preflights} > {maximum_preflights}"
        )

    by_family: dict[str, list[HandlerSpec]] = defaultdict(list)
    handler_preflights: dict[str, dict[str, Any]] = {}
    executed_preflights = 0
    for spec in ordered_specs:
        by_family[spec.family].append(spec)
        if spec.automatic:
            assessment, count = _preflight_automatic_handler(spec, preflight=preflight)
            handler_preflights[spec.id] = assessment
            executed_preflights += count
    rows = []
    for family in sorted(
        registered_families | set(by_family) | set(normalized_policies)
    ):
        family_specs = sorted(by_family.get(family, []), key=lambda item: item.id)
        declared_automatic = [item for item in family_specs if item.automatic]
        safe_automatic = [
            item
            for item in declared_automatic
            if handler_preflights[item.id]["eligible"]
        ]
        blocked_automatic = [
            handler_preflights[item.id]
            for item in declared_automatic
            if not handler_preflights[item.id]["eligible"]
        ]
        manual = [item for item in family_specs if not item.automatic]
        detector = family in registered_families
        quality_policy = normalized_policies.get(family)
        quality_policy_declared = quality_policy is not None
        if safe_automatic and not quality_policy_declared:
            status = "quality_policy_missing"
            if detector:
                blocker = "quality_policy_missing"
                next_action = "config・network・最終payloadの必須条件policyを宣言する。"
            else:
                blocker = "detector_and_quality_policy_missing"
                next_action = "family固有detectorと必須成果物policyを追加する。"
        elif detector and safe_automatic:
            status = "fully_routable"
            blocker = None
            next_action = None
        elif safe_automatic:
            status = "candidate_verification_only"
            blocker = "detector_missing"
            next_action = "family固有detectorを追加し、候補検証から自動選択へ昇格させる。"
        elif declared_automatic:
            status = "automatic_handler_blocked"
            if detector:
                blocker = "automatic_handler_preflight_blocked"
                next_action = "安全preflightの阻害理由を解消し、静的handlerを再監査する。"
            else:
                blocker = "detector_and_automatic_handler_preflight_blocked"
                next_action = "detectorを追加し、安全preflightの阻害理由を解消する。"
        elif detector and family_specs:
            status = "manual_handler_only"
            blocker = "automatic_handler_missing"
            next_action = "既存handlerを副作用のない共通契約へ適合させる。"
        elif detector:
            status = "classification_only"
            blocker = "handler_missing"
            next_action = "config・通信先・特徴ロジックを返す静的handlerを追加する。"
        elif family_specs:
            status = "manual_only_without_detector"
            blocker = "detector_and_automatic_handler_missing"
            next_action = "detectorを追加し、既存handlerを共通契約へ適合させる。"
        else:
            status = "unsupported"
            blocker = "detector_and_handler_missing"
            next_action = "detectorと静的handlerを追加する。"
        rows.append(
            {
                "family": family,
                "status": status,
                "detector_registered": detector,
                "automatic_selection_possible": bool(detector and safe_automatic),
                "candidate_verification_possible": bool(safe_automatic),
                "quality_policy_declared": quality_policy_declared,
                "quality_policy": quality_policy,
                "automated_analysis_completion_possible": bool(
                    detector and safe_automatic and quality_policy_declared
                ),
                "declared_script_only_handler_available": bool(declared_automatic),
                "script_only_handler_available": bool(safe_automatic),
                "declared_automatic_handlers": [
                    item.id for item in declared_automatic
                ],
                "safe_automatic_handlers": [item.id for item in safe_automatic],
                "automatic_handlers": [item.id for item in safe_automatic],
                "blocked_automatic_handlers": blocked_automatic,
                "manual_or_unsupported_handlers": sorted(
                    [item.id for item in manual]
                    + [item["handler_id"] for item in blocked_automatic]
                ),
                "accepted_formats": sorted(
                    {
                        value
                        for item in safe_automatic
                        for value in handler_preflights[item.id]["eligible_formats"]
                    }
                ),
                "declared_accepted_formats": sorted(
                    {
                        value
                        for item in declared_automatic
                        for value in item.input_formats
                    }
                ),
                "automatic_handler_preflights": [
                    handler_preflights[item.id] for item in declared_automatic
                ],
                "blocker": blocker,
                "next_action_ja": next_action,
            }
        )
    status_counts = {
        status: sum(item["status"] == status for item in rows)
        for status in (
            "fully_routable",
            "candidate_verification_only",
            "quality_policy_missing",
            "automatic_handler_blocked",
            "manual_handler_only",
            "classification_only",
            "manual_only_without_detector",
            "unsupported",
        )
    }
    total = len(rows)
    fully = status_counts["fully_routable"]
    declared_script_only = sum(
        item["declared_script_only_handler_available"] for item in rows
    )
    safe_script_only = sum(item["script_only_handler_available"] for item in rows)
    declared_handler_count = sum(
        len(item["declared_automatic_handlers"]) for item in rows
    )
    safe_handler_count = sum(len(item["safe_automatic_handlers"]) for item in rows)
    blocked_handler_count = sum(
        len(item["blocked_automatic_handlers"]) for item in rows
    )
    quality_gated_script_only = sum(
        item["script_only_handler_available"] and item["quality_policy_declared"]
        for item in rows
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "counts": {
            "families": total,
            "detector_registered": sum(item["detector_registered"] for item in rows),
            "declared_script_only_handler_available": declared_script_only,
            "script_only_handler_available": safe_script_only,
            "declared_automatic_handlers": declared_handler_count,
            "safe_automatic_handlers": safe_handler_count,
            "blocked_automatic_handlers": blocked_handler_count,
            "quality_policy_declared": sum(
                item["quality_policy_declared"] for item in rows
            ),
            "quality_gated_script_only_handler_available": quality_gated_script_only,
            "automatic_family_selection_possible": sum(
                item["automatic_selection_possible"] for item in rows
            ),
            "automated_analysis_completion_possible": sum(
                item["automated_analysis_completion_possible"] for item in rows
            ),
            "fully_routable": fully,
            "candidate_verification_only": status_counts["candidate_verification_only"],
            "quality_policy_missing": status_counts["quality_policy_missing"],
            "automatic_handler_blocked": status_counts["automatic_handler_blocked"],
            "fully_routable_percent": round(100.0 * fully / total, 2) if total else 0.0,
            "declared_script_only_handler_percent": (
                round(100.0 * declared_script_only / total, 2) if total else 0.0
            ),
            "script_only_handler_percent": (
                round(100.0 * safe_script_only / total, 2) if total else 0.0
            ),
            "planned_preflight_count": planned_preflights,
            "executed_preflight_count": executed_preflights,
            "preflight_limit": maximum_preflights,
            "by_status": status_counts,
        },
        "families": rows,
        "preflight_policy": {
            "scope": "each_declared_format",
            "probe_input_size": PREFLIGHT_PROBE_INPUT_SIZE,
            "maximum_input_size": DEFAULT_MAXIMUM_ASSESSMENT_LAYER_SIZE,
            "maximum_preflight_count": maximum_preflights,
            "handler_imported": False,
            "sample_execution_allowed": False,
            "network_allowed": False,
            "filesystem_write_allowed": False,
        },
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
    }


def render_markdown(report: dict[str, Any]) -> str:
    """人向けの日本語カバレッジ表を生成する。"""

    counts = report["counts"]
    lines = [
        "# 既知マルウェア自動解析カバレッジ",
        "",
        "本表はdetectorと静的handlerの実装状況から自動生成しています。検体実行、外部通信、生成AIは使用しません。",
        "",
        f"- 対象family: {counts['families']}件",
        f"- detector＋安全handler＋品質policyで解析完結可能: {counts['fully_routable']}件（{counts['fully_routable_percent']}%）",
        f"- detector＋安全handlerでfamily自動選択可能: {counts['automatic_family_selection_possible']}件",
        f"- automatic宣言済みfamily: {counts['declared_script_only_handler_available']}件（{counts['declared_script_only_handler_percent']}%）",
        f"- 安全preflight済みscript-only handler利用可能: {counts['script_only_handler_available']}件（{counts['script_only_handler_percent']}%）",
        f"- 品質policy宣言済み: {counts['quality_policy_declared']}件 / 安全handler＋品質policy: {counts['quality_gated_script_only_handler_available']}件",
        f"- 安全handlerはあるが品質policy未宣言: {counts['quality_policy_missing']}件",
        f"- handler実装: 宣言{counts['declared_automatic_handlers']}件 / 安全{counts['safe_automatic_handlers']}件 / 停止{counts['blocked_automatic_handlers']}件",
        f"- automatic handlerが安全preflightで停止: {counts['automatic_handler_blocked']}件",
        f"- handlerによる候補検証のみ: {counts['candidate_verification_only']}件",
        f"- 実行したformat別preflight: {counts['executed_preflight_count']}件（上限{counts['preflight_limit']}件）",
        "",
        "| family | 状態 | detector | 品質policy | 宣言handler | 安全handler | blocker |",
        "|---|---|---:|---:|---:|---:|---|",
    ]
    for item in report["families"]:
        lines.append(
            "| {family} | {status} | {detector} | {policy} | {declared} | {safe} | {blocker} |".format(
                family=item["family"],
                status=item["status"],
                detector="あり" if item["detector_registered"] else "なし",
                policy="あり" if item["quality_policy_declared"] else "なし",
                declared=len(item["declared_automatic_handlers"]),
                safe=len(item["safe_automatic_handlers"]),
                blocker=item["blocker"] or "なし",
            )
        )
    lines.extend(
        [
            "",
            "## 判定の意味",
            "",
            "- `fully_routable`: detectorで候補を選び、安全な静的handlerを実行でき、family別品質policyも宣言済みです。",
            "- `candidate_verification_only`: 外部metadataなどから候補化できますが、family確定には強いhandler証拠が必要です。",
            "- `quality_policy_missing`: 安全handlerはありますが、解析完結に必要な成果物条件が未宣言です。",
            "- `automatic_handler_blocked`: automatic宣言はありますが、安全preflightを通過するformatがありません。",
            "- `classification_only`: family判定後のconfig・C2・ロジック抽出が未自動化です。",
            "- `manual_handler_only`: handlerは存在しますが共通の安全契約へ未適合です。",
            "",
            "blocked handlerのID、format別阻害理由、sourceとlocal dependencyから算出したSHA-256指紋はJSON正本に記録します。",
            "安全handlerがあることだけでは解析完結とは判定しません。family別品質policyの宣言と全品質gateの充足が別途必要です。",
            "",
        ]
    )
    return "\n".join(lines)


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except (OSError, UnicodeError):
        try:
            Path(temporary).unlink(missing_ok=True)
        finally:
            raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--requirements", type=Path, default=DEFAULT_REQUIREMENTS)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--markdown-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.json_output is None and args.markdown_output is None:
        raise SystemExit("--json-outputまたは--markdown-outputを指定してください")
    report = build_coverage(
        registered_families=_registered_families(args.registry),
        specs=discover_handlers(),
        quality_policies=_load_quality_policies(args.requirements),
    )
    if args.json_output is not None:
        _atomic_write_text(
            args.json_output,
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
    if args.markdown_output is not None:
        _atomic_write_text(args.markdown_output, render_markdown(report))
    print(json.dumps(report["counts"], ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
