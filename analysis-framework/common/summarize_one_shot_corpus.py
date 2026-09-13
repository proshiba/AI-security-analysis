#!/usr/bin/env python3
"""one-shot静的解析成果物と既知family registryから品質を安全に集計する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

COMMON_ROOT = Path(__file__).resolve().parent
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import analysis_contract  # noqa: E402
import batch_error_contract  # noqa: E402

SCHEMA_VERSION = 1
FAMILY_REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registry" / "malware_types.json"
UNRECOGNIZED_FAMILY = "unrecognized_family"
MAX_RUNS = 64
MAX_INPUT_UNITS = 64_000
MAX_CASE_OBSERVATIONS = 64_000
MAX_TOTAL_JSON_BYTES = 512 * 1024 * 1024
MAX_FUNCTION_RECORDS = 100_000
MAX_HANDLER_EXECUTIONS = 1_024
MAX_CANDIDATE_FAMILIES = 1_024
MAX_REASON_CODES = 4_096

SHA256_RE = re.compile(r"[0-9a-f]{64}")
IMPHASH_RE = re.compile(r"[0-9a-f]{32}")
TELFHASH_RE = re.compile(r"t1[0-9a-f]{70}")
FAMILY_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,127}")
CODE_RE = re.compile(r"[a-z0-9][a-z0-9_:-]{0,255}")

REQUIRED_CASE_ARTIFACTS = (
    "orchestration.json",
    "candidate-handler-assessment.json",
    "route-config-candidates.json",
    "static-logic.json",
)
OPTIONAL_GAP_ARTIFACTS = (
    "classification.json",
    "static-layers.json",
)
HANDLER_STATUSES = frozenset(
    {
        "succeeded",
        "no_evidence",
        "ambiguous_evidence",
        "failed",
        "preflight_failed",
        "incompatible_input_format",
    }
)
FAMILY_RESOLUTION_STATUSES = frozenset({"resolved", "unresolved", "ambiguous"})
ORCHESTRATION_STATUSES = frozenset({"complete", "partial", "triaged_unknown"})
SUPPORTED_ORCHESTRATION_SCHEMAS = frozenset({1, 2})
CASE_STATUSES = frozenset({"complete", "partial", "failed", "triaged_unknown", "assessment_only_complete"})
CANDIDATE_ASSESSMENT_STATUSES = frozenset(
    {
        "not_run_assessment_only",
        "no_candidates",
        "no_automatic_handler",
        "no_eligible_layer_within_limits",
        "partial",
        "confirmed",
        "no_confirmed_family",
    }
)
CANDIDATE_FAMILY_STATUSES = frozenset(
    {
        "blocked",
        "confirmed",
        "partial_budget_exhausted",
        "partial_result_quota_exhausted",
        "handler_evidence_without_detector",
        "detector_only",
        "handler_timed_out",
        "handler_failed",
        "no_evidence",
        "no_compatible_handler_layer_pair",
        "no_automatic_handler",
    }
)
CANDIDATE_ATTEMPT_STATUSES = frozenset(
    {
        "preflight_blocked",
        "timed_out",
        "failed",
        "partial_result_quota_exhausted",
        "no_evidence",
        "corroborated",
        "handler_evidence_without_detector",
    }
)
CANDIDATE_BUDGET_BLOCKERS = frozenset(
    {
        "maximum_retained_attempt_details_exhausted",
        "maximum_wall_seconds_exhausted",
        "maximum_attempts_exhausted",
        "maximum_response_bytes_exhausted",
        "worker_result_structure_quota_exhausted",
        "maximum_verified_outputs_exhausted",
    }
)
CANDIDATE_LAYER_LIMIT_REASONS = frozenset(
    {
        "candidate_layer_size_limit",
        "candidate_layer_limit",
        "candidate_total_size_limit",
    }
)
STATIC_LAYER_LIMIT_REASONS = frozenset(
    {
        "layer_count_limit",
        "recovered_total_limit",
        "malformed_artifact_rejected",
        "non_bytes_artifact_rejected",
        "empty_artifact_rejected",
        "layer_size_limit",
    }
)
ROUTE_STATUSES = frozenset(
    {
        "route_config_candidates_recovered",
        "partial_route_config_candidates_recovered",
        "assessment_rejected",
        "assessment_incomplete_no_route_config_candidate",
        "no_route_config_candidate",
    }
)
ROUTE_PROJECTION_DISPOSITIONS = frozenset(
    {"not_applicable", "not_run", "blocked", "rejected", "completed", "partial", "incomplete"}
)
ROUTE_PROJECTION_REASONS = frozenset(
    {
        "no_candidate_verification_routes",
        "candidate_verification_disabled_in_assessment_only_mode",
        "no_automatic_candidate_handler",
        "no_eligible_candidate_layer_within_limits",
        "assessment_contract_rejected",
        "route_config_candidates_recovered",
        "partial_route_config_candidates_recovered",
        "route_attempt_projection_rejected",
        "candidate_assessment_incomplete",
        "no_route_config_candidate",
    }
)
ASSESSMENT_REJECTION_REASONS = frozenset(
    {
        "assessment_schema_version_invalid",
        "sample_execution_safety_contract_invalid",
        "network_safety_contract_invalid",
        "filesystem_safety_contract_invalid",
        "confirmed_family_summary_invalid",
        "confirmed_family_present",
        "assessment_status_not_projection_eligible",
        "family_details_invalid",
        "family_detail_limit_exceeded",
    }
)
ROUTE_ATTEMPT_REJECTION_REASONS = frozenset(
    {
        "family_route_contract_invalid",
        "handler_evidence_contract_invalid",
        "detector_non_corroboration_contract_invalid",
        "attempt_wrapper_contract_invalid",
        "layer_identity_invalid",
        "handler_result_contract_invalid",
        "handler_result_quota_incomplete",
        "handler_safety_contract_invalid",
        "handler_quality_threshold_invalid",
        "handler_quality_recalculation_mismatch",
        "trusted_handler_lineage_invalid",
        "handler_family_lineage_invalid",
        "static_config_contract_invalid",
        "config_variant_or_endpoint_count_invalid",
        "config_endpoint_invalid",
        "config_endpoint_duplicate",
        "network_finding_contract_invalid",
        "config_finding_endpoint_mismatch",
        "route_candidate_projection_failed",
        "family_attempt_detail_limit_exceeded",
    }
)
ASSESSMENT_EXCLUSION_REASONS = frozenset(
    {
        "no_routing_candidates",
        "no_planned_handler_attempts",
        "unattempted_handler_attempts",
        "omitted_handler_attempt_details",
        "assessment_budget_exhausted",
        "assessment_blocker_detail_limit_exceeded",
        "excluded_layer_detail_limit_exceeded",
        *{f"assessment_blocker_{reason}" for reason in CANDIDATE_BUDGET_BLOCKERS},
        *{f"excluded_layer_{reason}" for reason in CANDIDATE_LAYER_LIMIT_REASONS},
    }
)
ROUTE_ATTEMPT_EXCLUSION_REASONS = frozenset(
    {
        "family_detail_invalid",
        "family_attempt_details_invalid",
        "attempt_detail_invalid",
        *{f"attempt_status_{status}" for status in CANDIDATE_ATTEMPT_STATUSES},
    }
)
VALLEYRAT_LOADER_PROFILES = frozenset(
    {
        "appdomainmanager_pixel_loader",
        "bin_hell_resource_dropper",
        "run_dll_native_core",
        "compact_cef_wininet_loader",
        "ares_service_facade_loader",
        "mingw_resource_stage_dropper",
        "d3d11_system_probe_loader",
        "d3dserver_debug_attribute_loader",
        "d3d11_eventlog_context_loader",
        "symtab_thread_context_loader",
    }
)
VALLEYRAT_ROUTE_PROFILES = frozenset(
    {
        "nvml_compact_dat_loader",
        "nvml_proxy",
        "cef_proxy",
        "pdfcore8_winos_proxy",
        "pdfcore8_minimal_protected_proxy",
        "msocf_rc4_ff_proxy",
    }
)
VALLEYRAT_HANDLER_IDS = frozenset(
    {
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.appdomainmanager.pixel.loader.analyze.py:analyze",
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.msi.lzx.protected.pe.analyze.py:analyze",
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.onyx.qt.loader.analyze.py:analyze",
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.protected.installer.bundle.analyze.py:analyze",
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.signed.proxy.sideload.analyze.py:analyze",
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.single.pe.analyze.dotnet.il.py:analyze",
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.single.pe.analyze.single.pe.py:analyze",
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.single.pe.vvas.resource.analyze.py:analyze",
        "valleyrat:analysis.framework.malware.valleyrat.campaigns.yuanbao.sideload.analyze.bundle.py:analyze",
        "valleyrat:extractors.valleyrat.extractor.py:extract",
    }
)
CONFIG_SIGNAL_KEYS = frozenset(
    {
        "terminal_config_probe",
        "static_config_candidate_probe",
        "vvas_pe_config_candidate",
        "codemark_stage",
        "recovered_codemark_stage",
        "nvml_dat",
        "msocf_terminal_config",
    }
)
PUBLIC_BLOCKER_CODES = frozenset(
    {
        "config",
        "network",
        "function_analysis",
        "generic_triage",
        "family_resolution",
        "terminal_payload",
        "requirements_policy",
        "static_layer_limit_reached",
        "generic_triage_failed",
        "generic_triage_partial",
        "selected_family_layer_incomplete",
        "representative_function_analysis_required",
        "c2_protocol_confirmation_pending",
        *CANDIDATE_BUDGET_BLOCKERS,
    }
)
GAP_STATUSES = frozenset(
    {
        "terminal_config_recovered",
        "terminal_config_missing",
        "route_config_candidate_only",
        "loader_only",
        "route_only",
        "detector_matched_nonterminal",
        "detector_unmatched",
        "unknown_legacy_schema",
        "unknown_invalid_schema",
        "unknown_incomplete_evaluations",
        "unknown_detector_error",
    }
)


class CorpusSummaryError(ValueError):
    """秘密値を含まない固定codeを持つコーパス入力エラー。"""

    def __init__(self, code: str, message_ja: str) -> None:
        super().__init__(message_ja)
        self.code = code


@dataclass
class _ReadBudget:
    """全runを通じたJSON読取量を制限する。"""

    used: int = 0

    def consume(self, size: int) -> None:
        if size < 0 or self.used + size > MAX_TOTAL_JSON_BYTES:
            raise CorpusSummaryError(
                "aggregate_json_budget_exhausted",
                "コーパス成果物のJSON読取量が上限を超えています。",
            )
        self.used += size


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return _sha256_bytes(payload)


def _safe_code(value: Any, *, fallback: str) -> str:
    candidate = str(value or "").strip().casefold()
    if CODE_RE.fullmatch(candidate) is None or "://" in candidate or re.search(r":\d{1,5}$", candidate) is not None:
        return fallback
    return candidate


def _allowlisted_code(
    value: Any,
    allowed: frozenset[str],
    *,
    fallback: str = "unrecognized_code",
) -> str:
    """入力文字列を反射せず、固定allowlist内のcodeだけを返す。"""

    return value if isinstance(value, str) and value in allowed else fallback


def _valid_family(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().casefold()
    return candidate if FAMILY_RE.fullmatch(candidate) else None


def _registered_family_ids(value: Mapping[str, Any]) -> frozenset[str]:
    """canonical registryから公開可能なfamily IDだけを厳格に取得する。"""

    families = value.get("malware_types")
    if value.get("schema_version") != 3 or not isinstance(families, Mapping):
        raise CorpusSummaryError(
            "family_registry_schema_invalid",
            "既知family registryのschemaが不正です。",
        )
    if not families or len(families) > MAX_CANDIDATE_FAMILIES:
        raise CorpusSummaryError(
            "family_registry_size_invalid",
            "既知family registryのfamily件数が不正です。",
        )
    normalized: set[str] = set()
    for family, metadata in families.items():
        if not isinstance(family, str) or _valid_family(family) != family or not isinstance(metadata, Mapping):
            raise CorpusSummaryError(
                "family_registry_entry_invalid",
                "既知family registryのentryが不正です。",
            )
        normalized.add(family)
    return frozenset(normalized)


def _public_family(
    value: str | None,
    *,
    registered_families: frozenset[str],
    expected_family: str | None,
) -> str | None:
    """registry既知値または明示expected値だけを公開し、未知値を反射しない。"""

    if value is None:
        return None
    if value in registered_families or value == expected_family:
        return value
    return UNRECOGNIZED_FAMILY


def _non_negative_int(value: Any) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _read_json_snapshot(
    path: Path,
    budget: _ReadBudget,
    *,
    error_prefix: str,
) -> tuple[dict[str, Any], bytes]:
    """通常fileの同一snapshotを上限付きで読み、厳密JSON objectへ変換する。"""

    try:
        raw = analysis_contract._read_regular_file_snapshot(
            path,
            max_bytes=analysis_contract.MAX_JSON_OBJECT_SIZE,
        )
        budget.consume(len(raw))
        value = analysis_contract._decode_json_object_strict(raw, path=path)
    except analysis_contract._SnapshotReadError as exc:
        reason = _safe_code(getattr(exc, "reason", None), fallback="snapshot_failed")
        raise CorpusSummaryError(
            f"{error_prefix}_{reason}",
            "成果物を安全な通常file snapshotとして読み取れません。",
        ) from exc
    except CorpusSummaryError:
        raise
    except (OSError, TypeError, UnicodeError, ValueError) as exc:
        raise CorpusSummaryError(
            f"{error_prefix}_json_invalid",
            "成果物のJSON契約を検証できません。",
        ) from exc
    return value, raw


def _regular_directory(path: Path, *, code: str) -> Path:
    """既存の非reparse通常directoryを返す。"""

    try:
        analysis_contract.ensure_no_reparse_components(path)
        resolved = path.resolve(strict=True)
        information = resolved.lstat()
    except (OSError, ValueError) as exc:
        raise CorpusSummaryError(code, "入力directoryを安全に検証できません。") from exc
    if not stat.S_ISDIR(information.st_mode) or analysis_contract._stat_has_reparse_attribute(information):
        raise CorpusSummaryError(code, "入力は通常directoryである必要があります。")
    return resolved


def _validate_run_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    """one-shot summaryの母数と安全flagをfail-closedで検証する。"""

    if value.get("schema_version") != 1:
        raise CorpusSummaryError(
            "run_summary_schema_invalid",
            "one-shot summaryのschema versionが不正です。",
        )
    if any(value.get(key) is not False for key in ("executed_sample", "network_contacted", "ai_used")):
        raise CorpusSummaryError(
            "run_summary_safety_invalid",
            "one-shot summaryの安全flagが不正です。",
        )
    counts = value.get("counts")
    cases = value.get("cases")
    errors = value.get("errors")
    duplicates = value.get("duplicates")
    if not isinstance(counts, Mapping) or not all(isinstance(item, list) for item in (cases, errors, duplicates)):
        raise CorpusSummaryError(
            "run_summary_shape_invalid",
            "one-shot summaryのcase/error構造が不正です。",
        )
    input_files = _non_negative_int(counts.get("input_files"))
    analyzed = _non_negative_int(counts.get("analyzed"))
    error_count = _non_negative_int(counts.get("errors"))
    duplicate_count = _non_negative_int(counts.get("duplicates"))
    if (
        input_files is None
        or analyzed != len(cases)
        or error_count != len(errors)
        or duplicate_count != len(duplicates)
        or input_files != len(cases) + len(errors) + len(duplicates)
    ):
        raise CorpusSummaryError(
            "run_summary_counts_invalid",
            "one-shot summaryの母数がcase/error一覧と一致しません。",
        )
    observed: set[str] = set()
    normalized_cases = []
    for item in cases:
        digest = str(item.get("sha256", "")).casefold() if isinstance(item, Mapping) else ""
        if SHA256_RE.fullmatch(digest) is None or digest in observed:
            raise CorpusSummaryError(
                "run_summary_case_identity_invalid",
                "one-shot summaryのcase SHA-256が不正または重複しています。",
            )
        if item.get("report") != f"cases/{digest}/report.json":
            raise CorpusSummaryError(
                "run_summary_case_report_invalid",
                "one-shot summaryのreport参照が固定case境界と一致しません。",
            )
        observed.add(digest)
        normalized_cases.append(digest)
    normalized_errors = []
    for item in errors:
        try:
            normalized_errors.append(batch_error_contract.validate_record(item))
        except batch_error_contract.BatchErrorContractError as exc:
            raise CorpusSummaryError(
                "run_summary_batch_error_invalid",
                "one-shot summaryのbatch error契約が不正です。",
            ) from exc
    normalized_duplicates = []
    for item in duplicates:
        digest = str(item.get("sha256", "")).casefold() if isinstance(item, Mapping) else ""
        if SHA256_RE.fullmatch(digest) is None:
            raise CorpusSummaryError(
                "run_summary_duplicate_invalid",
                "one-shot summaryのduplicate SHA-256が不正です。",
            )
        normalized_duplicates.append(digest)
    return {
        "input_files": input_files,
        "cases": normalized_cases,
        "errors": normalized_errors,
        "duplicates": normalized_duplicates,
    }


def _validate_report(report: Mapping[str, Any], digest: str) -> None:
    """report seal、case identity、安全flag、最小状態契約を検証する。"""

    if report.get("schema_version") != 1 or analysis_contract.verify_report_semantics(report):
        raise CorpusSummaryError(
            "report_semantics_invalid",
            "case reportのschemaまたは意味sealが不正です。",
        )
    sample = report.get("sample")
    if not isinstance(sample, Mapping) or sample.get("sha256") != digest:
        raise CorpusSummaryError(
            "report_sample_identity_invalid",
            "case reportのsample SHA-256がcase境界と一致しません。",
        )
    if any(report.get(key) is not False for key in ("executed_sample", "network_contacted", "ai_used")):
        raise CorpusSummaryError(
            "report_safety_invalid",
            "case reportの安全flagが不正です。",
        )
    if type(report.get("assessment_only")) is not bool:
        raise CorpusSummaryError(
            "report_mode_invalid",
            "case reportの解析modeが不正です。",
        )
    classification = report.get("classification")
    state = report.get("case_state")
    if not isinstance(classification, Mapping) or not isinstance(state, Mapping):
        raise CorpusSummaryError(
            "report_state_invalid",
            "case reportの分類または完了状態がありません。",
        )
    selected = classification.get("selected_families")
    if (
        not isinstance(selected, list)
        or len(selected) > MAX_CANDIDATE_FAMILIES
        or selected != sorted(set(selected))
        or any(_valid_family(item) != item for item in selected)
    ):
        raise CorpusSummaryError(
            "report_selected_families_invalid",
            "case reportのselected family一覧が不正です。",
        )
    if state.get("status") not in CASE_STATUSES:
        raise CorpusSummaryError(
            "report_case_status_invalid",
            "case reportの完了状態が不正です。",
        )
    blockers = state.get("blockers")
    if (
        not isinstance(blockers, list)
        or len(blockers) > MAX_REASON_CODES
        or blockers != sorted(set(blockers))
        or any(not isinstance(item, str) or not item for item in blockers)
    ):
        raise CorpusSummaryError(
            "report_case_blockers_invalid",
            "case reportのblocker一覧が不正です。",
        )
    contract = report.get("analysis_contract")
    if not isinstance(contract, Mapping) or contract.get("schema_version") != 1:
        raise CorpusSummaryError(
            "report_analysis_contract_invalid",
            "case reportの解析契約が不正です。",
        )
    try:
        analysis_contract.normalize_sha256_digest(contract.get("sha256"))
    except ValueError as exc:
        raise CorpusSummaryError(
            "report_analysis_contract_invalid",
            "case reportの解析契約SHA-256が不正です。",
        ) from exc
    manifest = report.get("artifact_sha256")
    if not isinstance(manifest, Mapping) or not manifest:
        raise CorpusSummaryError(
            "report_artifact_manifest_invalid",
            "case reportの成果物hash manifestがありません。",
        )
    if len(manifest) > analysis_contract.MAX_ARTIFACT_COUNT:
        raise CorpusSummaryError(
            "report_artifact_manifest_too_large",
            "case reportの成果物hash manifestが上限を超えています。",
        )
    for relative, artifact_digest in manifest.items():
        try:
            analysis_contract.normalize_artifact_path(relative)
            analysis_contract.normalize_sha256_digest(artifact_digest)
        except ValueError as exc:
            raise CorpusSummaryError(
                "report_artifact_manifest_invalid",
                "case reportの成果物hash manifestが不正です。",
            ) from exc


def _case_artifact(
    case_dir: Path,
    report: Mapping[str, Any],
    relative: str,
    budget: _ReadBudget,
) -> tuple[dict[str, Any], str]:
    """manifestに封印された選択JSON成果物だけを読み、raw hashを照合する。"""

    manifest = report["artifact_sha256"]
    expected = manifest.get(relative)
    if not isinstance(expected, str) or SHA256_RE.fullmatch(expected) is None:
        raise CorpusSummaryError(
            f"artifact_manifest_missing_{relative.replace('.', '_').replace('-', '_')}",
            "集計に必要なJSON成果物がreport manifestにありません。",
        )
    try:
        path = analysis_contract.resolve_case_artifact(case_dir, relative)
    except ValueError as exc:
        raise CorpusSummaryError(
            f"artifact_boundary_invalid_{relative.replace('.', '_').replace('-', '_')}",
            "集計に必要なJSON成果物のcase境界を検証できません。",
        ) from exc
    token = relative.replace(".", "_").replace("-", "_")
    value, raw = _read_json_snapshot(path, budget, error_prefix=f"artifact_{token}")
    actual = _sha256_bytes(raw)
    if actual != expected:
        raise CorpusSummaryError(
            f"artifact_hash_mismatch_{token}",
            "集計に必要なJSON成果物のSHA-256がreport manifestと一致しません。",
        )
    return value, actual


def _validate_orchestration(value: Mapping[str, Any], digest: str) -> None:
    if value.get("schema_version") not in SUPPORTED_ORCHESTRATION_SCHEMAS or value.get("sample_sha256") != digest:
        raise CorpusSummaryError(
            "orchestration_identity_invalid",
            "orchestrationのschemaまたはcase identityが不正です。",
        )
    if value.get("status") not in ORCHESTRATION_STATUSES:
        raise CorpusSummaryError(
            "orchestration_status_invalid",
            "orchestration statusが不正です。",
        )
    resolution = value.get("family_resolution")
    if not isinstance(resolution, Mapping) or resolution.get("status") not in FAMILY_RESOLUTION_STATUSES:
        raise CorpusSummaryError(
            "family_resolution_invalid",
            "family resolution契約が不正です。",
        )
    family = resolution.get("family")
    if resolution.get("status") == "resolved":
        if _valid_family(family) != family:
            raise CorpusSummaryError(
                "resolved_family_invalid",
                "resolved family IDが不正です。",
            )
    elif family is not None:
        raise CorpusSummaryError(
            "unresolved_family_value_present",
            "未解決familyに確定family値が含まれています。",
        )
    blockers = value.get("blockers")
    if (
        not isinstance(blockers, list)
        or len(blockers) > MAX_REASON_CODES
        or blockers != sorted(set(blockers))
        or any(not isinstance(item, str) or not item for item in blockers)
    ):
        raise CorpusSummaryError(
            "orchestration_blockers_invalid",
            "orchestration blocker一覧が不正です。",
        )
    outputs = value.get("outputs")
    candidates = value.get("candidate_outputs")
    quality_gates = value.get("quality_gates")
    if not all(isinstance(item, Mapping) for item in (outputs, candidates, quality_gates)):
        raise CorpusSummaryError(
            "orchestration_outputs_invalid",
            "orchestrationの出力または品質gateが不正です。",
        )
    if type(outputs.get("config_recovered")) is not bool:
        raise CorpusSummaryError(
            "orchestration_config_state_invalid",
            "確認済みconfig回収状態がbooleanではありません。",
        )
    if type(candidates.get("config_candidate_recovered")) is not bool:
        raise CorpusSummaryError(
            "orchestration_candidate_config_state_invalid",
            "候補config回収状態がbooleanではありません。",
        )
    config_gate = quality_gates.get("config")
    if not isinstance(config_gate, Mapping) or config_gate.get("required") not in {True, False, None}:
        raise CorpusSummaryError(
            "orchestration_config_gate_invalid",
            "config品質gateが不正です。",
        )
    automation = value.get("automation")
    if not isinstance(automation, Mapping) or any(
        automation.get(key) is not False for key in ("sample_executed", "network_contacted", "ai_used")
    ):
        raise CorpusSummaryError(
            "orchestration_safety_invalid",
            "orchestrationの安全flagが不正です。",
        )


def _validate_candidate_assessment(value: Mapping[str, Any]) -> None:
    if value.get("schema_version") != 1 or any(
        value.get(key) is not False
        for key in ("executed_sample", "network_contacted", "filesystem_written_by_handlers")
    ):
        raise CorpusSummaryError(
            "candidate_assessment_contract_invalid",
            "candidate handler assessment契約が不正です。",
        )
    if not isinstance(value.get("status"), str):
        raise CorpusSummaryError(
            "candidate_assessment_status_invalid",
            "candidate handler assessment statusが不正です。",
        )
    if _non_negative_int(value.get("planned_attempt_count")) is None:
        raise CorpusSummaryError(
            "candidate_assessment_count_invalid",
            "candidate handler assessmentの試行件数が不正です。",
        )
    families = value.get("families")
    if not isinstance(families, list) or len(families) > MAX_CANDIDATE_FAMILIES:
        raise CorpusSummaryError(
            "candidate_assessment_families_invalid",
            "candidate family一覧が不正または上限超過です。",
        )


def _validate_route(value: Mapping[str, Any], digest: str) -> None:
    safety = value.get("safety")
    if (
        value.get("schema_version") != 1
        or value.get("sha256") != digest
        or not isinstance(safety, Mapping)
        or any(
            safety.get(key) is not False
            for key in (
                "sample_executed",
                "network_contacted",
                "raw_config_included",
                "raw_payload_published",
                "credentials_published",
            )
        )
    ):
        raise CorpusSummaryError(
            "route_projection_contract_invalid",
            "route config候補成果物のidentityまたは安全契約が不正です。",
        )


def _handler_reason_codes(report: Mapping[str, Any]) -> tuple[set[str], Counter[str]]:
    executions = report.get("handler_executions")
    if not isinstance(executions, list) or len(executions) > MAX_HANDLER_EXECUTIONS:
        raise CorpusSummaryError(
            "handler_execution_list_invalid",
            "handler実行一覧が不正または上限超過です。",
        )
    reasons: set[str] = set()
    statuses: Counter[str] = Counter()
    for execution in executions:
        status = execution.get("status") if isinstance(execution, Mapping) else None
        if status not in HANDLER_STATUSES:
            raise CorpusSummaryError(
                "handler_execution_status_invalid",
                "handler実行statusが不正です。",
            )
        statuses[status] += 1
        if status != "succeeded":
            reasons.add(f"handler:{status}")
    return reasons, statuses


def _candidate_diagnostics(value: Mapping[str, Any]) -> set[str]:
    reasons = {"candidate:status:" + _allowlisted_code(value.get("status"), CANDIDATE_ASSESSMENT_STATUSES)}
    blockers = value.get("blockers")
    if isinstance(blockers, list):
        reasons.update(
            "candidate:blocker:" + _allowlisted_code(item, CANDIDATE_BUDGET_BLOCKERS)
            for item in blockers[:MAX_REASON_CODES]
        )
    retained_attempts = 0
    for family in value.get("families", []):
        if not isinstance(family, Mapping):
            continue
        reasons.add("candidate-family:status:" + _allowlisted_code(family.get("status"), CANDIDATE_FAMILY_STATUSES))
        attempts = family.get("attempts")
        if isinstance(attempts, list) and retained_attempts < MAX_REASON_CODES:
            remaining = MAX_REASON_CODES - retained_attempts
            selected_attempts = attempts[:remaining]
            reasons.update(
                "candidate-attempt:status:"
                + _allowlisted_code(
                    attempt.get("status") if isinstance(attempt, Mapping) else None,
                    CANDIDATE_ATTEMPT_STATUSES,
                )
                for attempt in selected_attempts
            )
            retained_attempts += len(selected_attempts)
    return set(sorted(reasons)[:MAX_REASON_CODES])


def _route_diagnostics(value: Mapping[str, Any]) -> tuple[set[str], set[str]]:
    overall: set[str] = set()
    diagnostic = {"route:status:" + _allowlisted_code(value.get("status"), ROUTE_STATUSES)}
    reason = value.get("projection_reason")
    if isinstance(reason, str) and reason:
        code = "route:projection:" + _allowlisted_code(
            reason,
            ROUTE_PROJECTION_REASONS,
        )
        if value.get("overall_analysis_result_affected") is True:
            overall.add(code)
        else:
            diagnostic.add(code)
    return overall, diagnostic


def _allowlisted_count_map(
    value: Any,
    allowed: frozenset[str],
) -> tuple[dict[str, int], bool]:
    """件数mapを固定codeへ縮約し、未知keyは単一sentinelへ畳み込む。"""

    if not isinstance(value, Mapping) or len(value) > MAX_REASON_CODES:
        return {}, False
    counts: Counter[str] = Counter()
    for raw_code, raw_count in value.items():
        count = _non_negative_int(raw_count)
        if count is None:
            return {}, False
        if count:
            counts[_allowlisted_code(raw_code, allowed)] += count
    return dict(sorted(counts.items())), True


def _allowlisted_list_counts(
    value: Any,
    allowed: frozenset[str],
) -> tuple[dict[str, int], bool]:
    """文字列listを固定code件数へ縮約する。"""

    if not isinstance(value, list) or len(value) > MAX_REASON_CODES:
        return {}, False
    counts = Counter(_allowlisted_code(item, allowed) for item in value)
    return dict(sorted(counts.items())), True


def _schema_availability(*, missing: bool, valid: bool) -> str:
    if valid:
        return "available"
    return "unknown_legacy_schema" if missing else "unknown_invalid_schema"


def _candidate_attempt_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    """candidate試行を秘密値非保持の固定status・handler IDへ縮約する。"""

    count_fields = (
        "planned_attempt_count",
        "actual_attempt_count",
        "retained_attempt_detail_count",
        "omitted_attempt_detail_count",
        "unattempted_attempt_count",
    )
    counts = {field: _non_negative_int(value.get(field)) for field in count_fields}
    missing_counts = any(field not in value for field in count_fields)
    family_status_counts: Counter[str] = Counter()
    attempt_status_counts: Counter[str] = Counter()
    handler_status_counts: dict[str, Counter[str]] = defaultdict(Counter)
    observed_details = 0
    detail_valid = True
    for family in value.get("families", []):
        if not isinstance(family, Mapping):
            detail_valid = False
            continue
        family_status_counts[_allowlisted_code(family.get("status"), CANDIDATE_FAMILY_STATUSES)] += 1
        attempts = family.get("attempts")
        if not isinstance(attempts, list):
            detail_valid = False
            continue
        if observed_details + len(attempts) > MAX_REASON_CODES:
            detail_valid = False
            break
        for attempt in attempts:
            observed_details += 1
            if not isinstance(attempt, Mapping):
                detail_valid = False
                status = "unrecognized_code"
                handler_id = "unrecognized_handler"
            else:
                status = _allowlisted_code(
                    attempt.get("status"),
                    CANDIDATE_ATTEMPT_STATUSES,
                )
                supplied_handler = attempt.get("handler_id")
                handler_id = (
                    supplied_handler
                    if isinstance(supplied_handler, str) and supplied_handler in VALLEYRAT_HANDLER_IDS
                    else "unrecognized_handler"
                )
            attempt_status_counts[status] += 1
            handler_status_counts[handler_id][status] += 1

    numeric_valid = all(count is not None for count in counts.values())
    if numeric_valid:
        planned = counts["planned_attempt_count"]
        actual = counts["actual_attempt_count"]
        retained = counts["retained_attempt_detail_count"]
        omitted = counts["omitted_attempt_detail_count"]
        unattempted = counts["unattempted_attempt_count"]
        assert all(item is not None for item in (planned, actual, retained, omitted, unattempted))
        numeric_valid = bool(
            planned == actual + unattempted and actual == retained + omitted and retained == observed_details
        )
    accounting_availability = _schema_availability(
        missing=missing_counts,
        valid=bool(numeric_valid and detail_valid),
    )

    blockers = value.get("blockers")
    budget_reason_counts, blockers_valid = _allowlisted_list_counts(
        blockers,
        CANDIDATE_BUDGET_BLOCKERS,
    )
    budget_missing = "blockers" not in value
    budget = value.get("budget")
    budget_exhausted = (
        budget.get("exhausted") if isinstance(budget, Mapping) and type(budget.get("exhausted")) is bool else None
    )
    if budget_exhausted is True and not budget_reason_counts:
        budget_reason_counts["budget_exhausted_without_known_reason"] = 1

    excluded_layers = value.get("excluded_layers")
    layer_limit_counts: Counter[str] = Counter()
    excluded_valid = isinstance(excluded_layers, list) and len(excluded_layers) <= MAX_REASON_CODES
    if excluded_valid:
        for excluded in excluded_layers:
            reason = excluded.get("reason") if isinstance(excluded, Mapping) else None
            layer_limit_counts[_allowlisted_code(reason, CANDIDATE_LAYER_LIMIT_REASONS)] += 1

    return {
        "availability": {
            "attempt_accounting": accounting_availability,
            "budget_reasons": _schema_availability(
                missing=budget_missing,
                valid=blockers_valid,
            ),
            "layer_limit_reasons": _schema_availability(
                missing="excluded_layers" not in value,
                valid=excluded_valid,
            ),
        },
        "assessment_status": _allowlisted_code(
            value.get("status"),
            CANDIDATE_ASSESSMENT_STATUSES,
        ),
        **counts,
        "observed_retained_attempt_detail_count": observed_details,
        "attempt_status_counts": dict(sorted(attempt_status_counts.items())),
        "family_status_counts": dict(sorted(family_status_counts.items())),
        "handler_attempt_status_counts": {
            handler_id: dict(sorted(statuses.items())) for handler_id, statuses in sorted(handler_status_counts.items())
        },
        "budget_exhausted": budget_exhausted,
        "budget_reason_counts": dict(sorted(budget_reason_counts.items())),
        "layer_limit_reason_counts": dict(sorted(layer_limit_counts.items())),
    }


def _route_projection_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    """route投影を固定status・reasonと件数だけへ縮約する。"""

    count_fields = (
        "planned_handler_attempt_count",
        "actual_handler_attempt_count",
        "unattempted_handler_attempt_count",
        "omitted_handler_attempt_detail_count",
        "evaluated_route_attempt_count",
        "observed_excluded_route_attempt_count",
        "rejected_route_attempt_count",
    )
    counts = {field: _non_negative_int(value.get(field)) for field in count_fields}
    missing_counts = any(field not in value for field in count_fields)
    assessment_rejections, assessment_rejections_valid = _allowlisted_list_counts(
        value.get("assessment_rejection_reasons"),
        ASSESSMENT_REJECTION_REASONS,
    )
    assessment_exclusions, assessment_exclusions_valid = _allowlisted_count_map(
        value.get("assessment_exclusion_reason_counts"),
        ASSESSMENT_EXCLUSION_REASONS,
    )
    attempt_exclusions, attempt_exclusions_valid = _allowlisted_count_map(
        value.get("route_attempt_exclusion_reason_counts"),
        ROUTE_ATTEMPT_EXCLUSION_REASONS,
    )
    attempt_rejections, attempt_rejections_valid = _allowlisted_count_map(
        value.get("route_attempt_rejection_reason_counts"),
        ROUTE_ATTEMPT_REJECTION_REASONS,
    )
    reason_fields = (
        "assessment_rejection_reasons",
        "assessment_exclusion_reason_counts",
        "route_attempt_exclusion_reason_counts",
        "route_attempt_rejection_reason_counts",
    )
    reasons_missing = any(field not in value for field in reason_fields)
    accounting_valid = all(count is not None for count in counts.values())
    if accounting_valid:
        planned = counts["planned_handler_attempt_count"]
        actual = counts["actual_handler_attempt_count"]
        unattempted = counts["unattempted_handler_attempt_count"]
        omitted = counts["omitted_handler_attempt_detail_count"]
        evaluated = counts["evaluated_route_attempt_count"]
        observed_excluded = counts["observed_excluded_route_attempt_count"]
        rejected = counts["rejected_route_attempt_count"]
        assert all(
            item is not None
            for item in (
                planned,
                actual,
                unattempted,
                omitted,
                evaluated,
                observed_excluded,
                rejected,
            )
        )
        accounting_valid = bool(
            planned == actual + unattempted
            and actual == evaluated + observed_excluded + omitted
            and rejected == sum(attempt_rejections.values())
        )
    status_valid = value.get("status") in ROUTE_STATUSES
    disposition_valid = value.get("projection_disposition") in ROUTE_PROJECTION_DISPOSITIONS
    projection_reason_valid = value.get("projection_reason") in ROUTE_PROJECTION_REASONS
    route_candidate_recovered = value.get("route_config_candidate_recovered")
    state_valid = type(route_candidate_recovered) is bool
    reason_accounting_valid = bool(
        assessment_rejections_valid
        and assessment_exclusions_valid
        and attempt_exclusions_valid
        and attempt_rejections_valid
        and accounting_valid
        and status_valid
        and disposition_valid
        and projection_reason_valid
        and state_valid
    )
    return {
        "availability": {
            "reason_accounting": _schema_availability(
                missing=missing_counts or reasons_missing,
                valid=reason_accounting_valid,
            )
        },
        "status": _allowlisted_code(value.get("status"), ROUTE_STATUSES),
        "projection_disposition": _allowlisted_code(
            value.get("projection_disposition"),
            ROUTE_PROJECTION_DISPOSITIONS,
        ),
        "projection_reason": _allowlisted_code(
            value.get("projection_reason"),
            ROUTE_PROJECTION_REASONS,
        ),
        **counts,
        "route_config_candidate_recovered": (route_candidate_recovered if state_valid else None),
        "assessment_rejection_reason_counts": assessment_rejections,
        "assessment_exclusion_reason_counts": assessment_exclusions,
        "attempt_exclusion_reason_counts": attempt_exclusions,
        "attempt_rejection_reason_counts": attempt_rejections,
    }


def _static_limit_summary(value: Mapping[str, Any] | None) -> dict[str, Any]:
    """static-layerのlimit eventから固定reason件数だけを返す。"""

    if value is None:
        return {
            "availability": "unknown_legacy_schema",
            "reason_counts": {},
        }
    events = value.get("limit_events")
    valid = bool(
        value.get("schema_version") == 1
        and value.get("executed_sample") is False
        and value.get("network_contacted") is False
        and isinstance(events, list)
        and len(events) <= MAX_REASON_CODES
    )
    if not valid:
        return {
            "availability": "unknown_invalid_schema",
            "reason_counts": {},
        }
    counts: Counter[str] = Counter()
    for event in events:
        reason = event.get("reason") if isinstance(event, Mapping) else None
        counts[_allowlisted_code(reason, STATIC_LAYER_LIMIT_REASONS)] += 1
    return {
        "availability": "available",
        "reason_counts": dict(sorted(counts.items())),
    }


def _valleyrat_detector_summary(
    value: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """classificationからValleyRAT detectorの固定boolean/profileだけを読む。"""

    empty = {
        "total_layer_count": None,
        "evaluated_layer_count": 0,
        "matched_layer_count": 0,
        "terminal_layer_count": 0,
        "automatic_route_layer_count": 0,
        "known_hash_layer_count": 0,
        "loader_profile_layer_counts": {},
        "route_profile_layer_counts": {},
        "config_signal_layer_counts": {},
        "unrecognized_profile_count": 0,
    }
    if value is None:
        return {
            "availability": "unknown_legacy_schema",
            "state": "unknown_legacy_schema",
            **empty,
        }
    layers = value.get("layer_classifications")
    if not isinstance(layers, list) or not layers or len(layers) > MAX_CASE_OBSERVATIONS:
        return {
            "availability": "unknown_invalid_schema",
            "state": "unknown_invalid_schema",
            **empty,
        }

    loader_profiles: Counter[str] = Counter()
    route_profiles: Counter[str] = Counter()
    config_signals: Counter[str] = Counter()
    evaluated = 0
    matched = 0
    terminal = 0
    automatic = 0
    known_hash = 0
    missing_evaluations = 0
    detector_errors = 0
    invalid = False
    unrecognized_profiles = 0
    for layer_record in layers:
        if not isinstance(layer_record, Mapping):
            invalid = True
            continue
        classification = layer_record.get("classification")
        evaluations = classification.get("detector_evaluations") if isinstance(classification, Mapping) else None
        if not isinstance(evaluations, list):
            invalid = True
            continue
        valley_evaluations = [
            item for item in evaluations if isinstance(item, Mapping) and item.get("malware_type") == "valleyrat"
        ]
        if len(valley_evaluations) != 1:
            missing_evaluations += 1
            continue
        evaluation = valley_evaluations[0]
        evaluated += 1
        if evaluation.get("error") not in (None, ""):
            detector_errors += 1
            continue
        detection = evaluation.get("detection")
        detector_matched = evaluation.get("detector_matched")
        if (
            not isinstance(detection, Mapping)
            or type(detector_matched) is not bool
            or type(detection.get("matched")) is not bool
            or detection.get("matched") is not detector_matched
        ):
            invalid = True
            continue
        if detector_matched:
            matched += 1
        if evaluation.get("automatic_route_eligible") is True:
            automatic += 1
        if any(
            evaluation.get(field) is True
            for field in (
                "known_outer_sha256",
                "known_inner_sha256",
                "known_routing_sha256",
            )
        ):
            known_hash += 1
        observations = detection.get("observations")
        campaigns = detection.get("campaigns")
        if not isinstance(observations, Mapping) or not isinstance(campaigns, list):
            invalid = True
            continue
        terminal_present = any(
            isinstance(campaign, Mapping) and campaign.get("terminal_family_confirmed") is True
            for campaign in campaigns
        )
        if terminal_present:
            terminal += 1
            if not detector_matched:
                invalid = True

        loader = observations.get("validated_static_loader_profile")
        if isinstance(loader, Mapping) and "profile" in loader:
            profile = loader.get("profile")
            if profile in VALLEYRAT_LOADER_PROFILES:
                loader_profiles[str(profile)] += 1
            else:
                unrecognized_profiles += 1
        appdomain = observations.get("appdomainmanager_loader")
        if isinstance(appdomain, Mapping) and appdomain.get("matched") is True:
            loader_profiles["appdomainmanager_pixel_loader"] += 1
        if "validated_route_only_proxy_profile" in observations:
            profile = observations.get("validated_route_only_proxy_profile")
            if profile in VALLEYRAT_ROUTE_PROFILES:
                route_profiles[str(profile)] += 1
            else:
                unrecognized_profiles += 1
        for signal in CONFIG_SIGNAL_KEYS:
            if signal in observations and observations.get(signal) is not None:
                config_signals[signal] += 1

    if invalid:
        availability = "unknown_invalid_schema"
    elif missing_evaluations:
        availability = "unknown_incomplete_evaluations"
    elif detector_errors:
        availability = "unknown_detector_error"
    else:
        availability = "available"
    if availability != "available":
        state = availability
    elif terminal:
        state = "matched_terminal"
    elif matched:
        state = "matched_nonterminal"
    else:
        state = "unmatched"
    return {
        "availability": availability,
        "state": state,
        "total_layer_count": len(layers),
        "evaluated_layer_count": evaluated,
        "matched_layer_count": matched,
        "terminal_layer_count": terminal,
        "automatic_route_layer_count": automatic,
        "known_hash_layer_count": known_hash,
        "loader_profile_layer_counts": dict(sorted(loader_profiles.items())),
        "route_profile_layer_counts": dict(sorted(route_profiles.items())),
        "config_signal_layer_counts": dict(sorted(config_signals.items())),
        "unrecognized_profile_count": unrecognized_profiles,
    }


def _logic_profile_digest(value: Mapping[str, Any]) -> str | None:
    functions = value.get("functions")
    if not isinstance(functions, list) or len(functions) > MAX_FUNCTION_RECORDS:
        return None
    fingerprints: set[str] = set()
    for function in functions:
        if not isinstance(function, Mapping):
            continue
        supplied = function.get("fingerprints")
        if not isinstance(supplied, Mapping):
            continue
        token_count = _non_negative_int(supplied.get("semantic_token_count")) or 0
        if token_count < 4:
            continue
        semantic = str(supplied.get("semantic_sequence_sha256") or "").casefold()
        normalized = str(supplied.get("normalized_logic_sha256") or "").casefold()
        if SHA256_RE.fullmatch(semantic):
            fingerprints.add(f"semantic:{semantic}")
        elif SHA256_RE.fullmatch(normalized):
            fingerprints.add(f"normalized:{normalized}")
    if len(fingerprints) < 2:
        return None
    return _canonical_sha256(sorted(fingerprints))


def _structure_axes(
    generic: Mapping[str, Any] | None,
    static_logic: Mapping[str, Any],
) -> dict[str, str]:
    """raw構造値を公開せず、完全一致軸のcommitmentだけを返す。"""

    axes: dict[str, str] = {}
    if isinstance(generic, Mapping):
        pe = generic.get("pe")
        elf = generic.get("elf")
        imphash = str(pe.get("imphash") or "").casefold() if isinstance(pe, Mapping) else ""
        telfhash = str(elf.get("telfhash") or "").casefold() if isinstance(elf, Mapping) else ""
        if IMPHASH_RE.fullmatch(imphash):
            axes["imphash"] = _canonical_sha256(["imphash", imphash])
        if TELFHASH_RE.fullmatch(telfhash):
            axes["telfhash"] = _canonical_sha256(["telfhash", telfhash])
    logic_digest = _logic_profile_digest(static_logic)
    if logic_digest is not None:
        axes["static_logic_fingerprint_set"] = _canonical_sha256(["static_logic_fingerprint_set", logic_digest])
    return axes


def _automation_gap_record(
    *,
    detector: Mapping[str, Any],
    candidate: Mapping[str, Any],
    route: Mapping[str, Any],
    static_limits: Mapping[str, Any],
    config_status: str,
) -> dict[str, Any]:
    """一caseの自動化gapを固定語彙とcommitmentだけで表現する。"""

    detector_availability = str(detector["availability"])
    loader_profiles = sorted(detector["loader_profile_layer_counts"])
    route_profiles = sorted(detector["route_profile_layer_counts"])
    if detector_availability != "available":
        status = detector_availability
    elif detector["terminal_layer_count"]:
        status = "terminal_config_recovered" if config_status == "confirmed_recovered" else "terminal_config_missing"
    elif route.get("route_config_candidate_recovered") is True:
        status = "route_config_candidate_only"
    elif loader_profiles:
        status = "loader_only"
    elif route_profiles or detector["config_signal_layer_counts"]:
        status = "route_only"
    elif detector["matched_layer_count"]:
        status = "detector_matched_nonterminal"
    else:
        status = "detector_unmatched"
    if status not in GAP_STATUSES:
        status = "unknown_invalid_schema"

    budget_limits: Counter[str] = Counter()
    for reason, count in candidate["budget_reason_counts"].items():
        budget_limits[f"candidate_budget:{reason}"] += count
    for reason, count in candidate["layer_limit_reason_counts"].items():
        budget_limits[f"candidate_layer:{reason}"] += count
    for reason, count in static_limits["reason_counts"].items():
        budget_limits[f"static_layer:{reason}"] += count

    pattern = {
        "gap_status": status,
        "detector_state": detector["state"],
        "loader_profiles": loader_profiles,
        "route_profiles": route_profiles,
        "candidate_assessment_status": candidate["assessment_status"],
        "route_status": route["status"],
        "budget_limit_reasons": sorted(budget_limits),
    }
    commitment = _canonical_sha256(pattern)
    return {
        "status": status,
        "gap_pattern_commitment_sha256": commitment,
        "gap_cluster_id": f"gap-{commitment[:16]}",
        "detector": dict(detector),
        "candidate_attempts": dict(candidate),
        "route_projection": dict(route),
        "budget_limits": {
            "static_layer_availability": static_limits["availability"],
            "reason_counts": dict(sorted(budget_limits.items())),
        },
    }


def _availability_rollup(states: Sequence[Any]) -> dict[str, Any]:
    known = sum(state == "available" for state in states)
    unknown_reasons = Counter(
        state
        for state in states
        if state
        in {
            "unknown_legacy_schema",
            "unknown_invalid_schema",
            "unknown_incomplete_evaluations",
            "unknown_detector_error",
        }
    )
    unknown = len(states) - known
    return {
        "status": ("available" if states and unknown == 0 else "partial" if known else "not_available"),
        "known_case_denominator": known,
        "unknown_case_count": unknown,
        "unknown_reason_case_counts": dict(sorted(unknown_reasons.items())),
        "denominator_basis": "unique_valid_cases_with_current_artifact_schema",
    }


def _automation_gap_aggregate(cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """case gapを固定語彙の件数と安全なpattern commitmentへ集約する。"""

    gap_statuses: Counter[str] = Counter()
    loader_case_counts: Counter[str] = Counter()
    loader_layer_counts: Counter[str] = Counter()
    route_profile_case_counts: Counter[str] = Counter()
    route_profile_layer_counts: Counter[str] = Counter()
    attempt_status_counts: Counter[str] = Counter()
    handler_attempt_status_counts: dict[str, Counter[str]] = defaultdict(Counter)
    assessment_rejections: Counter[str] = Counter()
    assessment_exclusions: Counter[str] = Counter()
    attempt_exclusions: Counter[str] = Counter()
    attempt_rejections: Counter[str] = Counter()
    budget_limits: Counter[str] = Counter()
    cluster_members: dict[str, list[str]] = defaultdict(list)
    cluster_records: dict[str, dict[str, Any]] = {}

    detector_states = []
    attempt_states = []
    budget_states = []
    candidate_layer_states = []
    route_states = []
    static_limit_states = []
    for case in cases:
        gap = case["automation_gap"]
        detector = gap["detector"]
        candidate = gap["candidate_attempts"]
        route = gap["route_projection"]
        gap_statuses[gap["status"]] += 1
        detector_states.append(detector["availability"])
        attempt_states.append(candidate["availability"]["attempt_accounting"])
        budget_states.append(candidate["availability"]["budget_reasons"])
        candidate_layer_states.append(candidate["availability"]["layer_limit_reasons"])
        route_states.append(route["availability"]["reason_accounting"])
        static_limit_states.append(gap["budget_limits"]["static_layer_availability"])
        for profile, count in detector["loader_profile_layer_counts"].items():
            loader_case_counts[profile] += 1
            loader_layer_counts[profile] += count
        for profile, count in detector["route_profile_layer_counts"].items():
            route_profile_case_counts[profile] += 1
            route_profile_layer_counts[profile] += count
        attempt_status_counts.update(candidate["attempt_status_counts"])
        for handler_id, statuses in candidate["handler_attempt_status_counts"].items():
            handler_attempt_status_counts[handler_id].update(statuses)
        assessment_rejections.update(route["assessment_rejection_reason_counts"])
        assessment_exclusions.update(route["assessment_exclusion_reason_counts"])
        attempt_exclusions.update(route["attempt_exclusion_reason_counts"])
        attempt_rejections.update(route["attempt_rejection_reason_counts"])
        budget_limits.update(gap["budget_limits"]["reason_counts"])
        commitment = gap["gap_pattern_commitment_sha256"]
        cluster_members[commitment].append(case["sha256"])
        cluster_records.setdefault(
            commitment,
            {
                "cluster_id": gap["gap_cluster_id"],
                "gap_status": gap["status"],
                "evidence_commitment_sha256": commitment,
            },
        )

    clusters = []
    for commitment, members in sorted(cluster_members.items()):
        clusters.append(
            {
                **cluster_records[commitment],
                "member_count": len(members),
                "members": sorted(members),
            }
        )
    return {
        "contract": {
            "target_family": "valleyrat",
            "raw_values_published": False,
            "endpoint_values_published": False,
            "source_names_published": False,
            "unknown_values_collapsed_to_fixed_sentinel": True,
            "detector_unmatched_requires_complete_error_free_layer_evaluations": True,
        },
        "availability": {
            "detector_and_profiles": _availability_rollup(detector_states),
            "candidate_attempt_accounting": _availability_rollup(attempt_states),
            "candidate_budget_reasons": _availability_rollup(budget_states),
            "candidate_layer_limits": _availability_rollup(candidate_layer_states),
            "route_reason_accounting": _availability_rollup(route_states),
            "static_layer_limits": _availability_rollup(static_limit_states),
        },
        "gap_status_case_counts": dict(sorted(gap_statuses.items())),
        "loader_profile_case_counts": dict(sorted(loader_case_counts.items())),
        "loader_profile_layer_counts": dict(sorted(loader_layer_counts.items())),
        "route_profile_case_counts": dict(sorted(route_profile_case_counts.items())),
        "route_profile_layer_counts": dict(sorted(route_profile_layer_counts.items())),
        "candidate_attempt_status_counts": dict(sorted(attempt_status_counts.items())),
        "candidate_handler_attempt_status_counts": {
            handler_id: dict(sorted(statuses.items()))
            for handler_id, statuses in sorted(handler_attempt_status_counts.items())
        },
        "route_rejection_reasons": {
            "assessment_rejection_reason_counts": dict(sorted(assessment_rejections.items())),
            "assessment_exclusion_reason_counts": dict(sorted(assessment_exclusions.items())),
            "attempt_exclusion_reason_counts": dict(sorted(attempt_exclusions.items())),
            "attempt_rejection_reason_counts": dict(sorted(attempt_rejections.items())),
        },
        "budget_limit_reason_counts": dict(sorted(budget_limits.items())),
        "gap_clusters": clusters,
    }


def _case_record(
    run_root: Path,
    digest: str,
    budget: _ReadBudget,
    *,
    expected_family: str | None,
    registered_families: frozenset[str],
) -> dict[str, Any]:
    case_dir = _regular_directory(
        run_root / "cases" / digest,
        code="case_directory_invalid",
    )
    if case_dir.name != digest:
        raise CorpusSummaryError(
            "case_directory_identity_invalid",
            "case directory名がSHA-256と一致しません。",
        )
    try:
        report_path = analysis_contract.resolve_case_artifact(case_dir, "report.json")
    except ValueError as exc:
        raise CorpusSummaryError(
            "report_boundary_invalid",
            "case reportの境界を検証できません。",
        ) from exc
    report, report_raw = _read_json_snapshot(
        report_path,
        budget,
        error_prefix="report",
    )
    _validate_report(report, digest)

    documents: dict[str, dict[str, Any]] = {}
    artifact_hashes: dict[str, str] = {}
    for relative in REQUIRED_CASE_ARTIFACTS:
        documents[relative], artifact_hashes[relative] = _case_artifact(
            case_dir,
            report,
            relative,
            budget,
        )
    generic: dict[str, Any] | None = None
    if "generic-triage.json" in report["artifact_sha256"]:
        generic, artifact_hashes["generic-triage.json"] = _case_artifact(
            case_dir,
            report,
            "generic-triage.json",
            budget,
        )
    optional_gap_documents: dict[str, dict[str, Any]] = {}
    for relative in OPTIONAL_GAP_ARTIFACTS:
        if relative in report["artifact_sha256"]:
            optional_gap_documents[relative], artifact_hashes[relative] = _case_artifact(
                case_dir,
                report,
                relative,
                budget,
            )

    orchestration = documents["orchestration.json"]
    candidate = documents["candidate-handler-assessment.json"]
    route = documents["route-config-candidates.json"]
    static_logic = documents["static-logic.json"]
    _validate_orchestration(orchestration, digest)
    _validate_candidate_assessment(candidate)
    _validate_route(route, digest)
    if static_logic.get("schema_version") != 1 or static_logic.get("sha256") != digest:
        raise CorpusSummaryError(
            "static_logic_identity_invalid",
            "static logicのschemaまたはcase identityが不正です。",
        )
    if generic is not None:
        generic_sha = generic.get("sha256")
        if generic_sha is not None and generic_sha != digest:
            raise CorpusSummaryError(
                "generic_triage_identity_invalid",
                "generic triageのcase identityが不正です。",
            )

    classification = report["classification"]
    resolution = orchestration["family_resolution"]
    automation_status = classification.get("automation_status")
    automation_family = classification.get("automation_family")
    if automation_status is not None and automation_status != resolution.get("status"):
        raise CorpusSummaryError(
            "report_orchestration_family_status_mismatch",
            "reportとorchestrationのfamily状態が一致しません。",
        )
    if automation_family is not None and automation_family != resolution.get("family"):
        raise CorpusSummaryError(
            "report_orchestration_family_mismatch",
            "reportとorchestrationのfamilyが一致しません。",
        )

    case_state = report["case_state"]
    overall_reasons = {
        "case:blocker:" + _allowlisted_code(item, PUBLIC_BLOCKER_CODES) for item in case_state["blockers"]
    }
    overall_reasons.update(
        "gate:blocker:" + _allowlisted_code(item, PUBLIC_BLOCKER_CODES) for item in orchestration["blockers"]
    )
    handler_reasons, handler_statuses = _handler_reason_codes(report)
    overall_reasons.update(handler_reasons)
    if orchestration["status"] != "complete":
        overall_reasons.add(f"automation:status:{orchestration['status']}")
    if resolution["status"] != "resolved":
        overall_reasons.add(f"family:status:{resolution['status']}")
    route_overall, route_diagnostic = _route_diagnostics(route)
    overall_reasons.update(route_overall)
    diagnostic_reasons = _candidate_diagnostics(candidate) | route_diagnostic

    outputs = orchestration["outputs"]
    candidate_outputs = orchestration["candidate_outputs"]
    config_gate = orchestration["quality_gates"]["config"]
    if outputs["config_recovered"]:
        config_status = "confirmed_recovered"
    elif candidate_outputs["config_candidate_recovered"] or route.get("route_config_candidate_recovered") is True:
        config_status = "candidate_only"
    elif config_gate.get("required") is True:
        config_status = "required_missing"
    elif config_gate.get("required") is False:
        config_status = "not_required"
    else:
        config_status = "undetermined"

    detector_summary = _valleyrat_detector_summary(optional_gap_documents.get("classification.json"))
    candidate_summary = _candidate_attempt_summary(candidate)
    route_summary = _route_projection_summary(route)
    static_limit_summary = _static_limit_summary(optional_gap_documents.get("static-layers.json"))
    automation_gap = _automation_gap_record(
        detector=detector_summary,
        candidate=candidate_summary,
        route=route_summary,
        static_limits=static_limit_summary,
        config_status=config_status,
    )
    selected_families_raw = list(classification["selected_families"])
    resolved_family_raw = resolution.get("family")
    selected_families = sorted(
        {
            _public_family(
                family,
                registered_families=registered_families,
                expected_family=expected_family,
            )
            for family in selected_families_raw
        }
    )
    resolved_family = _public_family(
        resolved_family_raw,
        registered_families=registered_families,
        expected_family=expected_family,
    )
    record = {
        "sha256": digest,
        "artifact_commitment_sha256": _canonical_sha256(
            {
                "report_sha256": _sha256_bytes(report_raw),
                "selected_artifacts": artifact_hashes,
            }
        ),
        "analysis_contract_sha256": report["analysis_contract"]["sha256"],
        "case_state": case_state["status"],
        "family": {
            "selected_families": selected_families,
            "resolution_status": resolution["status"],
            "resolved_family": resolved_family,
            "expected_family": expected_family,
            "matches_expected": (
                resolved_family_raw == expected_family
                if expected_family is not None and resolution["status"] == "resolved"
                else False
                if expected_family is not None
                else None
            ),
            "unrecognized_selected_family_count": sum(
                family not in registered_families and family != expected_family for family in selected_families_raw
            ),
            "resolved_family_publication_status": (
                "not_applicable"
                if resolved_family_raw is None
                else "registered"
                if resolved_family_raw in registered_families
                else "explicit_expected_family"
                if resolved_family_raw == expected_family
                else "redacted_unregistered"
            ),
        },
        "config": {
            "status": config_status,
            "required": config_gate.get("required"),
            "confirmed_recovered": outputs["config_recovered"],
            "candidate_only": config_status == "candidate_only",
        },
        "automation_status": orchestration["status"],
        "failure_reason_codes": sorted(overall_reasons),
        "diagnostic_reason_codes": sorted(diagnostic_reasons),
        "handler_status_counts": dict(sorted(handler_statuses.items())),
        "automation_gap": automation_gap,
        "structure_cluster_ids": [],
        "_structure_axes": _structure_axes(generic, static_logic),
    }
    return record


def _rate(numerator: int, denominator: int, basis: str) -> dict[str, Any]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "percentage": round(numerator * 100.0 / denominator, 2) if denominator else None,
        "denominator_basis": basis,
    }


def _exact_clusters(cases: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int, dict[str, int]]:
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    available = Counter()
    for case in cases:
        for axis, commitment in case["_structure_axes"].items():
            groups[(axis, commitment)].append(case["sha256"])
            available[axis] += 1
    clusters = []
    memberships: dict[str, list[str]] = defaultdict(list)
    for (axis, commitment), members in sorted(groups.items()):
        unique_members = sorted(set(members))
        if len(unique_members) < 2:
            continue
        cluster_id = f"exact-{axis}-{commitment[:16]}"
        clusters.append(
            {
                "cluster_id": cluster_id,
                "axis": axis,
                "evidence_commitment_sha256": commitment,
                "member_count": len(unique_members),
                "members": unique_members,
                "assessment_ja": (
                    "完全一致する静的構造の近縁候補です。同一campaign、operator、familyの確定には使用しません。"
                ),
            }
        )
        for digest in unique_members:
            memberships[digest].append(cluster_id)
    for case in cases:
        case["structure_cluster_ids"] = sorted(memberships.get(case["sha256"], []))
    unclustered = sum(not case["structure_cluster_ids"] for case in cases)
    return clusters, unclustered, dict(sorted(available.items()))


def _counter_from_case_codes(cases: Sequence[Mapping[str, Any]], field: str) -> dict[str, int]:
    counts = Counter(code for case in cases for code in case.get(field, []) if isinstance(code, str))
    return dict(sorted(counts.items()))


def summarize_runs(
    run_paths: Sequence[Path],
    *,
    expected_family: str | None = None,
) -> dict[str, Any]:
    """1〜64件のone-shot出力から決定的な秘密値非保持summaryを構築する。"""

    if not 1 <= len(run_paths) <= MAX_RUNS:
        raise CorpusSummaryError(
            "run_count_invalid",
            f"one-shot runは1件以上{MAX_RUNS}件以下で指定してください。",
        )
    normalized_expected = _valid_family(expected_family) if expected_family is not None else None
    if expected_family is not None and normalized_expected != expected_family:
        raise CorpusSummaryError(
            "expected_family_invalid",
            "expected family IDが不正です。",
        )
    roots = [_regular_directory(Path(path), code="run_directory_invalid") for path in run_paths]
    if len(set(roots)) != len(roots):
        raise CorpusSummaryError(
            "duplicate_run_path",
            "同じone-shot runを複数回指定できません。",
        )

    budget = _ReadBudget()
    family_registry, family_registry_raw = _read_json_snapshot(
        FAMILY_REGISTRY_PATH,
        budget,
        error_prefix="family_registry",
    )
    registered_families = _registered_family_ids(family_registry)
    family_registry_sha256 = _sha256_bytes(family_registry_raw)
    run_commitments = []
    observations: dict[str, list[dict[str, Any]]] = defaultdict(list)
    invalid_observations: dict[str, dict[str, Any]] = {}
    batch_reason_counts: Counter[str] = Counter()
    input_units = 0
    case_observation_count = 0
    input_duplicate_count = 0

    for root in roots:
        summary_path = root / "summary.json"
        summary, summary_raw = _read_json_snapshot(
            summary_path,
            budget,
            error_prefix="run_summary",
        )
        normalized = _validate_run_summary(summary)
        input_units += normalized["input_files"]
        case_observation_count += len(normalized["cases"])
        input_duplicate_count += len(normalized["duplicates"])
        if input_units > MAX_INPUT_UNITS or case_observation_count > MAX_CASE_OBSERVATIONS:
            raise CorpusSummaryError(
                "corpus_case_limit_exceeded",
                "コーパスの入力件数またはcase観測件数が上限を超えています。",
            )
        summary_digest = _sha256_bytes(summary_raw)
        run_commitments.append(
            {
                "summary_sha256": summary_digest,
                "input_units": normalized["input_files"],
                "case_observations": len(normalized["cases"]),
                "batch_errors": len(normalized["errors"]),
                "input_duplicates": len(normalized["duplicates"]),
            }
        )
        for error in normalized["errors"]:
            code = f"batch:{error['stage']}:{error['error_code']}"
            batch_reason_counts[code] += 1
        for digest in normalized["cases"]:
            try:
                record = _case_record(
                    root,
                    digest,
                    budget,
                    expected_family=normalized_expected,
                    registered_families=registered_families,
                )
                observations[digest].append(record)
            except CorpusSummaryError as exc:
                entry = invalid_observations.setdefault(
                    digest,
                    {"sha256": digest, "observation_count": 0, "reason_codes": set()},
                )
                entry["observation_count"] += 1
                entry["reason_codes"].add(f"integrity:{exc.code}")
        _summary_after, summary_raw_after = _read_json_snapshot(
            summary_path,
            budget,
            error_prefix="run_summary_recheck",
        )
        if _sha256_bytes(summary_raw_after) != summary_digest:
            raise CorpusSummaryError(
                "run_summary_changed_during_collection",
                "集計中にone-shot summaryが変更されました。",
            )

    cases: list[dict[str, Any]] = []
    duplicate_case_observations = 0
    conflicting_sha256 = []
    for digest, values in sorted(observations.items()):
        commitments = {value["artifact_commitment_sha256"] for value in values}
        duplicate_case_observations += max(0, len(values) - 1)
        if len(commitments) != 1:
            conflicting_sha256.append(digest)
            entry = invalid_observations.setdefault(
                digest,
                {"sha256": digest, "observation_count": 0, "reason_codes": set()},
            )
            entry["observation_count"] += len(values)
            entry["reason_codes"].add("integrity:duplicate_case_conflict")
            continue
        cases.append(values[0])

    clusters, unclustered_count, evidence_counts = _exact_clusters(cases)
    automation_gaps = _automation_gap_aggregate(cases)
    valid_count = len(cases)
    resolution_counts = Counter(case["family"]["resolution_status"] for case in cases)
    resolved_family_counts = Counter(
        case["family"]["resolved_family"] for case in cases if case["family"]["resolution_status"] == "resolved"
    )
    selected_family_counts = Counter(family for case in cases for family in case["family"]["selected_families"])
    config_counts = Counter(case["config"]["status"] for case in cases)
    automation_counts = Counter(case["automation_status"] for case in cases)
    case_state_counts = Counter(case["case_state"] for case in cases)
    handler_status_counts = Counter(
        {
            status: sum(case["handler_status_counts"].get(status, 0) for case in cases)
            for status in sorted(HANDLER_STATUSES)
        }
    )
    handler_status_counts += Counter()
    required_config_cases = [case for case in cases if case["config"]["required"] is True]
    expected_matches = sum(case["family"]["matches_expected"] is True for case in cases)
    expected_resolved_other = sum(
        case["family"]["resolution_status"] == "resolved" and case["family"]["matches_expected"] is False
        for case in cases
    )
    expected_not_resolved = sum(case["family"]["resolution_status"] != "resolved" for case in cases)

    invalid_cases = [
        {
            "sha256": digest,
            "observation_count": item["observation_count"],
            "reason_codes": sorted(item["reason_codes"]),
        }
        for digest, item in sorted(invalid_observations.items())
    ]
    integrity_reason_counts = Counter(reason for item in invalid_cases for reason in item["reason_codes"])
    public_cases = []
    for case in cases:
        public_cases.append({key: value for key, value in case.items() if not key.startswith("_")})

    summary = {
        "schema_version": SCHEMA_VERSION,
        "analysis_mode": "one_shot_artifacts_only",
        "input_commitment": {
            "runs": sorted(
                run_commitments,
                key=lambda item: (
                    item["summary_sha256"],
                    item["input_units"],
                    item["case_observations"],
                ),
            ),
            "family_registry_sha256": family_registry_sha256,
            "aggregate_sha256": _canonical_sha256(
                {
                    "family_registry_sha256": family_registry_sha256,
                    "run_summary_sha256": sorted(item["summary_sha256"] for item in run_commitments),
                }
            ),
        },
        "scope": {
            "run_count": len(roots),
            "root_cases_only": True,
            "family_publication_allowlist": ("canonical_registry_plus_explicit_expected_family"),
            "expected_family_source": (
                "uniform_operator_assertion" if normalized_expected is not None else "not_supplied"
            ),
            "expected_family": normalized_expected,
        },
        "counts": {
            "input_units": input_units,
            "case_observations": case_observation_count,
            "unique_valid_cases": valid_count,
            "duplicate_case_observations": duplicate_case_observations,
            "conflicting_case_sha256": len(conflicting_sha256),
            "input_duplicates": input_duplicate_count,
            "batch_errors": sum(batch_reason_counts.values()),
            "invalid_case_observations": sum(item["observation_count"] for item in invalid_cases),
            "invalid_unique_cases": len(invalid_cases),
        },
        "rates": {
            "family_resolution": _rate(
                resolution_counts["resolved"],
                valid_count,
                "unique_valid_cases",
            ),
            "confirmed_config_all_cases": _rate(
                config_counts["confirmed_recovered"],
                valid_count,
                "unique_valid_cases",
            ),
            "confirmed_config_when_required": _rate(
                sum(case["config"]["confirmed_recovered"] for case in required_config_cases),
                len(required_config_cases),
                "resolved_or_declared_cases_with_config_required",
            ),
            "automation_complete": _rate(
                automation_counts["complete"],
                valid_count,
                "unique_valid_cases",
            ),
            "expected_family_resolution": (
                {
                    "status": "available",
                    **_rate(expected_matches, valid_count, "unique_valid_cases_with_uniform_expectation"),
                }
                if normalized_expected is not None
                else {
                    "status": "not_available",
                    "reason": "independent_ground_truth_not_supplied",
                    "numerator": None,
                    "denominator": None,
                    "percentage": None,
                    "denominator_basis": None,
                }
            ),
        },
        "family": {
            "resolution_status_counts": dict(sorted(resolution_counts.items())),
            "resolved_family_counts": dict(sorted(resolved_family_counts.items())),
            "selected_family_counts": dict(sorted(selected_family_counts.items())),
            "expected_family_assessment": (
                {
                    "status": "available",
                    "family": normalized_expected,
                    "matched": expected_matches,
                    "resolved_other": expected_resolved_other,
                    "not_resolved": expected_not_resolved,
                }
                if normalized_expected is not None
                else {
                    "status": "not_available",
                    "reason": "independent_ground_truth_not_supplied",
                }
            ),
        },
        "config": {"status_counts": dict(sorted(config_counts.items()))},
        "automation": {
            "status_counts": dict(sorted(automation_counts.items())),
            "case_state_counts": dict(sorted(case_state_counts.items())),
            "handler_status_counts": {key: value for key, value in sorted(handler_status_counts.items()) if value},
        },
        "automation_gaps": automation_gaps,
        "failure_reasons": {
            "batch_input_reason_counts": dict(sorted(batch_reason_counts.items())),
            "case_reason_counts": _counter_from_case_codes(cases, "failure_reason_codes"),
            "diagnostic_case_reason_counts": _counter_from_case_codes(
                cases,
                "diagnostic_reason_codes",
            ),
            "integrity_reason_counts": dict(sorted(integrity_reason_counts.items())),
        },
        "structure": {
            "contract": {
                "mode": "exact_static_artifact_axes_only",
                "raw_axis_values_published": False,
                "minimum_members": 2,
                "axes": ["imphash", "telfhash", "static_logic_fingerprint_set"],
                "family_name_is_evidence": False,
                "network_indicator_is_evidence": False,
                "campaign_or_actor_attribution_automatic": False,
            },
            "evidence_available_case_counts": evidence_counts,
            "cluster_count": len(clusters),
            "unclustered_case_count": unclustered_count,
            "exact_clusters": clusters,
        },
        "cases": public_cases,
        "invalid_cases": invalid_cases,
        "safety": {
            "scope": "aggregate_reader_process_only",
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
            "subprocess_started": False,
            "source_analysis_worker_processes_assessed_by_this_flag": False,
            "raw_config_included": False,
            "network_values_included": False,
            "source_names_included": False,
            "unregistered_family_values_included": False,
            "integrity_scope": ("report_seal_selected_json_artifact_hashes_and_family_registry_snapshot"),
            "maximum_runs": MAX_RUNS,
            "maximum_input_units": MAX_INPUT_UNITS,
            "maximum_case_observations": MAX_CASE_OBSERVATIONS,
            "maximum_total_json_bytes": MAX_TOTAL_JSON_BYTES,
        },
    }
    return summary


def _rate_text(rate: Mapping[str, Any]) -> str:
    if rate.get("denominator") in {None, 0}:
        return "計算対象なし"
    return f"{rate['numerator']}/{rate['denominator']} ({rate['percentage']:.2f}%)"


def render_markdown(summary: Mapping[str, Any]) -> str:
    """machine-readable summaryと同じ母数を持つ日本語Markdownを生成する。"""

    counts = summary["counts"]
    rates = summary["rates"]
    lines = [
        "# one-shot静的解析コーパス集計",
        "",
        "## 結論",
        "",
        (
            f"{counts['unique_valid_cases']}件の一意な検証済みcaseを、"
            "検体本体を開かずone-shotの封印済みJSON成果物だけから集計しました。"
        ),
        "raw config、通信先、source nameはこの集計へ転記していません。",
        "",
        "## 母数",
        "",
        "| 項目 | 件数 |",
        "|---|---:|",
        f"| run | {summary['scope']['run_count']} |",
        f"| 入力単位 | {counts['input_units']} |",
        f"| case観測 | {counts['case_observations']} |",
        f"| 一意な検証済みcase | {counts['unique_valid_cases']} |",
        f"| batch error | {counts['batch_errors']} |",
        f"| integrity不合格case | {counts['invalid_unique_cases']} |",
        "",
        "## 成功率",
        "",
        "| 指標 | 結果 | 分母 |",
        "|---|---:|---|",
        f"| family確定 | {_rate_text(rates['family_resolution'])} | `unique_valid_cases` |",
        f"| config回収（全case） | {_rate_text(rates['confirmed_config_all_cases'])} | `unique_valid_cases` |",
        (
            "| config回収（config必須case） | "
            f"{_rate_text(rates['confirmed_config_when_required'])} | "
            "`resolved_or_declared_cases_with_config_required` |"
        ),
        f"| 自動解析完了 | {_rate_text(rates['automation_complete'])} | `unique_valid_cases` |",
    ]
    expected = rates["expected_family_resolution"]
    if expected.get("status") == "available":
        lines.append(f"| 期待family一致 | {_rate_text(expected)} | `unique_valid_cases_with_uniform_expectation` |")
    lines.extend(
        [
            "",
            "## family確定状態",
            "",
            "| 状態 | 件数 |",
            "|---|---:|",
        ]
    )
    for status, count in summary["family"]["resolution_status_counts"].items():
        lines.append(f"| `{status}` | {count} |")
    lines.extend(["", "## config状態", "", "| 状態 | 件数 |", "|---|---:|"])
    for status, count in summary["config"]["status_counts"].items():
        lines.append(f"| `{status}` | {count} |")
    gaps = summary["automation_gaps"]
    lines.extend(
        [
            "",
            "## ValleyRAT自動化gap",
            "",
            "旧schemaで根拠JSONが欠けるcaseは0件扱いにせず、不明母数へ分離しています。",
            "",
            "### 利用可能な母数",
            "",
            "| 集計軸 | 状態 | 既知case | 不明case |",
            "|---|---|---:|---:|",
        ]
    )
    for axis, availability in gaps["availability"].items():
        lines.append(
            f"| `{axis}` | `{availability['status']}` | "
            f"{availability['known_case_denominator']} | "
            f"{availability['unknown_case_count']} |"
        )
    lines.extend(
        [
            "",
            "### gap分類",
            "",
            "| 分類 | case数 |",
            "|---|---:|",
        ]
    )
    for status, count in gaps["gap_status_case_counts"].items():
        lines.append(f"| `{status}` | {count} |")
    if not gaps["gap_status_case_counts"]:
        lines.append("| なし | 0 |")
    lines.extend(
        [
            "",
            "### loader・route profile",
            "",
            "| 種別 | profile | case数 | layer数 |",
            "|---|---|---:|---:|",
        ]
    )
    profile_rows = 0
    for profile, count in gaps["loader_profile_case_counts"].items():
        lines.append(f"| loader | `{profile}` | {count} | {gaps['loader_profile_layer_counts'].get(profile, 0)} |")
        profile_rows += 1
    for profile, count in gaps["route_profile_case_counts"].items():
        lines.append(f"| route | `{profile}` | {count} | {gaps['route_profile_layer_counts'].get(profile, 0)} |")
        profile_rows += 1
    if not profile_rows:
        lines.append("| なし | - | 0 | 0 |")
    lines.extend(
        [
            "",
            "### candidate試行status",
            "",
            "| status | retained attempt数 |",
            "|---|---:|",
        ]
    )
    for status, count in gaps["candidate_attempt_status_counts"].items():
        lines.append(f"| `{status}` | {count} |")
    if not gaps["candidate_attempt_status_counts"]:
        lines.append("| なし | 0 |")
    lines.extend(
        [
            "",
            "### candidate handler別status",
            "",
            "| handler ID | status | retained attempt数 |",
            "|---|---|---:|",
        ]
    )
    handler_rows = 0
    for handler_id, statuses in gaps["candidate_handler_attempt_status_counts"].items():
        for status, count in statuses.items():
            lines.append(f"| `{handler_id}` | `{status}` | {count} |")
            handler_rows += 1
    if not handler_rows:
        lines.append("| なし | - | 0 |")
    lines.extend(
        [
            "",
            "### route rejection・exclusion",
            "",
            "| 区分 | reason | 件数 |",
            "|---|---|---:|",
        ]
    )
    rejection_rows = 0
    for category, reason_counts in gaps["route_rejection_reasons"].items():
        for reason, count in reason_counts.items():
            lines.append(f"| `{category}` | `{reason}` | {count} |")
            rejection_rows += 1
    if not rejection_rows:
        lines.append("| なし | - | 0 |")
    lines.extend(
        [
            "",
            "### budget・limit理由",
            "",
            "| reason | 件数 |",
            "|---|---:|",
        ]
    )
    for reason, count in gaps["budget_limit_reason_counts"].items():
        lines.append(f"| `{reason}` | {count} |")
    if not gaps["budget_limit_reason_counts"]:
        lines.append("| なし | 0 |")
    lines.extend(["", "## 失敗理由", "", "| 名前空間付きcode | 件数 |", "|---|---:|"])
    failure_groups = summary["failure_reasons"]
    merged = Counter()
    for field in (
        "batch_input_reason_counts",
        "case_reason_counts",
        "integrity_reason_counts",
    ):
        merged.update(failure_groups[field])
    if merged:
        for code, count in sorted(merged.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"| `{code}` | {count} |")
    else:
        lines.append("| なし | 0 |")
    structure = summary["structure"]
    lines.extend(
        [
            "",
            "## exact構造cluster",
            "",
            f"- cluster数: {structure['cluster_count']}",
            f"- cluster未所属case: {structure['unclustered_case_count']}",
            "- imphash、telfhash、または複数関数の静的logic fingerprint集合の完全一致だけを使用しています。",
            "- 同一campaign、operator、familyの確定には使用しません。",
            "",
            "| cluster ID | 軸 | 件数 |",
            "|---|---|---:|",
        ]
    )
    for cluster in structure["exact_clusters"][:100]:
        lines.append(f"| `{cluster['cluster_id']}` | `{cluster['axis']}` | {cluster['member_count']} |")
    if not structure["exact_clusters"]:
        lines.append("| なし | - | 0 |")
    if len(structure["exact_clusters"]) > 100:
        lines.extend(
            [
                "",
                "Markdownは先頭100件だけを表示しています。全件はJSONへ保持しています。",
            ]
        )
    lines.extend(
        [
            "",
            "## 安全境界",
            "",
            "- この集計器による検体本体の読込み・実行: なし",
            "- この集計器によるnetwork接続・subprocess起動: なし",
            "- 元のone-shot解析workerのprocess起動有無: この集計flagの対象外（各成果物の検体実行・network安全flagは検証）",
            "- raw config・通信先・source nameの収録: なし",
            "- 未登録family ID: 固定sentinelへ縮約",
            "- integrity確認: report意味sealと集計対象JSON成果物のSHA-256",
            "",
        ]
    )
    return "\n".join(lines)


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ変換する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("show this help message and exit", "このヘルプを表示して終了します")
        )


def build_parser() -> argparse.ArgumentParser:
    """成果物専用コーパス集計CLIの引数parserを返す。"""

    parser = JapaneseArgumentParser(description=__doc__)
    parser.add_argument(
        "--run",
        action="append",
        required=True,
        type=Path,
        help="analyze_sample.pyの出力root。1〜64回指定できます。",
    )
    parser.add_argument(
        "--expected-family",
        help="入力全caseへ独立に付与済みの期待family。既知コーパスの場合だけ指定します。",
    )
    parser.add_argument("--output-json", type=Path, help="決定的JSONの明示出力先。")
    parser.add_argument("--output-markdown", type=Path, help="日本語Markdownの明示出力先。")
    return parser


def _validate_output_paths(paths: Sequence[Path | None], runs: Sequence[Path]) -> None:
    resolved = [Path(path).resolve() for path in paths if path is not None]
    if len(resolved) != len(set(resolved)):
        raise CorpusSummaryError(
            "output_path_duplicate",
            "JSONとMarkdownの出力先は分けてください。",
        )
    for output in resolved:
        for run in runs:
            root = Path(run).resolve()
            if output == root / "summary.json":
                raise CorpusSummaryError(
                    "output_overwrites_run_summary",
                    "one-shot summaryを上書きする出力先は使用できません。",
                )
            try:
                output.relative_to(root / "cases")
            except ValueError:
                continue
            raise CorpusSummaryError(
                "output_inside_case_tree",
                "case tree内を集計出力先に使用できません。",
            )


def _atomic_write_text(path: Path, content: str) -> None:
    """明示出力だけを通常fileへatomicに書き込む。"""

    lexical = Path(os.path.abspath(os.fspath(path)))
    analysis_contract.ensure_no_reparse_components(lexical)
    lexical.parent.mkdir(parents=True, exist_ok=True)
    analysis_contract.ensure_no_reparse_components(lexical.parent)
    parent_before = lexical.parent.lstat()
    if not stat.S_ISDIR(parent_before.st_mode) or analysis_contract._stat_has_reparse_attribute(parent_before):
        raise CorpusSummaryError(
            "output_parent_invalid",
            "出力先parentが通常directoryではありません。",
        )
    if os.path.lexists(lexical):
        analysis_contract.ensure_no_reparse_components(lexical)
        information = lexical.lstat()
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or analysis_contract._stat_has_reparse_attribute(information)
        ):
            raise CorpusSummaryError(
                "output_target_invalid",
                "既存の出力先が単一linkの通常fileではありません。",
            )
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{lexical.name}.",
        suffix=".tmp",
        dir=lexical.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        analysis_contract.ensure_no_reparse_components(lexical.parent)
        parent_after = lexical.parent.lstat()
        if (
            not stat.S_ISDIR(parent_after.st_mode)
            or analysis_contract._stat_has_reparse_attribute(parent_after)
            or not analysis_contract._same_file_identity(parent_before, parent_after)
        ):
            raise CorpusSummaryError(
                "output_parent_changed",
                "出力中にparent directoryが変更されました。",
            )
        os.replace(temporary, lexical)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    """CLIを実行してJSONまたは日本語Markdownを明示先へ出力する。"""

    args = build_parser().parse_args(argv)
    _validate_output_paths((args.output_json, args.output_markdown), args.run)
    summary = summarize_runs(args.run, expected_family=args.expected_family)
    rendered_json = (
        json.dumps(
            summary,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    )
    if args.output_json:
        _atomic_write_text(args.output_json, rendered_json)
    if args.output_markdown:
        _atomic_write_text(args.output_markdown, render_markdown(summary))
    if not args.output_json:
        print(rendered_json, end="")
    else:
        print(
            json.dumps(
                {
                    "unique_valid_cases": summary["counts"]["unique_valid_cases"],
                    "invalid_unique_cases": summary["counts"]["invalid_unique_cases"],
                    "output_written": True,
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
