"""解析blockerを既存互換の修復actionへ厳密に対応付ける正本。"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

BLOCKER_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,159}$")
_LIFECYCLE_HANDLER_BLOCKER_RE = re.compile(
    r"^selected_family_has_no_(?:automatic_handler|valid_handler_evidence):"
    r"[a-z0-9][a-z0-9_-]{0,63}$"
)
_PLANNER_FAMILY_BLOCKER_RES = (
    re.compile(
        r"^selected_family_has_no_automatic_handler:"
        r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$"
    ),
    re.compile(
        r"^selected_family_has_no_valid_handler_evidence:"
        r"[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$"
    ),
)


class UnknownBlockerError(ValueError):
    """未登録blockerを自動actionへ変換しようとした場合に送出する。"""


@dataclass(frozen=True)
class PlannerPolicySpec:
    """再開plannerがblockerへ適用する副作用なしの固定policy。"""

    action_id: str
    target_phase: str | None
    retryable: bool
    priority: int
    changed_evidence: tuple[str, ...]


# lifecycleの公開action IDを変更せず、分類語彙だけをこのmoduleへ集約する。
ACTION_SPECS: Mapping[
    str,
    tuple[str, str, str, bool, bool, tuple[str, ...]],
] = MappingProxyType(
    {
        "family": (
            "family_attribution_review",
            "family_resolution",
            "classifier_verification",
            False,
            True,
            ("independent_static_family_evidence",),
        ),
        "function": (
            "representative_function_static_review",
            "function_analysis",
            "ghidra_function_batch",
            False,
            True,
            ("reviewed_program_available",),
        ),
        "static": (
            "deeper_static_layer_analysis",
            "static_analysis",
            "analysis_job_runner",
            False,
            True,
            ("new_static_evidence_or_implementation",),
        ),
        "static_limit": (
            "start_successor_with_extended_static_layer_limit",
            "static_analysis",
            "analysis_job_runner",
            True,
            True,
            ("reviewed_higher_static_layer_limit", "successor_workflow"),
        ),
        "terminal": (
            "terminal_payload_static_recovery",
            "terminal_payload_recovery",
            "terminal_payload_acquisition",
            False,
            True,
            ("new_terminal_evidence_or_implementation",),
        ),
        "config": (
            "configuration_and_c2_static_recovery",
            "configuration_recovery",
            "family_config_extractor",
            False,
            True,
            ("verified_family_or_terminal_payload",),
        ),
        "protocol": (
            "offline_protocol_evidence_review",
            "protocol_analysis",
            "c2_profile_review",
            False,
            True,
            ("offline_protocol_evidence",),
        ),
        "handler": (
            "handler_evidence_review",
            "handler_execution",
            "family_handler",
            False,
            True,
            ("handler_fix_or_new_evidence",),
        ),
        "publication": (
            "complete_case_or_enable_reviewed_partial_staging",
            "publication",
            "publish_one_shot_collection",
            False,
            True,
            ("reviewed_partial_staging_contract",),
        ),
        "manual": (
            "review_machine_readable_blocker",
            "manual_review",
            "human_review",
            False,
            True,
            ("new_verified_evidence_or_implementation",),
        ),
    }
)

BLOCKER_ACTION_KEYS: Mapping[str, str] = MappingProxyType(
    {
        "batch_error:input_read_failed": "manual",
        "batch_error:resume_validation_failed": "static",
        "batch_error:root_static_analysis_failed": "static",
        "analysis_partial": "static",
        "canonical_reclassification_move_pending": "family",
        "config": "config",
        "config_and_c2_not_recovered": "config",
        "c2_analysis_unresolved": "config",
        "c2_contract_invalid": "protocol",
        "detector_error_present": "handler",
        "family_attribution_unresolved": "family",
        "family_resolution": "family",
        "final_c2_endpoint_unresolved": "config",
        "function_analysis": "function",
        "function_analysis_pending": "function",
        "generic_triage": "static",
        "generic_triage_failed": "static",
        "generic_triage_partial": "static",
        "handler_ambiguous_evidence": "handler",
        "handler_failed": "handler",
        "handler_incompatible_input_format": "handler",
        "handler_no_evidence": "handler",
        "handler_preflight_failed": "handler",
        "live_c2_unverified": "protocol",
        "live_protocol_confirmation_pending": "protocol",
        "network": "protocol",
        "operational_c2_not_recovered": "config",
        "publication_requires_complete_or_partial_staging_opt_in": "publication",
        "representative_function_analysis_required": "function",
        "root_to_terminal_byte_derivation_incomplete": "terminal",
        "selected_family_layer_incomplete": "static",
        "static_c2_config_unresolved": "config",
        "static_layer_incomplete": "static",
        "static_layer_limit_reached": "static_limit",
        "static_layers": "static",
        "terminal_family_unresolved": "family",
        "terminal_payload": "terminal",
        "terminal_payload_not_recovered": "terminal",
        "virtualized_terminal_payload_not_recovered": "terminal",
    }
)

ORCHESTRATION_GATE_ACTION_KEYS: Mapping[str, str] = MappingProxyType(
    {
        key: BLOCKER_ACTION_KEYS[key]
        for key in (
            "config",
            "family_resolution",
            "function_analysis",
            "network",
            "static_layers",
            "terminal_payload",
        )
    }
)

TERMINAL_ACQUISITION_REASONS = frozenset(
    {
        "artifact_count_limit",
        "child_analysis_failed",
        "child_analysis_incomplete",
        "child_case_invalid",
        "child_not_analyzed",
        "child_timeout",
        "cycle_detected",
        "depth_limit",
        "disabled_assessment_only",
        "disabled_repository_output",
        "fixed_point_failed",
        "follow_on_errors",
        "omitted_metadata",
        "omitted_metadata_commitment",
        "payload_size_limit",
        "terminal_verification_incomplete",
        "total_bytes_limit",
        "wall_clock_exhausted",
        "wall_clock_limit",
    }
)

# 既存IDを保持する。従来fallbackだった2理由も同じ既存IDへ明示的に閉じる。
TERMINAL_NEXT_ACTION_BY_REASON: Mapping[str, str] = MappingProxyType(
    {
        "artifact_count_limit": "prioritize_retained_payload_graph",
        "child_analysis_failed": "inspect_child_analysis_failure",
        "child_analysis_incomplete": "continue_child_static_analysis",
        "child_case_invalid": "repair_child_case_integrity",
        "child_not_analyzed": "continue_child_static_analysis",
        "child_timeout": "retry_child_static_analysis",
        "cycle_detected": "review_payload_cycle",
        "depth_limit": "continue_terminal_static_recovery",
        "disabled_assessment_only": "run_full_static_analysis",
        "disabled_repository_output": "use_isolated_output_directory",
        "fixed_point_failed": "repair_follow_on_analysis",
        "follow_on_errors": "inspect_follow_on_errors",
        "omitted_metadata": "prioritize_retained_payload_graph",
        "omitted_metadata_commitment": "prioritize_retained_payload_graph",
        "payload_size_limit": "review_oversized_payload_offline",
        "terminal_verification_incomplete": "continue_child_static_analysis",
        "total_bytes_limit": "prioritize_retained_payload_graph",
        "wall_clock_exhausted": "retry_child_static_analysis",
        "wall_clock_limit": "continue_child_static_analysis",
    }
)

if set(TERMINAL_NEXT_ACTION_BY_REASON) != set(TERMINAL_ACQUISITION_REASONS):
    raise RuntimeError("terminal acquisition blocker registryが閉じていません")


PLANNER_EXACT_POLICIES: Mapping[str, PlannerPolicySpec] = MappingProxyType(
    {
        "batch_error:input_read_failed": PlannerPolicySpec(
            "review_machine_readable_blocker",
            "static_analysis",
            False,
            30,
            ("operator_review",),
        ),
        "batch_error:resume_validation_failed": PlannerPolicySpec(
            "reanalyze_static_pipeline",
            "static_analysis",
            False,
            30,
            ("analysis_contract_sha256", "static_analysis_evidence_sha256"),
        ),
        "batch_error:root_static_analysis_failed": PlannerPolicySpec(
            "reanalyze_static_pipeline",
            "static_analysis",
            False,
            30,
            ("analysis_contract_sha256", "static_analysis_evidence_sha256"),
        ),
        "analysis_partial": PlannerPolicySpec(
            "reanalyze_static_pipeline",
            "static_analysis",
            False,
            30,
            ("analysis_contract_sha256", "static_analysis_evidence_sha256"),
        ),
        "generic_triage_failed": PlannerPolicySpec(
            "repair_generic_triage",
            "static_analysis",
            False,
            30,
            ("analysis_contract_sha256", "generic_triage_evidence_sha256"),
        ),
        "generic_triage_partial": PlannerPolicySpec(
            "repair_generic_triage",
            "static_analysis",
            False,
            30,
            ("analysis_contract_sha256", "generic_triage_evidence_sha256"),
        ),
        "static_layer_limit_reached": PlannerPolicySpec(
            "expand_static_layer_budget",
            "static_analysis",
            False,
            31,
            ("analysis_contract_sha256", "static_layer_budget"),
        ),
        "static_layer_incomplete": PlannerPolicySpec(
            "repair_static_layer_pipeline",
            "static_analysis",
            False,
            32,
            ("analysis_contract_sha256", "static_layer_evidence_sha256"),
        ),
        "detector_error_present": PlannerPolicySpec(
            "repair_family_detector",
            "static_analysis",
            False,
            40,
            ("detector_fingerprint_sha256", "classification_evidence_sha256"),
        ),
        "handler_failed": PlannerPolicySpec(
            "repair_family_handler",
            "static_analysis",
            False,
            41,
            ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
        ),
        "handler_preflight_failed": PlannerPolicySpec(
            "repair_handler_preflight",
            "static_analysis",
            False,
            41,
            ("handler_dependency_fingerprint_sha256",),
        ),
        "handler_no_evidence": PlannerPolicySpec(
            "strengthen_family_handler_evidence",
            "static_analysis",
            False,
            42,
            ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
        ),
        "handler_ambiguous_evidence": PlannerPolicySpec(
            "resolve_handler_evidence_ambiguity",
            "static_analysis",
            False,
            42,
            ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
        ),
        "handler_incompatible_input_format": PlannerPolicySpec(
            "add_handler_input_support",
            "static_analysis",
            False,
            43,
            ("handler_dependency_fingerprint_sha256", "selected_layer_sha256"),
        ),
        "selected_family_layer_incomplete": PlannerPolicySpec(
            "repair_selected_family_layer_analysis",
            "static_analysis",
            False,
            43,
            ("handler_dependency_fingerprint_sha256", "selected_layer_sha256"),
        ),
        "representative_function_analysis_required": PlannerPolicySpec(
            "perform_representative_function_static_review",
            "function_validation",
            False,
            70,
            ("function_analysis_evidence_sha256",),
        ),
        "terminal_payload_not_recovered": PlannerPolicySpec(
            "recover_terminal_payload_statically",
            "static_analysis",
            False,
            50,
            ("terminal_payload_evidence_sha256",),
        ),
        "root_to_terminal_byte_derivation_incomplete": PlannerPolicySpec(
            "recover_terminal_payload_statically",
            "static_analysis",
            False,
            50,
            ("terminal_payload_evidence_sha256", "root_to_terminal_lineage_sha256"),
        ),
        "required_terminal_bytes_absent": PlannerPolicySpec(
            "recover_terminal_payload_statically",
            "static_analysis",
            False,
            50,
            ("terminal_payload_evidence_sha256",),
        ),
        "c2_protocol_confirmation_pending": PlannerPolicySpec(
            "confirm_c2_protocol_statically",
            "static_analysis",
            False,
            60,
            ("network_configuration_evidence_sha256", "protocol_evidence_sha256"),
        ),
        "orchestration:config": PlannerPolicySpec(
            "recover_configuration_statically",
            "static_analysis",
            False,
            60,
            ("configuration_evidence_sha256",),
        ),
        "orchestration:network": PlannerPolicySpec(
            "recover_network_configuration_statically",
            "static_analysis",
            False,
            61,
            ("network_configuration_evidence_sha256",),
        ),
        "orchestration:terminal_payload": PlannerPolicySpec(
            "recover_terminal_payload_statically",
            "static_analysis",
            False,
            50,
            ("terminal_payload_evidence_sha256",),
        ),
        "orchestration:function_analysis": PlannerPolicySpec(
            "perform_representative_function_static_review",
            "function_validation",
            False,
            70,
            ("function_analysis_evidence_sha256",),
        ),
        "orchestration:static_layers": PlannerPolicySpec(
            "repair_static_layer_pipeline",
            "static_analysis",
            False,
            32,
            ("analysis_contract_sha256", "static_layer_evidence_sha256"),
        ),
        "orchestration:family_resolution": PlannerPolicySpec(
            "strengthen_family_resolution",
            "static_analysis",
            False,
            40,
            ("detector_fingerprint_sha256", "classification_evidence_sha256"),
        ),
        "orchestration:handler_evidence": PlannerPolicySpec(
            "strengthen_family_handler_evidence",
            "static_analysis",
            False,
            42,
            ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
        ),
        "requirements_policy": PlannerPolicySpec(
            "declare_family_analysis_requirements",
            "completion_gate",
            False,
            65,
            ("family_requirements_policy_sha256",),
        ),
        "publication_requires_complete_or_partial_staging_opt_in": PlannerPolicySpec(
            "review_partial_publication_policy",
            "publication",
            False,
            80,
            ("publication_policy_sha256",),
        ),
        "function_validation_incomplete": PlannerPolicySpec(
            "perform_representative_function_static_review",
            "function_validation",
            False,
            70,
            ("function_analysis_evidence_sha256",),
        ),
        "publication_incomplete": PlannerPolicySpec(
            "repair_publication",
            "publication",
            False,
            80,
            ("publication_evidence_sha256",),
        ),
        "static_analysis_failed": PlannerPolicySpec("resume_workflow", "static_analysis", True, 10, ()),
        "preflight_failed": PlannerPolicySpec("resume_workflow", "preflight", True, 10, ()),
        "publication_failed": PlannerPolicySpec("resume_workflow", "publication", True, 10, ()),
        "function_validation_failed": PlannerPolicySpec("resume_workflow", "function_validation", True, 10, ()),
        "completion_gate_failed": PlannerPolicySpec("resume_workflow", "completion_gate", True, 10, ()),
        "derived_refresh_failed": PlannerPolicySpec("resume_workflow", "derived_refresh", True, 10, ()),
        "private_archive_failed": PlannerPolicySpec("resume_workflow", "private_archive", True, 10, ()),
        "workflow_execution_failed": PlannerPolicySpec("resume_workflow", None, True, 10, ()),
        "stage_contract_changed": PlannerPolicySpec(
            "start_successor_workflow",
            None,
            False,
            5,
            ("new_workflow_id", "updated_request_sha256"),
        ),
        "unexpected_lifecycle_state": PlannerPolicySpec(
            "repair_lifecycle_state",
            None,
            False,
            5,
            ("lifecycle_state_integrity_sha256",),
        ),
        "lifecycle_state_invalid": PlannerPolicySpec(
            "repair_lifecycle_state",
            None,
            False,
            5,
            ("lifecycle_state_integrity_sha256",),
        ),
        "analysis_blocked": PlannerPolicySpec("manual_review_required", None, False, 0, ("operator_review",)),
    }
)

PLANNER_PREFIX_POLICIES = (
    (
        _PLANNER_FAMILY_BLOCKER_RES[0],
        PlannerPolicySpec(
            "implement_family_handler",
            "static_analysis",
            False,
            40,
            ("handler_dependency_fingerprint_sha256",),
        ),
    ),
    (
        _PLANNER_FAMILY_BLOCKER_RES[1],
        PlannerPolicySpec(
            "strengthen_family_handler_evidence",
            "static_analysis",
            False,
            41,
            ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
        ),
    ),
)

PLANNER_LIFECYCLE_TRANSLATIONS: Mapping[str, tuple[str, str | None, int]] = MappingProxyType(
    {
        "family": ("family_resolution", "static_analysis", 40),
        "function": ("function_analysis", "function_validation", 70),
        "static": ("static_analysis", "static_analysis", 30),
        "static_limit": ("static_analysis", "static_analysis", 31),
        "terminal": ("terminal_payload_recovery", "static_analysis", 50),
        "config": ("configuration_recovery", "static_analysis", 60),
        "protocol": ("protocol_analysis", "static_analysis", 61),
        "handler": ("handler_execution", "static_analysis", 42),
        "publication": ("publication", "publication", 80),
        "manual": ("manual_review", None, 0),
    }
)


def terminal_next_action(reason: str) -> str:
    """終端取得理由をexact matchし、未登録値は例外で停止する。"""

    if not isinstance(reason, str) or reason not in TERMINAL_ACQUISITION_REASONS:
        raise UnknownBlockerError("terminal acquisition blockerがregistryに登録されていません")
    return TERMINAL_NEXT_ACTION_BY_REASON[reason]


def terminal_next_actions(reasons: Iterable[str]) -> list[str]:
    """終端取得理由集合を既存互換の重複なしaction列へ変換する。"""

    actions = {terminal_next_action(reason) for reason in reasons}
    if actions & {
        "inspect_child_analysis_failure",
        "repair_child_case_integrity",
        "retry_child_static_analysis",
    }:
        actions.discard("continue_child_static_analysis")
    return sorted(actions)


def terminal_blocker_code(reason: str) -> str:
    """登録済み理由だけをlifecycle用のnamespaced blockerへ変換する。"""

    terminal_next_action(reason)
    return f"terminal_acquisition:{reason}"


def action_key_for_blocker(blocker: str) -> str | None:
    """登録済みblockerだけをlifecycle action keyへ厳密に分類する。"""

    if not isinstance(blocker, str) or BLOCKER_RE.fullmatch(blocker) is None:
        return None
    direct = BLOCKER_ACTION_KEYS.get(blocker)
    if direct is not None:
        return direct
    orchestration = re.fullmatch(r"orchestration:([a-z_]+)", blocker)
    if orchestration is not None:
        return ORCHESTRATION_GATE_ACTION_KEYS.get(orchestration.group(1))
    terminal = re.fullmatch(r"terminal_acquisition:([a-z_]+)", blocker)
    if terminal is not None and terminal.group(1) in TERMINAL_ACQUISITION_REASONS:
        return "terminal"
    if _LIFECYCLE_HANDLER_BLOCKER_RE.fullmatch(blocker) is not None:
        return "handler"
    return None


def planner_policy_for_blocker(blocker: str) -> PlannerPolicySpec | None:
    """未知値を推測せず、登録済みblockerだけの再開policyを返す。"""

    if not isinstance(blocker, str) or BLOCKER_RE.fullmatch(blocker) is None:
        return None
    exact = PLANNER_EXACT_POLICIES.get(blocker)
    if exact is not None:
        return exact
    for pattern, policy in PLANNER_PREFIX_POLICIES:
        if pattern.fullmatch(blocker) is not None:
            return policy
    action_key = action_key_for_blocker(blocker)
    if action_key is None:
        return None
    translation = PLANNER_LIFECYCLE_TRANSLATIONS.get(action_key)
    action_spec = ACTION_SPECS.get(action_key)
    if translation is None or not isinstance(action_spec, tuple) or len(action_spec) != 6:
        return None
    expected_target, target_phase, priority = translation
    action_id, abstract_target, executor, automatic, changed, prerequisites = action_spec
    if (
        not isinstance(action_id, str)
        or BLOCKER_RE.fullmatch(action_id) is None
        or abstract_target != expected_target
        or not isinstance(executor, str)
        or BLOCKER_RE.fullmatch(executor) is None
        or not isinstance(automatic, bool)
        or not isinstance(changed, bool)
        or not isinstance(prerequisites, tuple)
        or not prerequisites
        or any(not isinstance(item, str) or BLOCKER_RE.fullmatch(item) is None for item in prerequisites)
    ):
        return None
    return PlannerPolicySpec(
        action_id=action_id,
        target_phase=target_phase,
        retryable=False,
        priority=priority,
        changed_evidence=prerequisites if changed else (),
    )


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and BLOCKER_RE.fullmatch(value) is not None


def _valid_planner_policy(policy: object) -> bool:
    return (
        isinstance(policy, PlannerPolicySpec)
        and _valid_identifier(policy.action_id)
        and (policy.target_phase is None or _valid_identifier(policy.target_phase))
        and isinstance(policy.retryable, bool)
        and not isinstance(policy.priority, bool)
        and isinstance(policy.priority, int)
        and policy.priority >= 0
        and isinstance(policy.changed_evidence, tuple)
        and all(_valid_identifier(value) for value in policy.changed_evidence)
    )


def _validate_registry() -> None:
    """定数間のclosureと公開identifierの固定schemaをimport時に検証する。"""

    if set(BLOCKER_ACTION_KEYS.values()) - set(ACTION_SPECS):
        raise RuntimeError("blocker action keyに未登録値があります")
    if set(ORCHESTRATION_GATE_ACTION_KEYS.values()) - set(ACTION_SPECS):
        raise RuntimeError("orchestration action keyに未登録値があります")
    if set(PLANNER_LIFECYCLE_TRANSLATIONS) != set(ACTION_SPECS):
        raise RuntimeError("planner lifecycle translationが閉じていません")
    if any(not _valid_identifier(blocker) for blocker in BLOCKER_ACTION_KEYS):
        raise RuntimeError("blocker identifierが不正です")
    if any(not _valid_identifier(reason) for reason in TERMINAL_ACQUISITION_REASONS):
        raise RuntimeError("terminal acquisition reasonが不正です")
    for action_key, spec in ACTION_SPECS.items():
        if (
            not _valid_identifier(action_key)
            or not isinstance(spec, tuple)
            or len(spec) != 6
            or not all(_valid_identifier(value) for value in spec[:3])
            or not isinstance(spec[3], bool)
            or not isinstance(spec[4], bool)
            or not isinstance(spec[5], tuple)
            or not spec[5]
            or not all(_valid_identifier(value) for value in spec[5])
        ):
            raise RuntimeError("lifecycle action specが不正です")
    if any(not _valid_identifier(action) for action in TERMINAL_NEXT_ACTION_BY_REASON.values()):
        raise RuntimeError("terminal next action identifierが不正です")
    if any(
        not _valid_identifier(blocker) or not _valid_planner_policy(policy)
        for blocker, policy in PLANNER_EXACT_POLICIES.items()
    ):
        raise RuntimeError("planner exact policyが不正です")
    if any(not _valid_planner_policy(policy) for _, policy in PLANNER_PREFIX_POLICIES):
        raise RuntimeError("planner prefix policyが不正です")
    for action_key, translation in PLANNER_LIFECYCLE_TRANSLATIONS.items():
        if (
            not _valid_identifier(action_key)
            or not isinstance(translation, tuple)
            or len(translation) != 3
            or not _valid_identifier(translation[0])
            or (translation[1] is not None and not _valid_identifier(translation[1]))
            or isinstance(translation[2], bool)
            or not isinstance(translation[2], int)
            or translation[2] < 0
        ):
            raise RuntimeError("planner lifecycle translationが不正です")
    registered_blockers = {
        *BLOCKER_ACTION_KEYS,
        *(f"orchestration:{gate}" for gate in ORCHESTRATION_GATE_ACTION_KEYS),
        *(terminal_blocker_code(reason) for reason in TERMINAL_ACQUISITION_REASONS),
    }
    if any(planner_policy_for_blocker(blocker) is None for blocker in registered_blockers):
        raise RuntimeError("登録済みblockerにplanner policyがありません")


_validate_registry()
