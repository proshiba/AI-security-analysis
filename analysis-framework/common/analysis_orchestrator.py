#!/usr/bin/env python3
"""複数の解析lifecycleを直列・再開可能・fail-closedに統括する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import analysis_job_runner
import analysis_lifecycle

SCHEMA_VERSION = 1
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_WORKFLOWS = 256
MAX_ATTEMPTS = 5
TOP_LEVEL_KEYS = frozenset({"schema_version", "orchestration_id", "workflows", "policy"})
POLICY_KEYS = frozenset({"continue_after_partial", "continue_after_failure"})
RECORD_KEYS = frozenset(
    {
        "index",
        "workflow_id",
        "job_id",
        "request_sha256",
        "status",
        "attempts",
        "started_at_utc",
        "finished_at_utc",
        "blockers",
        "lifecycle_report_sha256",
        "result",
    }
)
RECORD_STATUSES = frozenset({"pending", "running", "complete", "partial", "failed", "deferred"})
ORCHESTRATION_STATUSES = frozenset({"pending", "running", "complete", "partial", "failed"})


class OrchestrationError(RuntimeError):
    """全体オーケストレーションの公開可能なerror codeを保持する。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class OrchestrationRequest:
    """検証・正規化済みの複数workflow要求。"""

    orchestration_id: str
    workflows: tuple[analysis_lifecycle.LifecycleRequest, ...]
    policy: Mapping[str, bool]

    def public(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "orchestration_id": self.orchestration_id,
            "workflows": [request.public() for request in self.workflows],
            "policy": dict(self.policy),
        }


@dataclass(frozen=True)
class OrchestrationContext:
    """固定rootと保存先を持つ実行context。"""

    repository: Path
    input_root: Path
    work_root: Path
    orchestration_root: Path
    request: OrchestrationRequest
    timeout_seconds: int


@dataclass(frozen=True)
class _LifecycleActions:
    """production APIへ公開しないunit test用adapter集合。"""

    run: Callable[..., Mapping[str, Any]]
    resume: Callable[..., Mapping[str, Any]]
    verify: Callable[..., Mapping[str, Any]]
    snapshot: Callable[..., Mapping[str, Any]]


def _exact_keys(value: Any, expected: frozenset[str], *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise OrchestrationError("request_schema_invalid", f"{label}のkey集合が固定schemaと一致しません")
    return value


def _boolean(value: Any, *, label: str) -> bool:
    if not isinstance(value, bool):
        raise OrchestrationError("request_schema_invalid", f"{label}はbooleanで指定してください")
    return value


def validate_request_object(value: Mapping[str, Any]) -> OrchestrationRequest:
    """任意処理fieldを持たない固定一括requestを検証する。"""

    raw = _exact_keys(dict(value), TOP_LEVEL_KEYS, label="orchestration request")
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise OrchestrationError("schema_version_unsupported", "schema_versionは1だけを許可します")
    orchestration_id = raw.get("orchestration_id")
    if (
        not isinstance(orchestration_id, str)
        or analysis_lifecycle.WORKFLOW_ID_RE.fullmatch(orchestration_id) is None
    ):
        raise OrchestrationError("orchestration_id_invalid", "orchestration_idの形式が不正です")
    raw_workflows = raw.get("workflows")
    if not isinstance(raw_workflows, list) or not 1 <= len(raw_workflows) <= MAX_WORKFLOWS:
        raise OrchestrationError(
            "workflow_count_invalid",
            f"workflowsは1..{MAX_WORKFLOWS}件で指定してください",
        )
    workflows: list[analysis_lifecycle.LifecycleRequest] = []
    for index, item in enumerate(raw_workflows):
        try:
            workflows.append(analysis_lifecycle.validate_request_object(item))
        except (analysis_lifecycle.LifecycleError, TypeError) as exc:
            code = getattr(exc, "code", "workflow_request_invalid")
            raise OrchestrationError(str(code), f"workflows[{index}]がlifecycle契約に適合しません") from exc
    workflow_ids = [item.workflow_id for item in workflows]
    job_ids = [item.job.job_id for item in workflows]
    if len(workflow_ids) != len(set(workflow_ids)):
        raise OrchestrationError("workflow_id_duplicate", "workflow_idは一括request内で一意にしてください")
    if len(job_ids) != len(set(job_ids)):
        raise OrchestrationError("job_id_duplicate", "job_idは一括request内で一意にしてください")
    refresh_indices = [
        index
        for index, item in enumerate(workflows)
        if item.maintenance["refresh_repository"]
    ]
    if len(refresh_indices) > 1 or (refresh_indices and refresh_indices[0] != len(workflows) - 1):
        raise OrchestrationError(
            "repository_refresh_order_invalid",
            "repository refreshは最大1件とし、一括requestの最後へ配置してください",
        )
    policy_raw = _exact_keys(raw.get("policy"), POLICY_KEYS, label="policy")
    policy = {
        "continue_after_partial": _boolean(
            policy_raw.get("continue_after_partial"),
            label="policy.continue_after_partial",
        ),
        "continue_after_failure": _boolean(
            policy_raw.get("continue_after_failure"),
            label="policy.continue_after_failure",
        ),
    }
    return OrchestrationRequest(
        orchestration_id=orchestration_id,
        workflows=tuple(workflows),
        policy=policy,
    )


def load_request(path: Path) -> OrchestrationRequest:
    """strict UTF-8 JSONから一括requestを読む。"""

    path = Path(os.path.abspath(os.fspath(path)))
    analysis_lifecycle._reject_existing_reparse_components(path, label="orchestration request")
    if not path.is_file() or analysis_lifecycle._is_reparse(path):
        raise OrchestrationError("request_file_invalid", "一括requestは通常fileで指定してください")
    try:
        document = analysis_job_runner.load_json_object_strict(path, max_bytes=MAX_REQUEST_BYTES)
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise OrchestrationError("json_invalid", "一括request JSONを安全に読めません") from exc
    return validate_request_object(document)


def request_json_schema() -> dict[str, Any]:
    """operator tool用の厳格JSON Schemaを返す。"""

    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "Static malware analysis orchestration request",
        "type": "object",
        "additionalProperties": False,
        "required": sorted(TOP_LEVEL_KEYS),
        "properties": {
            "schema_version": {"const": SCHEMA_VERSION},
            "orchestration_id": {
                "type": "string",
                "pattern": analysis_lifecycle.WORKFLOW_ID_RE.pattern,
            },
            "workflows": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_WORKFLOWS,
                "items": analysis_lifecycle.request_json_schema(),
            },
            "policy": {
                "type": "object",
                "additionalProperties": False,
                "required": sorted(POLICY_KEYS),
                "properties": {
                    "continue_after_partial": {"type": "boolean"},
                    "continue_after_failure": {"type": "boolean"},
                },
            },
        },
    }


def build_plan(request: OrchestrationRequest) -> dict[str, Any]:
    """副作用なしで直列workflow planと安全境界を返す。"""

    workflows = []
    for index, item in enumerate(request.workflows):
        workflows.append(
            {
                "index": index,
                "workflow_id": item.workflow_id,
                "job_id": item.job.job_id,
                "request_sha256": analysis_lifecycle._sha256_value(item.public()),
                "runs_after": request.workflows[index - 1].workflow_id if index else None,
                "lifecycle": analysis_lifecycle.build_plan(item),
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "orchestration_id": request.orchestration_id,
        "request_sha256": analysis_lifecycle._sha256_value(request.public()),
        "execution": {
            "mode": "sequential",
            "maximum_parallel_workflows": 1,
            "workflow_count": len(workflows),
            "policy": dict(request.policy),
        },
        "workflows": workflows,
        "safety": {
            "arbitrary_commands_allowed": False,
            "arbitrary_modules_allowed": False,
            "sample_execution_allowed": False,
            "live_c2_allowed": False,
            "analysis_network_allowed": False,
            "datastore_network_enabled": any(item.private_archive["enabled"] for item in request.workflows),
            "repository_writes_serialized": True,
        },
    }


def _validate_context(
    request: OrchestrationRequest,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
    create: bool,
) -> OrchestrationContext:
    contexts = [
        analysis_lifecycle._validate_context_roots(
            item,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=timeout_seconds,
            create=create,
        )
        for item in request.workflows
    ]
    first = contexts[0]
    orchestration_root = first.work_root / "orchestrations" / request.orchestration_id
    analysis_lifecycle._reject_existing_reparse_components(
        orchestration_root,
        label="orchestration state",
    )
    return OrchestrationContext(
        repository=first.repository,
        input_root=first.input_root,
        work_root=first.work_root,
        orchestration_root=orchestration_root,
        request=request,
        timeout_seconds=timeout_seconds,
    )


def _implementation_sha256() -> str:
    return analysis_lifecycle._sha256_file(Path(__file__).resolve())


def _new_state(context: OrchestrationContext) -> dict[str, Any]:
    now = analysis_lifecycle.utc_now()
    return {
        "schema_version": SCHEMA_VERSION,
        "orchestration_id": context.request.orchestration_id,
        "request_sha256": analysis_lifecycle._sha256_value(context.request.public()),
        "implementation_sha256": _implementation_sha256(),
        "status": "pending",
        "created_at_utc": now,
        "updated_at_utc": now,
        "policy": dict(context.request.policy),
        "workflows": [
            {
                "index": index,
                "workflow_id": item.workflow_id,
                "job_id": item.job.job_id,
                "request_sha256": analysis_lifecycle._sha256_value(item.public()),
                "status": "pending",
                "attempts": 0,
                "started_at_utc": None,
                "finished_at_utc": None,
                "blockers": [],
                "lifecycle_report_sha256": None,
                "result": {},
            }
            for index, item in enumerate(context.request.workflows)
        ],
        "safety": build_plan(context.request)["safety"],
    }


def _write_state(context: OrchestrationContext, state: dict[str, Any]) -> None:
    state["updated_at_utc"] = analysis_lifecycle.utc_now()
    analysis_lifecycle._atomic_json(context.orchestration_root / "state.json", state)


def _valid_timestamp(value: Any) -> bool:
    return value is None or (isinstance(value, str) and 1 <= len(value) <= 64)


def _canonical_public_codes(value: Any, *, maximum: int) -> bool:
    """公開code配列が有界・文字列限定・整列済みuniqueかを返す。"""

    return bool(
        isinstance(value, list)
        and len(value) <= maximum
        and all(
            isinstance(item, str) and analysis_lifecycle.BLOCKER_RE.fullmatch(item) is not None
            for item in value
        )
        and value == sorted(set(value))
    )


def _completed_result_valid(record: Mapping[str, Any]) -> bool:
    """完了またはpartial childの公開resultが固定形かを返す。"""

    result = record.get("result")
    stage_status = result.get("stage_status") if isinstance(result, Mapping) else None
    next_actions = result.get("next_actions") if isinstance(result, Mapping) else None
    plan_sha256 = result.get("remediation_plan_sha256") if isinstance(result, Mapping) else None
    return bool(
        isinstance(result, dict)
        and set(result)
        == {
            "lifecycle_status",
            "stage_status",
            "sample_executed",
            "analysis_network_contacted",
            "next_actions",
            "remediation_plan_sha256",
            "same_workflow_resume_allowed",
            "lifecycle_state_sha256",
            "lifecycle_implementation_sha256",
        }
        and result.get("lifecycle_status") == record.get("status")
        and isinstance(stage_status, dict)
        and set(stage_status) == set(analysis_lifecycle.STAGE_ORDER)
        and all(value in analysis_lifecycle.STAGE_STATUSES for value in stage_status.values())
        and result.get("sample_executed") is False
        and result.get("analysis_network_contacted") is False
        and _canonical_public_codes(next_actions, maximum=analysis_lifecycle.MAX_REMEDIATION_ACTIONS)
        and isinstance(plan_sha256, str)
        and analysis_lifecycle.SHA256_RE.fullmatch(plan_sha256)
        and result.get("same_workflow_resume_allowed") is False
        and isinstance(result.get("lifecycle_state_sha256"), str)
        and analysis_lifecycle.SHA256_RE.fullmatch(result["lifecycle_state_sha256"]) is not None
        and isinstance(result.get("lifecycle_implementation_sha256"), str)
        and analysis_lifecycle.SHA256_RE.fullmatch(result["lifecycle_implementation_sha256"]) is not None
    )


def _record_semantics_valid(record: Mapping[str, Any]) -> bool:
    """workflow recordのstatusと試行・時刻・成果物の意味的整合を返す。"""

    status = record.get("status")
    attempts = record.get("attempts")
    started = record.get("started_at_utc")
    finished = record.get("finished_at_utc")
    blockers = record.get("blockers")
    report_sha256 = record.get("lifecycle_report_sha256")
    result = record.get("result")
    if status == "pending":
        return attempts == 0 and started is None and finished is None and blockers == [] and report_sha256 is None and result == {}
    if status == "running":
        return attempts >= 1 and isinstance(started, str) and finished is None and blockers == [] and report_sha256 is None and result == {}
    if status in {"complete", "partial"}:
        return (
            attempts >= 1
            and isinstance(started, str)
            and isinstance(finished, str)
            and isinstance(report_sha256, str)
            and _completed_result_valid(record)
        )
    if status == "deferred":
        return (
            attempts == 0
            and started is None
            and isinstance(finished, str)
            and blockers == ["orchestration_policy_stop"]
            and report_sha256 is None
            and result == {"reason": "prior_workflow_policy_stop"}
        )
    return status == "failed" and attempts >= 1 and isinstance(started, str) and isinstance(finished, str) and bool(blockers)


def _load_state(root: Path, request: OrchestrationRequest) -> dict[str, Any]:
    state = analysis_lifecycle._load_json(root / "state.json", maximum_bytes=MAX_STATE_BYTES)
    if set(state) != {
        "schema_version",
        "orchestration_id",
        "request_sha256",
        "implementation_sha256",
        "status",
        "created_at_utc",
        "updated_at_utc",
        "policy",
        "workflows",
        "safety",
    }:
        raise OrchestrationError("state_invalid", "orchestration state schemaが不正です")
    if (
        state.get("schema_version") != SCHEMA_VERSION
        or state.get("orchestration_id") != request.orchestration_id
        or state.get("request_sha256") != analysis_lifecycle._sha256_value(request.public())
        or state.get("policy") != dict(request.policy)
        or state.get("status") not in ORCHESTRATION_STATUSES
        or not _valid_timestamp(state.get("created_at_utc"))
        or not _valid_timestamp(state.get("updated_at_utc"))
        or state.get("safety") != build_plan(request)["safety"]
    ):
        raise OrchestrationError("state_invalid", "orchestration state fieldが不正です")
    implementation = state.get("implementation_sha256")
    if (
        not isinstance(implementation, str)
        or analysis_lifecycle.SHA256_RE.fullmatch(implementation) is None
        or implementation != _implementation_sha256()
    ):
        raise OrchestrationError(
            "orchestrator_contract_changed",
            "orchestrator実装が保存時から変更されました。新しいIDで再実行してください",
        )
    records = state.get("workflows")
    if not isinstance(records, list) or len(records) != len(request.workflows):
        raise OrchestrationError("state_invalid", "workflow state件数が一致しません")
    for index, (record, child) in enumerate(zip(records, request.workflows, strict=True)):
        attempts = record.get("attempts") if isinstance(record, dict) else None
        blockers = record.get("blockers") if isinstance(record, dict) else None
        report_sha256 = record.get("lifecycle_report_sha256") if isinstance(record, dict) else None
        if (
            not isinstance(record, dict)
            or set(record) != RECORD_KEYS
            or record.get("index") != index
            or record.get("workflow_id") != child.workflow_id
            or record.get("job_id") != child.job.job_id
            or record.get("request_sha256") != analysis_lifecycle._sha256_value(child.public())
            or record.get("status") not in RECORD_STATUSES
            or isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 0 <= attempts <= MAX_ATTEMPTS
            or not _valid_timestamp(record.get("started_at_utc"))
            or not _valid_timestamp(record.get("finished_at_utc"))
            or not isinstance(blockers, list)
            or blockers != analysis_lifecycle._bounded_blockers(blockers)
            or not isinstance(record.get("result"), dict)
            or (
                report_sha256 is not None
                and (
                    not isinstance(report_sha256, str)
                    or analysis_lifecycle.SHA256_RE.fullmatch(report_sha256) is None
                )
            )
            or not _record_semantics_valid(record)
        ):
            raise OrchestrationError("state_invalid", f"workflow state[{index}]が不正です")
    statuses = [record["status"] for record in records]
    overall = state["status"]
    final_status_invalid = (
        (overall == "pending" and any(status != "pending" for status in statuses))
        or (overall == "complete" and any(status != "complete" for status in statuses))
        or (
            overall == "failed"
            and ("failed" not in statuses or any(status in {"pending", "running"} for status in statuses))
        )
        or (
            overall == "partial"
            and (
                "failed" in statuses
                or all(status == "complete" for status in statuses)
                or any(status in {"pending", "running"} for status in statuses)
            )
        )
    )
    if final_status_invalid:
        raise OrchestrationError("state_invalid", "orchestration statusとworkflow stateが一致しません")
    return state


def _lifecycle_kwargs(context: OrchestrationContext) -> dict[str, Any]:
    return {
        "repository": context.repository,
        "input_root": context.input_root,
        "work_root": context.work_root,
        "timeout_seconds": context.timeout_seconds,
    }


def _lifecycle_report_path(context: OrchestrationContext, workflow_id: str) -> Path:
    return context.work_root / "lifecycles" / workflow_id / "report.json"


def _remediation_summary(lifecycle_state: Mapping[str, Any]) -> tuple[list[str], str]:
    """child completionの構造化planを検証し、公開用の最小要約を返す。"""

    stages = lifecycle_state.get("stages")
    completion = stages.get("completion_gate") if isinstance(stages, Mapping) else None
    result = completion.get("result") if isinstance(completion, Mapping) else None
    fields = ("remediation_actions", "remediation_plan_sha256", "next_actions")
    if isinstance(completion, Mapping) and "result" in completion and not isinstance(result, Mapping):
        raise OrchestrationError("lifecycle_remediation_invalid", "child remediation planが不正です")
    present = tuple(isinstance(result, Mapping) and field in result for field in fields)
    if not any(present):
        actions = analysis_lifecycle._remediation_actions([], _record_blockers(lifecycle_state))
        return analysis_lifecycle._next_actions(actions), analysis_lifecycle._sha256_value(
            {"actions": actions}
        )
    if not all(present):
        raise OrchestrationError("lifecycle_remediation_invalid", "child remediation planが不正です")
    if not isinstance(result, Mapping):
        raise OrchestrationError("lifecycle_remediation_invalid", "child remediation planが不正です")
    cases = result.get("cases")
    workflow_blockers = result.get("blockers")
    valid = bool(
        isinstance(cases, list)
        and len(cases) <= analysis_lifecycle.MAX_PUBLIC_CASES
        and _canonical_public_codes(
            workflow_blockers,
            maximum=analysis_lifecycle.MAX_PUBLIC_BLOCKERS,
        )
    )
    case_digests: set[str] = set()
    if valid:
        allowed_statuses = {
            "assessment_only_complete",
            "complete",
            "failed",
            "invalid",
            "partial",
            "triaged_unknown",
        }
        for case in cases:
            digest = case.get("sha256") if isinstance(case, Mapping) else None
            report_blockers = case.get("report_blockers") if isinstance(case, Mapping) else None
            orchestration_blockers = (
                case.get("orchestration_blockers") if isinstance(case, Mapping) else None
            )
            if (
                not isinstance(case, dict)
                or set(case) != {"sha256", "status", "report_blockers", "orchestration_blockers"}
                or not isinstance(digest, str)
                or analysis_lifecycle.SHA256_RE.fullmatch(digest) is None
                or case.get("status") not in allowed_statuses
                or not _canonical_public_codes(
                    report_blockers,
                    maximum=analysis_lifecycle.MAX_PUBLIC_BLOCKERS,
                )
                or not _canonical_public_codes(
                    orchestration_blockers,
                    maximum=analysis_lifecycle.MAX_PUBLIC_BLOCKERS,
                )
            ):
                valid = False
                break
            case_digests.add(digest)
        if valid and len(case_digests) != len(cases):
            valid = False
    actions = result["remediation_actions"]
    plan_sha256 = result["remediation_plan_sha256"]
    next_actions = result["next_actions"]
    required = {
        "case_sha256",
        "blocker_code",
        "action_id",
        "target_phase",
        "executor",
        "automatic",
        "requires_changed_evidence",
        "prerequisites",
    }
    valid = bool(
        valid
        and isinstance(actions, list)
        and len(actions) <= analysis_lifecycle.MAX_REMEDIATION_ACTIONS
    )
    if valid:
        for action in actions:
            prerequisites = action.get("prerequisites") if isinstance(action, Mapping) else None
            digest = action.get("case_sha256") if isinstance(action, Mapping) else None
            if (
                not isinstance(action, dict)
                or set(action) != required
                or (
                    digest is not None
                    and (not isinstance(digest, str) or analysis_lifecycle.SHA256_RE.fullmatch(digest) is None)
                )
                or (digest is not None and digest not in case_digests)
                or any(
                    not isinstance(action.get(key), str)
                    or analysis_lifecycle.BLOCKER_RE.fullmatch(action[key]) is None
                    for key in ("blocker_code", "action_id", "target_phase", "executor")
                )
                or not isinstance(action.get("automatic"), bool)
                or not isinstance(action.get("requires_changed_evidence"), bool)
                or not _canonical_public_codes(prerequisites, maximum=16)
            ):
                valid = False
                break
            expected = analysis_lifecycle._remediation_action(action["blocker_code"], case_sha256=digest)
            if action != expected:
                valid = False
                break
    if valid:
        keys = [(action["case_sha256"] or "", action["blocker_code"], action["action_id"]) for action in actions]
        valid = keys == sorted(keys) and len(keys) == len(set(keys))
    if valid:
        expected_actions = analysis_lifecycle._remediation_actions(cases, workflow_blockers)
        valid = actions == expected_actions
    expected_next = analysis_lifecycle._next_actions(actions) if valid else None
    expected_sha256 = analysis_lifecycle._sha256_value({"actions": actions}) if valid else None
    if (
        not valid
        or not _canonical_public_codes(next_actions, maximum=analysis_lifecycle.MAX_REMEDIATION_ACTIONS)
        or next_actions != expected_next
        or not isinstance(plan_sha256, str)
        or analysis_lifecycle.SHA256_RE.fullmatch(plan_sha256) is None
        or plan_sha256 != expected_sha256
    ):
        raise OrchestrationError("lifecycle_remediation_invalid", "child remediation planが不正です")
    return expected_next, expected_sha256


def _lifecycle_attempts(lifecycle_state: Mapping[str, Any]) -> int:
    """enabled child stageの最大attemptを親workflow attemptとして再導出する。"""

    stages = lifecycle_state.get("stages")
    if not isinstance(stages, Mapping) or set(stages) != set(analysis_lifecycle.STAGE_ORDER):
        raise OrchestrationError("lifecycle_state_invalid", "child lifecycle stageが不正です")
    attempts: list[int] = []
    for stage in analysis_lifecycle.STAGE_ORDER:
        record = stages.get(stage)
        if not isinstance(record, Mapping) or not isinstance(record.get("enabled"), bool):
            raise OrchestrationError("lifecycle_state_invalid", "child lifecycle stageが不正です")
        value = record.get("attempts")
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= analysis_lifecycle.MAX_ATTEMPTS:
            raise OrchestrationError("lifecycle_state_invalid", "child lifecycle attemptが不正です")
        if record["enabled"]:
            attempts.append(value)
    if not attempts or max(attempts) < 1:
        raise OrchestrationError("lifecycle_state_invalid", "terminal child lifecycleにattemptがありません")
    return max(attempts)


def _lifecycle_implementation_sha256(lifecycle_state: Mapping[str, Any]) -> str:
    """保存child stage fingerprint集合をcanonical digestへ固定する。"""

    stages = lifecycle_state.get("stages")
    if not isinstance(stages, Mapping) or set(stages) != set(analysis_lifecycle.STAGE_ORDER):
        raise OrchestrationError("lifecycle_state_invalid", "child lifecycle stageが不正です")
    fingerprints: dict[str, str] = {}
    for stage in analysis_lifecycle.STAGE_ORDER:
        record = stages.get(stage)
        fingerprint = record.get("fingerprint") if isinstance(record, Mapping) else None
        if not isinstance(fingerprint, str) or analysis_lifecycle.SHA256_RE.fullmatch(fingerprint) is None:
            raise OrchestrationError("lifecycle_state_invalid", "child lifecycle fingerprintが不正です")
        fingerprints[stage] = fingerprint
    return analysis_lifecycle._sha256_value({"stage_fingerprints": fingerprints})


def _record_result(lifecycle_state: Mapping[str, Any]) -> dict[str, Any]:
    stages = lifecycle_state.get("stages")
    if not isinstance(stages, Mapping):
        raise OrchestrationError("lifecycle_state_invalid", "child lifecycle stateが不正です")
    stage_status = {
        stage: stages.get(stage, {}).get("status") if isinstance(stages.get(stage), Mapping) else None
        for stage in analysis_lifecycle.STAGE_ORDER
    }
    next_actions, plan_sha256 = _remediation_summary(lifecycle_state)
    lifecycle_status = lifecycle_state.get("status")
    return {
        "lifecycle_status": lifecycle_status,
        "stage_status": stage_status,
        "sample_executed": False,
        "analysis_network_contacted": False,
        "next_actions": next_actions,
        "remediation_plan_sha256": plan_sha256,
        "same_workflow_resume_allowed": lifecycle_status == "failed",
        "lifecycle_state_sha256": analysis_lifecycle._sha256_value(lifecycle_state),
        "lifecycle_implementation_sha256": _lifecycle_implementation_sha256(lifecycle_state),
    }


def _record_blockers(lifecycle_state: Mapping[str, Any]) -> list[str]:
    stages = lifecycle_state.get("stages")
    if not isinstance(stages, Mapping):
        return ["lifecycle_state_invalid"]
    blockers: list[Any] = []
    for stage in analysis_lifecycle.STAGE_ORDER:
        record = stages.get(stage)
        if not isinstance(record, Mapping):
            blockers.append("lifecycle_state_invalid")
            continue
        values = record.get("blockers", [])
        if not isinstance(values, list):
            blockers.append("analysis_blocked")
            continue
        blockers.extend(values)
    return analysis_lifecycle._bounded_blockers(blockers)


def _mark_deferred(state: dict[str, Any], start: int) -> None:
    now = analysis_lifecycle.utc_now()
    for record in state["workflows"][start:]:
        if record["status"] in {"pending", "deferred"}:
            record.update(
                {
                    "status": "deferred",
                    "finished_at_utc": now,
                    "blockers": ["orchestration_policy_stop"],
                    "result": {"reason": "prior_workflow_policy_stop"},
                }
            )


def _public_report_from_state(context: OrchestrationContext, state: Mapping[str, Any]) -> dict[str, Any]:
    records = []
    for record in state["workflows"]:
        records.append(
            {
                "index": record["index"],
                "workflow_id": record["workflow_id"],
                "job_id": record["job_id"],
                "status": record["status"],
                "attempts": record["attempts"],
                "blockers": record["blockers"],
                "lifecycle_report_sha256": record["lifecycle_report_sha256"],
                "result": record["result"],
            }
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "orchestration_id": context.request.orchestration_id,
        "request_sha256": state["request_sha256"],
        "status": state["status"],
        "policy": dict(context.request.policy),
        "workflows": records,
        "safety": {
            "sample_executed": False,
            "live_c2_contacted": False,
            "analysis_network_contacted": False,
            "datastore_network_contacted": any(
                record["result"].get("stage_status", {}).get("private_archive") == "succeeded"
                for record in state["workflows"]
            ),
            "arbitrary_command_executed": False,
            "repository_writes_serialized": True,
        },
    }


def _finalize(context: OrchestrationContext, state: dict[str, Any]) -> dict[str, Any]:
    statuses = [record["status"] for record in state["workflows"]]
    if "failed" in statuses:
        state["status"] = "failed"
    elif all(status == "complete" for status in statuses):
        state["status"] = "complete"
    else:
        state["status"] = "partial"
    _write_state(context, state)
    analysis_lifecycle._atomic_json(
        context.orchestration_root / "report.json",
        _public_report_from_state(context, state),
    )
    return state


def _production_lifecycle_snapshot(
    workflow_id: str,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    """validated child stateと、それにexact一致するreport digestを同時に返す。"""

    child_context, child_state = analysis_lifecycle._existing_context(
        workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    try:
        raw_report = analysis_job_runner._read_regular_file_once(
            child_context.lifecycle_root / "report.json",
            max_bytes=analysis_lifecycle.MAX_STATE_BYTES,
        )
        report = analysis_job_runner._decode_json_object_strict(raw_report)
    except (analysis_job_runner.JobContractError, OSError) as exc:
        raise OrchestrationError("lifecycle_report_mismatch", "child lifecycle reportを検証できません") from exc
    if report != analysis_lifecycle._public_report_from_state(child_context, child_state):
        raise OrchestrationError("lifecycle_report_mismatch", "child lifecycle reportとstateが一致しません")
    return {
        "state": child_state,
        "report_sha256": hashlib.sha256(raw_report).hexdigest(),
    }


def _terminal_record_values(
    context: OrchestrationContext,
    workflow_id: str,
    actions: _LifecycleActions,
) -> dict[str, Any]:
    """childの保存state/reportからterminal親record fieldを再導出する。"""

    try:
        snapshot = actions.snapshot(workflow_id, **_lifecycle_kwargs(context))
    except OrchestrationError:
        raise
    except Exception as exc:
        raise OrchestrationError("lifecycle_snapshot_invalid", "child lifecycle snapshotが不正です") from exc
    if not isinstance(snapshot, dict) or set(snapshot) != {"state", "report_sha256"}:
        raise OrchestrationError("lifecycle_snapshot_invalid", "child lifecycle snapshot schemaが不正です")
    child_state = snapshot.get("state")
    report_sha256 = snapshot.get("report_sha256")
    if (
        not isinstance(child_state, dict)
        or child_state.get("workflow_id") != workflow_id
        or child_state.get("status") not in {"complete", "partial"}
        or not isinstance(report_sha256, str)
        or analysis_lifecycle.SHA256_RE.fullmatch(report_sha256) is None
    ):
        raise OrchestrationError("lifecycle_snapshot_invalid", "child lifecycle snapshot fieldが不正です")
    child_request = next(item for item in context.request.workflows if item.workflow_id == workflow_id)
    expected_request_sha256 = analysis_lifecycle._sha256_value(child_request.public())
    if child_state.get("request_sha256") != expected_request_sha256:
        raise OrchestrationError("lifecycle_snapshot_invalid", "child lifecycle request digestが一致しません")
    return {
        "status": child_state["status"],
        "attempts": _lifecycle_attempts(child_state),
        "blockers": _record_blockers(child_state),
        "lifecycle_report_sha256": report_sha256,
        "result": _record_result(child_state),
    }


def _verification_envelope_matches(
    verification: Any,
    *,
    workflow_id: str,
    request_sha256: str,
    stage_status: Mapping[str, Any],
) -> bool:
    """verify_lifecycleの公開envelopeをexact schema・child snapshotへ束縛する。"""

    errors = verification.get("errors") if isinstance(verification, Mapping) else None
    return bool(
        isinstance(verification, dict)
        and set(verification)
        == {
            "schema_version",
            "workflow_id",
            "valid",
            "errors",
            "request_sha256",
            "stage_status",
            "sample_executed",
            "analysis_network_contacted",
        }
        and verification.get("schema_version") == analysis_lifecycle.SCHEMA_VERSION
        and verification.get("workflow_id") == workflow_id
        and verification.get("valid") is True
        and _canonical_public_codes(errors, maximum=analysis_lifecycle.MAX_PUBLIC_BLOCKERS)
        and errors == []
        and verification.get("request_sha256") == request_sha256
        and verification.get("stage_status") == dict(stage_status)
        and verification.get("sample_executed") is False
        and verification.get("analysis_network_contacted") is False
    )


def _terminal_record_mismatch(
    context: OrchestrationContext,
    record: Mapping[str, Any],
    actions: _LifecycleActions,
) -> str | None:
    """terminal親recordと再導出したchild state/reportの不一致種別を返す。"""

    try:
        verification = actions.verify(record["workflow_id"], **_lifecycle_kwargs(context))
    except Exception:  # noqa: BLE001 - read-only child検証境界でerrorを正規化する
        return "lifecycle_verification_failed"
    try:
        values = _terminal_record_values(context, record["workflow_id"], actions)
    except OrchestrationError as exc:
        if exc.code == "lifecycle_report_mismatch":
            return "lifecycle_report_mismatch"
        return "lifecycle_verification_failed"
    if record.get("lifecycle_report_sha256") != values["lifecycle_report_sha256"]:
        return "lifecycle_report_mismatch"
    stage_status = values["result"]["stage_status"]
    if not _verification_envelope_matches(
        verification,
        workflow_id=record["workflow_id"],
        request_sha256=record["request_sha256"],
        stage_status=stage_status,
    ):
        return "lifecycle_invalid"
    if any(
        record.get(key) != values[key]
        for key in ("status", "attempts", "blockers", "result")
    ):
        return "lifecycle_parent_mismatch"
    return None


def _verify_completed_record(
    context: OrchestrationContext,
    record: Mapping[str, Any],
    actions: _LifecycleActions,
) -> None:
    mismatch = _terminal_record_mismatch(context, record, actions)
    if mismatch is not None:
        raise OrchestrationError(
            "completed_workflow_changed",
            f"成功済みworkflowの再検証に失敗しました: {record['workflow_id']} ({mismatch})",
        )


def _verify_saved_parent_report(
    context: OrchestrationContext,
    state: Mapping[str, Any],
) -> None:
    """terminal recordをskipする前に親reportも保存stateへexact束縛する。"""

    try:
        report = analysis_lifecycle._load_json(
            context.orchestration_root / "report.json",
            maximum_bytes=MAX_STATE_BYTES,
        )
    except analysis_lifecycle.LifecycleError as exc:
        raise OrchestrationError("completed_workflow_changed", "保存済みorchestration reportがありません") from exc
    if report != _public_report_from_state(context, state):
        raise OrchestrationError("completed_workflow_changed", "保存済みorchestration reportとstateが一致しません")


def _mark_foreign_unstarted_workflow(
    context: OrchestrationContext,
    state: dict[str, Any],
    *,
    start: int,
) -> bool:
    """未開始recordに外部lifecycleがあればfail-closedで記録する。"""

    found = False
    for record, request in zip(
        state["workflows"][start:],
        context.request.workflows[start:],
        strict=True,
    ):
        lifecycle_root = context.work_root / "lifecycles" / request.workflow_id
        if record["status"] not in {"pending", "deferred"} or not lifecycle_root.exists():
            continue
        now = analysis_lifecycle.utc_now()
        record.update(
            {
                "status": "failed",
                "attempts": max(1, record["attempts"]),
                "started_at_utc": now,
                "finished_at_utc": now,
                "blockers": ["unexpected_lifecycle_state"],
                "lifecycle_report_sha256": None,
                "result": {
                    "error": {
                        "code": "unexpected_lifecycle_state",
                        "message": "未開始workflowに既存lifecycle stateがあります",
                    }
                },
            }
        )
        found = True
    if found:
        _mark_deferred(state, start)
    return found


def _execute(
    context: OrchestrationContext,
    state: dict[str, Any],
    actions: _LifecycleActions,
) -> dict[str, Any]:
    terminal_records = [
        record
        for record in state["workflows"]
        if record["status"] == "complete"
        or (
            record["status"] == "partial"
            and record["result"].get("same_workflow_resume_allowed") is False
        )
    ]
    if terminal_records:
        _verify_saved_parent_report(context, state)
    for record in terminal_records:
        _verify_completed_record(context, record, actions)
    state["status"] = "running"
    _write_state(context, state)
    for index, (record, request) in enumerate(
        zip(state["workflows"], context.request.workflows, strict=True)
    ):
        if record["status"] == "complete":
            continue
        if record["status"] == "partial" and record["result"].get("same_workflow_resume_allowed") is False:
            if not context.request.policy["continue_after_partial"]:
                if _mark_foreign_unstarted_workflow(context, state, start=index + 1):
                    _write_state(context, state)
                    return _finalize(context, state)
                _mark_deferred(state, index + 1)
                _write_state(context, state)
                break
            continue
        if record["attempts"] >= MAX_ATTEMPTS:
            record.update(
                {
                    "status": "failed",
                    "finished_at_utc": analysis_lifecycle.utc_now(),
                    "blockers": ["maximum_workflow_attempts_exceeded"],
                    "result": {"error": "maximum_workflow_attempts_exceeded"},
                }
            )
            _write_state(context, state)
            if not context.request.policy["continue_after_failure"]:
                _mark_deferred(state, index + 1)
                break
            continue
        previous_status = record["status"]
        previous_blockers = tuple(record["blockers"])
        record.update(
            {
                "status": "running",
                "attempts": record["attempts"] + 1,
                "started_at_utc": analysis_lifecycle.utc_now(),
                "finished_at_utc": None,
                "lifecycle_report_sha256": None,
                "blockers": [],
                "result": {},
            }
        )
        _write_state(context, state)
        lifecycle_root = context.work_root / "lifecycles" / request.workflow_id
        try:
            if lifecycle_root.exists() and (
                previous_status in {"pending", "deferred"}
                or "unexpected_lifecycle_state" in previous_blockers
            ):
                raise OrchestrationError(
                    "unexpected_lifecycle_state",
                    "未開始workflowに既存lifecycle stateがあります",
                )
            if lifecycle_root.exists():
                child_state = actions.resume(request.workflow_id, **_lifecycle_kwargs(context))
            else:
                child_state = actions.run(request, **_lifecycle_kwargs(context))
            status = child_state.get("status")
            if status not in {"complete", "partial", "failed"}:
                raise OrchestrationError("lifecycle_state_invalid", "child lifecycle statusが不正です")
            if status in {"complete", "partial"}:
                values = _terminal_record_values(context, request.workflow_id, actions)
                returned_state_sha256 = analysis_lifecycle._sha256_value(child_state)
                if (
                    values["status"] != status
                    or values["attempts"] != record["attempts"]
                    or values["result"]["lifecycle_state_sha256"] != returned_state_sha256
                ):
                    raise OrchestrationError(
                        "lifecycle_snapshot_invalid",
                        "返却child stateと保存snapshotが一致しません",
                    )
                record.update(values)
                record["finished_at_utc"] = analysis_lifecycle.utc_now()
            else:
                report_path = _lifecycle_report_path(context, request.workflow_id)
                if not report_path.is_file():
                    raise OrchestrationError("lifecycle_report_missing", "child lifecycle reportがありません")
                record.update(
                    {
                        "status": status,
                        "finished_at_utc": analysis_lifecycle.utc_now(),
                        "blockers": _record_blockers(child_state),
                        "lifecycle_report_sha256": analysis_lifecycle._sha256_file(report_path),
                        "result": _record_result(child_state),
                    }
                )
        except Exception as exc:  # noqa: BLE001 - child lifecycle境界で公開errorへ正規化する
            code = getattr(exc, "code", "workflow_execution_failed")
            if not isinstance(code, str) or analysis_lifecycle.BLOCKER_RE.fullmatch(code) is None:
                code = "workflow_execution_failed"
            record.update(
                {
                    "status": "failed",
                    "finished_at_utc": analysis_lifecycle.utc_now(),
                    "blockers": [code],
                    "result": {
                        "error": {
                            "code": code,
                            "message": f"workflowを安全に完了できませんでした ({type(exc).__name__})",
                        }
                    },
                }
            )
        _write_state(context, state)
        stop_for_partial = record["status"] == "partial" and not context.request.policy["continue_after_partial"]
        stop_for_failure = record["status"] == "failed" and not context.request.policy["continue_after_failure"]
        if stop_for_partial or stop_for_failure:
            _mark_deferred(state, index + 1)
            _write_state(context, state)
            break
    return _finalize(context, state)


PRODUCTION_ACTIONS = _LifecycleActions(
    run=analysis_lifecycle.run_lifecycle,
    resume=analysis_lifecycle.resume_lifecycle,
    verify=analysis_lifecycle.verify_lifecycle,
    snapshot=_production_lifecycle_snapshot,
)


def _initialize_context(
    request: OrchestrationRequest,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
) -> tuple[OrchestrationContext, dict[str, Any]]:
    context = _validate_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
        create=True,
    )
    collisions = [
        item.workflow_id
        for item in request.workflows
        if (context.work_root / "lifecycles" / item.workflow_id).exists()
    ]
    if collisions:
        raise OrchestrationError(
            "workflow_already_exists",
            f"新規runと衝突するworkflowがあります: {collisions[0]}",
        )
    try:
        context.orchestration_root.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise OrchestrationError(
            "orchestration_already_exists",
            "同じorchestration_idはrunで再利用できません",
        ) from exc
    analysis_lifecycle._atomic_json(context.orchestration_root / "request.json", request.public())
    state = _new_state(context)
    _write_state(context, state)
    return context, state


def run_orchestration(
    request: OrchestrationRequest,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int = analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """production lifecycleだけで新規一括解析を直列実行する。"""

    context, state = _initialize_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    with analysis_lifecycle._execution_lock(context.orchestration_root):
        return _execute(context, state, PRODUCTION_ACTIONS)


def _run_orchestration_for_test(
    request: OrchestrationRequest,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
    actions: _LifecycleActions,
) -> dict[str, Any]:
    """production APIへ注入点を公開しないunit test専用入口。"""

    context, state = _initialize_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    with analysis_lifecycle._execution_lock(context.orchestration_root):
        return _execute(context, state, actions)


def _existing_context(
    orchestration_id: str,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int,
) -> tuple[OrchestrationContext, dict[str, Any]]:
    if analysis_lifecycle.WORKFLOW_ID_RE.fullmatch(orchestration_id) is None:
        raise OrchestrationError("orchestration_id_invalid", "orchestration_idの形式が不正です")
    root = Path(os.path.abspath(os.fspath(work_root))) / "orchestrations" / orchestration_id
    request = load_request(root / "request.json")
    if request.orchestration_id != orchestration_id:
        raise OrchestrationError("state_invalid", "保存requestのorchestration_idが一致しません")
    context = _validate_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
        create=False,
    )
    return context, _load_state(context.orchestration_root, request)


def resume_orchestration(
    orchestration_id: str,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int = analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """保存requestを再検証し、complete以外のworkflowだけを再開する。"""

    existing, _ = _existing_context(
        orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    with analysis_lifecycle._execution_lock(existing.orchestration_root):
        context, state = _existing_context(
            orchestration_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=timeout_seconds,
        )
        return _execute(context, state, PRODUCTION_ACTIONS)


def _verification_errors(
    context: OrchestrationContext,
    state: Mapping[str, Any],
    actions: _LifecycleActions,
) -> list[str]:
    errors: list[str] = []
    for record in state["workflows"]:
        lifecycle_root = context.work_root / "lifecycles" / record["workflow_id"]
        if record["status"] in {"pending", "deferred"}:
            if lifecycle_root.exists():
                errors.append(f"unexpected_lifecycle:{record['workflow_id']}")
            continue
        if not lifecycle_root.is_dir():
            errors.append(f"lifecycle_missing:{record['workflow_id']}")
            continue
        if record["status"] in {"complete", "partial"}:
            mismatch = _terminal_record_mismatch(context, record, actions)
            if mismatch is not None:
                errors.append(f"{mismatch}:{record['workflow_id']}")
            continue
        try:
            verification = actions.verify(record["workflow_id"], **_lifecycle_kwargs(context))
            if verification.get("valid") is not True:
                errors.append(f"lifecycle_invalid:{record['workflow_id']}")
            report_path = _lifecycle_report_path(context, record["workflow_id"])
            if (
                not report_path.is_file()
                or analysis_lifecycle._sha256_file(report_path) != record.get("lifecycle_report_sha256")
            ):
                errors.append(f"lifecycle_report_mismatch:{record['workflow_id']}")
        except Exception:  # noqa: BLE001 - read-only child検証境界でerrorを正規化する
            errors.append(f"lifecycle_verification_failed:{record['workflow_id']}")
    try:
        report = analysis_lifecycle._load_json(
            context.orchestration_root / "report.json",
            maximum_bytes=MAX_STATE_BYTES,
        )
        if report != _public_report_from_state(context, state):
            errors.append("orchestration_report_state_mismatch")
    except analysis_lifecycle.LifecycleError:
        errors.append("orchestration_report_missing")
    return sorted(set(errors))


def verify_orchestration(
    orchestration_id: str,
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    timeout_seconds: int = analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """一括state、child lifecycle、report hashをread-onlyで再検証する。"""

    context, state = _existing_context(
        orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=timeout_seconds,
    )
    errors = _verification_errors(context, state, PRODUCTION_ACTIONS)
    return {
        "schema_version": SCHEMA_VERSION,
        "orchestration_id": orchestration_id,
        "valid": not errors,
        "errors": errors,
        "request_sha256": state["request_sha256"],
        "workflow_status": {
            record["workflow_id"]: record["status"] for record in state["workflows"]
        },
        "sample_executed": False,
        "analysis_network_contacted": False,
    }


def read_status(work_root: Path, orchestration_id: str) -> dict[str, Any]:
    """保存済みstateと一致する公開reportだけを返す。"""

    if analysis_lifecycle.WORKFLOW_ID_RE.fullmatch(orchestration_id) is None:
        raise OrchestrationError("orchestration_id_invalid", "orchestration_idの形式が不正です")
    root = Path(os.path.abspath(os.fspath(work_root))) / "orchestrations" / orchestration_id
    analysis_lifecycle._reject_existing_reparse_components(root, label="orchestration state")
    request = load_request(root / "request.json")
    state = _load_state(root, request)
    report = analysis_lifecycle._load_json(root / "report.json", maximum_bytes=MAX_STATE_BYTES)
    if report != _public_report_from_state(
        OrchestrationContext(Path(), Path(), Path(), root, request, 1),
        state,
    ):
        raise OrchestrationError("orchestration_report_state_mismatch", "reportとstateが一致しません")
    return report


class JapaneseArgumentParser(argparse.ArgumentParser):
    """argparseの固定見出しを日本語へ置換する。"""

    def format_help(self) -> str:
        return (
            super()
            .format_help()
            .replace("usage:", "使用法:")
            .replace("options:", "オプション:")
            .replace("positional arguments:", "サブコマンド:")
            .replace("show this help message and exit", "このhelpを表示して終了します")
        )


def _add_roots(parser: argparse.ArgumentParser, *, request: bool) -> None:
    if request:
        parser.add_argument("--request", required=True, type=Path, help="UTF-8 orchestration request JSON")
    else:
        parser.add_argument("--orchestration-id", required=True, help="保存済みorchestration ID")
    parser.add_argument("--repository", required=True, type=Path, help="解析repository root")
    parser.add_argument("--input-root", required=True, type=Path, help="検体を置くrepository外root")
    parser.add_argument("--work-root", required=True, type=Path, help="jobとstateを置くrepository外root")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
        help="各静的解析jobの時間上限",
    )


def build_parser() -> argparse.ArgumentParser:
    """固定subcommandだけを持つCLI parserを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("schema", help="固定一括request JSON Schemaを出力します")
    plan = commands.add_parser("plan", help="副作用なしで直列planと安全境界を確認します")
    _add_roots(plan, request=True)
    run = commands.add_parser("run", help="新規一括解析を直列実行します")
    _add_roots(run, request=True)
    resume = commands.add_parser("resume", help="未完workflowだけを順番に再開します")
    _add_roots(resume, request=False)
    verify = commands.add_parser("verify", help="保存済み成果物をread-onlyで一括検証します")
    _add_roots(verify, request=False)
    status = commands.add_parser("status", help="公開可能な一括reportを読みます")
    status.add_argument("--work-root", required=True, type=Path)
    status.add_argument("--orchestration-id", required=True)
    return parser


def _print_json(value: Any, *, stream: Any | None = None) -> None:
    print(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False),
        file=sys.stdout if stream is None else stream,
    )


def _exit_code(status: str) -> int:
    return 0 if status == "complete" else 20 if status == "partial" else 1


def main(argv: list[str] | None = None) -> int:
    """CLIを実行し、JSON結果と状態別終了codeを返す。"""

    args = build_parser().parse_args(argv)
    try:
        if args.command == "schema":
            _print_json(request_json_schema())
            return 0
        if args.command == "status":
            _print_json(read_status(args.work_root, args.orchestration_id))
            return 0
        if args.command == "plan":
            request = load_request(args.request)
            _validate_context(
                request,
                repository=args.repository,
                input_root=args.input_root,
                work_root=args.work_root,
                timeout_seconds=args.timeout_seconds,
                create=False,
            )
            _print_json(build_plan(request))
            return 0
        if args.command == "run":
            state = run_orchestration(
                load_request(args.request),
                repository=args.repository,
                input_root=args.input_root,
                work_root=args.work_root,
                timeout_seconds=args.timeout_seconds,
            )
            _print_json(read_status(args.work_root, state["orchestration_id"]))
            return _exit_code(state["status"])
        if args.command == "resume":
            state = resume_orchestration(
                args.orchestration_id,
                repository=args.repository,
                input_root=args.input_root,
                work_root=args.work_root,
                timeout_seconds=args.timeout_seconds,
            )
            _print_json(read_status(args.work_root, state["orchestration_id"]))
            return _exit_code(state["status"])
        result = verify_orchestration(
            args.orchestration_id,
            repository=args.repository,
            input_root=args.input_root,
            work_root=args.work_root,
            timeout_seconds=args.timeout_seconds,
        )
        _print_json(result)
        return 0 if result["valid"] else 1
    except (OrchestrationError, analysis_lifecycle.LifecycleError) as exc:
        code = getattr(exc, "code", "orchestration_failed")
        _print_json(
            {"schema_version": SCHEMA_VERSION, "error": {"code": code, "message": str(exc)}},
            stream=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
