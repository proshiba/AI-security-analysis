#!/usr/bin/env python3
"""保存済み解析stateから、副作用のない決定的な再開計画を構築する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import analysis_job_runner
import analysis_lifecycle
import analysis_orchestrator

SCHEMA_VERSION = 1
MAX_SNAPSHOT_FILES = analysis_orchestrator.MAX_WORKFLOWS * 4 + 32
MAX_TOTAL_SNAPSHOT_BYTES = 64 * 1024 * 1024
SNAPSHOT_HASH_CHUNK_BYTES = 64 * 1024
MAX_CODE_SOURCE_BYTES = 8 * 1024 * 1024
MAX_ANCHORED_INPUT_BYTES = analysis_job_runner.MAX_SUMMARY_BYTES
_FAMILY_SUFFIX_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")


class ResumePlannerError(RuntimeError):
    """公開可能な固定error codeを持つplanner例外。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _FileSnapshot:
    """単一handleで読んだ通常fileのraw bytes commitment。"""

    path: Path
    maximum_bytes: int
    sha256: str
    identity: os.stat_result
    size: int


@dataclass(frozen=True)
class _Snapshot(_FileSnapshot):
    """strict JSON documentを含むfile snapshot。"""

    document: dict[str, Any]


class _SnapshotReader:
    """複数fileを件数・合計bytesとも有界に読み、置換も検出する。"""

    def __init__(
        self,
        *,
        maximum_files: int = MAX_SNAPSHOT_FILES,
        maximum_total_bytes: int = MAX_TOTAL_SNAPSHOT_BYTES,
    ) -> None:
        if (
            isinstance(maximum_files, bool)
            or not isinstance(maximum_files, int)
            or maximum_files <= 0
            or isinstance(maximum_total_bytes, bool)
            or not isinstance(maximum_total_bytes, int)
            or maximum_total_bytes <= 0
        ):
            raise ResumePlannerError("snapshot_contract_invalid", "snapshot上限が不正です")
        self._maximum_files = maximum_files
        self._maximum_total_bytes = maximum_total_bytes
        self._total_bytes = 0
        self._snapshots: dict[Path, _FileSnapshot] = {}

    @staticmethod
    def _read_committed_file(path: Path, *, maximum_bytes: int) -> tuple[bytes, os.stat_result]:
        """単一handle読込をpath identityとsizeの外側commitmentで挟む。"""

        before = path.lstat()
        raw = analysis_job_runner._read_regular_file_once(
            path,
            max_bytes=maximum_bytes,
        )
        after = path.lstat()
        if (
            not analysis_job_runner._same_file_identity(before, after)
            or before.st_size != after.st_size
            or after.st_size != len(raw)
        ):
            raise analysis_job_runner.JobContractError(
                "snapshot_changed_during_read",
                "source fileがsnapshot中に変更されました",
            )
        return raw, after

    def _new_snapshot_read_limit(
        self,
        path: Path,
        *,
        maximum_bytes: int,
        label: str,
    ) -> int:
        if len(self._snapshots) >= self._maximum_files:
            raise ResumePlannerError("snapshot_count_exceeded", "検証対象file件数が上限を超えています")
        try:
            size = path.lstat().st_size
        except OSError as exc:
            raise ResumePlannerError(f"{label}_invalid", f"{label}を安全に読み取れません") from exc
        remaining = self._maximum_total_bytes - self._total_bytes
        if size > remaining:
            raise ResumePlannerError(
                "snapshot_total_bytes_exceeded",
                "検証対象fileの合計sizeが上限を超えています",
            )
        return min(maximum_bytes, remaining)

    def _commit(self, snapshot: _FileSnapshot) -> None:
        remaining = self._maximum_total_bytes - self._total_bytes
        if snapshot.size > remaining:
            raise ResumePlannerError(
                "snapshot_total_bytes_exceeded",
                "検証対象fileの合計sizeが上限を超えています",
            )
        self._snapshots[snapshot.path] = snapshot
        self._total_bytes += snapshot.size

    def read(self, path: Path, *, maximum_bytes: int, label: str) -> _Snapshot:
        resolved = Path(os.path.abspath(os.fspath(path)))
        existing = self._snapshots.get(resolved)
        if existing is not None:
            if existing.maximum_bytes != maximum_bytes or not isinstance(existing, _Snapshot):
                raise ResumePlannerError("snapshot_contract_invalid", "JSON読込上限が一致しません")
            return existing
        read_limit = self._new_snapshot_read_limit(
            resolved,
            maximum_bytes=maximum_bytes,
            label=label,
        )
        try:
            raw, identity = self._read_committed_file(
                resolved,
                maximum_bytes=read_limit,
            )
            document = analysis_job_runner._decode_json_object_strict(raw)
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise ResumePlannerError(f"{label}_invalid", f"{label}を安全に読み取れません") from exc
        snapshot = _Snapshot(
            path=resolved,
            maximum_bytes=maximum_bytes,
            sha256=hashlib.sha256(raw).hexdigest(),
            document=document,
            identity=identity,
            size=len(raw),
        )
        self._commit(snapshot)
        return snapshot

    def read_file(self, path: Path, *, maximum_bytes: int, label: str) -> _FileSnapshot:
        """通常fileを単一handle・固定上限で読み、raw bytesを固定する。"""

        resolved = Path(os.path.abspath(os.fspath(path)))
        existing = self._snapshots.get(resolved)
        if existing is not None:
            if existing.maximum_bytes != maximum_bytes:
                raise ResumePlannerError("snapshot_contract_invalid", "file読込上限が一致しません")
            return existing
        read_limit = self._new_snapshot_read_limit(
            resolved,
            maximum_bytes=maximum_bytes,
            label=label,
        )
        try:
            raw, identity = self._read_committed_file(
                resolved,
                maximum_bytes=read_limit,
            )
        except (analysis_job_runner.JobContractError, OSError) as exc:
            raise ResumePlannerError(f"{label}_invalid", f"{label}を安全に読み取れません") from exc
        snapshot = _FileSnapshot(
            path=resolved,
            maximum_bytes=maximum_bytes,
            sha256=hashlib.sha256(raw).hexdigest(),
            identity=identity,
            size=len(raw),
        )
        self._commit(snapshot)
        return snapshot

    @staticmethod
    def _hash_committed_file(snapshot: _FileSnapshot) -> tuple[str, os.stat_result, int]:
        """再検証時はraw全体を保持せず、固定chunkでhashとidentityを再照合する。"""

        analysis_job_runner._ensure_no_reparse(
            snapshot.path,
            code="snapshot_changed_during_plan",
            message="source fileのpathが変更されました",
        )
        before = snapshot.path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or analysis_job_runner._stat_has_reparse_attribute(before)
            or before.st_nlink != 1
            or before.st_size != snapshot.size
        ):
            raise analysis_job_runner.JobContractError(
                "snapshot_changed_during_plan",
                "source fileが変更されました",
            )
        flags = os.O_RDONLY | int(getattr(os, "O_BINARY", 0)) | int(getattr(os, "O_CLOEXEC", 0))
        flags |= int(getattr(os, "O_NOINHERIT", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
        descriptor = os.open(snapshot.path, flags)
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or analysis_job_runner._stat_has_reparse_attribute(opened)
                or opened.st_nlink != 1
                or not analysis_job_runner._same_file_identity(before, opened)
            ):
                raise analysis_job_runner.JobContractError(
                    "snapshot_changed_during_plan",
                    "source fileが変更されました",
                )
            while chunk := handle.read(SNAPSHOT_HASH_CHUNK_BYTES):
                total += len(chunk)
                if total > snapshot.size:
                    raise analysis_job_runner.JobContractError(
                        "snapshot_changed_during_plan",
                        "source fileのsizeが変更されました",
                    )
                digest.update(chunk)
            after_handle = os.fstat(handle.fileno())
        after_path = snapshot.path.lstat()
        if (
            total != snapshot.size
            or opened.st_size != total
            or after_handle.st_size != total
            or before.st_mtime_ns != after_path.st_mtime_ns
            or opened.st_mtime_ns != after_handle.st_mtime_ns
            or before.st_ctime_ns != after_path.st_ctime_ns
            or opened.st_ctime_ns != after_handle.st_ctime_ns
            or not analysis_job_runner._same_file_identity(opened, after_path)
            or after_path.st_nlink != 1
            or analysis_job_runner._stat_has_reparse_attribute(after_path)
        ):
            raise analysis_job_runner.JobContractError(
                "snapshot_changed_during_plan",
                "source fileが変更されました",
            )
        return digest.hexdigest(), after_path, total

    def verify_unchanged(self) -> None:
        """計画構築中にsource snapshotが変わっていないことを再確認する。"""

        for snapshot in self._snapshots.values():
            try:
                digest, identity, size = self._hash_committed_file(snapshot)
            except (analysis_job_runner.JobContractError, OSError) as exc:
                raise ResumePlannerError(
                    "snapshot_changed_during_plan",
                    "計画構築中にsource fileが変更されました",
                ) from exc
            if (
                not analysis_job_runner._same_file_identity(snapshot.identity, identity)
                or size != snapshot.size
                or digest != snapshot.sha256
            ):
                raise ResumePlannerError(
                    "snapshot_changed_during_plan",
                    "計画構築中にsource fileが変更されました",
                )


@dataclass(frozen=True)
class _BlockerPolicy:
    """blockerから安全な次動作へ変換する固定policy。"""

    action_id: str
    target_phase: str | None
    retryable: bool
    priority: int
    changed_evidence: tuple[str, ...]


_EXACT_BLOCKER_POLICIES: Mapping[str, _BlockerPolicy] = {
    "analysis_partial": _BlockerPolicy(
        "reanalyze_static_pipeline",
        "static_analysis",
        False,
        30,
        ("analysis_contract_sha256", "static_analysis_evidence_sha256"),
    ),
    "generic_triage_failed": _BlockerPolicy(
        "repair_generic_triage",
        "static_analysis",
        False,
        30,
        ("analysis_contract_sha256", "generic_triage_evidence_sha256"),
    ),
    "generic_triage_partial": _BlockerPolicy(
        "repair_generic_triage",
        "static_analysis",
        False,
        30,
        ("analysis_contract_sha256", "generic_triage_evidence_sha256"),
    ),
    "static_layer_limit_reached": _BlockerPolicy(
        "expand_static_layer_budget",
        "static_analysis",
        False,
        31,
        ("analysis_contract_sha256", "static_layer_budget"),
    ),
    "static_layer_incomplete": _BlockerPolicy(
        "repair_static_layer_pipeline",
        "static_analysis",
        False,
        32,
        ("analysis_contract_sha256", "static_layer_evidence_sha256"),
    ),
    "detector_error_present": _BlockerPolicy(
        "repair_family_detector",
        "static_analysis",
        False,
        40,
        ("detector_fingerprint_sha256", "classification_evidence_sha256"),
    ),
    "handler_failed": _BlockerPolicy(
        "repair_family_handler",
        "static_analysis",
        False,
        41,
        ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
    ),
    "handler_preflight_failed": _BlockerPolicy(
        "repair_handler_preflight",
        "static_analysis",
        False,
        41,
        ("handler_dependency_fingerprint_sha256",),
    ),
    "handler_no_evidence": _BlockerPolicy(
        "strengthen_family_handler_evidence",
        "static_analysis",
        False,
        42,
        ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
    ),
    "handler_ambiguous_evidence": _BlockerPolicy(
        "resolve_handler_evidence_ambiguity",
        "static_analysis",
        False,
        42,
        ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
    ),
    "handler_incompatible_input_format": _BlockerPolicy(
        "add_handler_input_support",
        "static_analysis",
        False,
        43,
        ("handler_dependency_fingerprint_sha256", "selected_layer_sha256"),
    ),
    "selected_family_layer_incomplete": _BlockerPolicy(
        "repair_selected_family_layer_analysis",
        "static_analysis",
        False,
        43,
        ("handler_dependency_fingerprint_sha256", "selected_layer_sha256"),
    ),
    "representative_function_analysis_required": _BlockerPolicy(
        "perform_representative_function_static_review",
        "function_validation",
        False,
        70,
        ("function_analysis_evidence_sha256",),
    ),
    "terminal_payload_not_recovered": _BlockerPolicy(
        "recover_terminal_payload_statically",
        "static_analysis",
        False,
        50,
        ("terminal_payload_evidence_sha256",),
    ),
    "root_to_terminal_byte_derivation_incomplete": _BlockerPolicy(
        "recover_terminal_payload_statically",
        "static_analysis",
        False,
        50,
        ("terminal_payload_evidence_sha256", "root_to_terminal_lineage_sha256"),
    ),
    "required_terminal_bytes_absent": _BlockerPolicy(
        "recover_terminal_payload_statically",
        "static_analysis",
        False,
        50,
        ("terminal_payload_evidence_sha256",),
    ),
    "c2_protocol_confirmation_pending": _BlockerPolicy(
        "confirm_c2_protocol_statically",
        "static_analysis",
        False,
        60,
        ("network_configuration_evidence_sha256", "protocol_evidence_sha256"),
    ),
    "orchestration:config": _BlockerPolicy(
        "recover_configuration_statically",
        "static_analysis",
        False,
        60,
        ("configuration_evidence_sha256",),
    ),
    "orchestration:network": _BlockerPolicy(
        "recover_network_configuration_statically",
        "static_analysis",
        False,
        61,
        ("network_configuration_evidence_sha256",),
    ),
    "orchestration:terminal_payload": _BlockerPolicy(
        "recover_terminal_payload_statically",
        "static_analysis",
        False,
        50,
        ("terminal_payload_evidence_sha256",),
    ),
    "orchestration:function_analysis": _BlockerPolicy(
        "perform_representative_function_static_review",
        "function_validation",
        False,
        70,
        ("function_analysis_evidence_sha256",),
    ),
    "orchestration:static_layers": _BlockerPolicy(
        "repair_static_layer_pipeline",
        "static_analysis",
        False,
        32,
        ("analysis_contract_sha256", "static_layer_evidence_sha256"),
    ),
    "orchestration:family_resolution": _BlockerPolicy(
        "strengthen_family_resolution",
        "static_analysis",
        False,
        40,
        ("detector_fingerprint_sha256", "classification_evidence_sha256"),
    ),
    "orchestration:handler_evidence": _BlockerPolicy(
        "strengthen_family_handler_evidence",
        "static_analysis",
        False,
        42,
        ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
    ),
    "requirements_policy": _BlockerPolicy(
        "declare_family_analysis_requirements",
        "completion_gate",
        False,
        65,
        ("family_requirements_policy_sha256",),
    ),
    "publication_requires_complete_or_partial_staging_opt_in": _BlockerPolicy(
        "review_partial_publication_policy",
        "publication",
        False,
        80,
        ("publication_policy_sha256",),
    ),
    "function_validation_incomplete": _BlockerPolicy(
        "perform_representative_function_static_review",
        "function_validation",
        False,
        70,
        ("function_analysis_evidence_sha256",),
    ),
    "publication_incomplete": _BlockerPolicy(
        "repair_publication",
        "publication",
        False,
        80,
        ("publication_evidence_sha256",),
    ),
    "static_analysis_failed": _BlockerPolicy(
        "resume_workflow",
        "static_analysis",
        True,
        10,
        (),
    ),
    "preflight_failed": _BlockerPolicy(
        "resume_workflow",
        "preflight",
        True,
        10,
        (),
    ),
    "publication_failed": _BlockerPolicy(
        "resume_workflow",
        "publication",
        True,
        10,
        (),
    ),
    "function_validation_failed": _BlockerPolicy(
        "resume_workflow",
        "function_validation",
        True,
        10,
        (),
    ),
    "completion_gate_failed": _BlockerPolicy(
        "resume_workflow",
        "completion_gate",
        True,
        10,
        (),
    ),
    "derived_refresh_failed": _BlockerPolicy(
        "resume_workflow",
        "derived_refresh",
        True,
        10,
        (),
    ),
    "private_archive_failed": _BlockerPolicy(
        "resume_workflow",
        "private_archive",
        True,
        10,
        (),
    ),
    "workflow_execution_failed": _BlockerPolicy(
        "resume_workflow",
        None,
        True,
        10,
        (),
    ),
    "stage_contract_changed": _BlockerPolicy(
        "start_successor_workflow",
        None,
        False,
        5,
        ("new_workflow_id", "updated_request_sha256"),
    ),
    "unexpected_lifecycle_state": _BlockerPolicy(
        "repair_lifecycle_state",
        None,
        False,
        5,
        ("lifecycle_state_integrity_sha256",),
    ),
    "lifecycle_state_invalid": _BlockerPolicy(
        "repair_lifecycle_state",
        None,
        False,
        5,
        ("lifecycle_state_integrity_sha256",),
    ),
    "analysis_blocked": _BlockerPolicy(
        "manual_review_required",
        None,
        False,
        0,
        ("operator_review",),
    ),
}

_PREFIX_BLOCKER_POLICIES: tuple[tuple[str, _BlockerPolicy], ...] = (
    (
        "selected_family_has_no_automatic_handler:",
        _BlockerPolicy(
            "implement_family_handler",
            "static_analysis",
            False,
            40,
            ("handler_dependency_fingerprint_sha256",),
        ),
    ),
    (
        "selected_family_has_no_valid_handler_evidence:",
        _BlockerPolicy(
            "strengthen_family_handler_evidence",
            "static_analysis",
            False,
            41,
            ("handler_dependency_fingerprint_sha256", "handler_evidence_sha256"),
        ),
    ),
)

# lifecycleのremediation registryをplannerの実stageへ変換する。blocker自体の
# 分類は共通registryだけを正とし、この表は抽象phaseから保存stateのstageへの
# 明示的な変換と優先度だけを担う。未知のaction keyはmanualへfail-closedする。
_LIFECYCLE_POLICY_TRANSLATIONS: Mapping[str, tuple[str, str | None, int]] = {
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

_BUDGET_BLOCKERS = frozenset(
    {
        "maximum_workflow_attempts_exceeded",
        "maximum_stage_attempts_exceeded",
    }
)

# downstream stageのskip理由であり、再開根拠として単独利用できない。
_DERIVED_BLOCKERS = frozenset({"dependency_not_succeeded"})


def _canonical_sha256(value: Any) -> str:
    return analysis_lifecycle._sha256_value(value)


def _valid_timestamp(value: Any) -> bool:
    return value is None or (isinstance(value, str) and 1 <= len(value) <= 64)


def _failure_code(record: Mapping[str, Any]) -> str | None:
    """runnerが生成した固定failure envelopeから安全なcodeだけを返す。"""

    result = record.get("result")
    error = result.get("error") if isinstance(result, Mapping) else None
    if (
        record.get("status") != "failed"
        or not isinstance(error, dict)
        or set(error) != {"code", "message"}
        or not isinstance(error.get("code"), str)
        or analysis_lifecycle.BLOCKER_RE.fullmatch(error["code"]) is None
        or not isinstance(error.get("message"), str)
        or not 1 <= len(error["message"]) <= 512
    ):
        return None
    return error["code"]


def _validate_orchestration_state(
    state: dict[str, Any],
    request: analysis_orchestrator.OrchestrationRequest,
) -> None:
    """fingerprintの新旧比較を除き、保存stateをcoreと同じ固定契約で検証する。"""

    required = {
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
    }
    if set(state) != required or state.get("schema_version") != analysis_orchestrator.SCHEMA_VERSION:
        raise ResumePlannerError("orchestration_state_invalid", "orchestration state schemaが不正です")
    if (
        state.get("orchestration_id") != request.orchestration_id
        or state.get("request_sha256") != _canonical_sha256(request.public())
        or state.get("policy") != dict(request.policy)
        or state.get("status") not in {"complete", "partial", "failed"}
        or not _valid_timestamp(state.get("created_at_utc"))
        or not _valid_timestamp(state.get("updated_at_utc"))
        or state.get("safety") != analysis_orchestrator.build_plan(request)["safety"]
    ):
        raise ResumePlannerError("orchestration_state_invalid", "orchestration state fieldが不正です")
    implementation = state.get("implementation_sha256")
    if not isinstance(implementation, str) or analysis_lifecycle.SHA256_RE.fullmatch(implementation) is None:
        raise ResumePlannerError("orchestration_state_invalid", "implementation commitmentが不正です")
    records = state.get("workflows")
    if not isinstance(records, list) or len(records) != len(request.workflows):
        raise ResumePlannerError("orchestration_state_invalid", "workflow state件数が一致しません")
    for index, (record, child) in enumerate(zip(records, request.workflows, strict=True)):
        attempts = record.get("attempts") if isinstance(record, dict) else None
        blockers = record.get("blockers") if isinstance(record, dict) else None
        report_sha256 = record.get("lifecycle_report_sha256") if isinstance(record, dict) else None
        if (
            not isinstance(record, dict)
            or set(record) != analysis_orchestrator.RECORD_KEYS
            or record.get("index") != index
            or record.get("workflow_id") != child.workflow_id
            or record.get("job_id") != child.job.job_id
            or record.get("request_sha256") != _canonical_sha256(child.public())
            or record.get("status") not in analysis_orchestrator.RECORD_STATUSES
            or isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 0 <= attempts <= analysis_orchestrator.MAX_ATTEMPTS
            or not _valid_timestamp(record.get("started_at_utc"))
            or not _valid_timestamp(record.get("finished_at_utc"))
            or not isinstance(blockers, list)
            or blockers != analysis_lifecycle._bounded_blockers(blockers)
            or not isinstance(record.get("result"), dict)
            or (
                report_sha256 is not None
                and (
                    not isinstance(report_sha256, str) or analysis_lifecycle.SHA256_RE.fullmatch(report_sha256) is None
                )
            )
            or not analysis_orchestrator._record_semantics_valid(record)
        ):
            raise ResumePlannerError(
                "orchestration_state_invalid",
                f"workflow state[{index}]が不正です",
            )
    statuses = [record["status"] for record in records]
    overall = state["status"]
    invalid = (
        (overall == "complete" and any(status != "complete" for status in statuses))
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
    if invalid:
        raise ResumePlannerError("orchestration_state_invalid", "全体statusとworkflow stateが一致しません")


def _current_stage_fingerprint(
    reader: _SnapshotReader,
    context: analysis_lifecycle.LifecycleContext,
    stage: str,
) -> str:
    """current stage実装とanchored inputをtracked snapshotからfingerprint化する。"""

    common = Path(analysis_lifecycle.__file__).resolve().parent
    source_hashes = {
        name: reader.read_file(
            common / name,
            maximum_bytes=MAX_CODE_SOURCE_BYTES,
            label="stage_source",
        ).sha256
        for name in analysis_lifecycle.STAGE_CODE_FILES[stage]
    }
    anchored_inputs: dict[str, str] = {}
    if stage == "publication" and context.request.publication["enabled"]:
        relative = context.request.publication["manifest"]
        try:
            manifest = analysis_lifecycle._resolve_repository_file(context.repository, relative)
        except analysis_lifecycle.LifecycleError as exc:
            raise ResumePlannerError(
                "stage_anchored_input_invalid",
                "publication manifestを安全に固定できません",
            ) from exc
        anchored_inputs[relative] = reader.read_file(
            manifest,
            maximum_bytes=MAX_ANCHORED_INPUT_BYTES,
            label="stage_anchored_input",
        ).sha256
    return _canonical_sha256(
        {
            "schema_version": analysis_lifecycle.SCHEMA_VERSION,
            "stage": stage,
            "request_sha256": _canonical_sha256(context.request.public()),
            "source_sha256": source_hashes,
            "anchored_input_sha256": anchored_inputs,
        }
    )


def _validate_lifecycle_state(
    reader: _SnapshotReader,
    context: analysis_lifecycle.LifecycleContext,
    state: dict[str, Any],
) -> list[dict[str, Any]]:
    """保存fingerprintを受理したまま、current実装との差をprovenanceへ分離する。"""

    required = {
        "schema_version",
        "workflow_id",
        "request_sha256",
        "status",
        "created_at_utc",
        "updated_at_utc",
        "stage_order",
        "stages",
        "safety",
    }
    if set(state) != required or state.get("schema_version") != analysis_lifecycle.SCHEMA_VERSION:
        raise ResumePlannerError("lifecycle_state_invalid", "lifecycle state schemaが不正です")
    if (
        state.get("workflow_id") != context.request.workflow_id
        or state.get("status") not in analysis_lifecycle.WORKFLOW_STATUSES
        or state.get("status") == "pending"
        or not _valid_timestamp(state.get("created_at_utc"))
        or not _valid_timestamp(state.get("updated_at_utc"))
        or state.get("request_sha256") != _canonical_sha256(context.request.public())
        or state.get("stage_order") != list(analysis_lifecycle.STAGE_ORDER)
        or not isinstance(state.get("stages"), dict)
        or set(state["stages"]) != set(analysis_lifecycle.STAGE_ORDER)
        or state.get("safety") != analysis_lifecycle.build_plan(context.request)["safety"]
    ):
        raise ResumePlannerError("lifecycle_state_invalid", "lifecycle state fieldが不正です")
    phases: list[dict[str, Any]] = []
    for stage in analysis_lifecycle.STAGE_ORDER:
        record = state["stages"].get(stage)
        enabled = analysis_lifecycle._stage_enabled(context.request, stage)
        attempts = record.get("attempts") if isinstance(record, dict) else None
        blockers = record.get("blockers") if isinstance(record, dict) else None
        fingerprint = record.get("fingerprint") if isinstance(record, dict) else None
        if (
            not isinstance(record, dict)
            or set(record) != analysis_lifecycle.STAGE_RECORD_KEYS
            or record.get("status") not in analysis_lifecycle.STAGE_STATUSES
            or record.get("enabled") is not enabled
            or record.get("dependencies") != list(analysis_lifecycle.STAGE_DEPENDENCIES[stage])
            or isinstance(attempts, bool)
            or not isinstance(attempts, int)
            or not 0 <= attempts <= analysis_lifecycle.MAX_ATTEMPTS
            or not isinstance(fingerprint, str)
            or analysis_lifecycle.SHA256_RE.fullmatch(fingerprint) is None
            or not _valid_timestamp(record.get("started_at_utc"))
            or not _valid_timestamp(record.get("finished_at_utc"))
            or not isinstance(blockers, list)
            or blockers != analysis_lifecycle._bounded_blockers(blockers)
            or not isinstance(record.get("result"), dict)
            or not analysis_lifecycle._stage_semantics_valid(record, enabled=enabled)
        ):
            raise ResumePlannerError("lifecycle_state_invalid", f"{stage}のstateが不正です")
        current_fingerprint = _current_stage_fingerprint(reader, context, stage)
        phases.append(
            {
                "phase": stage,
                "enabled": enabled,
                "status": record["status"],
                "attempts": attempts,
                "stored_fingerprint_sha256": fingerprint,
                "current_fingerprint_sha256": current_fingerprint,
                "fingerprint_matches_current": current_fingerprint == fingerprint,
                "fingerprint_scope": "declared_stage_sources_and_anchored_inputs",
                "transitive_implementation_status": "not_committed_by_saved_stage_state",
                "result_sha256": _canonical_sha256(record["result"]),
                "blocker_snapshot_sha256": _canonical_sha256(blockers),
                "blockers": list(blockers),
                "failure_code": _failure_code(record),
            }
        )
    if not analysis_lifecycle._workflow_semantics_valid(state):
        raise ResumePlannerError("lifecycle_state_invalid", "workflow statusとstage stateが一致しません")
    return phases


def _policy_for_blocker(blocker: str) -> _BlockerPolicy | None:
    policy = _EXACT_BLOCKER_POLICIES.get(blocker)
    if policy is not None:
        return policy
    for prefix, prefix_policy in _PREFIX_BLOCKER_POLICIES:
        if blocker.startswith(prefix):
            suffix = blocker.removeprefix(prefix)
            return prefix_policy if _FAMILY_SUFFIX_RE.fullmatch(suffix) is not None else None

    action_key = analysis_lifecycle._BLOCKER_ACTION_KEYS.get(blocker)
    if blocker.startswith("orchestration:"):
        gate = blocker.removeprefix("orchestration:")
        action_key = analysis_lifecycle._ORCHESTRATION_GATE_ACTION_KEYS.get(gate)
    elif analysis_lifecycle._HANDLER_EVIDENCE_BLOCKER_RE.fullmatch(blocker):
        action_key = "handler"
    if action_key is None:
        return None
    translation = _LIFECYCLE_POLICY_TRANSLATIONS.get(action_key)
    spec = analysis_lifecycle._ACTION_SPECS.get(action_key)
    if translation is None or not isinstance(spec, tuple) or len(spec) != 6:
        return None
    expected_target, target_phase, priority = translation
    action_id, abstract_target, executor, automatic, changed, prerequisites = spec
    if (
        not isinstance(action_id, str)
        or analysis_lifecycle.BLOCKER_RE.fullmatch(action_id) is None
        or abstract_target != expected_target
        or not isinstance(executor, str)
        or analysis_lifecycle.BLOCKER_RE.fullmatch(executor) is None
        or not isinstance(automatic, bool)
        or not isinstance(changed, bool)
        or not isinstance(prerequisites, tuple)
        or not prerequisites
        or any(
            not isinstance(item, str) or analysis_lifecycle.BLOCKER_RE.fullmatch(item) is None
            for item in prerequisites
        )
    ):
        return None
    return _BlockerPolicy(
        action_id=action_id,
        target_phase=target_phase,
        retryable=False,
        priority=priority,
        changed_evidence=prerequisites if changed else (),
    )


def _phase_by_id(phases: list[dict[str, Any]], phase: str | None) -> dict[str, Any] | None:
    if phase is not None:
        return next((item for item in phases if item["phase"] == phase), None)
    return next(
        (item for item in phases if item["enabled"] and item["status"] not in {"succeeded", "skipped"}),
        None,
    )


def _budget(used: int, limit: int, *, history_complete: bool) -> dict[str, Any]:
    return {
        "used": used,
        "limit": limit,
        "remaining": max(0, limit - used),
        "history_complete": history_complete,
    }


def _select_root_policy(blockers: list[str]) -> tuple[str | None, _BlockerPolicy | None]:
    """派生markerを除き、blind retryを避ける最優先root policyを返す。"""

    candidates = [
        (blocker, policy)
        for blocker in blockers
        if blocker not in _BUDGET_BLOCKERS and blocker not in _DERIVED_BLOCKERS
        for policy in [_policy_for_blocker(blocker)]
        if policy is not None
    ]
    if not candidates:
        return None, None
    non_retryable = [item for item in candidates if not item[1].retryable]
    selected = min(
        non_retryable or candidates,
        key=lambda item: (
            item[1].priority,
            item[1].action_id,
            item[1].target_phase or "",
            item[0],
        ),
    )
    return selected


def _retry_evidence_is_bound(
    record: Mapping[str, Any],
    *,
    phases: list[dict[str, Any]],
    blocker: str | None,
    policy: _BlockerPolicy | None,
) -> bool:
    """retryable codeが実際のfailed stage envelopeへ完全一致するか返す。"""

    if blocker is None or policy is None or not policy.retryable:
        return True
    if blocker == "workflow_execution_failed":
        return bool(
            not phases
            and record.get("status") == "failed"
            and record.get("lifecycle_report_sha256") is None
            and record.get("blockers") == [blocker]
            and _failure_code(record) == blocker
        )
    if policy.target_phase is None:
        return False
    phase = _phase_by_id(phases, policy.target_phase)
    return bool(
        phase is not None
        and phase["status"] == "failed"
        and phase["blockers"] == [blocker]
        and phase["failure_code"] == blocker
    )


def _decision_for_record(
    record: Mapping[str, Any],
    *,
    phases: list[dict[str, Any]],
    orchestrator_implementation_matches_current: bool,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    blockers = list(record["blockers"])
    workflow_budget = _budget(
        int(record["attempts"]),
        analysis_orchestrator.MAX_ATTEMPTS,
        history_complete=int(record["attempts"]) <= 1,
    )
    evidence_value = {
        "blockers": blockers,
        "lifecycle_report_sha256": record.get("lifecycle_report_sha256"),
        "phases": [
            {
                "phase": item["phase"],
                "fingerprint": item["stored_fingerprint_sha256"],
                "result": item["result_sha256"],
                "blockers": item["blocker_snapshot_sha256"],
            }
            for item in phases
        ],
    }
    evidence_sha256 = _canonical_sha256(evidence_value)
    status = record["status"]
    unknown = [
        blocker
        for blocker in blockers
        if blocker not in _BUDGET_BLOCKERS and blocker not in _DERIVED_BLOCKERS and _policy_for_blocker(blocker) is None
    ]
    fingerprints_current = all(item["fingerprint_matches_current"] for item in phases)
    selected_blocker, selected_policy = _select_root_policy(blockers)
    target_phase = selected_policy.target_phase if selected_policy is not None else None
    phase = _phase_by_id(phases, target_phase)
    phase_budget = (
        _budget(
            int(phase["attempts"]),
            analysis_lifecycle.MAX_ATTEMPTS,
            history_complete=int(record["attempts"]) <= 1,
        )
        if phase is not None
        else None
    )
    budget_exhausted = (
        workflow_budget["remaining"] == 0
        or (phase_budget is not None and phase_budget["remaining"] == 0)
        or bool(set(blockers) & _BUDGET_BLOCKERS)
    )
    contract_drift = not orchestrator_implementation_matches_current or not fingerprints_current
    changed_phase = next(
        (item["phase"] for item in phases if not item["fingerprint_matches_current"]),
        target_phase,
    )
    retry_evidence_bound = _retry_evidence_is_bound(
        record,
        phases=phases,
        blocker=selected_blocker,
        policy=selected_policy,
    )

    if status == "complete" and not contract_drift:
        decision = {
            "action_id": "no_op_complete",
            "target_phase": None,
            "eligible": False,
            "retryable": False,
            "successor_required": False,
            "blocked_action_id": None,
            "requires_changed_evidence": [],
            "reason_codes": [],
        }
    elif status == "deferred" and not contract_drift:
        decision = {
            "action_id": "wait_for_predecessor",
            "target_phase": None,
            "eligible": False,
            "retryable": False,
            "successor_required": False,
            "blocked_action_id": None,
            "requires_changed_evidence": ["predecessor_workflow_completion"],
            "reason_codes": blockers,
        }
    elif status == "partial":
        underlying_action = selected_policy.action_id if selected_policy is not None else "manual_review_required"
        if contract_drift:
            partial_target = changed_phase
            changed_evidence = [
                "new_orchestration_id",
                "new_workflow_id",
                "updated_request_sha256",
            ]
        else:
            partial_target = phase["phase"] if phase is not None else target_phase
            changed_evidence = [
                "new_orchestration_id",
                "new_workflow_id",
                "updated_request_sha256",
            ]
            changed_evidence.extend(
                selected_policy.changed_evidence if selected_policy is not None else ("operator_review",)
            )
        decision = {
            "action_id": "start_successor_workflow",
            "target_phase": partial_target,
            "eligible": False,
            "retryable": False,
            "successor_required": True,
            "blocked_action_id": underlying_action,
            "requires_changed_evidence": list(dict.fromkeys(changed_evidence)),
            "reason_codes": blockers,
        }
    elif status not in {"complete", "deferred"} and (
        unknown or (selected_policy is not None and not retry_evidence_bound)
    ):
        decision = {
            "action_id": "manual_review_required",
            "target_phase": None,
            "eligible": False,
            "retryable": False,
            "successor_required": False,
            "blocked_action_id": None,
            "requires_changed_evidence": ["operator_review"],
            "reason_codes": blockers,
        }
    elif contract_drift:
        decision = {
            "action_id": "start_successor_workflow",
            "target_phase": changed_phase,
            "eligible": False,
            "retryable": False,
            "successor_required": True,
            "blocked_action_id": (selected_policy.action_id if selected_policy is not None else None),
            "requires_changed_evidence": [
                "new_orchestration_id",
                "new_workflow_id",
                "updated_request_sha256",
            ],
            "reason_codes": blockers,
        }
    elif budget_exhausted:
        decision = {
            "action_id": "stop_budget_exhausted",
            "target_phase": phase["phase"] if phase is not None else target_phase,
            "eligible": False,
            "retryable": False,
            "successor_required": False,
            "blocked_action_id": None,
            "requires_changed_evidence": [],
            "reason_codes": blockers,
        }
    elif selected_policy is None:
        decision = {
            "action_id": "manual_review_required",
            "target_phase": None,
            "eligible": False,
            "retryable": False,
            "successor_required": False,
            "blocked_action_id": None,
            "requires_changed_evidence": ["operator_review"],
            "reason_codes": blockers,
        }
    else:
        decision = {
            "action_id": selected_policy.action_id,
            "target_phase": phase["phase"] if phase is not None else target_phase,
            "eligible": selected_policy.retryable,
            "retryable": selected_policy.retryable,
            "successor_required": selected_policy.action_id == "start_successor_workflow",
            "blocked_action_id": None,
            "requires_changed_evidence": list(selected_policy.changed_evidence),
            "reason_codes": blockers,
        }

    # 保存stateは累積attemptsだけを持ち、各attemptのevidence snapshotを保持しない。
    # 現在値が同じだけでは「進展なし」を立証できないため、履歴がない旧stateでは
    # no-progressを断定せず、明示的なattempt budgetだけでretryを制限する。
    no_progress = False
    history_unavailable = decision["retryable"] and int(record["attempts"]) > 1 and bool(blockers)
    return (
        decision,
        {"workflow": workflow_budget, "phase": phase_budget},
        {
            "detected": no_progress,
            "evidence_sha256": evidence_sha256,
            "basis": ["retry_history_not_preserved"] if history_unavailable else [],
        },
    )


def _load_child_provenance(
    reader: _SnapshotReader,
    *,
    record: Mapping[str, Any],
    request: analysis_lifecycle.LifecycleRequest,
    repository: Path,
    input_root: Path,
    work_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    lifecycle_root = work_root / "lifecycles" / request.workflow_id
    if record["status"] == "deferred":
        if lifecycle_root.exists():
            raise ResumePlannerError("deferred_lifecycle_exists", "deferred workflowにchild stateがあります")
        return [], {
            "request_file_sha256": None,
            "state_file_sha256": None,
            "report_file_sha256": None,
        }
    if not lifecycle_root.exists():
        if record["status"] == "failed" and record.get("lifecycle_report_sha256") is None:
            return [], {
                "request_file_sha256": None,
                "state_file_sha256": None,
                "report_file_sha256": None,
            }
        raise ResumePlannerError("lifecycle_missing", "child lifecycle stateがありません")
    try:
        analysis_lifecycle._reject_existing_reparse_components(
            lifecycle_root,
            label="lifecycle state",
        )
    except (analysis_lifecycle.LifecycleError, OSError) as exc:
        raise ResumePlannerError("lifecycle_path_invalid", "lifecycle pathが不正です") from exc
    request_snapshot = reader.read(
        lifecycle_root / "request.json",
        maximum_bytes=analysis_lifecycle.MAX_REQUEST_BYTES,
        label="lifecycle_request",
    )
    try:
        stored_request = analysis_lifecycle.validate_request_object(request_snapshot.document)
    except (analysis_lifecycle.LifecycleError, TypeError) as exc:
        raise ResumePlannerError("lifecycle_request_invalid", "child lifecycle requestが不正です") from exc
    if stored_request.public() != request.public():
        raise ResumePlannerError("lifecycle_request_mismatch", "child lifecycle requestが親requestと一致しません")
    try:
        context = analysis_lifecycle._validate_context_roots(
            stored_request,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
            create=False,
        )
    except (analysis_lifecycle.LifecycleError, OSError) as exc:
        raise ResumePlannerError("lifecycle_context_invalid", "child lifecycle contextが不正です") from exc
    state_snapshot = reader.read(
        lifecycle_root / "state.json",
        maximum_bytes=analysis_lifecycle.MAX_STATE_BYTES,
        label="lifecycle_state",
    )
    phases = _validate_lifecycle_state(reader, context, state_snapshot.document)
    report_snapshot = reader.read(
        lifecycle_root / "report.json",
        maximum_bytes=analysis_lifecycle.MAX_STATE_BYTES,
        label="lifecycle_report",
    )
    expected_report = analysis_lifecycle._public_report_from_state(
        context,
        state_snapshot.document,
    )
    if report_snapshot.document != expected_report:
        raise ResumePlannerError("lifecycle_report_mismatch", "child lifecycle reportとstateが一致しません")
    pinned_report = record.get("lifecycle_report_sha256")
    if pinned_report is not None and pinned_report != report_snapshot.sha256:
        raise ResumePlannerError("lifecycle_report_hash_mismatch", "child lifecycle report hashが一致しません")
    if record["status"] in {"complete", "partial"}:
        if (
            state_snapshot.document["status"] != record["status"]
            or analysis_orchestrator._record_blockers(state_snapshot.document) != record["blockers"]
            or analysis_orchestrator._record_result(state_snapshot.document) != record["result"]
        ):
            raise ResumePlannerError("lifecycle_parent_mismatch", "親子workflow stateが一致しません")
    elif (
        record["status"] == "failed"
        and pinned_report is not None
        and "maximum_workflow_attempts_exceeded" not in record["blockers"]
        and (
            state_snapshot.document["status"] != "failed"
            or analysis_orchestrator._record_blockers(state_snapshot.document) != record["blockers"]
            or analysis_orchestrator._record_result(state_snapshot.document) != record["result"]
        )
    ):
        raise ResumePlannerError("lifecycle_parent_mismatch", "親子workflow failure stateが一致しません")
    return phases, {
        "request_file_sha256": request_snapshot.sha256,
        "state_file_sha256": state_snapshot.sha256,
        "report_file_sha256": report_snapshot.sha256,
    }


def build_resume_plan(
    *,
    repository: Path,
    input_root: Path,
    work_root: Path,
    orchestration_id: str,
) -> dict[str, Any]:
    """保存済み成果物だけを読み、machine-readableな次動作を返す。"""

    if analysis_lifecycle.WORKFLOW_ID_RE.fullmatch(orchestration_id) is None:
        raise ResumePlannerError("orchestration_id_invalid", "orchestration IDの形式が不正です")
    reader = _SnapshotReader()
    work_root = Path(os.path.abspath(os.fspath(work_root)))
    orchestration_root = work_root / "orchestrations" / orchestration_id
    try:
        analysis_lifecycle._reject_existing_reparse_components(
            orchestration_root,
            label="orchestration state",
        )
    except (analysis_lifecycle.LifecycleError, OSError) as exc:
        raise ResumePlannerError("orchestration_path_invalid", "orchestration pathが不正です") from exc
    request_snapshot = reader.read(
        orchestration_root / "request.json",
        maximum_bytes=analysis_orchestrator.MAX_REQUEST_BYTES,
        label="orchestration_request",
    )
    try:
        request = analysis_orchestrator.validate_request_object(request_snapshot.document)
    except (analysis_orchestrator.OrchestrationError, TypeError) as exc:
        raise ResumePlannerError("orchestration_request_invalid", "orchestration requestが不正です") from exc
    if request.orchestration_id != orchestration_id:
        raise ResumePlannerError("orchestration_request_mismatch", "orchestration IDが一致しません")
    try:
        context = analysis_orchestrator._validate_context(
            request,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=analysis_job_runner.DEFAULT_TIMEOUT_SECONDS,
            create=False,
        )
    except (
        analysis_orchestrator.OrchestrationError,
        analysis_lifecycle.LifecycleError,
        OSError,
    ) as exc:
        raise ResumePlannerError("orchestration_context_invalid", "orchestration contextが不正です") from exc
    state_snapshot = reader.read(
        orchestration_root / "state.json",
        maximum_bytes=analysis_orchestrator.MAX_STATE_BYTES,
        label="orchestration_state",
    )
    _validate_orchestration_state(state_snapshot.document, request)
    report_snapshot = reader.read(
        orchestration_root / "report.json",
        maximum_bytes=analysis_orchestrator.MAX_STATE_BYTES,
        label="orchestration_report",
    )
    expected_report = analysis_orchestrator._public_report_from_state(
        context,
        state_snapshot.document,
    )
    if report_snapshot.document != expected_report:
        raise ResumePlannerError("orchestration_report_mismatch", "orchestration reportとstateが一致しません")

    current_implementation = reader.read_file(
        Path(analysis_orchestrator.__file__).resolve(),
        maximum_bytes=MAX_CODE_SOURCE_BYTES,
        label="orchestrator_source",
    ).sha256
    implementation_matches = state_snapshot.document["implementation_sha256"] == current_implementation
    workflows: list[dict[str, Any]] = []
    for record, child_request in zip(
        state_snapshot.document["workflows"],
        request.workflows,
        strict=True,
    ):
        phases, child_source = _load_child_provenance(
            reader,
            record=record,
            request=child_request,
            repository=context.repository,
            input_root=context.input_root,
            work_root=context.work_root,
        )
        decision, retry_budget, no_progress = _decision_for_record(
            record,
            phases=phases,
            orchestrator_implementation_matches_current=implementation_matches,
        )
        workflows.append(
            {
                "index": record["index"],
                "workflow_id": record["workflow_id"],
                "job_id": record["job_id"],
                "current_status": record["status"],
                "request_sha256": record["request_sha256"],
                "blocker_snapshot": {
                    "codes": list(record["blockers"]),
                    "sha256": _canonical_sha256(record["blockers"]),
                },
                "source_provenance": child_source,
                "phase_provenance": phases,
                "retry_budget": retry_budget,
                "no_progress": no_progress,
                "decision": decision,
            }
        )
    reader.verify_unchanged()
    if all(item["decision"]["action_id"] == "no_op_complete" for item in workflows):
        status = "complete"
    elif any(item["decision"]["eligible"] for item in workflows):
        status = "actionable"
    else:
        status = "blocked"
    plan: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "orchestration_id": orchestration_id,
        "request_sha256": state_snapshot.document["request_sha256"],
        "status": status,
        "snapshot_limits": {
            "maximum_files": MAX_SNAPSHOT_FILES,
            "maximum_total_bytes": MAX_TOTAL_SNAPSHOT_BYTES,
            "verification_chunk_bytes": SNAPSHOT_HASH_CHUNK_BYTES,
        },
        "source_provenance": {
            "request_file_sha256": request_snapshot.sha256,
            "state_file_sha256": state_snapshot.sha256,
            "report_file_sha256": report_snapshot.sha256,
            "stored_implementation_sha256": state_snapshot.document["implementation_sha256"],
            "current_implementation_sha256": current_implementation,
            "implementation_matches_current": implementation_matches,
            "implementation_fingerprint_scope": "orchestrator_source_only",
            "transitive_implementation_status": "not_committed_by_saved_orchestration_state",
        },
        "workflows": workflows,
        "safety": {
            "read_only": True,
            "write_performed": False,
            "sample_bytes_read": False,
            "sample_executed": False,
            "analysis_network_contacted": False,
            "live_c2_contacted": False,
            "arbitrary_command_executed": False,
        },
    }
    plan["plan_id"] = _canonical_sha256(plan)
    return plan


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


def build_parser() -> argparse.ArgumentParser:
    """read-only再開計画CLIの引数parserを構築する。"""

    parser = JapaneseArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan-resume", help="保存済みstateからread-only再開計画を構築します")
    plan.add_argument("--orchestration-id", required=True, help="保存済みorchestration ID")
    plan.add_argument("--repository", required=True, type=Path, help="解析repository root")
    plan.add_argument("--input-root", required=True, type=Path, help="検体を置くrepository外root")
    plan.add_argument("--work-root", required=True, type=Path, help="stateを置くrepository外root")
    return parser


def _print_json(value: Any, *, stream: Any | None = None) -> None:
    print(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False),
        file=sys.stdout if stream is None else stream,
    )


def main(argv: list[str] | None = None) -> int:
    """再開計画をJSONで出力し、状態に応じた固定終了codeを返す。"""

    args = build_parser().parse_args(argv)
    try:
        plan = build_resume_plan(
            repository=args.repository,
            input_root=args.input_root,
            work_root=args.work_root,
            orchestration_id=args.orchestration_id,
        )
    except ResumePlannerError as exc:
        _print_json(
            {
                "schema_version": SCHEMA_VERSION,
                "error": {"code": exc.code, "message": str(exc)},
                "safety": {
                    "read_only": True,
                    "write_performed": False,
                    "sample_executed": False,
                    "analysis_network_contacted": False,
                },
            },
            stream=sys.stderr,
        )
        return 2
    _print_json(plan)
    return 0 if plan["status"] == "complete" else 20


if __name__ == "__main__":
    raise SystemExit(main())
