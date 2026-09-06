"""副作用のない解析再開plannerのstate契約と決定性を検証する。"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

planner = importlib.import_module("analysis_resume_planner")
lifecycle = importlib.import_module("analysis_lifecycle")
orchestrator = importlib.import_module("analysis_orchestrator")
registry = importlib.import_module("remediation_registry")


def _lifecycle_request(workflow_id: str) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "workflow_id": workflow_id,
        "job": {
            "schema_version": 1,
            "job_id": f"job-{workflow_id}",
            "inputs": [f"set/{workflow_id}.bin"],
            "options": {},
        },
        "publication": {
            "enabled": False,
            "manifest": None,
            "collection_id": None,
            "expected_contract_sha256": None,
            "allow_partial_staging": False,
        },
        "maintenance": {"refresh_repository": False},
        "private_archive": {
            "enabled": False,
            "target": None,
            "include": [],
        },
    }


def _orchestration_request(workflow_ids: tuple[str, ...]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "orchestration_id": "resume-plan-001",
        "workflows": [_lifecycle_request(workflow_id) for workflow_id in workflow_ids],
        "policy": {
            "continue_after_partial": False,
            "continue_after_failure": False,
        },
    }


def _make_roots(
    tmp_path: Path,
    workflow_ids: tuple[str, ...],
) -> tuple[Path, Path, Path]:
    repository = tmp_path / "repository"
    common = repository / "analysis-framework" / "common"
    common.mkdir(parents=True)
    (common / "analyze_sample.py").write_text("# fixture\n", encoding="utf-8")
    (common / "publish_one_shot_collection.py").write_text("# fixture\n", encoding="utf-8")
    (repository / "analysis-results").mkdir()
    (repository / "ui").mkdir()
    input_root = tmp_path / "inputs"
    for workflow_id in workflow_ids:
        sample = input_root / "set" / f"{workflow_id}.bin"
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_bytes(f"MZ synthetic {workflow_id}".encode())
    work_root = tmp_path / "work"
    work_root.mkdir()
    return repository, input_root, work_root


def _actions(
    *,
    blocker: str | None = None,
    static_failure: bool = False,
) -> lifecycle._Actions:
    def succeeded(result: dict[str, Any]) -> lifecycle.StageOutcome:
        return lifecycle.StageOutcome("succeeded", result)

    def preflight(*_: Any) -> lifecycle.StageOutcome:
        return succeeded({"valid": True})

    def static(*_: Any) -> lifecycle.StageOutcome:
        if static_failure:
            raise lifecycle.LifecycleError("static_analysis_failed", "fixture static failure")
        return succeeded(
            {
                "analysis_state": "partial" if blocker else "complete",
                "result_sha256": "a" * 64,
                "summary_sha256": "b" * 64,
            }
        )

    def publication(*_: Any) -> lifecycle.StageOutcome:
        return succeeded({"published": 0})

    def function_validation(*_: Any) -> lifecycle.StageOutcome:
        return succeeded({"complete": True})

    def completion(*_: Any) -> lifecycle.StageOutcome:
        if blocker is not None:
            return lifecycle.StageOutcome(
                "blocked",
                {"complete": False, "blockers": [blocker]},
                (blocker,),
            )
        return succeeded({"complete": True, "blockers": []})

    def refresh(*_: Any) -> lifecycle.StageOutcome:
        return succeeded({"repository_verification_passed": True})

    def archive(*_: Any) -> lifecycle.StageOutcome:
        return succeeded({"status": "verified"})

    return lifecycle._Actions(
        preflight=preflight,
        static_analysis=static,
        publication=publication,
        function_validation=function_validation,
        completion_gate=completion,
        derived_refresh=refresh,
        private_archive=archive,
    )


def _attach_child(
    context: orchestrator.OrchestrationContext,
    state: dict[str, Any],
    *,
    index: int,
    actions: lifecycle._Actions,
    attempts: int,
) -> dict[str, Any]:
    request = context.request.workflows[index]
    child = lifecycle._run_lifecycle_for_test(
        request,
        repository=context.repository,
        input_root=context.input_root,
        work_root=context.work_root,
        timeout_seconds=60,
        actions=actions,
    )
    report = context.work_root / "lifecycles" / request.workflow_id / "report.json"
    record = state["workflows"][index]
    record.update(
        {
            "status": child["status"],
            "attempts": attempts,
            "started_at_utc": lifecycle.utc_now(),
            "finished_at_utc": lifecycle.utc_now(),
            "blockers": orchestrator._record_blockers(child),
            "lifecycle_report_sha256": lifecycle._sha256_file(report),
            "result": orchestrator._record_result(child),
        }
    )
    return child


def _fixture(
    tmp_path: Path,
    *,
    blocker: str | None = "terminal_payload_not_recovered",
    static_failure: bool = False,
    attempts: int = 1,
) -> tuple[Path, Path, Path, str]:
    workflow_ids = ("sample-001",)
    repository, input_root, work_root = _make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(_orchestration_request(workflow_ids))
    context, state = orchestrator._initialize_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    _attach_child(
        context,
        state,
        index=0,
        actions=_actions(blocker=blocker, static_failure=static_failure),
        attempts=attempts,
    )
    orchestrator._finalize(context, state)
    return repository, input_root, work_root, request.orchestration_id


def _plan(
    roots: tuple[Path, Path, Path, str],
) -> dict[str, Any]:
    repository, input_root, work_root, orchestration_id = roots
    return planner.build_resume_plan(
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        orchestration_id=orchestration_id,
    )


def _synthetic_phase(
    phase: str,
    *,
    status: str = "failed",
    blocker: str,
    failure_code: str | None,
    attempts: int = 1,
) -> dict[str, Any]:
    blockers = [blocker]
    return {
        "phase": phase,
        "enabled": True,
        "status": status,
        "attempts": attempts,
        "stored_fingerprint_sha256": "1" * 64,
        "current_fingerprint_sha256": "1" * 64,
        "fingerprint_matches_current": True,
        "result_sha256": "2" * 64,
        "blocker_snapshot_sha256": lifecycle._sha256_value(blockers),
        "blockers": blockers,
        "failure_code": failure_code,
    }


def _synthetic_failed_record(blockers: list[str], *, attempts: int = 1) -> dict[str, Any]:
    return {
        "status": "failed",
        "attempts": attempts,
        "blockers": blockers,
        "lifecycle_report_sha256": "3" * 64,
        "result": {},
    }


def test_complete_workflow_is_verified_no_op(tmp_path: Path) -> None:
    result = _plan(_fixture(tmp_path, blocker=None))

    assert result["status"] == "complete"
    workflow = result["workflows"][0]
    assert workflow["current_status"] == "complete"
    assert workflow["decision"] == {
        "action_id": "no_op_complete",
        "blocked_action_id": None,
        "eligible": False,
        "reason_codes": [],
        "requires_changed_evidence": [],
        "retryable": False,
        "successor_required": False,
        "target_phase": None,
    }
    assert len(workflow["phase_provenance"]) == len(lifecycle.STAGE_ORDER)
    assert all(len(item["result_sha256"]) == 64 for item in workflow["phase_provenance"])
    assert all(
        item["fingerprint_scope"] == "declared_stage_sources_and_anchored_inputs"
        and item["transitive_implementation_status"] == "not_committed_by_saved_stage_state"
        for item in workflow["phase_provenance"]
    )
    assert result["source_provenance"]["implementation_fingerprint_scope"] == "orchestrator_source_only"
    assert (
        result["source_provenance"]["transitive_implementation_status"] == "not_committed_by_saved_orchestration_state"
    )


@pytest.mark.parametrize(
    ("blocker", "action_id", "target_phase"),
    [
        ("terminal_payload_not_recovered", "recover_terminal_payload_statically", "static_analysis"),
        (
            "representative_function_analysis_required",
            "perform_representative_function_static_review",
            "function_validation",
        ),
        ("orchestration:config", "recover_configuration_statically", "static_analysis"),
        (
            "selected_family_has_no_automatic_handler:valleyrat",
            "implement_family_handler",
            "static_analysis",
        ),
        (
            "terminal_acquisition:child_timeout",
            "terminal_payload_static_recovery",
            "static_analysis",
        ),
        (
            "batch_error:root_static_analysis_failed",
            "reanalyze_static_pipeline",
            "static_analysis",
        ),
        (
            "batch_error:resume_validation_failed",
            "reanalyze_static_pipeline",
            "static_analysis",
        ),
        (
            "batch_error:input_read_failed",
            "review_machine_readable_blocker",
            "static_analysis",
        ),
    ],
)
def test_exact_and_prefix_blockers_have_deterministic_root_action(
    tmp_path: Path,
    blocker: str,
    action_id: str,
    target_phase: str | None,
) -> None:
    result = _plan(_fixture(tmp_path, blocker=blocker))
    decision = result["workflows"][0]["decision"]

    assert result["status"] == "blocked"
    assert decision["action_id"] == "start_successor_workflow"
    assert decision["blocked_action_id"] == action_id
    assert decision["target_phase"] == target_phase
    assert decision["eligible"] is False
    assert decision["retryable"] is False
    assert decision["successor_required"] is True
    assert decision["requires_changed_evidence"][:3] == [
        "new_orchestration_id",
        "new_workflow_id",
        "updated_request_sha256",
    ]


def test_every_lifecycle_registered_blocker_has_a_planner_policy() -> None:
    blockers = set(lifecycle._BLOCKER_ACTION_KEYS)
    blockers.update(f"orchestration:{gate}" for gate in lifecycle._ORCHESTRATION_GATE_ACTION_KEYS)

    assert blockers
    assert all(planner._policy_for_blocker(blocker) is not None for blocker in blockers)
    assert planner._policy_for_blocker("orchestration:unregistered_gate") is None


def test_every_terminal_acquisition_blocker_has_a_planner_policy() -> None:
    for reason in registry.TERMINAL_ACQUISITION_REASONS:
        policy = planner._policy_for_blocker(f"terminal_acquisition:{reason}")

        assert policy is not None
        assert policy.action_id == "terminal_payload_static_recovery"
        assert policy.target_phase == "static_analysis"
        assert policy.retryable is False


@pytest.mark.parametrize(
    ("blocker", "action_id", "target_phase"),
    [
        ("config_and_c2_not_recovered", "configuration_and_c2_static_recovery", "static_analysis"),
        ("operational_c2_not_recovered", "configuration_and_c2_static_recovery", "static_analysis"),
        ("virtualized_terminal_payload_not_recovered", "terminal_payload_static_recovery", "static_analysis"),
        ("family_attribution_unresolved", "family_attribution_review", "static_analysis"),
        ("final_c2_endpoint_unresolved", "configuration_and_c2_static_recovery", "static_analysis"),
        ("static_c2_config_unresolved", "configuration_and_c2_static_recovery", "static_analysis"),
    ],
)
def test_lifecycle_registry_fallback_covers_completion_blockers(
    blocker: str,
    action_id: str,
    target_phase: str,
) -> None:
    policy = planner._policy_for_blocker(blocker)

    assert policy is not None
    assert policy.action_id == action_id
    assert policy.target_phase == target_phase
    assert policy.retryable is False
    assert policy.changed_evidence


def test_malformed_lifecycle_action_spec_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    malformed = dict(registry.ACTION_SPECS)
    malformed["config"] = ("invalid",)
    monkeypatch.setattr(registry, "ACTION_SPECS", malformed)

    assert planner._policy_for_blocker("config_and_c2_not_recovered") is None


def test_unknown_or_malformed_prefix_blocker_fails_closed(tmp_path: Path) -> None:
    result = _plan(
        _fixture(
            tmp_path,
            blocker="selected_family_has_no_automatic_handler:bad:family",
        )
    )
    decision = result["workflows"][0]["decision"]

    assert decision["action_id"] == "manual_review_required"
    assert decision["blocked_action_id"] is None
    assert decision["eligible"] is False
    assert decision["retryable"] is False
    assert decision["successor_required"] is False
    assert decision["requires_changed_evidence"] == ["operator_review"]


def test_transient_failure_is_resumable_once_with_explicit_budget(tmp_path: Path) -> None:
    result = _plan(_fixture(tmp_path, blocker=None, static_failure=True))
    workflow = result["workflows"][0]

    assert result["status"] == "actionable"
    assert workflow["current_status"] == "failed"
    assert workflow["decision"]["action_id"] == "resume_workflow"
    assert workflow["decision"]["target_phase"] == "static_analysis"
    assert workflow["decision"]["eligible"] is True
    assert workflow["retry_budget"]["workflow"] == {
        "history_complete": True,
        "limit": 5,
        "remaining": 4,
        "used": 1,
    }


def test_attempt_count_without_evidence_history_does_not_assert_no_progress(tmp_path: Path) -> None:
    result = _plan(
        _fixture(
            tmp_path,
            blocker=None,
            static_failure=True,
            attempts=2,
        )
    )
    workflow = result["workflows"][0]

    assert workflow["no_progress"]["detected"] is False
    assert workflow["no_progress"]["basis"] == ["retry_history_not_preserved"]
    assert lifecycle.SHA256_RE.fullmatch(workflow["no_progress"]["evidence_sha256"])
    assert workflow["retry_budget"]["workflow"]["history_complete"] is False
    assert workflow["decision"]["action_id"] == "resume_workflow"
    assert workflow["decision"]["blocked_action_id"] is None
    assert workflow["decision"]["eligible"] is True


def test_exhausted_workflow_budget_stops_without_retry(tmp_path: Path) -> None:
    result = _plan(
        _fixture(
            tmp_path,
            blocker=None,
            static_failure=True,
            attempts=orchestrator.MAX_ATTEMPTS,
        )
    )
    workflow = result["workflows"][0]

    assert workflow["retry_budget"]["workflow"]["remaining"] == 0
    assert workflow["decision"]["action_id"] == "stop_budget_exhausted"
    assert workflow["decision"]["eligible"] is False


def test_stale_implementation_requires_successor_workflow(tmp_path: Path) -> None:
    roots = _fixture(tmp_path)
    work_root = roots[2]
    state_path = work_root / "orchestrations" / roots[3] / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["implementation_sha256"] = "0" * 64
    state_path.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")

    result = _plan(roots)
    decision = result["workflows"][0]["decision"]

    assert result["source_provenance"]["implementation_matches_current"] is False
    assert decision["action_id"] == "start_successor_workflow"
    assert decision["blocked_action_id"] == "recover_terminal_payload_statically"
    assert decision["target_phase"] == "static_analysis"
    assert decision["successor_required"] is True
    assert decision["eligible"] is False
    assert decision["requires_changed_evidence"] == [
        "new_orchestration_id",
        "new_workflow_id",
        "updated_request_sha256",
    ]


def test_stale_phase_fingerprint_requires_successor_workflow(tmp_path: Path) -> None:
    roots = _fixture(tmp_path)
    child_context, _ = lifecycle._existing_context(
        "sample-001",
        repository=roots[0],
        input_root=roots[1],
        work_root=roots[2],
        timeout_seconds=60,
    )
    orchestration_context, _ = orchestrator._existing_context(
        roots[3],
        repository=roots[0],
        input_root=roots[1],
        work_root=roots[2],
        timeout_seconds=60,
    )
    child_state_path = roots[2] / "lifecycles" / "sample-001" / "state.json"
    child_report_path = roots[2] / "lifecycles" / "sample-001" / "report.json"
    state = json.loads(child_state_path.read_text(encoding="utf-8"))
    state["stages"]["completion_gate"]["fingerprint"] = "0" * 64
    child_state_path.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    child_report_path.write_text(
        json.dumps(lifecycle._public_report_from_state(child_context, state), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    orchestration_state_path = roots[2] / "orchestrations" / roots[3] / "state.json"
    orchestration_report_path = roots[2] / "orchestrations" / roots[3] / "report.json"
    orchestration_state = json.loads(orchestration_state_path.read_text(encoding="utf-8"))
    parent_record = orchestration_state["workflows"][0]
    parent_record["blockers"] = orchestrator._record_blockers(state)
    parent_record["result"] = orchestrator._record_result(state)
    parent_record["lifecycle_report_sha256"] = lifecycle._sha256_file(child_report_path)
    orchestration_state_path.write_text(
        json.dumps(orchestration_state, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    orchestration_report_path.write_text(
        json.dumps(
            orchestrator._public_report_from_state(orchestration_context, orchestration_state),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    result = _plan(roots)
    decision = result["workflows"][0]["decision"]

    assert decision["action_id"] == "start_successor_workflow"
    assert decision["blocked_action_id"] == "recover_terminal_payload_statically"
    assert decision["target_phase"] == "completion_gate"
    assert decision["successor_required"] is True
    assert decision["requires_changed_evidence"] == [
        "new_orchestration_id",
        "new_workflow_id",
        "updated_request_sha256",
    ]


def test_deferred_workflow_waits_without_consuming_budget(tmp_path: Path) -> None:
    workflow_ids = ("sample-001", "sample-002")
    repository, input_root, work_root = _make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(_orchestration_request(workflow_ids))
    context, state = orchestrator._initialize_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    _attach_child(
        context,
        state,
        index=0,
        actions=_actions(blocker="terminal_payload_not_recovered"),
        attempts=1,
    )
    state["workflows"][1].update(
        {
            "status": "deferred",
            "finished_at_utc": lifecycle.utc_now(),
            "blockers": ["orchestration_policy_stop"],
            "result": {"reason": "prior_workflow_policy_stop"},
        }
    )
    orchestrator._finalize(context, state)

    result = _plan((repository, input_root, work_root, request.orchestration_id))
    deferred = result["workflows"][1]

    assert deferred["current_status"] == "deferred"
    assert deferred["phase_provenance"] == []
    assert deferred["retry_budget"]["workflow"]["used"] == 0
    assert deferred["decision"]["action_id"] == "wait_for_predecessor"


@pytest.mark.parametrize("source_kind", ["stage", "orchestrator"])
def test_current_source_change_after_stage_fingerprint_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source_kind: str,
) -> None:
    roots = _fixture(tmp_path)
    if source_kind == "stage":
        source_root = tmp_path / "current-common"
        source_root.mkdir()
        source_names = {name for stage_names in lifecycle.STAGE_CODE_FILES.values() for name in stage_names}
        for name in source_names:
            (source_root / name).write_text(f"# {name}\n", encoding="utf-8")
        target = source_root / "analysis_lifecycle.py"
        monkeypatch.setattr(lifecycle, "__file__", str(target))
    else:
        target = tmp_path / "current-analysis-orchestrator.py"
        target.write_text("# current orchestrator\n", encoding="utf-8")
        monkeypatch.setattr(orchestrator, "__file__", str(target))

    original = planner._current_stage_fingerprint
    mutation_injected = False

    def fingerprint_then_change_source(
        reader: planner._SnapshotReader,
        context: lifecycle.LifecycleContext,
        stage: str,
    ) -> str:
        nonlocal mutation_injected
        fingerprint = original(reader, context, stage)
        if not mutation_injected:
            if source_kind == "orchestrator":
                replacement = target.with_name("replacement-orchestrator.py")
                replacement.write_bytes(target.read_bytes())
                replacement.replace(target)
            else:
                target.write_text("# changed after snapshot\n", encoding="utf-8")
            mutation_injected = True
        return fingerprint

    monkeypatch.setattr(planner, "_current_stage_fingerprint", fingerprint_then_change_source)

    with pytest.raises(planner.ResumePlannerError) as caught:
        _plan(roots)

    assert mutation_injected is True
    assert caught.value.code == "snapshot_changed_during_plan"
    assert str(tmp_path) not in str(caught.value)


def test_publication_manifest_change_after_stage_fingerprint_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    workflow_ids = ("sample-001",)
    repository, input_root, work_root = _make_roots(tmp_path, workflow_ids)
    manifest = repository / "manifests" / "resume.json"
    manifest.parent.mkdir()
    manifest.write_text('{"schema_version":1}\n', encoding="utf-8")
    raw_request = _orchestration_request(workflow_ids)
    raw_request["workflows"][0]["publication"] = {
        "enabled": True,
        "manifest": "manifests/resume.json",
        "collection_id": "resume-test-001",
        "expected_contract_sha256": None,
        "allow_partial_staging": True,
    }
    request = orchestrator.validate_request_object(raw_request)
    context, state = orchestrator._initialize_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    _attach_child(
        context,
        state,
        index=0,
        actions=_actions(blocker="terminal_payload_not_recovered"),
        attempts=1,
    )
    orchestrator._finalize(context, state)
    original = planner._current_stage_fingerprint
    mutation_injected = False

    def fingerprint_then_change_manifest(
        reader: planner._SnapshotReader,
        child_context: lifecycle.LifecycleContext,
        stage: str,
    ) -> str:
        nonlocal mutation_injected
        fingerprint = original(reader, child_context, stage)
        if stage == "publication" and not mutation_injected:
            manifest.write_text('{"schema_version":2}\n', encoding="utf-8")
            mutation_injected = True
        return fingerprint

    monkeypatch.setattr(planner, "_current_stage_fingerprint", fingerprint_then_change_manifest)

    with pytest.raises(planner.ResumePlannerError) as caught:
        _plan((repository, input_root, work_root, request.orchestration_id))

    assert mutation_injected is True
    assert caught.value.code == "snapshot_changed_during_plan"
    assert str(tmp_path) not in str(caught.value)


def test_snapshot_reader_enforces_aggregate_bytes_and_chunked_recheck(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document_path = tmp_path / "document.json"
    source_path = tmp_path / "source.py"
    document_path.write_text('{"value":1}\n', encoding="utf-8")
    source_path.write_bytes(b"source")
    document_size = len(document_path.read_bytes())
    source_size = len(source_path.read_bytes())
    exact_limit = document_size + source_size
    monkeypatch.setattr(planner, "SNAPSHOT_HASH_CHUNK_BYTES", 2)

    reader = planner._SnapshotReader(maximum_total_bytes=exact_limit)
    reader.read(document_path, maximum_bytes=document_size, label="document")
    reader.read_file(source_path, maximum_bytes=source_size, label="source")
    reader.verify_unchanged()

    exceeded = planner._SnapshotReader(maximum_total_bytes=exact_limit - 1)
    exceeded.read(document_path, maximum_bytes=document_size, label="document")
    with pytest.raises(planner.ResumePlannerError) as caught:
        exceeded.read_file(source_path, maximum_bytes=source_size, label="source")

    assert caught.value.code == "snapshot_total_bytes_exceeded"
    assert str(tmp_path) not in str(caught.value)


def test_snapshot_reader_enforces_configurable_file_count_without_path_leak(tmp_path: Path) -> None:
    first = tmp_path / "first.json"
    second = tmp_path / "second.json"
    first.write_text("{}\n", encoding="utf-8")
    second.write_text("{}\n", encoding="utf-8")
    reader = planner._SnapshotReader(maximum_files=1)

    first_size = len(first.read_bytes())
    second_size = len(second.read_bytes())
    reader.read(first, maximum_bytes=first_size, label="first")
    with pytest.raises(planner.ResumePlannerError) as caught:
        reader.read(second, maximum_bytes=second_size, label="second")

    assert caught.value.code == "snapshot_count_exceeded"
    assert str(tmp_path) not in str(caught.value)


def test_plan_is_stable_read_only_and_does_not_expose_local_paths(tmp_path: Path) -> None:
    roots = _fixture(tmp_path)
    before = {path.relative_to(roots[2]).as_posix(): path.read_bytes() for path in roots[2].rglob("*.json")}

    first = _plan(roots)
    second = _plan(roots)
    after = {path.relative_to(roots[2]).as_posix(): path.read_bytes() for path in roots[2].rglob("*.json")}

    assert first == second
    assert first["plan_id"] == second["plan_id"]
    assert first["snapshot_limits"] == {
        "maximum_files": planner.MAX_SNAPSHOT_FILES,
        "maximum_total_bytes": 64 * 1024 * 1024,
        "verification_chunk_bytes": planner.SNAPSHOT_HASH_CHUNK_BYTES,
    }
    assert before == after
    assert str(tmp_path) not in json.dumps(first, ensure_ascii=False)
    assert first["safety"] == {
        "analysis_network_contacted": False,
        "arbitrary_command_executed": False,
        "live_c2_contacted": False,
        "read_only": True,
        "sample_bytes_read": False,
        "sample_executed": False,
        "write_performed": False,
    }


def test_failed_parent_and_child_reports_must_describe_same_failure(tmp_path: Path) -> None:
    roots = _fixture(tmp_path, blocker=None, static_failure=True)
    orchestration_root = roots[2] / "orchestrations" / roots[3]
    state_path = orchestration_root / "state.json"
    report_path = orchestration_root / "report.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    state["workflows"][0]["blockers"] = ["workflow_execution_failed"]
    report["workflows"][0]["blockers"] = ["workflow_execution_failed"]
    state_path.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    report_path.write_text(json.dumps(report, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(planner.ResumePlannerError) as caught:
        _plan(roots)
    assert caught.value.code == "lifecycle_parent_mismatch"


def test_report_tamper_is_rejected_before_planning(tmp_path: Path) -> None:
    roots = _fixture(tmp_path)
    report_path = roots[2] / "orchestrations" / roots[3] / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["forged"] = True
    report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")

    with pytest.raises(planner.ResumePlannerError) as caught:
        _plan(roots)
    assert caught.value.code == "orchestration_report_mismatch"


def test_child_reparse_rejection_is_normalized_without_local_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    roots = _fixture(tmp_path)
    original = lifecycle._reject_existing_reparse_components

    def reject_child(path: Path, *, label: str) -> None:
        if label == "lifecycle state":
            raise OSError(f"private path: {path}")
        original(path, label=label)

    monkeypatch.setattr(lifecycle, "_reject_existing_reparse_components", reject_child)

    with pytest.raises(planner.ResumePlannerError) as caught:
        _plan(roots)

    assert caught.value.code == "lifecycle_path_invalid"
    assert str(tmp_path) not in str(caught.value)


def test_cli_outputs_machine_plan_and_partial_exit_code(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    repository, input_root, work_root, orchestration_id = _fixture(tmp_path)

    exit_code = planner.main(
        [
            "plan-resume",
            "--orchestration-id",
            orchestration_id,
            "--repository",
            str(repository),
            "--input-root",
            str(input_root),
            "--work-root",
            str(work_root),
        ]
    )
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 20
    assert output["schema_version"] == 1
    assert output["status"] == "blocked"
    assert len(output["plan_id"]) == 64
    assert output["workflows"][0]["decision"]["action_id"] == "start_successor_workflow"
    assert output["workflows"][0]["decision"]["successor_required"] is True
    assert output["workflows"][0]["decision"]["eligible"] is False


@pytest.mark.parametrize(
    ("blocker", "target_phase"),
    [
        ("preflight_failed", "preflight"),
        ("publication_failed", "publication"),
        ("function_validation_failed", "function_validation"),
        ("completion_gate_failed", "completion_gate"),
        ("derived_refresh_failed", "derived_refresh"),
        ("private_archive_failed", "private_archive"),
    ],
)
def test_exact_transient_stage_failure_is_resumable_only_when_bound(
    blocker: str,
    target_phase: str,
) -> None:
    record = _synthetic_failed_record([blocker])
    phase = _synthetic_phase(
        target_phase,
        blocker=blocker,
        failure_code=blocker,
    )

    decision, budget, _ = planner._decision_for_record(
        record,
        phases=[phase],
        orchestrator_implementation_matches_current=True,
    )

    assert decision["action_id"] == "resume_workflow"
    assert decision["target_phase"] == target_phase
    assert decision["eligible"] is True
    assert budget["phase"]["remaining"] == lifecycle.MAX_ATTEMPTS - 1


@pytest.mark.parametrize(
    ("status", "failure_code"),
    [
        ("blocked", "publication_failed"),
        ("failed", None),
        ("failed", "static_analysis_failed"),
    ],
)
def test_transient_code_without_matching_failed_stage_fails_closed(
    status: str,
    failure_code: str | None,
) -> None:
    blocker = "publication_failed"
    record = _synthetic_failed_record([blocker])
    phase = _synthetic_phase(
        "publication",
        status=status,
        blocker=blocker,
        failure_code=failure_code,
    )

    decision, _, _ = planner._decision_for_record(
        record,
        phases=[phase],
        orchestrator_implementation_matches_current=True,
    )

    assert decision["action_id"] == "manual_review_required"
    assert decision["eligible"] is False


def test_workflow_execution_failure_requires_exact_parent_envelope() -> None:
    blocker = "workflow_execution_failed"
    valid = _synthetic_failed_record([blocker])
    valid["lifecycle_report_sha256"] = None
    valid["result"] = {
        "error": {
            "code": blocker,
            "message": "workflowを安全に完了できませんでした (RuntimeError)",
        }
    }

    decision, _, _ = planner._decision_for_record(
        valid,
        phases=[],
        orchestrator_implementation_matches_current=True,
    )
    assert decision["action_id"] == "resume_workflow"
    assert decision["eligible"] is True

    invalid = dict(valid)
    invalid["result"] = {"error": {"code": blocker, "message": 1}}
    decision, _, _ = planner._decision_for_record(
        invalid,
        phases=[],
        orchestrator_implementation_matches_current=True,
    )
    assert decision["action_id"] == "manual_review_required"
    assert decision["eligible"] is False


def test_non_retryable_root_blocker_precedes_dependency_marker() -> None:
    record = _synthetic_failed_record(["dependency_not_succeeded", "publication_incomplete"])
    phase = _synthetic_phase(
        "publication",
        status="blocked",
        blocker="publication_incomplete",
        failure_code=None,
    )

    decision, _, _ = planner._decision_for_record(
        record,
        phases=[phase],
        orchestrator_implementation_matches_current=True,
    )

    assert decision["action_id"] == "repair_publication"
    assert decision["retryable"] is False
    assert decision["eligible"] is False


def test_non_retryable_evidence_work_precedes_transient_stage_failure() -> None:
    record = _synthetic_failed_record(["publication_failed", "terminal_payload_not_recovered"])
    publication = _synthetic_phase(
        "publication",
        blocker="publication_failed",
        failure_code="publication_failed",
    )

    decision, _, _ = planner._decision_for_record(
        record,
        phases=[publication],
        orchestrator_implementation_matches_current=True,
    )

    assert decision["action_id"] == "recover_terminal_payload_statically"
    assert decision["target_phase"] == "static_analysis"
    assert decision["retryable"] is False
    assert decision["eligible"] is False


def test_unknown_blocker_stays_manual_when_budget_is_exhausted(tmp_path: Path) -> None:
    result = _plan(
        _fixture(
            tmp_path,
            blocker="future_unreviewed_blocker",
            attempts=orchestrator.MAX_ATTEMPTS,
        )
    )
    decision = result["workflows"][0]["decision"]

    assert decision["action_id"] == "manual_review_required"
    assert decision["blocked_action_id"] is None
    assert decision["successor_required"] is False
    assert decision["eligible"] is False


@pytest.mark.parametrize("implementation_matches", [False, True])
@pytest.mark.parametrize("known_blocker", [None, "terminal_payload_not_recovered"])
def test_partial_unknown_blocker_cannot_be_cleared_by_contract_drift(
    implementation_matches: bool,
    known_blocker: str | None,
) -> None:
    """既知actionや新実装があっても、未知blockerのレビュー要件を残す。"""

    blockers = ["future_unreviewed_blocker"]
    if known_blocker:
        blockers.append(known_blocker)
    record = _synthetic_failed_record(sorted(blockers))
    record["status"] = "partial"
    decision, _, _ = planner._decision_for_record(
        record,
        phases=[],
        orchestrator_implementation_matches_current=implementation_matches,
    )

    assert decision["action_id"] == "manual_review_required"
    assert decision["requires_changed_evidence"] == ["operator_review"]
    assert decision["eligible"] is False
    assert decision["successor_required"] is False
    assert decision["reason_codes"] == sorted(blockers)


def test_partial_retryable_label_requires_bound_failure_envelope() -> None:
    """partial caseに付いた失敗ラベルだけでは新workflowへ進めない。"""

    record = _synthetic_failed_record(["static_analysis_failed"])
    record["status"] = "partial"
    phase = _synthetic_phase(
        "static_analysis",
        status="blocked",
        blocker="static_analysis_failed",
        failure_code=None,
    )
    decision, _, _ = planner._decision_for_record(
        record,
        phases=[phase],
        orchestrator_implementation_matches_current=False,
    )

    assert decision["action_id"] == "manual_review_required"
    assert decision["requires_changed_evidence"] == ["operator_review"]
    assert decision["eligible"] is False


@pytest.mark.parametrize("complete", [False, True])
def test_contract_drift_requires_successor_even_for_complete_or_exhausted(
    tmp_path: Path,
    complete: bool,
) -> None:
    roots = _fixture(
        tmp_path,
        blocker=None if complete else "terminal_payload_not_recovered",
        attempts=1 if complete else orchestrator.MAX_ATTEMPTS,
    )
    state_path = roots[2] / "orchestrations" / roots[3] / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["implementation_sha256"] = "0" * 64
    state_path.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")

    result = _plan(roots)
    decision = result["workflows"][0]["decision"]

    assert result["status"] == "blocked"
    assert decision["action_id"] == "start_successor_workflow"
    assert decision["successor_required"] is True
    assert decision["eligible"] is False


def test_sample_bytes_are_not_read_or_exposed(tmp_path: Path) -> None:
    roots = _fixture(tmp_path)
    marker = "PRIVATE-SAMPLE-BYTES-MUST-NOT-APPEAR"
    sample = roots[1] / "set" / "sample-001.bin"
    sample.write_bytes(marker.encode("ascii"))

    result = _plan(roots)
    rendered = json.dumps(result, ensure_ascii=False)

    assert marker not in rendered
    assert result["safety"]["sample_bytes_read"] is False


def test_cli_complete_and_invalid_state_exit_codes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, input_root, work_root, orchestration_id = _fixture(
        tmp_path,
        blocker=None,
    )
    argv = [
        "plan-resume",
        "--orchestration-id",
        orchestration_id,
        "--repository",
        str(repository),
        "--input-root",
        str(input_root),
        "--work-root",
        str(work_root),
    ]
    assert planner.main(argv) == 0
    complete_output = json.loads(capsys.readouterr().out)
    assert complete_output["status"] == "complete"

    monkeypatch.setattr(orchestrator, "MAX_STATE_BYTES", 64)
    assert planner.main(argv) == 2
    captured = capsys.readouterr()
    error_output = json.loads(captured.err)
    assert captured.out == ""
    assert error_output["error"]["code"] == "orchestration_state_invalid"
    assert str(tmp_path) not in captured.err
