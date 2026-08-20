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
    ],
)
def test_exact_and_prefix_blockers_have_deterministic_root_action(
    tmp_path: Path,
    blocker: str,
    action_id: str,
    target_phase: str,
) -> None:
    result = _plan(_fixture(tmp_path, blocker=blocker))
    decision = result["workflows"][0]["decision"]

    assert result["status"] == "blocked"
    assert decision["action_id"] == action_id
    assert decision["target_phase"] == target_phase
    assert decision["eligible"] is False
    assert decision["retryable"] is False
    assert decision["requires_changed_evidence"]


def test_unknown_or_malformed_prefix_blocker_fails_closed(tmp_path: Path) -> None:
    result = _plan(
        _fixture(
            tmp_path,
            blocker="selected_family_has_no_automatic_handler:bad:family",
        )
    )
    decision = result["workflows"][0]["decision"]

    assert decision["action_id"] == "manual_review_required"
    assert decision["eligible"] is False
    assert decision["retryable"] is False
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


def test_same_evidence_multiple_attempts_engages_no_progress_guard(tmp_path: Path) -> None:
    result = _plan(
        _fixture(
            tmp_path,
            blocker=None,
            static_failure=True,
            attempts=2,
        )
    )
    workflow = result["workflows"][0]

    assert workflow["no_progress"]["detected"] is True
    assert workflow["retry_budget"]["workflow"]["history_complete"] is False
    assert workflow["decision"]["action_id"] == "wait_for_evidence_change"
    assert workflow["decision"]["blocked_action_id"] == "resume_workflow"
    assert workflow["decision"]["eligible"] is False


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
    assert decision["successor_required"] is True
    assert decision["eligible"] is False


def test_stale_phase_fingerprint_requires_successor_workflow(tmp_path: Path) -> None:
    roots = _fixture(tmp_path)
    child_state_path = roots[2] / "lifecycles" / "sample-001" / "state.json"
    state = json.loads(child_state_path.read_text(encoding="utf-8"))
    state["stages"]["completion_gate"]["fingerprint"] = "0" * 64
    child_state_path.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")

    result = _plan(roots)
    decision = result["workflows"][0]["decision"]

    assert decision["action_id"] == "start_successor_workflow"
    assert decision["target_phase"] == "completion_gate"
    assert decision["successor_required"] is True


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
        source_names = {
            name
            for stage_names in lifecycle.STAGE_CODE_FILES.values()
            for name in stage_names
        }
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


def test_plan_is_stable_read_only_and_does_not_expose_local_paths(tmp_path: Path) -> None:
    roots = _fixture(tmp_path)
    before = {
        path.relative_to(roots[2]).as_posix(): path.read_bytes()
        for path in roots[2].rglob("*.json")
    }

    first = _plan(roots)
    second = _plan(roots)
    after = {
        path.relative_to(roots[2]).as_posix(): path.read_bytes()
        for path in roots[2].rglob("*.json")
    }

    assert first == second
    assert first["plan_id"] == second["plan_id"]
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
