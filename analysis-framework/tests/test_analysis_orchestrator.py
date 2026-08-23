"""複数解析lifecycleを統括する直列オーケストレータを検証する。"""

from __future__ import annotations

import importlib
import inspect
import json
import sys
from pathlib import Path
from typing import Any

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

orchestrator = importlib.import_module("analysis_orchestrator")


def lifecycle_request(
    workflow_id: str,
    *,
    refresh: bool = False,
    archive: bool = False,
) -> dict[str, Any]:
    """固定schemaのchild lifecycle requestを返す。"""

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
            "enabled": refresh,
            "manifest": "analysis-results/research/acquisition.json" if refresh else None,
            "collection_id": f"collection-{workflow_id}" if refresh else None,
            "expected_contract_sha256": None,
            "allow_partial_staging": False,
        },
        "maintenance": {"refresh_repository": refresh},
        "private_archive": {
            "enabled": archive,
            "target": f"archive-{workflow_id}" if archive else None,
            "include": ["inputs", "job_output"] if archive else [],
        },
    }


def orchestration_value(
    workflow_ids: tuple[str, ...] = ("sample-001", "sample-002"),
    *,
    continue_after_partial: bool = True,
    continue_after_failure: bool = False,
) -> dict[str, Any]:
    """固定schemaの一括requestを返す。"""

    return {
        "schema_version": 1,
        "orchestration_id": "daily-orchestration-001",
        "workflows": [lifecycle_request(item) for item in workflow_ids],
        "policy": {
            "continue_after_partial": continue_after_partial,
            "continue_after_failure": continue_after_failure,
        },
    }


def make_roots(
    tmp_path: Path,
    workflow_ids: tuple[str, ...] = ("sample-001", "sample-002"),
    *,
    publication: bool = False,
) -> tuple[Path, Path, Path]:
    """repository、input、workの分離rootを作る。"""

    repository = tmp_path / "repository"
    common = repository / "analysis-framework" / "common"
    common.mkdir(parents=True)
    (common / "analyze_sample.py").write_text("# fixture\n", encoding="utf-8")
    (common / "publish_one_shot_collection.py").write_text("# fixture\n", encoding="utf-8")
    (repository / "analysis-results").mkdir()
    (repository / "ui").mkdir()
    if publication:
        manifest = repository / "analysis-results" / "research" / "acquisition.json"
        manifest.parent.mkdir()
        manifest.write_text("{}\n", encoding="utf-8")
    input_root = tmp_path / "inputs"
    for workflow_id in workflow_ids:
        sample = input_root / "set" / f"{workflow_id}.bin"
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_bytes(f"MZ synthetic {workflow_id}".encode())
    work_root = tmp_path / "work"
    work_root.mkdir()
    return repository, input_root, work_root


def child_state(
    status: str,
    *,
    workflow_id: str = "sample-001",
    attempts: int = 1,
) -> dict[str, Any]:
    """親recordへ再導出できる合成child stateを返す。"""

    stages: dict[str, dict[str, Any]] = {}
    for stage in orchestrator.analysis_lifecycle.STAGE_ORDER:
        stage_status = "succeeded" if status == "complete" else "skipped"
        blockers: list[str] = []
        if status == "partial" and stage == "completion_gate":
            stage_status = "blocked"
            blockers = ["terminal_payload_not_recovered"]
        if status == "failed" and stage == "static_analysis":
            stage_status = "failed"
            blockers = ["static_analysis_failed"]
        stages[stage] = {
            "status": stage_status,
            "enabled": True,
            "attempts": attempts,
            "fingerprint": orchestrator.analysis_lifecycle._sha256_value({"stage": stage}),
            "blockers": blockers,
        }
    request_sha256 = orchestrator.analysis_lifecycle._sha256_value(
        orchestrator.analysis_lifecycle.validate_request_object(lifecycle_request(workflow_id)).public()
    )
    return {
        "workflow_id": workflow_id,
        "request_sha256": request_sha256,
        "status": status,
        "stages": stages,
    }


def structured_completion_result(cases: list[dict[str, Any]], blockers: list[str]) -> dict[str, Any]:
    """公開case/blockerからcanonical remediation planを組み立てる。"""

    actions = orchestrator.analysis_lifecycle._remediation_actions(cases, blockers)
    return {
        "cases": cases,
        "blockers": blockers,
        "remediation_actions": actions,
        "next_actions": orchestrator.analysis_lifecycle._next_actions(actions),
        "remediation_plan_sha256": orchestrator.analysis_lifecycle._sha256_value(
            {"actions": actions}
        ),
    }


def fake_actions(
    work_root: Path,
    outcomes: dict[str, list[str]],
    calls: list[tuple[str, str]],
    *,
    verification_valid: bool = True,
) -> orchestrator._LifecycleActions:
    """process／networkを使わないchild lifecycle adapterを返す。"""

    def state_path(workflow_id: str) -> Path:
        return work_root / "lifecycles" / workflow_id / "state.json"

    def load_state(workflow_id: str) -> dict[str, Any]:
        return json.loads(state_path(workflow_id).read_text(encoding="utf-8"))

    def next_state(workflow_id: str) -> dict[str, Any]:
        values = outcomes[workflow_id]
        status = values.pop(0) if len(values) > 1 else values[0]
        path = state_path(workflow_id)
        attempts = 1
        if path.is_file():
            previous = json.loads(path.read_text(encoding="utf-8"))
            attempts = max(item["attempts"] for item in previous["stages"].values()) + 1
        state = child_state(status, workflow_id=workflow_id, attempts=attempts)
        root = path.parent
        root.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
        (root / "report.json").write_text(
            json.dumps({"workflow_id": workflow_id, "status": status}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return state

    def run(request: Any, **_kwargs: Any) -> dict[str, Any]:
        calls.append(("run", request.workflow_id))
        return next_state(request.workflow_id)

    def resume(workflow_id: str, **_kwargs: Any) -> dict[str, Any]:
        calls.append(("resume", workflow_id))
        return next_state(workflow_id)

    def verify(workflow_id: str, **_kwargs: Any) -> dict[str, Any]:
        calls.append(("verify", workflow_id))
        state = load_state(workflow_id)
        errors = [] if verification_valid else ["fixture_verification_failed"]
        return {
            "schema_version": orchestrator.analysis_lifecycle.SCHEMA_VERSION,
            "workflow_id": workflow_id,
            "valid": verification_valid,
            "errors": errors,
            "request_sha256": state["request_sha256"],
            "stage_status": {
                stage: state["stages"][stage]["status"]
                for stage in orchestrator.analysis_lifecycle.STAGE_ORDER
            },
            "sample_executed": False,
            "analysis_network_contacted": False,
        }

    def snapshot(workflow_id: str, **_kwargs: Any) -> dict[str, Any]:
        report_path = work_root / "lifecycles" / workflow_id / "report.json"
        return {
            "state": load_state(workflow_id),
            "report_sha256": orchestrator.analysis_lifecycle._sha256_file(report_path),
        }

    return orchestrator._LifecycleActions(
        run=run,
        resume=resume,
        verify=verify,
        snapshot=snapshot,
    )


def test_schema_rejects_arbitrary_fields_and_duplicate_ids() -> None:
    schema = orchestrator.request_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["workflows"]["items"] == (
        orchestrator.analysis_lifecycle.request_json_schema()
    )

    arbitrary = orchestration_value()
    arbitrary["command"] = "powershell.exe"
    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator.validate_request_object(arbitrary)
    assert caught.value.code == "request_schema_invalid"

    duplicate = orchestration_value(("sample-001", "sample-001"))
    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator.validate_request_object(duplicate)
    assert caught.value.code == "workflow_id_duplicate"


def test_refresh_is_unique_and_last() -> None:
    value = orchestration_value(("sample-001", "sample-002"))
    value["workflows"][0] = lifecycle_request("sample-001", refresh=True)

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator.validate_request_object(value)
    assert caught.value.code == "repository_refresh_order_invalid"


def test_plan_is_sequential_and_only_child_archive_can_use_network() -> None:
    value = orchestration_value(("sample-001", "sample-002"))
    value["workflows"][1] = lifecycle_request("sample-002", archive=True)
    request = orchestrator.validate_request_object(value)

    plan = orchestrator.build_plan(request)

    assert plan["execution"]["mode"] == "sequential"
    assert plan["execution"]["maximum_parallel_workflows"] == 1
    assert [item["runs_after"] for item in plan["workflows"]] == [None, "sample-001"]
    assert plan["safety"] == {
        "analysis_network_allowed": False,
        "arbitrary_commands_allowed": False,
        "arbitrary_modules_allowed": False,
        "datastore_network_enabled": True,
        "live_c2_allowed": False,
        "repository_writes_serialized": True,
        "sample_execution_allowed": False,
    }


def test_public_run_has_no_action_injection_seam() -> None:
    parameters = inspect.signature(orchestrator.run_orchestration).parameters
    assert "actions" not in parameters
    assert "command" not in parameters
    assert "run_process" not in parameters


def test_complete_orchestration_runs_children_in_manifest_order(tmp_path: Path) -> None:
    workflow_ids = ("sample-001", "sample-002", "sample-003")
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    calls: list[tuple[str, str]] = []

    state = orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions(
            work_root,
            {item: ["complete"] for item in workflow_ids},
            calls,
        ),
    )

    assert state["status"] == "complete"
    assert calls == [("run", item) for item in workflow_ids]
    report = orchestrator.read_status(work_root, request.orchestration_id)
    assert report["status"] == "complete"
    assert report["safety"]["repository_writes_serialized"] is True
    assert str(tmp_path) not in json.dumps(report, ensure_ascii=False)


def test_partial_policy_requires_successor_without_blind_resume(tmp_path: Path) -> None:
    workflow_ids = ("sample-001", "sample-002")
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(
        orchestration_value(workflow_ids, continue_after_partial=False)
    )
    calls: list[tuple[str, str]] = []
    actions = fake_actions(
        work_root,
        {"sample-001": ["partial", "complete"], "sample-002": ["complete"]},
        calls,
    )
    first = orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )

    assert first["status"] == "partial"
    assert [record["status"] for record in first["workflows"]] == ["partial", "deferred"]
    assert calls == [("run", "sample-001")]

    context, saved = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    with orchestrator.analysis_lifecycle._execution_lock(context.orchestration_root):
        finished = orchestrator._execute(context, saved, actions)

    assert finished["status"] == "partial"
    assert [record["status"] for record in finished["workflows"]] == ["partial", "deferred"]
    assert calls == [("run", "sample-001"), ("verify", "sample-001")]
    assert finished["workflows"][0]["attempts"] == 1
    assert finished["workflows"][0]["result"]["same_workflow_resume_allowed"] is False
    assert finished["workflows"][0]["result"]["next_actions"] == [
        "terminal_payload_static_recovery"
    ]


def test_continue_policy_runs_other_children_but_does_not_repeat_partial(tmp_path: Path) -> None:
    workflow_ids = ("sample-001", "sample-002")
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    calls: list[tuple[str, str]] = []
    actions = fake_actions(
        work_root,
        {"sample-001": ["partial", "complete"], "sample-002": ["complete"]},
        calls,
    )
    first = orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )
    context, saved = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    with orchestrator.analysis_lifecycle._execution_lock(context.orchestration_root):
        second = orchestrator._execute(context, saved, actions)

    assert first["status"] == "partial"
    assert second["status"] == "partial"
    assert calls.count(("run", "sample-001")) == 1
    assert ("resume", "sample-001") not in calls
    assert calls.count(("run", "sample-002")) == 1


def test_continue_after_failure_runs_remaining_children(tmp_path: Path) -> None:
    workflow_ids = ("sample-001", "sample-002")
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(
        orchestration_value(workflow_ids, continue_after_failure=True)
    )
    calls: list[tuple[str, str]] = []

    state = orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions(
            work_root,
            {"sample-001": ["failed"], "sample-002": ["complete"]},
            calls,
        ),
    )

    assert state["status"] == "failed"
    assert calls == [("run", "sample-001"), ("run", "sample-002")]


def test_completed_child_is_verified_not_repeated_on_resume(tmp_path: Path) -> None:
    workflow_ids = ("sample-001", "sample-002")
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    calls: list[tuple[str, str]] = []
    first_actions = fake_actions(
        work_root,
        {"sample-001": ["complete"], "sample-002": ["failed"]},
        calls,
    )
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=first_actions,
    )
    context, saved = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    second_actions = fake_actions(
        work_root,
        {"sample-001": ["complete"], "sample-002": ["complete"]},
        calls,
    )

    with orchestrator.analysis_lifecycle._execution_lock(context.orchestration_root):
        finished = orchestrator._execute(context, saved, second_actions)

    assert finished["status"] == "complete"
    assert calls.count(("run", "sample-001")) == 1
    assert ("verify", "sample-001") in calls
    assert ("resume", "sample-002") in calls
    assert finished["workflows"][1]["result"]["same_workflow_resume_allowed"] is False


def test_malformed_child_remediation_plan_fails_closed(tmp_path: Path) -> None:
    state = child_state("partial")
    state["stages"]["completion_gate"]["result"] = {
        "remediation_actions": [{"action_id": "terminal_payload_static_recovery"}],
        "next_actions": ["terminal_payload_static_recovery"],
        "remediation_plan_sha256": "0" * 64,
    }

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._record_result(state)

    assert caught.value.code == "lifecycle_remediation_invalid"


def test_structured_remediation_plan_matches_public_case_blockers() -> None:
    state = child_state("partial")
    digest = "a" * 64
    case = {
        "sha256": digest,
        "status": "partial",
        "report_blockers": ["terminal_payload_not_recovered"],
        "orchestration_blockers": [],
    }
    state["stages"]["completion_gate"]["result"] = structured_completion_result(
        [case],
        ["terminal_payload_not_recovered"],
    )

    result = orchestrator._record_result(state)

    assert result["next_actions"] == ["terminal_payload_static_recovery"]
    assert orchestrator.analysis_lifecycle.SHA256_RE.fullmatch(
        result["remediation_plan_sha256"]
    )


def test_orphan_remediation_action_is_rejected() -> None:
    state = child_state("partial")
    case = {
        "sha256": "a" * 64,
        "status": "partial",
        "report_blockers": ["terminal_payload_not_recovered"],
        "orchestration_blockers": [],
    }
    result = structured_completion_result([case], ["terminal_payload_not_recovered"])
    orphan = dict(result["remediation_actions"][0])
    orphan["case_sha256"] = "b" * 64
    result["remediation_actions"] = [orphan]
    result["remediation_plan_sha256"] = orchestrator.analysis_lifecycle._sha256_value(
        {"actions": [orphan]}
    )
    state["stages"]["completion_gate"]["result"] = result

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._record_result(state)

    assert caught.value.code == "lifecycle_remediation_invalid"


def test_missing_remediation_action_is_rejected() -> None:
    state = child_state("partial")
    case = {
        "sha256": "a" * 64,
        "status": "partial",
        "report_blockers": ["terminal_payload_not_recovered"],
        "orchestration_blockers": [],
    }
    result = structured_completion_result([case], ["terminal_payload_not_recovered"])
    result["remediation_actions"] = []
    result["next_actions"] = []
    result["remediation_plan_sha256"] = orchestrator.analysis_lifecycle._sha256_value(
        {"actions": []}
    )
    state["stages"]["completion_gate"]["result"] = result

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._record_result(state)

    assert caught.value.code == "lifecycle_remediation_invalid"


def test_semantically_forged_remediation_action_fails_closed() -> None:
    state = child_state("partial")
    action = {
        "case_sha256": None,
        "blocker_code": "unknown_blocker",
        "action_id": "run_unregistered_action",
        "target_phase": "static_analysis",
        "executor": "analysis_job_runner",
        "automatic": True,
        "requires_changed_evidence": False,
        "prerequisites": [],
    }
    actions = [action]
    state["stages"]["completion_gate"]["result"] = {
        "remediation_actions": actions,
        "next_actions": ["run_unregistered_action"],
        "remediation_plan_sha256": orchestrator.analysis_lifecycle._sha256_value({"actions": actions}),
    }

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._record_result(state)

    assert caught.value.code == "lifecycle_remediation_invalid"


def test_duplicate_remediation_actions_are_not_canonical() -> None:
    state = child_state("partial")
    case = {
        "sha256": "a" * 64,
        "status": "partial",
        "report_blockers": ["terminal_payload_not_recovered"],
        "orchestration_blockers": [],
    }
    result = structured_completion_result(
        [case],
        ["terminal_payload_not_recovered"],
    )
    action = result["remediation_actions"][0]
    result["remediation_actions"] = [action, dict(action)]
    result["remediation_plan_sha256"] = orchestrator.analysis_lifecycle._sha256_value(
        {"actions": result["remediation_actions"]}
    )
    state["stages"]["completion_gate"]["result"] = result

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._record_result(state)

    assert caught.value.code == "lifecycle_remediation_invalid"


def test_malformed_remediation_arrays_fail_closed_without_type_error() -> None:
    state = child_state("partial")
    action = orchestrator.analysis_lifecycle._remediation_action(
        "terminal_payload_not_recovered",
        case_sha256=None,
    )
    action["prerequisites"] = [{}]
    actions = [action]
    state["stages"]["completion_gate"]["result"] = {
        "remediation_actions": actions,
        "next_actions": ["terminal_payload_static_recovery"],
        "remediation_plan_sha256": orchestrator.analysis_lifecycle._sha256_value({"actions": actions}),
    }

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._record_result(state)

    assert caught.value.code == "lifecycle_remediation_invalid"

    record = {"status": "partial", "result": orchestrator._record_result(child_state("partial"))}
    record["result"]["next_actions"] = [{}]
    assert orchestrator._completed_result_valid(record) is False

    malformed_blockers = child_state("partial")
    malformed_blockers["stages"]["completion_gate"]["blockers"] = "terminal_payload_not_recovered"
    assert orchestrator._record_blockers(malformed_blockers) == ["analysis_blocked"]


def test_explicit_null_remediation_fields_do_not_use_legacy_fallback() -> None:
    state = child_state("partial")
    state["stages"]["completion_gate"]["result"] = {
        "remediation_actions": None,
        "next_actions": None,
        "remediation_plan_sha256": None,
    }

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._record_result(state)

    assert caught.value.code == "lifecycle_remediation_invalid"


def test_verify_detects_child_report_change_without_writing_state(tmp_path: Path) -> None:
    workflow_ids = ("sample-001",)
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    calls: list[tuple[str, str]] = []
    actions = fake_actions(work_root, {"sample-001": ["complete"]}, calls)
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )
    context, state = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    state_path = context.orchestration_root / "state.json"
    before = state_path.read_bytes()
    report_path = work_root / "lifecycles" / "sample-001" / "report.json"
    report_path.write_text('{"changed":true}\n', encoding="utf-8")

    errors = orchestrator._verification_errors(context, state, actions)

    assert "lifecycle_report_mismatch:sample-001" in errors
    assert state_path.read_bytes() == before


def test_saved_state_schema_tamper_is_rejected(tmp_path: Path) -> None:
    workflow_ids = ("sample-001",)
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions(work_root, {"sample-001": ["complete"]}, []),
    )
    state_path = work_root / "orchestrations" / request.orchestration_id / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["workflows"][0]["attempts"] = "1"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._existing_context(
            request.orchestration_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=60,
        )
    assert caught.value.code == "state_invalid"


@pytest.mark.parametrize("mutation", ["missing_child_report_hash", "overall_status_mismatch"])
def test_saved_state_semantic_tamper_is_rejected(tmp_path: Path, mutation: str) -> None:
    """型が正しくてもstatusと成果物の意味が矛盾するstateを拒否する。"""

    workflow_ids = ("sample-001",)
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions(work_root, {"sample-001": ["complete"]}, []),
    )
    state_path = work_root / "orchestrations" / request.orchestration_id / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if mutation == "missing_child_report_hash":
        state["workflows"][0]["lifecycle_report_sha256"] = None
    else:
        state["status"] = "partial"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._existing_context(
            request.orchestration_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=60,
        )
    assert caught.value.code == "state_invalid"


def test_completed_child_verification_failure_does_not_mutate_state(tmp_path: Path) -> None:
    """成功済みchildの検証失敗はrunningへ遷移する前に停止する。"""

    workflow_ids = ("sample-001",)
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions(work_root, {"sample-001": ["complete"]}, []),
    )
    context, state = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    state_path = context.orchestration_root / "state.json"
    before = state_path.read_bytes()
    invalid_actions = fake_actions(
        work_root,
        {"sample-001": ["complete"]},
        [],

        verification_valid=False,
    )

    with orchestrator.analysis_lifecycle._execution_lock(
        context.orchestration_root
    ), pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._execute(context, state, invalid_actions)

    assert caught.value.code == "completed_workflow_changed"
    assert state_path.read_bytes() == before


def test_resume_rejects_foreign_lifecycle_for_deferred_child(tmp_path: Path) -> None:
    """未開始childの既存directoryを外部成果物として流用しない。"""

    workflow_ids = ("sample-001", "sample-002")
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(
        orchestration_value(workflow_ids, continue_after_partial=False)
    )
    calls: list[tuple[str, str]] = []
    actions = fake_actions(
        work_root,
        {"sample-001": ["partial", "complete"], "sample-002": ["complete"]},
        calls,
    )
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )
    foreign = work_root / "lifecycles" / "sample-002"
    foreign.mkdir(parents=True)
    (foreign / "report.json").write_text('{"foreign":true}\n', encoding="utf-8")
    context, state = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )

    with orchestrator.analysis_lifecycle._execution_lock(context.orchestration_root):
        finished = orchestrator._execute(context, state, actions)


    assert finished["status"] == "failed"
    assert finished["workflows"][1]["status"] == "failed"
    assert finished["workflows"][1]["blockers"] == ["unexpected_lifecycle_state"]
    assert ("run", "sample-002") not in calls


def test_partial_child_report_change_is_rejected_before_skip(tmp_path: Path) -> None:
    workflow_ids = ("sample-001", "sample-002")
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(
        orchestration_value(workflow_ids, continue_after_partial=False)
    )
    calls: list[tuple[str, str]] = []
    actions = fake_actions(
        work_root,
        {"sample-001": ["partial"], "sample-002": ["complete"]},
        calls,
    )
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )
    context, state = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    state_path = context.orchestration_root / "state.json"
    before = state_path.read_bytes()
    report_path = work_root / "lifecycles" / "sample-001" / "report.json"
    report_path.write_text('{"tampered":true}\n', encoding="utf-8")

    with orchestrator.analysis_lifecycle._execution_lock(
        context.orchestration_root
    ), pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._execute(context, state, actions)

    assert caught.value.code == "completed_workflow_changed"
    assert state_path.read_bytes() == before
    assert calls == [("run", "sample-001"), ("verify", "sample-001")]


@pytest.mark.parametrize("status", ["complete", "partial"])
def test_terminal_record_is_exactly_bound_to_child_snapshot(
    tmp_path: Path,
    status: str,
) -> None:
    workflow_ids = ("sample-001",)
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    calls: list[tuple[str, str]] = []
    actions = fake_actions(work_root, {"sample-001": [status]}, calls)
    state = orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )
    context, saved = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )

    record = state["workflows"][0]
    assert len(record["result"]["lifecycle_state_sha256"]) == 64
    assert len(record["result"]["lifecycle_implementation_sha256"]) == 64
    assert orchestrator._verification_errors(context, saved, actions) == []


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ("status", "lifecycle_parent_mismatch:sample-001"),
        ("attempts", "lifecycle_parent_mismatch:sample-001"),
        ("blockers", "lifecycle_parent_mismatch:sample-001"),
        ("next_action", "lifecycle_parent_mismatch:sample-001"),
        ("remediation_digest", "lifecycle_parent_mismatch:sample-001"),
        ("lifecycle_digest", "lifecycle_parent_mismatch:sample-001"),
        ("implementation_digest", "lifecycle_parent_mismatch:sample-001"),
        ("report_digest", "lifecycle_report_mismatch:sample-001"),
    ],
)
def test_terminal_parent_and_matching_parent_report_cannot_forge_child(
    tmp_path: Path,
    mutation: str,
    expected_error: str,
) -> None:
    workflow_ids = ("sample-001",)
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(orchestration_value(workflow_ids))
    actions = fake_actions(work_root, {"sample-001": ["complete"]}, [])
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )
    context, state = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    record = state["workflows"][0]
    if mutation == "status":
        record["status"] = "partial"
        record["result"]["lifecycle_status"] = "partial"
        state["status"] = "partial"
    elif mutation == "attempts":
        record["attempts"] += 1
    elif mutation == "blockers":
        record["blockers"] = ["forged_blocker"]
    elif mutation == "next_action":
        record["result"]["next_actions"] = ["forged_action"]
    elif mutation == "remediation_digest":
        record["result"]["remediation_plan_sha256"] = "1" * 64
    elif mutation == "lifecycle_digest":
        record["result"]["lifecycle_state_sha256"] = "2" * 64
    elif mutation == "implementation_digest":
        record["result"]["lifecycle_implementation_sha256"] = "3" * 64
    else:
        record["lifecycle_report_sha256"] = "4" * 64

    state_path = context.orchestration_root / "state.json"
    report_path = context.orchestration_root / "report.json"
    state_path.write_text(json.dumps(state, sort_keys=True) + "\n", encoding="utf-8")
    report_path.write_text(
        json.dumps(orchestrator._public_report_from_state(context, state), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    context, reloaded = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    before = state_path.read_bytes()

    errors = orchestrator._verification_errors(context, reloaded, actions)
    assert expected_error in errors
    with orchestrator.analysis_lifecycle._execution_lock(
        context.orchestration_root
    ), pytest.raises(orchestrator.OrchestrationError) as caught:
        orchestrator._execute(context, reloaded, actions)

    assert caught.value.code == "completed_workflow_changed"
    assert state_path.read_bytes() == before


def test_all_foreign_deferred_lifecycles_are_normalized(tmp_path: Path) -> None:
    workflow_ids = ("sample-001", "sample-002", "sample-003")
    repository, input_root, work_root = make_roots(tmp_path, workflow_ids)
    request = orchestrator.validate_request_object(
        orchestration_value(workflow_ids, continue_after_partial=False)
    )
    calls: list[tuple[str, str]] = []
    actions = fake_actions(
        work_root,
        {
            "sample-001": ["partial"],
            "sample-002": ["complete"],
            "sample-003": ["complete"],
        },
        calls,
    )
    orchestrator._run_orchestration_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )
    for workflow_id in workflow_ids[1:]:
        foreign = work_root / "lifecycles" / workflow_id
        foreign.mkdir(parents=True)
        (foreign / "report.json").write_text('{"foreign":true}\n', encoding="utf-8")
    context, state = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )

    with orchestrator.analysis_lifecycle._execution_lock(context.orchestration_root):
        finished = orchestrator._execute(context, state, actions)

    assert finished["status"] == "failed"
    assert [record["status"] for record in finished["workflows"]] == [
        "partial",
        "failed",
        "failed",
    ]
    assert all(
        record["blockers"] == ["unexpected_lifecycle_state"]
        for record in finished["workflows"][1:]
    )
    _, reloaded = orchestrator._existing_context(
        request.orchestration_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    assert reloaded == finished
    assert ("resume", "sample-002") not in calls
