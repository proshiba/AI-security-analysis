"""複数解析lifecycleを統括する直列オーケストレータを検証する。"""

from __future__ import annotations

import importlib
import inspect
import json
from pathlib import Path
import sys
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


def child_state(status: str) -> dict[str, Any]:
    """公開fieldだけを持つ合成child stateを返す。"""

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
        stages[stage] = {"status": stage_status, "blockers": blockers}
    return {"status": status, "stages": stages}


def fake_actions(
    work_root: Path,
    outcomes: dict[str, list[str]],
    calls: list[tuple[str, str]],
    *,
    verification_valid: bool = True,
) -> orchestrator._LifecycleActions:
    """process／networkを使わないchild lifecycle adapterを返す。"""

    def next_state(workflow_id: str) -> dict[str, Any]:
        values = outcomes[workflow_id]
        status = values.pop(0) if len(values) > 1 else values[0]
        state = child_state(status)
        root = work_root / "lifecycles" / workflow_id
        root.mkdir(parents=True, exist_ok=True)
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
        return {"valid": verification_valid}

    return orchestrator._LifecycleActions(run=run, resume=resume, verify=verify)


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


def test_partial_policy_defers_later_children_and_resume_finishes_them(tmp_path: Path) -> None:
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

    assert finished["status"] == "complete"
    assert calls == [
        ("run", "sample-001"),
        ("resume", "sample-001"),
        ("run", "sample-002"),
    ]


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

    with orchestrator.analysis_lifecycle._execution_lock(context.orchestration_root):
        with pytest.raises(orchestrator.OrchestrationError) as caught:
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
    assert ("resume", "sample-002") not in calls
