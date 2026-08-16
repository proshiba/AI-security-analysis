"""識別から公開・保管までの固定lifecycle runnerを検証する。"""

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

lifecycle = importlib.import_module("analysis_lifecycle")


def request_value(
    workflow_id: str = "lifecycle-001",
    *,
    publication: bool = False,
    refresh: bool = False,
    archive: bool = False,
    allow_partial: bool = False,
) -> dict[str, Any]:
    """固定schemaの最小requestを返す。"""

    return {
        "schema_version": 1,
        "workflow_id": workflow_id,
        "job": {
            "schema_version": 1,
            "job_id": workflow_id,
            "inputs": ["set/sample.bin"],
            "options": {},
        },
        "publication": {
            "enabled": publication,
            "manifest": "analysis-results/research/acquisition.json" if publication else None,
            "collection_id": "daily-static-collection" if publication else None,
            "expected_contract_sha256": None,
            "allow_partial_staging": allow_partial,
        },
        "maintenance": {"refresh_repository": refresh},
        "private_archive": {
            "enabled": archive,
            "target": "daily-static-target" if archive else None,
            "include": ["inputs", "job_output"] if archive else [],
        },
    }


def make_roots(tmp_path: Path, *, publication: bool = False) -> tuple[Path, Path, Path]:
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
    sample = input_root / "set" / "sample.bin"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(b"MZ synthetic static input")
    work_root = tmp_path / "work"
    work_root.mkdir()
    return repository, input_root, work_root


def fake_actions(
    calls: list[str],
    *,
    analysis_state: str = "complete",
    completion: str = "succeeded",
) -> lifecycle._Actions:
    """processやnetworkを使わない固定stage test adapterを返す。"""

    def outcome(stage: str, result: dict[str, Any]) -> lifecycle.StageOutcome:
        calls.append(stage)
        return lifecycle.StageOutcome("succeeded", result)

    def preflight(*_: Any) -> lifecycle.StageOutcome:
        return outcome("preflight", {"valid": True})

    def static(*_: Any) -> lifecycle.StageOutcome:
        return outcome(
            "static_analysis",
            {
                "analysis_state": analysis_state,
                "result_sha256": "a" * 64,
                "summary_sha256": "b" * 64,
            },
        )

    def publication(*_: Any) -> lifecycle.StageOutcome:
        return outcome(
            "publication",
            {
                "published": 1,
                "collection": "analysis-results/collections/daily-static-collection",
            },
        )

    def function_validation(*_: Any) -> lifecycle.StageOutcome:
        return outcome("function_validation", {"complete": True, "invalid_cases": 0})

    def completion_gate(*_: Any) -> lifecycle.StageOutcome:
        calls.append("completion_gate")
        if completion == "blocked":
            blocker = "terminal_payload_not_recovered"
            return lifecycle.StageOutcome(
                "blocked",
                {"complete": False, "blockers": [blocker]},
                (blocker,),
            )
        return lifecycle.StageOutcome("succeeded", {"complete": True, "blockers": []})

    def refresh(*_: Any) -> lifecycle.StageOutcome:
        return outcome("derived_refresh", {"repository_verification_passed": True})

    def archive(*_: Any) -> lifecycle.StageOutcome:
        return outcome(
            "private_archive",
            {
                "status": "verified",
                "archive_sha256": "c" * 64,
                "manifest_sha256": "d" * 64,
                "network_contacted": True,
            },
        )

    return lifecycle._Actions(
        preflight=preflight,
        static_analysis=static,
        publication=publication,
        function_validation=function_validation,
        completion_gate=completion_gate,
        derived_refresh=refresh,
        private_archive=archive,
    )


def test_schema_and_request_reject_arbitrary_execution_fields() -> None:
    schema = lifecycle.request_json_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["job"] == lifecycle.analysis_job_runner.job_request_json_schema()

    top_level = request_value()
    top_level["command"] = "powershell.exe"
    with pytest.raises(lifecycle.LifecycleError, match="key集合"):
        lifecycle.validate_request_object(top_level)

    job_option = request_value()
    job_option["job"]["options"]["command"] = "calc.exe"
    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle.validate_request_object(job_option)
    assert caught.value.code == "network_or_privileged_option_forbidden"

    archive_source = request_value(archive=True)
    archive_source["private_archive"]["source"] = "C:/arbitrary"
    with pytest.raises(lifecycle.LifecycleError, match="key集合"):
        lifecycle.validate_request_object(archive_source)


def test_disabled_stages_require_null_or_empty_fields() -> None:
    publication = request_value()
    publication["publication"]["manifest"] = "analysis-results/research/acquisition.json"
    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle.validate_request_object(publication)
    assert caught.value.code == "publication_disabled_fields"

    archive = request_value()
    archive["private_archive"]["include"] = ["inputs"]
    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle.validate_request_object(archive)
    assert caught.value.code == "archive_disabled_fields"


def test_plan_exposes_fixed_graph_and_only_archive_can_use_network() -> None:
    request = lifecycle.validate_request_object(request_value(archive=True))
    plan = lifecycle.build_plan(request)

    assert [item["id"] for item in plan["stages"]] == list(lifecycle.STAGE_ORDER)
    assert [item["id"] for item in plan["stages"] if item["external_network"]] == ["private_archive"]
    assert all(item["sample_execution"] is False for item in plan["stages"])
    assert plan["safety"] == {
        "arbitrary_commands_allowed": False,
        "arbitrary_modules_allowed": False,
        "sample_execution_allowed": False,
        "live_c2_allowed": False,
        "analysis_network_allowed": False,
        "datastore_network_enabled": True,
    }


def test_public_run_has_no_action_or_process_injection_seam() -> None:
    parameters = inspect.signature(lifecycle.run_lifecycle).parameters
    assert "actions" not in parameters
    assert "run_process" not in parameters
    assert "command" not in parameters


def test_complete_lifecycle_runs_enabled_stages_and_writes_public_report(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path, publication=True)
    request = lifecycle.validate_request_object(
        request_value(publication=True, refresh=True, archive=True)
    )
    calls: list[str] = []

    state = lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions(calls),
    )

    assert state["status"] == "complete"
    assert calls == list(lifecycle.STAGE_ORDER)
    report_path = work_root / "lifecycles" / request.workflow_id / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["status"] == "complete"
    assert report["safety"] == {
        "analysis_network_contacted": False,
        "arbitrary_command_executed": False,
        "datastore_network_contacted": True,
        "live_c2_contacted": False,
        "sample_executed": False,
    }
    assert str(tmp_path) not in report_path.read_text(encoding="utf-8")


def test_partial_completion_is_resumable_without_repeating_succeeded_stages(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("resume-001"))
    calls: list[str] = []
    first_actions = fake_actions(calls, analysis_state="partial", completion="blocked")
    state = lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=first_actions,
    )
    assert state["status"] == "partial"
    assert state["stages"]["completion_gate"]["blockers"] == ["terminal_payload_not_recovered"]

    context, resumed = lifecycle._resume_context(
        request.workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        verify_succeeded_artifacts=False,
    )
    second_actions = fake_actions(calls, analysis_state="complete", completion="succeeded")
    finished = lifecycle._execute(context, resumed, second_actions)

    assert finished["status"] == "complete"
    assert calls.count("preflight") == 1
    assert calls.count("static_analysis") == 1
    assert calls.count("completion_gate") == 2


def test_stage_fingerprint_tamper_is_rejected(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("fingerprint-001"))
    lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions([]),
    )
    state_path = work_root / "lifecycles" / request.workflow_id / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["stages"]["static_analysis"]["fingerprint"] = "0" * 64
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._existing_context(
            request.workflow_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=60,
        )
    assert caught.value.code == "stage_contract_changed"


def test_state_record_schema_tamper_is_rejected(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("state-schema-001"))
    lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions([]),
    )
    state_path = work_root / "lifecycles" / request.workflow_id / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    state["stages"]["static_analysis"]["attempts"] = "1"
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._existing_context(
            request.workflow_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=60,
        )
    assert caught.value.code == "state_invalid"


def test_final_workflow_status_must_match_stage_states(tmp_path: Path) -> None:
    """全stage成功と矛盾するfinal statusやstage改ざんを拒否する。"""

    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("state-semantics-001"))
    lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions([]),
    )
    state_path = work_root / "lifecycles" / request.workflow_id / "state.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    static = state["stages"]["static_analysis"]
    static.update(
        {
            "status": "pending",
            "started_at_utc": None,
            "finished_at_utc": None,
            "blockers": [],
            "result": {},
        }
    )
    state_path.write_text(json.dumps(state), encoding="utf-8")

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._existing_context(
            request.workflow_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=60,
        )
    assert caught.value.code == "state_invalid"


def test_resume_pending_state_remains_valid_after_interruption(tmp_path: Path) -> None:
    """再試行予約直後に中断しても正規化済みstateを再読込できる。"""

    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("resume-durable-001"))
    lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions([], completion="blocked"),
    )

    _, reset = lifecycle._resume_context(
        request.workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        verify_succeeded_artifacts=False,
    )
    assert reset["status"] == "pending"
    completion = reset["stages"]["completion_gate"]
    assert completion["status"] == "pending"
    assert completion["started_at_utc"] is None
    assert completion["finished_at_utc"] is None
    assert completion["blockers"] == []
    assert completion["result"] == {}

    _, reloaded = lifecycle._existing_context(
        request.workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    assert reloaded == reset


def test_static_artifact_hash_change_is_detected_before_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("artifact-pin-001"))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    job_dir = context.jobs_root / request.job.job_id
    analysis = job_dir / "analysis"
    analysis.mkdir(parents=True)
    contract_inputs = job_dir / "contract-inputs"
    samples = contract_inputs / "samples"
    samples.mkdir(parents=True)
    bundle_path = contract_inputs / "analysis-contract-bundle.json"
    snapshot_manifest_path = contract_inputs / "input-snapshot-manifest.json"
    bundle_path.write_text("{}\n", encoding="utf-8")
    snapshot_manifest_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "archive_mode": "raw",
                "file_count": 0,
                "total_bytes": 0,
                "files": [],
            }
        ) + "\n",
        encoding="utf-8",
    )
    result_path = job_dir / "result.json"
    summary_path = analysis / "summary.json"
    result_path.write_text("{}\n", encoding="utf-8")
    summary_path.write_text('{"state":"before"}\n', encoding="utf-8")
    fake_result = {
        "artifacts": {
            "analysis_output": lifecycle.analysis_job_runner.validate_analysis_output_tree(analysis),
            "analysis_contract_bundle": "contract-inputs/analysis-contract-bundle.json",
            "analysis_contract_bundle_sha256": lifecycle._sha256_file(bundle_path),
            "input_snapshot_manifest": "contract-inputs/input-snapshot-manifest.json",
            "input_snapshot_manifest_sha256": lifecycle._sha256_file(snapshot_manifest_path),
            "family_hint_manifest": None,
            "family_hint_manifest_sha256": None,
            "trusted_static_tools_manifest": None,
            "trusted_static_tools_manifest_sha256": None,
        }
    }
    monkeypatch.setattr(lifecycle, "_verified_static_result", lambda _context: fake_result)
    record = {
        "result": {
            "result_sha256": lifecycle._sha256_file(result_path),
            "summary_sha256": lifecycle._sha256_file(summary_path),
            "analysis_tree_sha256": lifecycle._analysis_tree_sha256(analysis),
        }
    }

    assert lifecycle._static_artifact_errors(context, record) == []
    summary_path.write_text('{"state":"after"}\n', encoding="utf-8")

    assert "static_summary_hash_mismatch" in lifecycle._static_artifact_errors(context, record)


def test_resume_fails_closed_when_succeeded_artifact_verification_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("resume-pin-001"))
    lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions([], analysis_state="partial", completion="blocked"),
    )
    monkeypatch.setattr(
        lifecycle,
        "_verification_errors",
        lambda *_args, **_kwargs: ["static_summary_hash_mismatch"],
    )

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._resume_context(
            request.workflow_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=60,
        )
    assert caught.value.code == "succeeded_artifact_changed"


def test_execution_lock_rejects_parallel_writer(tmp_path: Path) -> None:
    root = tmp_path / "workflow"
    root.mkdir()

    with lifecycle._execution_lock(root):
        with pytest.raises(lifecycle.LifecycleError) as caught:
            with lifecycle._execution_lock(root):
                pytest.fail("同じworkflowの二重lockを取得してはいけません")

    assert caught.value.code == "workflow_locked"


def test_verify_is_read_only_even_when_static_fixture_has_no_real_job(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("verify-001"))
    lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=fake_actions([]),
    )
    state_path = work_root / "lifecycles" / request.workflow_id / "state.json"
    before = state_path.read_bytes()

    result = lifecycle.verify_lifecycle(
        request.workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )

    assert result["valid"] is False
    assert "static_result_missing" in result["errors"]
    assert state_path.read_bytes() == before


def test_partial_publication_is_blocked_before_publisher_without_opt_in(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, input_root, work_root = make_roots(tmp_path, publication=True)
    request = lifecycle.validate_request_object(request_value(publication=True))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    monkeypatch.setattr(
        lifecycle.publish_one_shot_collection,
        "publish",
        lambda *_args, **_kwargs: pytest.fail("publisher must not run"),
    )
    state = {"stages": {"static_analysis": {"result": {"analysis_state": "partial"}}}}

    outcome = lifecycle._production_publication(context, state)

    assert outcome.status == "blocked"
    assert outcome.blockers == ("publication_requires_complete_or_partial_staging_opt_in",)


def test_completion_gate_surfaces_case_blockers_and_next_actions(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("gate-001"))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    digest = "a" * 64
    analysis = context.jobs_root / request.job.job_id / "analysis"
    case = analysis / "cases" / digest
    case.mkdir(parents=True)
    (analysis / "summary.json").write_text(
        json.dumps(
            {
                "cases": [{"sha256": digest, "case_state": "partial"}],
                "derived_cases": [],
            }
        ),
        encoding="utf-8",
    )
    (case / "report.json").write_text(
        json.dumps(
            {
                "case_state": {
                    "status": "partial",
                    "blockers": ["representative_function_analysis_required"],
                }
            }
        ),
        encoding="utf-8",
    )
    (case / "orchestration.json").write_text(
        json.dumps({"blockers": ["terminal_payload_not_recovered"]}),
        encoding="utf-8",
    )
    state = {
        "stages": {
            "static_analysis": {"result": {"analysis_state": "partial"}},
            "publication": {"enabled": False, "status": "skipped", "blockers": []},
            "function_validation": {"enabled": False, "status": "skipped", "blockers": []},
        }
    }

    outcome = lifecycle._production_completion(context, state)

    assert outcome.status == "blocked"
    assert outcome.result["blockers"] == [
        "representative_function_analysis_required",
        "terminal_payload_not_recovered",
    ]
    assert outcome.result["next_actions"] == [
        "representative_function_static_review",
        "terminal_payload_static_recovery",
    ]


def test_archive_sources_are_derived_only_from_fixed_input_and_job_roots(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("archive-001", archive=True))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    snapshots = work_root / "jobs" / request.job.job_id / "contract-inputs" / "samples"
    snapshots.mkdir(parents=True)
    (snapshots / "sample.bin").write_bytes(b"verified snapshot")

    sources = lifecycle._archive_sources(context)

    assert sources == [
        snapshots,
        work_root / "jobs" / request.job.job_id,
    ]
    assert all(str(repository) not in str(path) for path in sources)


def test_root_overlap_and_repository_manifest_escape_fail_closed(tmp_path: Path) -> None:
    repository, _input_root, work_root = make_roots(tmp_path, publication=True)
    request = lifecycle.validate_request_object(request_value(publication=True))
    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._validate_context_roots(
            request,
            repository=repository,
            input_root=repository,
            work_root=work_root,
            timeout_seconds=60,
            create=False,
        )
    assert caught.value.code == "root_overlap"

    escaped = request_value(publication=True)
    escaped["publication"]["manifest"] = "../acquisition.json"
    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle.validate_request_object(escaped)
    assert caught.value.code == "relative_path_invalid"


def test_publication_manifest_change_after_preflight_fails_before_publish(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path, publication=True)
    request = lifecycle.validate_request_object(request_value("manifest-change-001", publication=True))
    calls: list[str] = []
    base = fake_actions(calls)

    def mutate_manifest(*_: Any) -> lifecycle.StageOutcome:
        calls.append("preflight")
        manifest = repository / "analysis-results" / "research" / "acquisition.json"
        manifest.write_text('{"changed":true}\n', encoding="utf-8")
        return lifecycle.StageOutcome("succeeded", {"valid": True})

    actions = lifecycle._Actions(
        preflight=mutate_manifest,
        static_analysis=base.static_analysis,
        publication=base.publication,
        function_validation=base.function_validation,
        completion_gate=base.completion_gate,
        derived_refresh=base.derived_refresh,
        private_archive=base.private_archive,
    )

    state = lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=actions,
    )

    assert state["status"] == "failed"
    assert state["stages"]["publication"]["status"] == "failed"
    assert state["stages"]["publication"]["blockers"] == ["stage_contract_changed"]
    assert "publication" not in calls


def test_archive_inputs_require_verified_job_snapshot(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("archive-missing-001", archive=True))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._archive_sources(context)
    assert caught.value.code == "archive_source_invalid"
