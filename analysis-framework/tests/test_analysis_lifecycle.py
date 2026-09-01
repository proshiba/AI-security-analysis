"""識別から公開・保管までの固定lifecycle runnerを検証する。"""

from __future__ import annotations

import hashlib
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


def write_completion_contract_artifacts(
    repository: Path,
    analysis: Path,
    digest: str,
    *,
    follow_on: dict[str, Any] | None = None,
) -> None:
    """completion gate用のC2契約と終端payload台帳を同一graphから保存する。"""

    graph = follow_on or {
        "status": "no_retained_payloads",
        "roots": [digest],
        "nodes": [{"sha256": digest, "depth": 0, "state": "root"}],
        "edges": [],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "wall_clock_exhausted": False,
    }
    follow_on_path = analysis / "follow-on-analysis.json"
    follow_on_path.write_text(
        json.dumps(graph, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary_path = analysis / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    root_case_states = (
        {
            item["sha256"]: item["case_state"]
            for item in summary.get("cases", [])
            if item.get("sha256") in set(graph["roots"])
        }
        if graph["status"] in lifecycle.terminal_payload_acquisition.OPERATIONAL_STATUSES
        else None
    )
    acquisition = lifecycle.terminal_payload_acquisition.build_terminal_payload_acquisition(
        graph,
        root_case_states=root_case_states,
    )
    acquisition_path = analysis / "terminal-payload-acquisition.json"
    acquisition_path.write_text(
        json.dumps(acquisition, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary["follow_on_analysis"] = {
        "artifact": "follow-on-analysis.json",
        "sha256": lifecycle._sha256_file(follow_on_path),
        "status": graph["status"],
        "node_count": len(graph["nodes"]),
        "edge_count": len(graph["edges"]),
        "error_count": len(graph["errors"]),
    }
    summary["terminal_payload_acquisition"] = {
        "artifact": "terminal-payload-acquisition.json",
        "sha256": lifecycle._sha256_file(acquisition_path),
        "status": acquisition["status"],
        "frontier_count": len(acquisition["frontier"]),
        "selected_count": len(acquisition["selected_sha256"]),
        "pending_count": len(acquisition["pending_sha256"]),
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False), encoding="utf-8")

    c2_document = lifecycle.c2_analysis_contract.build_unresolved_contract(digest, "fixture")
    existing_automation = "analysis-framework/common/publish_one_shot_collection.py"
    c2_document["automation"]["handlers"] = [existing_automation]
    c2_document["automation"]["tests"] = [existing_automation]
    assert (repository / existing_automation).is_file()
    case_dir = analysis / "cases" / digest
    (case_dir / "c2-analysis.json").write_text(
        json.dumps(c2_document, ensure_ascii=False),
        encoding="utf-8",
    )


def test_lifecycle_rebinds_shared_root_case_state(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("shared-root-lifecycle-001"))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    left = "a" * 64
    right = "b" * 64
    analysis = context.jobs_root / request.job.job_id / "analysis"
    (analysis / "cases" / left).mkdir(parents=True)
    (analysis / "summary.json").write_text(
        json.dumps(
            {
                "cases": [
                    {"sha256": left, "case_state": "complete"},
                    {"sha256": right, "case_state": "complete"},
                ]
            }
        ),
        encoding="utf-8",
    )
    graph = {
        "status": "complete",
        "roots": [left, right],
        "nodes": [
            {"sha256": left, "depth": 0, "state": "root"},
            {"sha256": right, "depth": 0, "state": "root"},
        ],
        "edges": [
            {
                "parent_sha256": left,
                "child_sha256": right,
                "depth": 1,
                "path": "retained/shared.bin",
                "role": "payload",
                "kind": "binary",
                "size": 7,
                "status": "shared_sha256_reused_complete",
            }
        ],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "wall_clock_exhausted": False,
    }
    write_completion_contract_artifacts(repository, analysis, left, follow_on=graph)
    summary = json.loads((analysis / "summary.json").read_text(encoding="utf-8"))

    validated = lifecycle._validated_terminal_acquisition(context, summary)

    assert validated["status"] == "verified"
    assert validated["selected_sha256"] == [right]
    assert validated["pending_sha256"] == []


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


def test_partial_completion_requires_successor_without_repeating_succeeded_stages(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("resume-001"))
    calls: list[str] = []
    first_actions = fake_actions(calls, analysis_state="partial", completion="blocked")
    lifecycle._run_lifecycle_for_test(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        actions=first_actions,
    )

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._resume_context(
            request.workflow_id,
            repository=repository,
            input_root=input_root,
            work_root=work_root,
            timeout_seconds=60,
            verify_succeeded_artifacts=False,
        )

    assert caught.value.code == "successor_workflow_required"
    assert calls.count("preflight") == 1
    assert calls.count("static_analysis") == 1
    assert calls.count("completion_gate") == 1


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
    """stage実行中に中断しても正規化済みstateを再読込できる。"""

    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("resume-durable-001"))
    context, state = lifecycle._initialize_context(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
    )
    preflight = state["stages"]["preflight"]
    preflight.update(
        {
            "status": "running",
            "attempts": 1,
            "started_at_utc": lifecycle.utc_now(),
        }
    )
    lifecycle._write_state(context, state)

    _, reset = lifecycle._resume_context(
        request.workflow_id,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        verify_succeeded_artifacts=False,
    )
    assert reset["status"] == "pending"
    reset_preflight = reset["stages"]["preflight"]
    assert reset_preflight["status"] == "pending"
    assert reset_preflight["started_at_utc"] is None
    assert reset_preflight["finished_at_utc"] is None
    assert reset_preflight["blockers"] == []
    assert reset_preflight["result"] == {}

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
    inventory = contract_inputs / "inventory" / "000000"
    inventory.mkdir(parents=True)
    (inventory / "sample.bin").write_bytes(b"")
    bundle_path = contract_inputs / "analysis-contract-bundle.json"
    snapshot_manifest_path = contract_inputs / "input-snapshot-manifest.json"
    bundle_path.write_text("{}\n", encoding="utf-8")
    snapshot_manifest_path.write_text(
        json.dumps(
                {
                    "schema_version": 1,
                    "archive_mode": "malwarebazaar",
                    "input_records": [
                        {
                            "relative_path": "set/sample.bin",
                            "kind": "file",
                            "file_count": 1,
                            "analyzer_file_count": 0,
                            "total_bytes": 0,
                        }
                    ],
                    "source_inventory": [
                        {
                            "input_index": 0,
                            "relative_path": "set/sample.bin",
                            "files": [
                                {
                                    "source_relative_path": "set/sample.bin",
                                    "snapshot_relative_path": (
                                        "contract-inputs/inventory/000000/sample.bin"
                                    ),
                                    "size": 0,
                                    "sha256": hashlib.sha256(b"").hexdigest(),
                                }
                            ],
                        }
                    ],
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
        "analysis_state": "complete",
        "counts": {},
        "derived_counts": {},
        "follow_on_analysis": {},
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
    validation = {
        "result": fake_result,
        "result_sha256": lifecycle._sha256_file(result_path),
        "summary_sha256": lifecycle._sha256_file(summary_path),
        "analysis_output_sha256": lifecycle._analysis_tree_sha256(analysis),
    }
    monkeypatch.setattr(lifecycle, "_revalidated_static_bundle", lambda _context: validation)
    record = {"result": lifecycle._static_stage_result(context, validation)}

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

    with (
        lifecycle._execution_lock(root),
        pytest.raises(lifecycle.LifecycleError) as caught,
        lifecycle._execution_lock(root),
    ):
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


def test_publication_revalidates_static_seal_before_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, input_root, work_root = make_roots(tmp_path, publication=True)
    request = lifecycle.validate_request_object(request_value("publication-seal-001", publication=True))
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
    result_path = job_dir / "result.json"
    result_document = {
        "analysis_state": "complete",
        "counts": {},
        "derived_counts": {},
        "follow_on_analysis": {},
    }
    result_path.write_text(json.dumps(result_document), encoding="utf-8")
    summary_path = analysis / "summary.json"
    summary_path.write_text(
        json.dumps({"analysis_contract": {"sha256": "a" * 64}}),
        encoding="utf-8",
    )

    def current_validation(_context: lifecycle.LifecycleContext) -> dict[str, Any]:
        return {
            "result": result_document,
            "summary": json.loads(summary_path.read_text(encoding="utf-8")),
            "result_sha256": lifecycle._sha256_file(result_path),
            "summary_sha256": lifecycle._sha256_file(summary_path),
            "analysis_output_sha256": lifecycle._analysis_tree_sha256(analysis),
        }

    initial = current_validation(context)
    state = {
        "stages": {
            "static_analysis": {
                "result": lifecycle._static_stage_result(context, initial),
            }
        }
    }
    (analysis / "post-static-change.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(lifecycle, "_revalidated_static_bundle", current_validation)
    monkeypatch.setattr(
        lifecycle.publish_one_shot_collection,
        "publish",
        lambda *_args, **_kwargs: pytest.fail("publisher must not run"),
    )

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._production_publication(context, state)

    assert caught.value.code == "static_state_mismatch"


def test_publication_passes_only_exact_temporary_snapshot_to_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, input_root, work_root = make_roots(tmp_path, publication=True)
    request = lifecycle.validate_request_object(request_value("publication-snapshot-001", publication=True))
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
    result_path = job_dir / "result.json"
    result_document = {
        "analysis_state": "complete",
        "counts": {},
        "derived_counts": {},
        "follow_on_analysis": {},
    }
    result_path.write_text(json.dumps(result_document), encoding="utf-8")
    summary = {"analysis_contract": {"sha256": "a" * 64}}
    summary_path = analysis / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    (analysis / "evidence.json").write_text('{"verified":true}\n', encoding="utf-8")
    validation = {
        "result": result_document,
        "summary": summary,
        "result_sha256": lifecycle._sha256_file(result_path),
        "summary_sha256": lifecycle._sha256_file(summary_path),
        "analysis_output_sha256": lifecycle._analysis_tree_sha256(analysis),
    }
    state = {
        "stages": {
            "static_analysis": {
                "result": lifecycle._static_stage_result(context, validation),
            }
        }
    }
    observed: dict[str, Any] = {}

    def publish(
        _repository: Path,
        _manifest: Path,
        sources: list[Path],
        _collection_id: str,
        **_kwargs: Any,
    ) -> dict[str, Any]:
        observed["snapshot"] = sources[0]
        observed["payload"] = (sources[0] / "evidence.json").read_text(encoding="utf-8")
        collection = repository / "analysis-results" / "research" / "published-snapshot"
        collection.mkdir(parents=True)
        return {
            "collection": str(collection),
            "published": 1,
            "publication_stage": "complete",
            "analysis_contract_sha256": "a" * 64,
            "families": [],
        }

    monkeypatch.setattr(lifecycle, "_revalidated_static_bundle", lambda _context: validation)
    monkeypatch.setattr(lifecycle.publish_one_shot_collection, "publish", publish)

    outcome = lifecycle._production_publication(context, state)

    assert outcome.status == "succeeded"
    assert observed["snapshot"] != analysis
    assert observed["payload"] == '{"verified":true}\n'
    assert not observed["snapshot"].exists()


def test_publication_rejects_original_change_during_snapshot_before_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """snapshot copy直後に原本treeが変わればpublisherを呼ばず拒否する。"""

    repository, input_root, work_root = make_roots(tmp_path, publication=True)
    request = lifecycle.validate_request_object(
        request_value("publication-copy-race-001", publication=True)
    )
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
    result_path = job_dir / "result.json"
    result_document = {
        "analysis_state": "complete",
        "counts": {},
        "derived_counts": {},
        "follow_on_analysis": {},
    }
    result_path.write_text(json.dumps(result_document), encoding="utf-8")
    summary_path = analysis / "summary.json"
    summary_path.write_text(
        json.dumps({"analysis_contract": {"sha256": "a" * 64}}),
        encoding="utf-8",
    )
    evidence_path = analysis / "evidence.json"
    evidence_path.write_text('{"verified":true}\n', encoding="utf-8")

    def current_validation(_context: lifecycle.LifecycleContext) -> dict[str, Any]:
        return {
            "result": result_document,
            "summary": json.loads(summary_path.read_text(encoding="utf-8")),
            "result_sha256": lifecycle._sha256_file(result_path),
            "summary_sha256": lifecycle._sha256_file(summary_path),
            "analysis_output_sha256": lifecycle._analysis_tree_sha256(analysis),
        }

    state = {
        "stages": {
            "static_analysis": {
                "result": lifecycle._static_stage_result(context, current_validation(context)),
            }
        }
    }
    real_copytree = lifecycle.shutil.copytree
    publisher_calls = 0

    def copytree_then_mutate_source(
        source: Path,
        destination: Path,
        **kwargs: Any,
    ) -> Path:
        copied = real_copytree(source, destination, **kwargs)
        evidence_path.write_text('{"verified":false}\n', encoding="utf-8")
        return copied

    def publish(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal publisher_calls
        publisher_calls += 1
        pytest.fail("publisher must not run after the source tree changes")

    monkeypatch.setattr(lifecycle, "_revalidated_static_bundle", current_validation)
    monkeypatch.setattr(lifecycle.shutil, "copytree", copytree_then_mutate_source)
    monkeypatch.setattr(lifecycle.publish_one_shot_collection, "publish", publish)

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._production_publication(context, state)

    assert caught.value.code == "static_state_mismatch"
    assert publisher_calls == 0


def test_publication_rejects_temporary_snapshot_change_before_publisher(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """2回目のstatic再検証中に公開snapshotが変わればpublisherを呼ばず拒否する。"""

    repository, input_root, work_root = make_roots(tmp_path, publication=True)
    request = lifecycle.validate_request_object(
        request_value("publication-temp-race-001", publication=True)
    )
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
    result_path = job_dir / "result.json"
    result_document = {
        "analysis_state": "complete",
        "counts": {},
        "derived_counts": {},
        "follow_on_analysis": {},
    }
    result_path.write_text(json.dumps(result_document), encoding="utf-8")
    summary = {"analysis_contract": {"sha256": "a" * 64}}
    summary_path = analysis / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    (analysis / "evidence.json").write_text('{"verified":true}\n', encoding="utf-8")
    validation = {
        "result": result_document,
        "summary": summary,
        "result_sha256": lifecycle._sha256_file(result_path),
        "summary_sha256": lifecycle._sha256_file(summary_path),
        "analysis_output_sha256": lifecycle._analysis_tree_sha256(analysis),
    }
    state = {
        "stages": {
            "static_analysis": {
                "result": lifecycle._static_stage_result(context, validation),
            }
        }
    }
    real_revalidate = lifecycle._revalidated_current_static_stage
    revalidation_calls = 0
    publisher_calls = 0

    def revalidate(
        current_context: lifecycle.LifecycleContext,
        current_state: dict[str, Any],
    ) -> dict[str, Any]:
        nonlocal revalidation_calls
        revalidation_calls += 1
        if revalidation_calls == 2:
            snapshots = list(
                work_root.glob(
                    "publication-temp-race-001-publication-snapshot-*/analysis/evidence.json"
                )
            )
            assert len(snapshots) == 1
            snapshots[0].write_text('{"verified":false}\n', encoding="utf-8")
        return real_revalidate(current_context, current_state)

    def publish(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal publisher_calls
        publisher_calls += 1
        pytest.fail("publisher must not run after the temporary snapshot changes")

    monkeypatch.setattr(lifecycle, "_revalidated_static_bundle", lambda _context: validation)
    monkeypatch.setattr(lifecycle, "_revalidated_current_static_stage", revalidate)
    monkeypatch.setattr(lifecycle.publish_one_shot_collection, "publish", publish)

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._production_publication(context, state)

    assert caught.value.code == "publication_snapshot_mismatch"
    assert revalidation_calls == 2
    assert publisher_calls == 0


def test_completion_revalidates_result_seal_before_case_processing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("completion-result-seal-001"))
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
    result_document = {
        "analysis_state": "complete",
        "counts": {},
        "derived_counts": {},
        "follow_on_analysis": {},
    }
    result_path = job_dir / "result.json"
    result_path.write_text(json.dumps(result_document), encoding="utf-8")
    summary_path = analysis / "summary.json"
    summary_path.write_text("{}\n", encoding="utf-8")

    def current_validation(_context: lifecycle.LifecycleContext) -> dict[str, Any]:
        return {
            "result": result_document,
            "summary": {},
            "result_sha256": lifecycle._sha256_file(result_path),
            "summary_sha256": lifecycle._sha256_file(summary_path),
            "analysis_output_sha256": lifecycle._analysis_tree_sha256(analysis),
        }

    state = {
        "stages": {
            "static_analysis": {
                "result": lifecycle._static_stage_result(context, current_validation(context)),
            },
            "publication": {"enabled": False, "status": "skipped", "blockers": []},
            "function_validation": {"enabled": False, "status": "skipped", "blockers": []},
        }
    }
    result_path.write_text(json.dumps(result_document) + " \n", encoding="utf-8")
    monkeypatch.setattr(lifecycle, "_revalidated_static_bundle", current_validation)

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._production_completion(context, state)

    assert caught.value.code == "static_state_mismatch"


def test_completion_revalidates_result_seal_after_case_processing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """case blocker集約中のresult raw byte改変を末尾の全再検証で拒否する。"""

    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("completion-result-race-001"))
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
    result_document = {
        "analysis_state": "complete",
        "counts": {},
        "derived_counts": {},
        "follow_on_analysis": {},
    }
    result_path = job_dir / "result.json"
    result_path.write_text(json.dumps(result_document), encoding="utf-8")
    summary_document = {
        "counts": {},
        "derived_counts": {},
        "follow_on_analysis": {},
        "errors": [],
    }
    summary_path = analysis / "summary.json"
    summary_path.write_text(json.dumps(summary_document), encoding="utf-8")

    def current_validation(_context: lifecycle.LifecycleContext) -> dict[str, Any]:
        return {
            "result": result_document,
            "summary": summary_document,
            "result_sha256": lifecycle._sha256_file(result_path),
            "summary_sha256": lifecycle._sha256_file(summary_path),
            "analysis_output_sha256": lifecycle._analysis_tree_sha256(analysis),
        }

    state = {
        "stages": {
            "static_analysis": {
                "result": lifecycle._static_stage_result(context, current_validation(context)),
            },
            "publication": {"enabled": False, "status": "skipped", "blockers": []},
            "function_validation": {"enabled": False, "status": "skipped", "blockers": []},
        }
    }
    case_blocker_calls = 0

    def case_blockers(
        _context: lifecycle.LifecycleContext,
        *,
        summary: dict[str, Any] | None = None,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        nonlocal case_blocker_calls
        assert summary is summary_document
        case_blocker_calls += 1
        result_path.write_text(json.dumps(result_document) + " \n", encoding="utf-8")
        return [], []

    monkeypatch.setattr(lifecycle, "_revalidated_static_bundle", current_validation)
    monkeypatch.setattr(lifecycle, "_case_blockers", case_blockers)

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._production_completion(context, state)

    assert caught.value.code == "static_state_mismatch"
    assert case_blocker_calls == 1


def test_existing_static_job_is_fully_revalidated_before_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("existing-static-001"))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    (context.jobs_root / request.job.job_id).mkdir()
    observed: dict[str, Any] = {}

    def revalidate(
        jobs_root: Path,
        job: lifecycle.analysis_job_runner.JobRequest,
        *,
        temporary_root: Path,
        expected_timeout_seconds: int,
    ) -> dict[str, Any]:
        observed.update(
            {
                "jobs_root": jobs_root,
                "job": job,
                "temporary_root": temporary_root,
                "temporary_exists": temporary_root.is_dir(),
                "expected_timeout_seconds": expected_timeout_seconds,
            }
        )
        return {
            "result": {
                "accepted": True,
                "job_id": job.job_id,
                "request_sha256": lifecycle._sha256_value(job.public()),
                "safety": {
                    "executed_sample": False,
                    "network_contacted": False,
                    "ai_used": False,
                },
            }
        }

    monkeypatch.setattr(lifecycle.analysis_job_runner, "revalidate_completed_job", revalidate)

    result = lifecycle._verified_static_result(context)

    assert result is not None and result["accepted"] is True
    assert observed["jobs_root"] == context.jobs_root
    assert observed["job"] == request.job
    assert observed["temporary_exists"] is True
    assert observed["expected_timeout_seconds"] == 60
    assert not observed["temporary_root"].exists()


def test_completion_gate_surfaces_case_blockers_and_next_actions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
                    "counts": {"errors": 1},
                    "derived_counts": {"analyzed": 0},
                "errors": [
                    {
                        "input_index": 0,
                        "sha256": None,
                        "stage": "input_read",
                        "error_code": "input_read_failed",
                        "message": "入力を安全に読み込めませんでした (OSError)",
                    }
                ],
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
        json.dumps(
            {
                "blockers": ["terminal_payload_not_recovered"],
                "family_resolution": {"status": "resolved"},
                "quality_gates": {"network": {"required": True}},
            }
        ),
        encoding="utf-8",
    )
    write_completion_contract_artifacts(repository, analysis, digest)
    sealed_summary = json.loads((analysis / "summary.json").read_text(encoding="utf-8"))
    validation = {
        "result": {
            "analysis_state": "partial",
            "counts": sealed_summary["counts"],
            "derived_counts": sealed_summary["derived_counts"],
            "follow_on_analysis": sealed_summary["follow_on_analysis"],
        },
        "summary": sealed_summary,
        "result_sha256": "1" * 64,
        "summary_sha256": "2" * 64,
        "analysis_output_sha256": lifecycle._analysis_tree_sha256(analysis),
    }
    state = {
        "stages": {
            "static_analysis": {
                "result": lifecycle._static_stage_result(context, validation)
            },
            "publication": {"enabled": False, "status": "skipped", "blockers": []},
            "function_validation": {"enabled": False, "status": "skipped", "blockers": []},
        }
    }
    monkeypatch.setattr(lifecycle, "_revalidated_static_bundle", lambda _context: validation)

    outcome = lifecycle._production_completion(context, state)

    assert outcome.status == "blocked"
    assert outcome.result["cases"] == [
        {
            "sha256": digest,
            "status": "partial",
            "report_blockers": [
                "analysis_partial",
                "representative_function_analysis_required",
            ],
            "orchestration_blockers": ["terminal_payload_not_recovered"],
            "c2_status": "deferred",
            "c2_outcome": "unresolved",
            "c2_blockers": ["c2_analysis_unresolved"],
            "terminal_acquisition_blockers": [],
        }
    ]
    assert outcome.result["blockers"] == [
        "analysis_partial",
        "batch_error:input_read_failed",
        "c2_analysis_unresolved",
        "representative_function_analysis_required",
        "terminal_payload_not_recovered",
    ]
    assert outcome.result["next_actions"] == [
        "configuration_and_c2_static_recovery",
        "deeper_static_layer_analysis",
        "representative_function_static_review",
        "review_machine_readable_blocker",
        "terminal_payload_static_recovery",
    ]
    assert [item["case_sha256"] for item in outcome.result["remediation_actions"]] == [
        None,
        digest,
        digest,
        digest,
        digest,
    ]
    assert outcome.result["analysis_error_count"] == 1
    assert outcome.result["analysis_errors"][0]["error_code"] == "input_read_failed"
    representative = next(
        item
        for item in outcome.result["remediation_actions"]
        if item["blocker_code"] == "representative_function_analysis_required"
    )
    assert representative == {
        "case_sha256": digest,
        "blocker_code": "representative_function_analysis_required",
        "action_id": "representative_function_static_review",
        "target_phase": "function_analysis",
        "executor": "ghidra_function_batch",
        "automatic": False,
        "requires_changed_evidence": True,
        "prerequisites": ["reviewed_program_available"],
    }
    assert lifecycle.SHA256_RE.fullmatch(outcome.result["remediation_plan_sha256"])
    assert outcome.result["same_workflow_resume_allowed"] is False


def test_terminal_frontier_blocker_is_attributed_to_parent_case(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("terminal-gate-001"))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    digest = "a" * 64
    child_digest = "b" * 64
    analysis = context.jobs_root / request.job.job_id / "analysis"
    case = analysis / "cases" / digest
    case.mkdir(parents=True)
    (analysis / "summary.json").write_text(
        json.dumps(
            {
                "cases": [{"sha256": digest, "case_state": "partial"}],
                "derived_cases": [],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )
    (case / "report.json").write_text(
        json.dumps({"case_state": {"status": "partial", "blockers": []}}),
        encoding="utf-8",
    )
    (case / "orchestration.json").write_text(
        json.dumps(
            {
                "blockers": [],
                "family_resolution": {"status": "resolved"},
                "quality_gates": {"network": {"required": False}},
            }
        ),
        encoding="utf-8",
    )
    follow_on = {
        "status": "partial",
        "roots": [digest],
        "nodes": [
            {"sha256": digest, "depth": 0, "state": "root"},
            {
                "sha256": child_digest,
                "depth": 1,
                "size": 64,
                "state": "timeout",
                "family_hint_count": 0,
                "family_hint_root_sha256": None,
                "family_hint_lineage_depth": None,
            },
        ],
        "edges": [
            {
                "parent_sha256": digest,
                "child_sha256": child_digest,
                "size": 64,
                "depth": 1,
                "path": "retained/payload.bin",
                "role": "payload",
                "kind": "binary",
                "status": "child_incomplete",
            }
        ],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "wall_clock_exhausted": False,
    }
    write_completion_contract_artifacts(repository, analysis, digest, follow_on=follow_on)

    cases, blockers = lifecycle._case_blockers(context)

    assert cases[0]["terminal_acquisition_blockers"] == [
        "terminal_acquisition:child_analysis_incomplete",
        "terminal_acquisition:child_timeout",
    ]
    assert blockers == [
        "analysis_partial",
        "c2_analysis_unresolved",
        "terminal_acquisition:child_analysis_incomplete",
        "terminal_acquisition:child_timeout",
    ]
    actions = lifecycle._remediation_actions(cases, blockers)
    terminal_action = next(
        action
        for action in actions
        if action["action_id"] == "terminal_payload_static_recovery"
    )
    assert terminal_action["case_sha256"] == digest


def test_completion_contract_tampering_fails_closed(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("tamper-gate-001"))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    digest = "c" * 64
    analysis = context.jobs_root / request.job.job_id / "analysis"
    case = analysis / "cases" / digest
    case.mkdir(parents=True)
    (analysis / "summary.json").write_text(
        json.dumps(
            {
                "cases": [{"sha256": digest, "case_state": "partial"}],
                "derived_cases": [],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )
    (case / "report.json").write_text(
        json.dumps({"case_state": {"status": "partial", "blockers": []}}),
        encoding="utf-8",
    )
    (case / "orchestration.json").write_text(
        json.dumps(
            {
                "blockers": [],
                "family_resolution": {"status": "resolved"},
                "quality_gates": {"network": {"required": False}},
            }
        ),
        encoding="utf-8",
    )
    write_completion_contract_artifacts(repository, analysis, digest)
    c2_path = case / "c2-analysis.json"
    c2_document = json.loads(c2_path.read_text(encoding="utf-8"))
    c2_document["safety"]["sample_executed_locally"] = True
    c2_path.write_text(json.dumps(c2_document), encoding="utf-8")

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._case_blockers(context)
    assert caught.value.code == "c2_contract_invalid"


def test_network_required_case_rejects_no_c2_outcome(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """network必須familyでC2機能なしという矛盾した完了判定を拒否する。"""

    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("network-c2-gate-001"))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    digest = "e" * 64
    case = context.jobs_root / request.job.job_id / "analysis" / "cases" / digest
    case.mkdir(parents=True)
    (case / "c2-analysis.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(
        lifecycle.c2_analysis_contract,
        "validate_contract",
        lambda *_args, **_kwargs: {
            "daily_ready": True,
            "daily_blocking_finding_count": 0,
            "outcome": "no_c2_capability_verified",
            "complete": True,
        },
    )

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._validated_case_c2(
            context,
            case,
            digest,
            {
                "family_resolution": {"status": "resolved"},
                "quality_gates": {"network": {"required": True}},
            },
        )
    assert caught.value.code == "c2_contract_invalid"


def test_terminal_acquisition_must_equal_recomputed_graph(tmp_path: Path) -> None:
    repository, input_root, work_root = make_roots(tmp_path)
    request = lifecycle.validate_request_object(request_value("terminal-tamper-001"))
    context = lifecycle._validate_context_roots(
        request,
        repository=repository,
        input_root=input_root,
        work_root=work_root,
        timeout_seconds=60,
        create=True,
    )
    digest = "d" * 64
    analysis = context.jobs_root / request.job.job_id / "analysis"
    case = analysis / "cases" / digest
    case.mkdir(parents=True)
    (analysis / "summary.json").write_text(
        json.dumps(
            {
                "cases": [{"sha256": digest, "case_state": "partial"}],
                "derived_cases": [],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )
    (case / "report.json").write_text(
        json.dumps({"case_state": {"status": "partial", "blockers": []}}),
        encoding="utf-8",
    )
    (case / "orchestration.json").write_text(
        json.dumps(
            {
                "blockers": [],
                "family_resolution": {"status": "resolved"},
                "quality_gates": {"network": {"required": False}},
            }
        ),
        encoding="utf-8",
    )
    write_completion_contract_artifacts(repository, analysis, digest)
    acquisition_path = analysis / "terminal-payload-acquisition.json"
    acquisition = json.loads(acquisition_path.read_text(encoding="utf-8"))
    acquisition["status"] = "verified"
    acquisition_path.write_text(json.dumps(acquisition), encoding="utf-8")
    summary_path = analysis / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["terminal_payload_acquisition"]["sha256"] = lifecycle._sha256_file(acquisition_path)
    summary["terminal_payload_acquisition"]["status"] = "verified"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")

    with pytest.raises(lifecycle.LifecycleError) as caught:
        lifecycle._case_blockers(context)
    assert caught.value.code == "terminal_acquisition_invalid"


def test_remediation_registry_is_exact_and_unknown_values_fail_closed() -> None:
    known = lifecycle._remediation_action(
        "orchestration:config",
        case_sha256="b" * 64,
    )
    assert known["action_id"] == "configuration_and_c2_static_recovery"
    assert known["executor"] == "family_config_extractor"

    unknown = lifecycle._remediation_action(
        "configuration_like_but_unregistered",
        case_sha256="b" * 64,
    )
    assert unknown == {
        "case_sha256": "b" * 64,
        "blocker_code": "configuration_like_but_unregistered",
        "action_id": "review_machine_readable_blocker",
        "target_phase": "manual_review",
        "executor": "human_review",
        "automatic": False,
        "requires_changed_evidence": True,
        "prerequisites": ["new_verified_evidence_or_implementation"],
    }

    malformed_family = lifecycle._remediation_action(
        "selected_family_has_no_valid_handler_evidence:Bad/Family",
        case_sha256="b" * 64,
    )
    assert malformed_family["blocker_code"] == "analysis_blocked"
    assert malformed_family["automatic"] is False
    assert malformed_family["executor"] == "human_review"

@pytest.mark.parametrize(
    "blocker",
    [
        "handler_ambiguous_evidence",
        "handler_incompatible_input_format",
        "handler_preflight_failed",
        "selected_family_has_no_automatic_handler:valleyrat",
    ],
)
def test_known_handler_blockers_use_exact_handler_action(blocker: str) -> None:
    action = lifecycle._remediation_action(blocker, case_sha256="d" * 64)

    assert action["action_id"] == "handler_evidence_review"
    assert action["executor"] == "family_handler"
    assert action["automatic"] is False


def test_generic_triage_failure_uses_static_action_and_string_blockers_fail_closed() -> None:
    action = lifecycle._remediation_action("generic_triage_failed", case_sha256="e" * 64)

    assert action["action_id"] == "deeper_static_layer_analysis"
    assert lifecycle._bounded_blockers("terminal_payload_not_recovered") == ["analysis_blocked"]


def test_public_remediation_actions_only_reference_public_cases_at_capacity() -> None:
    digests = [format(index, "064x") for index in range(256, -1, -1)]
    cases = [
        {
            "sha256": digest,
            "status": "partial",
            "report_blockers": ["terminal_payload_not_recovered"],
            "orchestration_blockers": [],
        }
        for digest in digests
    ]

    public_cases, actions = lifecycle._public_remediation_plan(cases, ["terminal_payload_not_recovered"])

    public_digests = {case["sha256"] for case in public_cases}
    action_digests = {action["case_sha256"] for action in actions if action["case_sha256"] is not None}
    assert len(public_cases) == lifecycle.MAX_PUBLIC_CASES
    assert len(actions) == lifecycle.MAX_REMEDIATION_ACTIONS
    assert action_digests <= public_digests
    assert digests[-1] not in public_digests


def test_static_layer_limit_is_the_only_directly_automatable_case_action() -> None:
    action = lifecycle._remediation_action(
        "static_layer_limit_reached",
        case_sha256="c" * 64,
    )
    assert action["automatic"] is True
    assert action["action_id"] == "start_successor_with_extended_static_layer_limit"
    assert action["prerequisites"] == [
        "reviewed_higher_static_layer_limit",
        "successor_workflow",
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
