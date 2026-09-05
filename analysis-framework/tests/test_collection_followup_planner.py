"""collection静的follow-up plannerの安全境界・決定性・順序を検証する。"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

planner = importlib.import_module("collection_followup_planner")


def _sha(character: str) -> str:
    return character * 64


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


@pytest.fixture(autouse=True)
def _bounded_case_integrity_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    """plannerがseal検証を必ず呼ぶことを軽量fixtureで確認する。"""

    def validate(_case_root, report, **_kwargs):
        return [] if isinstance(report.get("artifact_sha256"), dict) else ["artifact_hash_manifest_missing"]

    monkeypatch.setattr(planner.analysis_contract, "case_integrity_errors", validate)


def _phases(*, blocked: bool) -> list[dict[str, object]]:
    names = (
        "root_static_analysis",
        "embedded_layer_recovery",
        "external_payload_retrieval",
        "sandbox_artifact_review",
        "memory_artifact_review",
        "terminal_payload_analysis",
        "family_config_extraction",
        "c2_endpoint_extraction",
        "c2_protocol_analysis",
        "automation_and_tests",
    )
    return [
        {
            "phase": name,
            "status": (
                "blocked"
                if blocked
                and name
                in {
                    "terminal_payload_analysis",
                    "family_config_extraction",
                    "c2_endpoint_extraction",
                    "c2_protocol_analysis",
                }
                else "completed"
            ),
            "evidence": ["fixture"],
        }
        for name in names
    ]


def _c2_document(
    digest: str,
    case_path: Path,
    *,
    complete: bool,
) -> dict[str, object]:
    """正式C2契約でcomplete/deferredの両fixtureを作る。"""

    return {
        "schema_version": 1,
        "sha256": digest,
        "analysis_attempted": True,
        "phase_evidence": _phases(blocked=not complete),
        "terminal_payload": {
            "reached": complete,
            "status": "recovered" if complete else "unresolved",
            "family": "alpha" if complete else None,
            "blockers": [] if complete else ["terminal fixture"],
        },
        "c2": {
            "outcome": "no_c2_capability_verified" if complete else "unresolved",
            "extraction_attempted": True,
            "evidence": ["fixture"],
            "endpoints": [],
            "protocol": {"status": "not_applicable"} if complete else {"status": "unresolved"},
            "live_check": {"status": "not_applicable"},
        },
        "automation": {
            "handlers": [(case_path / "report.json").as_posix()],
            "tests": [(case_path / "report.json").as_posix()],
            "reusable_logic_recorded": True,
        },
        "deep_analysis": (
            {"status": "complete"}
            if complete
            else {
                "status": "deferred_for_deep_analysis",
                "priority": "normal",
                "queue": "fixture-static-followup",
                "attempted_methods": ["bounded_static_analysis"],
                "blockers": ["terminal fixture"],
                "next_minimum_step": "recover terminal fixture",
            }
        ),
        "safety": {
            "sample_executed_locally": False,
            "credentials_published": False,
            "raw_payload_published": False,
        },
    }


def _case(
    repository: Path,
    digest: str,
    *,
    complete: bool,
    extra_blockers: list[str] | None = None,
) -> tuple[str, dict[str, object]]:
    family = "alpha" if complete else "unclassified"
    # Windowsの通常path長上限に依存しない短いfixture pathを使う。
    case_path = Path("analysis-results") / "cases" / digest
    case_root = repository / case_path
    state = "complete" if complete else "triaged_unknown"
    _write_json(
        case_root / "report.json",
        {
            "artifact_sha256": {"fixture.json": _sha("f")},
            "sample": {"sha256": digest},
            "executed_sample": False,
            "network_contacted": False,
            "case_state": {
                "status": state,
                "complete": complete,
                "resumable": complete,
                "blockers": extra_blockers or [],
            },
        },
    )
    _write_json(
        case_root / "c2-analysis.json",
        _c2_document(digest, case_path, complete=complete),
    )
    publication = {
        "sha256": digest,
        "family": family,
        "family_attribution_status": "statically_confirmed" if complete else "unresolved",
        "case_path": case_path.as_posix(),
        "case_state": state,
        "publication_stage": "complete" if complete else "partial_followup_required",
    }
    return case_path.as_posix(), publication


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, str]]:
    repository = tmp_path / "repository"
    collection = repository / "analysis-results" / "collections" / "malwarebazaar-windows-20260902-0002"
    input_root = tmp_path / "inputs"
    input_root.mkdir()
    digests = {"complete": _sha("a"), "pending": _sha("b")}
    publications = []
    acquisitions = []
    for name in ("complete", "pending"):
        digest = digests[name]
        _path, publication = _case(
            repository,
            digest,
            complete=name == "complete",
        )
        publications.append(publication)
        archive = f"encrypted fixture {digest}".encode()
        (input_root / f"{digest}.zip").write_bytes(archive)
        acquisitions.append(
            {
                "sha256": digest,
                "zip_sha256": hashlib.sha256(archive).hexdigest(),
                "zip_size": len(archive),
            }
        )
    hashes = sorted(digests.values())
    acquisitions.sort(key=lambda item: item["sha256"])
    publications.sort(key=lambda item: item["sha256"])
    _write_json(
        collection / "manifest.json",
        {
            "schema_version": 1,
            "collection_id": collection.name,
            "cases": [{"case_id": f"sha256:{digest}"} for digest in hashes],
            "acquisition_items": acquisitions,
        },
    )
    _write_json(
        collection / "publication-summary.json",
        {"schema_version": 1, "cases": publications},
    )
    return repository, collection, input_root, digests


def test_build_plan_excludes_complete_and_orders_static_followup(tmp_path: Path) -> None:
    repository, collection, input_root, digests = _fixture(tmp_path)

    first = planner.build_plan(repository, collection, input_root=input_root)
    second = planner.build_plan(repository, collection, input_root=input_root)

    assert first == second
    assert first["selection"] == {
        "mode": "all_collection_cases",
        "requested_case_count": 2,
        "planned_case_count": 1,
        "skipped_complete_count": 1,
    }
    case = first["cases"][0]
    assert case["sha256"] == digests["pending"]
    assert case["source"]["status"] == "verified"
    assert case["decision"] == "changed_evidence_required"
    assert case["automatic_dispatch_allowed"] is False
    assert case["c2_contract"]["daily_ready"] is True
    assert case["c2_contract"]["complete"] is False
    assert case["minimum_next_action"] == "recover_terminal_payload_statically"
    assert case["blocker_codes"] == sorted(
        {
            "terminal_payload_not_recovered",
            "terminal_family_unresolved",
            "static_c2_config_unresolved",
            "final_c2_endpoint_unresolved",
            "c2_protocol_confirmation_pending",
            "c2_analysis_unresolved",
            "publication_incomplete",
        }
    )
    action_ids = [item["action_id"] for item in case["actions"]]
    assert action_ids == [
        "recover_terminal_payload_statically",
        "family_attribution_review",
        "configuration_and_c2_static_recovery",
        "confirm_c2_protocol_statically",
        "repair_publication",
    ]
    assert [item["sequence"] for item in case["actions"]] == list(range(1, len(case["actions"]) + 1))
    assert first["execution_policy"]["sample_execution_allowed"] is False
    assert first["execution_policy"]["cpu_emulation_allowed"] is False
    assert first["execution_policy"]["network_contact_allowed"] is False


def test_verified_source_still_requires_runtime_state_for_retryable_label(
    tmp_path: Path,
) -> None:
    """検証済みarchiveと失敗ラベルだけでは残試行回数を証明できない。"""

    repository, collection, input_root, digests = _fixture(tmp_path)
    report_path = repository / "analysis-results" / "cases" / digests["pending"] / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["case_state"]["blockers"] = ["static_analysis_failed"]
    _write_json(report_path, report)

    case = planner.build_plan(repository, collection, input_root=input_root)["cases"][0]

    assert case["decision"] == "retry_state_verification_required"
    assert case["automatic_dispatch_allowed"] is False
    assert case["minimum_next_action"] == "resume_workflow"
    assert case["retry_state_verification"] == {
        "required": True,
        "status": "not_verified",
        "validator": "analysis_resume_planner.py",
        "required_evidence": [
            "bound_failed_stage_envelope",
            "current_stage_fingerprint",
            "remaining_workflow_and_stage_attempts",
        ],
    }
    retryable = [action for action in case["actions"] if action["same_workflow_retryable"]]
    assert [action["action_id"] for action in retryable] == ["resume_workflow"]


def test_retry_actions_keep_distinct_phase_and_failure_reason() -> None:
    """同じresume actionでも異なる失敗phaseを取り違えない。"""

    blockers = ["publication_failed", "static_analysis_failed", "workflow_execution_failed"]
    actions, unknown = planner._actions(blockers)
    reverse, _ = planner._actions(reversed(blockers))

    assert unknown == []
    assert actions == reverse
    assert len(actions) == 3
    assert {action["target_phase"]: action["reason_codes"] for action in actions} == {
        None: ["workflow_execution_failed"],
        "publication": ["publication_failed"],
        "static_analysis": ["static_analysis_failed"],
    }
    assert all(action["same_workflow_retryable"] is True for action in actions)


def test_same_action_and_phase_still_coalesces_reasons() -> None:
    """同じphaseの終端復元は重複実行せず、根拠だけを全件保持する。"""

    blockers = ["root_to_terminal_byte_derivation_incomplete", "terminal_payload_not_recovered"]
    actions, unknown = planner._actions(blockers)

    assert unknown == []
    assert len(actions) == 1
    assert actions[0]["reason_codes"] == sorted(blockers)
    assert actions[0]["changed_evidence"] == [
        "root_to_terminal_lineage_sha256",
        "terminal_payload_evidence_sha256",
    ]


def test_explicit_selection_and_sync_do_not_publish_private_path(tmp_path: Path) -> None:
    repository, collection, input_root, digests = _fixture(tmp_path)

    result = planner.sync_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[digests["pending"]],
        write=True,
    )

    assert result["write_performed"] is True
    document = json.loads((collection / "STATIC-FOLLOWUP-PLAN.json").read_text(encoding="utf-8"))
    assert document["selection"]["mode"] == "explicit_sha256"
    assert str(input_root) not in (collection / "STATIC-FOLLOWUP-PLAN.json").read_text(encoding="utf-8")
    assert str(input_root) not in (collection / "STATIC-FOLLOWUP-PLAN.md").read_text(encoding="utf-8")
    checked = planner.sync_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[digests["pending"]],
    )
    assert checked["mismatches"] == []


def test_unknown_blocker_stops_automatic_followup(tmp_path: Path) -> None:
    repository, collection, input_root, digests = _fixture(tmp_path)
    pending = digests["pending"]
    summary = json.loads((collection / "publication-summary.json").read_text(encoding="utf-8"))
    item = next(value for value in summary["cases"] if value["sha256"] == pending)
    report_path = repository / item["case_path"] / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["case_state"]["blockers"] = ["unregistered_static_gap"]
    _write_json(report_path, report)

    plan = planner.build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[pending],
    )

    case = plan["cases"][0]
    assert case["decision"] == "manual_review_required"
    assert case["automatic_dispatch_allowed"] is False
    assert case["unknown_blocker_codes"] == ["unregistered_static_gap"]


def test_unsealed_case_is_rejected_before_planning(tmp_path: Path) -> None:
    """artifact sealの無いlegacy caseを自動計画へ通さない。"""

    repository, collection, input_root, digests = _fixture(tmp_path)
    pending = digests["pending"]
    summary = json.loads((collection / "publication-summary.json").read_text(encoding="utf-8"))
    item = next(value for value in summary["cases"] if value["sha256"] == pending)
    report_path = repository / item["case_path"] / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report.pop("artifact_sha256")
    _write_json(report_path, report)

    with pytest.raises(planner.FollowupPlanError, match="artifact seal"):
        planner.build_plan(
            repository,
            collection,
            input_root=input_root,
            selected_sha256=[pending],
        )


def test_invalid_c2_contract_requires_manual_review(tmp_path: Path) -> None:
    """必須fieldを欠くC2契約を通常follow-upへ降格しない。"""

    repository, collection, input_root, digests = _fixture(tmp_path)
    pending = digests["pending"]
    summary = json.loads((collection / "publication-summary.json").read_text(encoding="utf-8"))
    item = next(value for value in summary["cases"] if value["sha256"] == pending)
    c2_path = repository / item["case_path"] / "c2-analysis.json"
    c2 = json.loads(c2_path.read_text(encoding="utf-8"))
    c2["analysis_attempted"] = False
    _write_json(c2_path, c2)

    case = planner.build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[pending],
    )["cases"][0]

    assert case["decision"] == "manual_review_required"
    assert case["automatic_dispatch_allowed"] is False
    assert case["c2_contract"]["daily_ready"] is False
    assert "c2_contract_invalid" in case["blocker_codes"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("phase_evidence", "not-a-list"),
        ("terminal_payload", "not-an-object"),
    ],
)
def test_malformed_c2_shape_is_routed_to_manual_review(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    """壊れたC2構造がcollection全体を停止せず、case単位でmanualになる。"""

    repository, collection, input_root, digests = _fixture(tmp_path)
    pending = digests["pending"]
    summary = json.loads((collection / "publication-summary.json").read_text(encoding="utf-8"))
    item = next(value for value in summary["cases"] if value["sha256"] == pending)
    c2_path = repository / item["case_path"] / "c2-analysis.json"
    c2 = json.loads(c2_path.read_text(encoding="utf-8"))
    c2[field] = value
    _write_json(c2_path, c2)

    case = planner.build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[pending],
    )["cases"][0]

    assert case["decision"] == "manual_review_required"
    assert case["automatic_dispatch_allowed"] is False
    assert case["c2_contract"]["daily_ready"] is False
    assert "c2_contract_invalid" in case["blocker_codes"]


def test_oversized_phase_list_is_rejected_before_formal_validator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """phase反復上限超過をformal validatorへ渡さずmanualへ閉じる。"""

    repository, collection, input_root, digests = _fixture(tmp_path)
    pending = digests["pending"]
    summary = json.loads((collection / "publication-summary.json").read_text(encoding="utf-8"))
    item = next(value for value in summary["cases"] if value["sha256"] == pending)
    c2_path = repository / item["case_path"] / "c2-analysis.json"
    c2 = json.loads(c2_path.read_text(encoding="utf-8"))
    c2["phase_evidence"] = c2["phase_evidence"] * 7
    _write_json(c2_path, c2)

    def must_not_run(*_args, **_kwargs):
        raise AssertionError("上限超過C2をformal validatorへ渡してはいけません")

    monkeypatch.setattr(planner.c2_analysis_contract, "validate_contract", must_not_run)
    case = planner.build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[pending],
    )["cases"][0]

    assert case["decision"] == "manual_review_required"
    assert case["automatic_dispatch_allowed"] is False
    assert case["c2_contract"]["daily_ready"] is False
    assert "c2_contract_invalid" in case["blocker_codes"]


def test_complete_report_with_incomplete_c2_is_not_skipped(tmp_path: Path) -> None:
    """report/publicationがcompleteでもC2未完なら計画へ残す。"""

    repository, collection, input_root, digests = _fixture(tmp_path)
    complete = digests["complete"]
    summary = json.loads((collection / "publication-summary.json").read_text(encoding="utf-8"))
    item = next(value for value in summary["cases"] if value["sha256"] == complete)
    c2_path = repository / item["case_path"] / "c2-analysis.json"
    _write_json(
        c2_path,
        _c2_document(complete, Path(item["case_path"]), complete=False),
    )

    plan = planner.build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[complete],
    )

    assert plan["selection"]["skipped_complete_count"] == 0
    case = plan["cases"][0]
    assert case["c2_contract"]["complete"] is False
    assert "c2_analysis_unresolved" in case["blocker_codes"]


def test_rejects_repository_internal_input_root(tmp_path: Path) -> None:
    repository, collection, _input_root, _digests = _fixture(tmp_path)
    internal = repository / "private"
    internal.mkdir()

    with pytest.raises(planner.FollowupPlanError, match="repository外"):
        planner.build_plan(repository, collection, input_root=internal)


def test_rejects_case_path_traversal(tmp_path: Path) -> None:
    repository, collection, input_root, digests = _fixture(tmp_path)
    summary_path = collection / "publication-summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    item = next(value for value in summary["cases"] if value["sha256"] == digests["pending"])
    item["case_path"] = "../outside"
    _write_json(summary_path, summary)

    with pytest.raises(planner.FollowupPlanError, match="相対path"):
        planner.build_plan(repository, collection, input_root=input_root)


def test_source_hash_mismatch_is_recorded_without_using_it(tmp_path: Path) -> None:
    repository, collection, input_root, digests = _fixture(tmp_path)
    pending = digests["pending"]
    archive = input_root / f"{pending}.zip"
    original_size = archive.stat().st_size
    archive.write_bytes(b"x" * original_size)

    plan = planner.build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[pending],
    )

    assert plan["cases"][0]["source"] == {
        "status": "sha256_mismatch",
        "verified": False,
    }
    assert plan["cases"][0]["decision"] == "source_verification_required"
    assert plan["cases"][0]["automatic_dispatch_allowed"] is False


def test_unchecked_source_disables_automatic_dispatch(tmp_path: Path) -> None:
    """input root未指定時はactionを残しても自動dispatchしない。"""

    repository, collection, _input_root, digests = _fixture(tmp_path)
    case = planner.build_plan(
        repository,
        collection,
        selected_sha256=[digests["pending"]],
    )["cases"][0]

    assert case["source"] == {"status": "not_checked", "verified": False}
    assert case["decision"] == "source_verification_required"
    assert case["automatic_dispatch_allowed"] is False


def test_source_archive_is_found_in_bounded_nested_staging(tmp_path: Path) -> None:
    repository, collection, input_root, digests = _fixture(tmp_path)
    pending = digests["pending"]
    source = input_root / f"{pending}.zip"
    nested = input_root / "nested" / "case" / "source"
    nested.mkdir(parents=True)
    source.replace(nested / source.name)

    plan = planner.build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[pending],
    )

    assert plan["cases"][0]["source"]["status"] == "verified"


def test_source_discovery_depth_limit_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, collection, input_root, digests = _fixture(tmp_path)
    (input_root / "level-1" / "level-2").mkdir(parents=True)
    monkeypatch.setattr(planner, "MAX_SOURCE_DISCOVERY_DEPTH", 1)

    with pytest.raises(planner.FollowupPlanError, match="探索深度"):
        planner.build_plan(
            repository,
            collection,
            input_root=input_root,
            selected_sha256=[digests["pending"]],
        )


def test_duplicate_source_archive_fails_closed(tmp_path: Path) -> None:
    repository, collection, input_root, digests = _fixture(tmp_path)
    pending = digests["pending"]
    source = input_root / f"{pending}.zip"
    duplicate = input_root / "duplicate" / source.name
    duplicate.parent.mkdir()
    duplicate.write_bytes(source.read_bytes())

    plan = planner.build_plan(
        repository,
        collection,
        input_root=input_root,
        selected_sha256=[pending],
    )

    assert plan["cases"][0]["source"] == {
        "status": "unsafe_or_invalid",
        "verified": False,
    }
    assert plan["cases"][0]["decision"] == "source_verification_required"
    assert plan["cases"][0]["automatic_dispatch_allowed"] is False


def test_rejects_manifest_collection_id_mismatch(tmp_path: Path) -> None:
    repository, collection, input_root, _digests = _fixture(tmp_path)
    manifest_path = collection / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["collection_id"] = "different-collection"
    _write_json(manifest_path, manifest)

    with pytest.raises(planner.FollowupPlanError, match="collection_id"):
        planner.build_plan(repository, collection, input_root=input_root)


def test_sync_rejects_non_regular_existing_output(tmp_path: Path) -> None:
    repository, collection, input_root, _digests = _fixture(tmp_path)
    output = collection / "STATIC-FOLLOWUP-PLAN.json"
    output.mkdir()

    with pytest.raises(planner.FollowupPlanError, match="通常file"):
        planner.sync_plan(
            repository,
            collection,
            input_root=input_root,
            write=True,
        )


def test_sync_rejects_oversized_existing_output(tmp_path: Path) -> None:
    repository, collection, input_root, _digests = _fixture(tmp_path)
    output = collection / "STATIC-FOLLOWUP-PLAN.json"
    with output.open("wb") as handle:
        handle.truncate(planner.MAX_PLAN_BYTES + 1)

    with pytest.raises(planner.FollowupPlanError, match="安全境界"):
        planner.sync_plan(
            repository,
            collection,
            input_root=input_root,
        )
