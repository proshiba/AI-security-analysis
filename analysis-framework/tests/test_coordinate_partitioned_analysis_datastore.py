"""分割production jobからcase別datastore handoffを構築する境界を検証する。"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner as runner  # noqa: E402
import archive_analysis_datastore as archive  # noqa: E402
import coordinate_partitioned_analysis_datastore as target  # noqa: E402


def _json(path: Path, value: object) -> bytes:
    payload = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return payload


def _complete_validation(*, actual: str, unit_name: str) -> dict[str, Any]:
    return {
        "result": {
            "accepted": True,
            "analysis_state": "complete",
            "artifacts": {
                "analysis_contract_bundle": "contract-inputs/analysis-contract-bundle.json",
                "analysis_contract_bundle_sha256": "0" * 64,
            },
        },
        "summary": {
            "cases": [{"sha256": actual, "source_name": unit_name, "case_state": "complete"}],
            "derived_cases": [],
            "derived_counts": {
                "analyzed": 0,
                "complete": 0,
                "triaged_unknown": 0,
                "partial": 0,
                "failed": 0,
            },
            "follow_on_analysis": {"status": "no_retained_payloads"},
        },
        "counts": {
            "analyzed": 1,
            "complete": 1,
            "duplicates": 0,
            "errors": 0,
            "triaged_unknown": 0,
            "partial": 0,
            "failed": 0,
        },
    }


def _partial_validation(*, actual: str, unit_name: str) -> dict[str, Any]:
    """runnerが厳格再検証したfailed partialの最小schemaを返す。"""

    value = _complete_validation(actual=actual, unit_name=unit_name)
    value["result"] = {
        "accepted": False,
        "analysis_state": "failed",
    }
    value["summary"]["cases"][0]["case_state"] = "partial"
    value["summary"]["follow_on_analysis"] = {"status": "partial"}
    value["counts"]["complete"] = 0
    value["counts"]["partial"] = 1
    value["staging_state"] = "partial"
    value["source_replay_verified"] = False
    value["staging_artifacts"] = {
        "analysis_contract_bundle": "contract-inputs/analysis-contract-bundle.json",
        "analysis_contract_bundle_sha256": "0" * 64,
    }
    return value


def test_partial_completed_job_is_rejected_before_staging() -> None:
    request = SimpleNamespace(job_id="job-001", inputs=("a" * 64,))
    validation = _complete_validation(actual="b" * 64, unit_name="sample.exe")
    validation["result"]["analysis_state"] = "partial"

    with pytest.raises(target.PartitionedDatastoreError, match="partial"):
        target._require_complete_job(validation, request=request)


def test_valid_partial_job_requires_explicit_flag_and_is_not_counted_complete() -> None:
    request = SimpleNamespace(job_id="job-001", inputs=("a" * 64,))
    validation = _partial_validation(actual="b" * 64, unit_name="sample.exe")

    with pytest.raises(target.PartitionedDatastoreError, match="allow-partial"):
        target._require_staging_job(
            validation,
            request=request,
            allow_partial_staging=False,
        )

    _result, summary = target._require_staging_job(
        validation,
        request=request,
        allow_partial_staging=True,
    )
    assert validation["counts"]["complete"] == 0
    assert validation["counts"]["partial"] == 1
    assert summary["cases"][0]["case_state"] == "partial"


def test_materialized_derived_sha256_cannot_cross_production_jobs() -> None:
    child = "a" * 64
    observed = target._bind_materialized_derived_jobs(
        {},
        job_id="job-001",
        child_sha256s=(child,),
    )

    with pytest.raises(target.PartitionedDatastoreError, match="複数production job"):
        target._bind_materialized_derived_jobs(
            observed,
            job_id="job-002",
            child_sha256s=(child,),
        )


@pytest.mark.parametrize("overlap_role", ["requested", "actual"])
def test_materialized_derived_sha256_cannot_overlap_any_root(
    overlap_role: str,
) -> None:
    child = "a" * 64
    other = "b" * 64
    requested = child if overlap_role == "requested" else other
    actual = child if overlap_role == "actual" else other
    binding = target.CaseJobBinding(requested, actual, "job-002", Path("job-002"))

    with pytest.raises(target.PartitionedDatastoreError, match="rootと重複"):
        target._reject_materialized_derived_root_overlap(
            {child: "job-001"},
            {requested: binding},
        )


@pytest.mark.parametrize("follow_on_status", ["complete", "no_retained_payloads"])
def test_root_partial_job_accepts_other_sealed_follow_on_terminal_states(
    follow_on_status: str,
) -> None:
    request = SimpleNamespace(job_id="job-001", inputs=("a" * 64,))
    validation = _partial_validation(actual="b" * 64, unit_name="sample.exe")
    validation["summary"]["follow_on_analysis"] = {
        "status": follow_on_status
    }

    result, summary = target._require_staging_job(
        validation,
        request=request,
        allow_partial_staging=True,
    )

    assert result["accepted"] is False
    assert result["analysis_state"] == "failed"
    assert summary["follow_on_analysis"]["status"] == follow_on_status


def test_partial_job_still_rejects_unsealed_follow_on_state() -> None:
    request = SimpleNamespace(job_id="job-001", inputs=("a" * 64,))
    validation = _partial_validation(actual="b" * 64, unit_name="sample.exe")
    validation["summary"]["follow_on_analysis"] = {"status": "failed"}

    with pytest.raises(target.PartitionedDatastoreError, match="follow-on状態"):
        target._require_staging_job(
            validation,
            request=request,
            allow_partial_staging=True,
        )


def test_derived_partial_job_requires_explicit_flag_and_exact_counts() -> None:
    request = SimpleNamespace(job_id="job-001", inputs=("a" * 64,))
    validation = _complete_validation(actual="b" * 64, unit_name="sample.exe")
    validation["result"]["analysis_state"] = "partial"
    validation["summary"]["derived_cases"] = [
        {"sha256": "c" * 64, "case_state": "partial"}
    ]
    validation["summary"]["derived_counts"] = {
        "analyzed": 1,
        "complete": 0,
        "triaged_unknown": 0,
        "partial": 1,
        "failed": 0,
    }
    validation["summary"]["follow_on_analysis"] = {"status": "partial"}

    with pytest.raises(target.PartitionedDatastoreError, match="allow-partial"):
        target._require_staging_job(
            validation,
            request=request,
            allow_partial_staging=False,
        )

    _result, summary = target._require_staging_job(
        validation,
        request=request,
        allow_partial_staging=True,
    )
    assert summary["derived_counts"]["partial"] == 1

    validation["summary"]["derived_counts"]["complete"] = 1
    with pytest.raises(target.PartitionedDatastoreError, match="preflight"):
        target._require_staging_job(
            validation,
            request=request,
            allow_partial_staging=True,
        )


def test_derived_partial_job_accepts_complete_follow_on_graph() -> None:
    request = SimpleNamespace(job_id="job-001", inputs=("a" * 64,))
    validation = _complete_validation(actual="b" * 64, unit_name="sample.exe")
    validation["result"]["analysis_state"] = "partial"
    validation["summary"]["derived_cases"] = [
        {"sha256": "c" * 64, "case_state": "partial"}
    ]
    validation["summary"]["derived_counts"] = {
        "analyzed": 1,
        "complete": 0,
        "triaged_unknown": 0,
        "partial": 1,
        "failed": 0,
    }
    validation["summary"]["follow_on_analysis"] = {"status": "complete"}

    result, summary = target._require_staging_job(
        validation,
        request=request,
        allow_partial_staging=True,
    )

    assert result["accepted"] is True
    assert result["analysis_state"] == "partial"
    assert summary["derived_counts"]["partial"] == 1
    assert summary["follow_on_analysis"]["status"] == "complete"


@pytest.mark.parametrize("case_state", ["failed", "triaged_unknown", "unknown"])
def test_derived_nonsealed_state_is_rejected(case_state: str) -> None:
    request = SimpleNamespace(job_id="job-001", inputs=("a" * 64,))
    validation = _complete_validation(actual="b" * 64, unit_name="sample.exe")
    validation["summary"]["derived_cases"] = [
        {"sha256": "c" * 64, "case_state": case_state}
    ]
    validation["summary"]["derived_counts"]["analyzed"] = 1
    validation["summary"]["derived_counts"][case_state] = 1

    with pytest.raises(target.PartitionedDatastoreError, match="preflight"):
        target._require_staging_job(
            validation,
            request=request,
            allow_partial_staging=True,
        )


def test_source_items_reject_uncommitted_metadata_mutation() -> None:
    digest = "a" * 64
    source_manifest = {
        "selected_hashes": [digest],
        "selected_metadata": [{"sha256_hash": digest, "signature": "committed"}],
        "items": [
            {
                "sha256": digest,
                "metadata": {"sha256_hash": digest, "signature": "mutated"},
            }
        ],
    }

    with pytest.raises(target.PartitionedDatastoreError, match="commit済みmetadata"):
        target._source_items(source_manifest)


def test_help_warns_not_to_store_stdout_in_repository() -> None:
    help_text = target.build_parser().format_help()

    assert "標準出力" in help_text
    assert "repository内へredirect" in help_text
    assert "--allow-partial-staging" in help_text
    assert "完了件数" in help_text


def test_global_binding_requires_exact_order_and_unique_actual_roots(tmp_path: Path) -> None:
    first = target.CaseJobBinding("a" * 64, "c" * 64, "job-001", tmp_path / "job-001")
    second = target.CaseJobBinding("b" * 64, "d" * 64, "job-002", tmp_path / "job-002")

    with pytest.raises(target.PartitionedDatastoreError, match="順序"):
        target._validated_global_binding_map(
            [second, first],
            selection_hashes=[first.requested_sha256, second.requested_sha256],
        )
    with pytest.raises(target.PartitionedDatastoreError, match="同じ解析root"):
        target._validated_global_binding_map(
            [first, target.CaseJobBinding(second.requested_sha256, first.case_sha256, "job-002", tmp_path)],
            selection_hashes=[first.requested_sha256, second.requested_sha256],
        )


def test_job_binding_uses_snapshot_contract_and_outer_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = "a" * 64
    actual = "b" * 64
    outer = "c" * 64
    request_input = requested
    source_relative = f"{requested}/{requested}.zip"
    source_name = f"{requested}.zip"
    unit_name = f"{requested}.exe"
    job_root = tmp_path / "job-001"
    snapshot_path = job_root / "contract-inputs" / "samples" / "000000" / source_name
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_bytes(b"snapshot")
    snapshot = runner.SnapshotInput(
        index=0,
        source_relative_path=source_relative,
        path=snapshot_path,
        snapshot_relative_path=f"contract-inputs/samples/000000/{source_name}",
        size=8,
        sha256=outer,
    )
    bundle = SimpleNamespace(inputs=(snapshot,))
    monkeypatch.setattr(runner, "_rehydrate_input_snapshot_bundle", lambda *_args, **_kwargs: bundle)
    monkeypatch.setattr(runner, "verify_input_snapshot_bundle", lambda *_args, **_kwargs: None)
    contract = {
        "input_manifest": [
            {
                "source_name": source_name,
                "unit_source_name": unit_name,
                "sha256": actual,
                "read_succeeded": True,
            }
        ]
    }
    contract_payload = _json(
        job_root / "contract-inputs" / "analysis-contract-bundle.json",
        contract,
    )
    validation = _complete_validation(actual=actual, unit_name=unit_name)
    validation["result"]["artifacts"]["analysis_contract_bundle_sha256"] = hashlib.sha256(
        contract_payload
    ).hexdigest()
    _json(
        job_root / "analysis" / "cases" / actual / "report.json",
        {
            "sample": {
                "sha256": actual,
                "input_kind": "authenticated_single_member_zip",
                "outer_sha256": outer,
                "outer_size": 8,
                "member_name": unit_name,
            }
        },
    )
    request = SimpleNamespace(job_id="job-001", inputs=(request_input,))

    bindings = target._job_case_bindings(
        request=request,
        job_root=job_root,
        validation=validation,
        source_items={requested: {"sha256": requested, "zip_sha256": outer, "zip_size": 8}},
    )

    assert bindings == (
        target.CaseJobBinding(
            requested_sha256=requested,
            case_sha256=actual,
            job_id="job-001",
            job_root=job_root,
        ),
    )


def test_partial_job_binding_rejects_unknown_report_blocker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = "a" * 64
    actual = "b" * 64
    outer = "c" * 64
    source_name = f"{requested}.zip"
    unit_name = f"{requested}.exe"
    job_root = tmp_path / "job-001"
    snapshot_path = (
        job_root / "contract-inputs" / "samples" / "000000" / source_name
    )
    snapshot_path.parent.mkdir(parents=True)
    snapshot_path.write_bytes(b"snapshot")
    snapshot = runner.SnapshotInput(
        index=0,
        source_relative_path=f"{requested}/{source_name}",
        path=snapshot_path,
        snapshot_relative_path=f"contract-inputs/samples/000000/{source_name}",
        size=8,
        sha256=outer,
    )
    monkeypatch.setattr(
        runner,
        "_rehydrate_input_snapshot_bundle",
        lambda *_args, **_kwargs: SimpleNamespace(inputs=(snapshot,)),
    )
    monkeypatch.setattr(
        runner,
        "verify_input_snapshot_bundle",
        lambda *_args, **_kwargs: None,
    )
    contract_payload = _json(
        job_root / "contract-inputs" / "analysis-contract-bundle.json",
        {
            "input_manifest": [
                {
                    "source_name": source_name,
                    "unit_source_name": unit_name,
                    "sha256": actual,
                    "read_succeeded": True,
                }
            ]
        },
    )
    validation = _partial_validation(actual=actual, unit_name=unit_name)
    validation["summary"]["analysis_contract"] = {
        "schema_version": 1,
        "sha256": "d" * 64,
    }
    validation["staging_artifacts"]["analysis_contract_bundle_sha256"] = (
        hashlib.sha256(contract_payload).hexdigest()
    )
    _json(
        job_root / "analysis" / "cases" / actual / "report.json",
        {
            "sample": {
                "sha256": actual,
                "input_kind": "authenticated_single_member_zip",
                "outer_sha256": outer,
                "outer_size": 8,
                "member_name": unit_name,
            }
        },
    )

    def reject_unknown(*_args: Any, **_kwargs: Any) -> None:
        raise ValueError("unknown blocker")

    monkeypatch.setattr(
        target.partitioned.publisher,
        "load_validated_source_report",
        reject_unknown,
    )

    with pytest.raises(target.PartitionedDatastoreError, match="途中staging契約"):
        target._job_case_bindings(
            request=SimpleNamespace(job_id="job-001", inputs=(requested,)),
            job_root=job_root,
            validation=validation,
            source_items={
                requested: {
                    "sha256": requested,
                    "zip_sha256": outer,
                    "zip_size": 8,
                }
            },
            allow_partial_staging=True,
        )


def test_coordinate_case_passes_only_own_job_root_set_to_stager(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = "a" * 64
    actual = "b" * 64
    sibling = "c" * 64
    job_root = tmp_path / "jobs" / "job-001"
    output = tmp_path / "staging"
    receipt = tmp_path / "receipts"
    receipt.mkdir()
    repository = tmp_path / "repository"
    repository.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    expected_lineage = {"schema_version": "fixture-lineage"}
    binding = target.CaseJobBinding(requested, actual, "job-001", job_root)
    plan = target.PartitionedDatastorePlan(
        repository=repository.resolve(),
        collection_id="latest-fixture",
        source_root=source.resolve(),
        temporary_root=(tmp_path / "temporary").resolve(),
        source_manifest_sha256="d" * 64,
        selection_commitment_sha256="e" * 64,
        bindings={requested: binding},
        job_root_case_sha256s={"job-001": (actual, sibling)},
        job_analysis_manifests={"job-001": {"tree": {}, "sha256": "f" * 64}},
        case_follow_on_lineage_documents={actual: expected_lineage},
        allow_partial_staging=True,
    )
    monkeypatch.setattr(target, "_analysis_output_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        target.case_staging,
        "_validate_one_shot_lineage",
        lambda *_args, **_kwargs: SimpleNamespace(
            unsafe_reasons_by_root={actual: ()}
        ),
    )
    monkeypatch.setattr(
        target.case_staging,
        "build_follow_on_lineage_case_document",
        lambda *_args, **_kwargs: expected_lineage,
    )
    monkeypatch.setattr(target, "_validate_staging_acquisition", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(target, "_reverify_receipt", lambda **_kwargs: None)
    captured: dict[str, Any] = {}

    def fake_stage(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        case_target = target.case_staging._datastore_target("latest-fixture", actual)
        source_path = output.resolve() / case_target
        return {
            "case_count": 1,
            "cases": [
                {
                    "case_sha256": actual,
                    "target": case_target,
                    "source_path": str(source_path),
                    "source_tree_sha256": "1" * 64,
                    "file_count": 3,
                    "total_size": 100,
                    "follow_on_lineage_sha256": target.case_staging._canonical_sha256(
                        expected_lineage
                    ),
                    "archive_arguments": ["--target", case_target, "--source", str(source_path)],
                }
            ],
        }

    monkeypatch.setattr(target.case_staging, "stage_cases_without_ghidra", fake_stage)

    result = target.coordinate_partitioned_case(
        plan,
        requested_sha256=requested,
        output_root=output,
        receipt_root=receipt,
    )

    assert result["status"] == "staging_ready"
    assert "repository内" in result["output_handling_warning_ja"]
    assert captured["source_requested_sha256"] == requested
    assert captured["case_sha256s"] == [actual]
    assert captured["expected_run_root_sha256s"] == (actual, sibling)
    assert captured["allow_partial_derived_cases"] is True
    assert captured["expected_analysis_output_sha256"] == "f" * 64
    assert captured["expected_follow_on_lineage_document"] == expected_lineage
    assert "--report" in result["archive_arguments"]


def test_coordinate_case_removes_only_remote_verified_owned_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested = actual = "a" * 64
    job_root = tmp_path / "jobs" / "job-001"
    output = tmp_path / "staging"
    receipt = tmp_path / "receipts"
    receipt.mkdir()
    repository = tmp_path / "repository"
    repository.mkdir()
    source = tmp_path / "source"
    source.mkdir()
    expected_lineage = {"schema_version": "fixture-lineage"}
    binding = target.CaseJobBinding(requested, actual, "job-001", job_root)
    plan = target.PartitionedDatastorePlan(
        repository=repository.resolve(),
        collection_id="latest-fixture",
        source_root=source.resolve(),
        temporary_root=(tmp_path / "temporary").resolve(),
        source_manifest_sha256="d" * 64,
        selection_commitment_sha256="e" * 64,
        bindings={requested: binding},
        job_root_case_sha256s={"job-001": (actual,)},
        job_analysis_manifests={"job-001": {"tree": {}, "sha256": "f" * 64}},
        case_follow_on_lineage_documents={actual: expected_lineage},
    )
    case_target = target.case_staging._datastore_target("latest-fixture", actual)
    source_path = output.resolve() / case_target
    monkeypatch.setattr(target, "_analysis_output_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        target.case_staging,
        "_validate_one_shot_lineage",
        lambda *_args, **_kwargs: SimpleNamespace(
            unsafe_reasons_by_root={actual: ()}
        ),
    )
    monkeypatch.setattr(
        target.case_staging,
        "build_follow_on_lineage_case_document",
        lambda *_args, **_kwargs: expected_lineage,
    )
    monkeypatch.setattr(target, "_validate_staging_acquisition", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        target.case_staging,
        "stage_cases_without_ghidra",
        lambda **_kwargs: {
            "case_count": 1,
            "cases": [
                {
                    "case_sha256": actual,
                    "target": case_target,
                    "source_path": str(source_path),
                    "source_tree_sha256": "1" * 64,
                    "file_count": 3,
                    "total_size": 100,
                    "follow_on_lineage_sha256": target.case_staging._canonical_sha256(
                        expected_lineage
                    ),
                    "archive_arguments": [],
                }
            ],
        },
    )
    verified = {
        "target": case_target,
        "status": "verified_reused",
        "archive_sha256": "2" * 64,
        "manifest_sha256": "3" * 64,
        "source_tree_sha256": "1" * 64,
        "file_count": 3,
        "total_size": 100,
    }
    monkeypatch.setattr(target, "_reverify_receipt", lambda **_kwargs: verified)
    cleanup_call: dict[str, Any] = {}

    def fake_cleanup(**kwargs: Any) -> dict[str, Any]:
        cleanup_call.update(kwargs)
        return {"removed": True}

    monkeypatch.setattr(
        target.case_staging,
        "remove_case_staging_after_verified_archive",
        fake_cleanup,
    )

    result = target.coordinate_partitioned_case(
        plan,
        requested_sha256=requested,
        output_root=output,
        receipt_root=receipt,
    )

    assert result["status"] == "verified_reused"
    assert result["owned_staging_removed"] is True
    assert result["source_deleted"] is False
    assert cleanup_call["source_path"] == source_path
    assert cleanup_call["archive_result"] is verified
    assert cleanup_call["allow_partial_derived_cases"] is False
    assert cleanup_call["expected_analysis_output_sha256"] == "f" * 64
    assert cleanup_call["expected_follow_on_lineage_document"] == expected_lineage


def test_receipt_reuse_reverifies_source_tree_and_creates_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    receipt_root = tmp_path / "receipts"
    receipt_root.mkdir()
    target_name = "latest-fixture-" + "a" * 64
    source_tree = "b" * 64
    archive_sha256 = "c" * 64
    manifest_sha256 = "d" * 64
    staged_case = {
        "target": target_name,
        "source_tree_sha256": source_tree,
        "file_count": 4,
        "total_size": 200,
    }
    report_path, binding_path = target._receipt_paths(receipt_root, target_name)
    _json(
        report_path,
        {
            "schema_version": "analysis-datastore-upload-report/v1",
            "status": "verified",
            "target": target_name,
            "object_uri": (
                f"s3://{archive.DEFAULT_BUCKET}/{archive.DEFAULT_PREFIX}/{target_name}/"
                "2026/11/archive.zip"
            ),
            "archive_sha256": archive_sha256,
            "manifest_sha256": manifest_sha256,
            "archive_size": 300,
            "file_count": 4,
            "total_uncompressed_size": 200,
            "source_tree_sha256": source_tree,
            "source_tree_commitment_verified": True,
            "s3_verification": {"server_side_encryption": "AES256"},
            "local_source_deleted": False,
        },
    )
    monkeypatch.setattr(archive, "find_aws_cli", lambda _path: Path("aws.exe"))
    monkeypatch.setattr(
        archive,
        "_run_aws",
        lambda *_args, **_kwargs: {
            "ContentLength": 300,
            "ServerSideEncryption": "AES256",
            "Metadata": {
                "archive-sha256": archive_sha256,
                "manifest-sha256": manifest_sha256,
                "analysis-target": target_name,
                "source-tree-sha256": source_tree,
            },
        },
    )

    result = target._reverify_receipt(
        repository=repository.resolve(),
        receipt_root=receipt_root.resolve(),
        staged_case=staged_case,
        aws_cli=None,
        region=archive.DEFAULT_REGION,
    )

    assert result is not None
    assert result["status"] == "verified_reused"
    assert result["remote_reverified"] is True
    assert result["receipt_binding_created"] is True
    assert binding_path.is_file()


def test_receipt_paths_reject_unsafe_target_before_creating_children(
    tmp_path: Path,
) -> None:
    receipt_root = tmp_path / "receipts"
    receipt_root.mkdir()

    with pytest.raises(target.PartitionedDatastoreError, match="receipt target"):
        target._receipt_paths(receipt_root, "../unsafe")
    assert list(receipt_root.iterdir()) == []


def test_receipt_reverify_rejects_binding_only_state(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    receipt_root = tmp_path / "receipts"
    receipt_root.mkdir()
    target_name = "latest-fixture-" + "a" * 64
    _report_path, binding_path = target._receipt_paths(receipt_root, target_name)
    _json(binding_path, {"schema_version": 1})

    with pytest.raises(target.PartitionedDatastoreError, match="bindingだけ"):
        target._reverify_receipt(
            repository=repository,
            receipt_root=receipt_root,
            staged_case={
                "target": target_name,
                "source_tree_sha256": "b" * 64,
                "file_count": 1,
                "total_size": 1,
            },
            aws_cli=None,
            region=archive.DEFAULT_REGION,
        )


def test_shared_receipt_context_tamper_is_rejected_before_remote_io() -> None:
    staged = {
        "child_sha256": "a" * 64,
        "child_case_state": "complete",
        "provenance_sha256": "b" * 64,
        "externalization_document_sha256": "c" * 64,
        "source_follow_on_sha256": "d" * 64,
        "owner_set_commitment_sha256": "e" * 64,
        "edge_set_commitment_sha256": "f" * 64,
    }
    expected = {
        "source_role": "shared_derived",
        **staged,
        "owner_set_commitment_sha256": "1" * 64,
    }

    with pytest.raises(target.PartitionedDatastoreError, match="contextと一致"):
        target._validated_receipt_binding_context(staged, expected)


def test_receipt_reverify_rejects_mismatched_lineage_commitment_before_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    receipt_root = tmp_path / "receipts"
    receipt_root.mkdir()
    target_name = "latest-fixture-" + "a" * 64
    monkeypatch.setattr(
        target,
        "_regular_json_with_digest",
        lambda *_args, **_kwargs: pytest.fail(
            "lineage mismatch後にreceiptを読んではいけません"
        ),
    )

    with pytest.raises(
        target.PartitionedDatastoreError,
        match="lineage commitment",
    ):
        target._reverify_receipt(
            repository=repository,
            receipt_root=receipt_root,
            staged_case={
                "target": target_name,
                "follow_on_lineage_sha256": "b" * 64,
            },
            aws_cli=None,
            region=archive.DEFAULT_REGION,
            expected_follow_on_lineage_sha256="c" * 64,
        )


def test_receipt_source_tree_mismatch_fails_before_remote_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    receipt_root = tmp_path / "receipts"
    receipt_root.mkdir()
    target_name = "latest-fixture-" + "a" * 64
    report_path, _binding_path = target._receipt_paths(receipt_root, target_name)
    _json(
        report_path,
        {
            "schema_version": "analysis-datastore-upload-report/v1",
            "status": "verified",
            "target": target_name,
            "object_uri": (
                f"s3://{archive.DEFAULT_BUCKET}/{archive.DEFAULT_PREFIX}/{target_name}/"
                "2026/11/archive.zip"
            ),
            "archive_sha256": "c" * 64,
            "manifest_sha256": "d" * 64,
            "archive_size": 300,
            "file_count": 4,
            "total_uncompressed_size": 200,
            "source_tree_sha256": "e" * 64,
            "source_tree_commitment_verified": True,
            "s3_verification": {"server_side_encryption": "AES256"},
            "local_source_deleted": False,
        },
    )
    monkeypatch.setattr(
        archive,
        "find_aws_cli",
        lambda _path: pytest.fail("source tree mismatch後にAWSへ到達してはいけません"),
    )

    with pytest.raises(target.PartitionedDatastoreError, match="receipt"):
        target._reverify_receipt(
            repository=repository.resolve(),
            receipt_root=receipt_root.resolve(),
            staged_case={
                "target": target_name,
                "source_tree_sha256": "f" * 64,
                "file_count": 4,
                "total_size": 200,
            },
            aws_cli=None,
            region=archive.DEFAULT_REGION,
        )


def test_shared_target_is_coordinated_before_root_and_receipt_context_is_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = "a" * 64
    child = "b" * 64
    job_root = tmp_path / "jobs" / "job-001"
    repository = tmp_path / "repository"
    source = tmp_path / "source"
    receipt = tmp_path / "receipts"
    output = tmp_path / "staging"
    for path in (job_root, repository, source, receipt):
        path.mkdir(parents=True)
    document = {
        "child_sha256": child,
        "child_case_state": "complete",
        "owners": [root],
        "source_follow_on_sha256": "c" * 64,
        "owner_set_commitment_sha256": "d" * 64,
        "edge_set_commitment_sha256": "e" * 64,
    }
    binding = target.CaseJobBinding(root, root, "job-001", job_root)
    plan = target.PartitionedDatastorePlan(
        repository=repository.resolve(),
        collection_id="latest-fixture",
        source_root=source.resolve(),
        temporary_root=(tmp_path / "temporary").resolve(),
        source_manifest_sha256="f" * 64,
        selection_commitment_sha256="1" * 64,
        bindings={root: binding},
        job_root_case_sha256s={"job-001": (root,)},
        job_analysis_manifests={"job-001": {"tree": {}, "sha256": "2" * 64}},
        externalize_shared_derived_cases=True,
        shared_derived_documents={child: document},
        shared_derived_job_ids={child: "job-001"},
        root_shared_derived_sha256s={root: (child,)},
    )
    live_lineage = SimpleNamespace(graph_sha256="c" * 64)
    monkeypatch.setattr(target, "_analysis_output_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        target.case_staging,
        "_validate_one_shot_lineage",
        lambda *_args, **_kwargs: live_lineage,
    )
    monkeypatch.setattr(
        target.case_staging,
        "build_shared_derived_externalization_documents",
        lambda *_args, **_kwargs: {child: document},
    )
    shared_target = target.case_staging._shared_derived_target(
        "latest-fixture",
        child,
    )
    shared_source = output.resolve() / shared_target
    staged = {
        "target": shared_target,
        "child_sha256": child,
        "child_case_state": "complete",
        "source_path": str(shared_source),
        "source_tree_sha256": "3" * 64,
        "file_count": 3,
        "total_size": 100,
        "provenance_sha256": "4" * 64,
        "externalization_document_sha256": target.case_staging._canonical_sha256(
            document
        ),
        "source_follow_on_sha256": "c" * 64,
        "owner_set_commitment_sha256": "d" * 64,
        "edge_set_commitment_sha256": "e" * 64,
        "archive_arguments": ["--target", shared_target],
    }
    monkeypatch.setattr(
        target.case_staging,
        "stage_externalized_shared_derived_case",
        lambda **_kwargs: staged,
    )
    captured: dict[str, Any] = {}

    def fake_reverify(**kwargs: Any) -> None:
        captured.update(kwargs)
        return None

    monkeypatch.setattr(target, "_reverify_receipt", fake_reverify)
    result = target.coordinate_externalized_shared_derived(
        plan,
        child_sha256=child,
        output_root=output,
        receipt_root=receipt,
    )

    assert result["status"] == "staging_ready"
    assert captured["expected_binding_context"]["source_role"] == "shared_derived"
    assert captured["expected_binding_context"]["child_sha256"] == child
    assert "--report" in result["archive_arguments"]


def test_root_externalization_stops_until_shared_receipt_is_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = "a" * 64
    child = "b" * 64
    job_root = tmp_path / "jobs" / "job-001"
    repository = tmp_path / "repository"
    source = tmp_path / "source"
    receipt = tmp_path / "receipts"
    for path in (job_root, repository, source, receipt):
        path.mkdir(parents=True)
    document = {
        "child_sha256": child,
        "owners": [root],
        "source_follow_on_sha256": "c" * 64,
    }
    expected_lineage = {"schema_version": "fixture-lineage"}
    binding = target.CaseJobBinding(root, root, "job-001", job_root)
    plan = target.PartitionedDatastorePlan(
        repository=repository.resolve(),
        collection_id="latest-fixture",
        source_root=source.resolve(),
        temporary_root=(tmp_path / "temporary").resolve(),
        source_manifest_sha256="d" * 64,
        selection_commitment_sha256="e" * 64,
        bindings={root: binding},
        job_root_case_sha256s={"job-001": (root,)},
        job_analysis_manifests={"job-001": {"tree": {}, "sha256": "f" * 64}},
        case_follow_on_lineage_documents={root: expected_lineage},
        externalize_shared_derived_cases=True,
        shared_derived_documents={child: document},
        shared_derived_job_ids={child: "job-001"},
        root_shared_derived_sha256s={root: (child,)},
    )
    live_lineage = SimpleNamespace(
        graph_sha256="c" * 64,
        unsafe_reasons_by_root={root: ("shared_or_cross_root_child",)},
    )
    monkeypatch.setattr(target, "_analysis_output_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        target.case_staging,
        "_validate_one_shot_lineage",
        lambda *_args, **_kwargs: live_lineage,
    )
    monkeypatch.setattr(
        target.case_staging,
        "build_shared_derived_externalization_documents",
        lambda *_args, **_kwargs: {child: document},
    )
    monkeypatch.setattr(
        target,
        "coordinate_externalized_shared_derived",
        lambda *_args, **_kwargs: {"status": "staging_ready"},
    )
    monkeypatch.setattr(
        target.case_staging,
        "stage_cases_without_ghidra",
        lambda **_kwargs: pytest.fail("shared receipt前にrootをstageしてはいけません"),
    )

    with pytest.raises(target.PartitionedDatastoreError, match="root staging前"):
        target.coordinate_partitioned_case(
            plan,
            requested_sha256=root,
            output_root=tmp_path / "staging",
            receipt_root=receipt,
        )


def test_verified_shared_receipt_is_bound_into_root_staging_and_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = "a" * 64
    child = "b" * 64
    graph_sha256 = "c" * 64
    job_root = tmp_path / "jobs" / "job-001"
    repository = tmp_path / "repository"
    source = tmp_path / "source"
    receipt_root = tmp_path / "receipts"
    output = tmp_path / "staging"
    for path in (job_root, repository, source, receipt_root):
        path.mkdir(parents=True)
    document = {
        "schema_version": target.case_staging.SHARED_DERIVED_PROVENANCE_SCHEMA_VERSION,
        "collection_id": "latest-fixture",
        "target": target.case_staging._shared_derived_target("latest-fixture", child),
        "child_sha256": child,
        "child_case_state": "complete",
        "source_follow_on_sha256": graph_sha256,
        "owners": [root],
        "owner_set_commitment_sha256": "d" * 64,
        "owner_edges": [],
        "edge_set_commitment_sha256": "e" * 64,
        "payload_size": 10,
        "partial_policy": {"allow_partial_derived_cases": False},
    }
    archive_result = {
        "target": document["target"],
        "status": "verified_reused",
        "archive_sha256": "1" * 64,
        "manifest_sha256": "2" * 64,
        "source_tree_sha256": "3" * 64,
        "provenance_sha256": "4" * 64,
        "archive_report_sha256": "5" * 64,
        "externalization_document_sha256": target.case_staging._canonical_sha256(
            document
        ),
        "source_follow_on_sha256": graph_sha256,
        "owner_set_commitment_sha256": "d" * 64,
        "edge_set_commitment_sha256": "e" * 64,
        "child_case_state": "complete",
        "remote_reverified": True,
        "file_count": 3,
        "total_size": 100,
    }
    expected_lineage = {"schema_version": "fixture-lineage"}
    binding = target.CaseJobBinding(root, root, "job-001", job_root)
    plan = target.PartitionedDatastorePlan(
        repository=repository.resolve(),
        collection_id="latest-fixture",
        source_root=source.resolve(),
        temporary_root=(tmp_path / "temporary").resolve(),
        source_manifest_sha256="6" * 64,
        selection_commitment_sha256="7" * 64,
        bindings={root: binding},
        job_root_case_sha256s={"job-001": (root,)},
        job_analysis_manifests={"job-001": {"tree": {}, "sha256": "8" * 64}},
        case_follow_on_lineage_documents={root: expected_lineage},
        externalize_shared_derived_cases=True,
        shared_derived_documents={child: document},
        shared_derived_job_ids={child: "job-001"},
        root_shared_derived_sha256s={root: (child,)},
    )
    live_lineage = SimpleNamespace(
        graph_sha256=graph_sha256,
        unsafe_reasons_by_root={root: ("shared_or_cross_root_child",)},
    )
    monkeypatch.setattr(target, "_analysis_output_matches", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(
        target.case_staging,
        "_validate_one_shot_lineage",
        lambda *_args, **_kwargs: live_lineage,
    )
    monkeypatch.setattr(
        target.case_staging,
        "build_shared_derived_externalization_documents",
        lambda *_args, **_kwargs: {child: document},
    )
    monkeypatch.setattr(
        target,
        "coordinate_externalized_shared_derived",
        lambda *_args, **_kwargs: {
            "status": "verified_reused",
            "archive_result": archive_result,
        },
    )
    monkeypatch.setattr(
        target.case_staging,
        "build_follow_on_lineage_case_document",
        lambda *_args, **_kwargs: expected_lineage,
    )
    monkeypatch.setattr(target, "_validate_staging_acquisition", lambda *_args, **_kwargs: None)
    captured_stage: dict[str, Any] = {}
    case_target = target.case_staging._datastore_target("latest-fixture", root)
    source_path = output.resolve() / case_target
    reference = target.case_staging.build_shared_derived_reference_document(
        collection_id="latest-fixture",
        root_sha256=root,
        source_follow_on_sha256=graph_sha256,
        externalization_documents={child: document},
        verified_receipts={child: archive_result},
    )
    assert reference is not None

    def fake_root_stage(**kwargs: Any) -> dict[str, Any]:
        captured_stage.update(kwargs)
        return {
            "case_count": 1,
            "cases": [
                {
                    "case_sha256": root,
                    "target": case_target,
                    "source_path": str(source_path),
                    "source_tree_sha256": "9" * 64,
                    "file_count": 4,
                    "total_size": 200,
                    "follow_on_lineage_sha256": target.case_staging._canonical_sha256(
                        expected_lineage
                    ),
                    "externalized_shared_reference_sha256": (
                        target.case_staging._canonical_sha256(reference)
                    ),
                    "archive_arguments": ["--target", case_target],
                }
            ],
        }

    monkeypatch.setattr(
        target.case_staging,
        "_stage_cases_without_ghidra",
        fake_root_stage,
    )
    captured_receipt: dict[str, Any] = {}

    def fake_root_reverify(**kwargs: Any) -> None:
        captured_receipt.update(kwargs)
        return None

    monkeypatch.setattr(target, "_reverify_receipt", fake_root_reverify)
    result = target.coordinate_partitioned_case(
        plan,
        requested_sha256=root,
        output_root=output,
        receipt_root=receipt_root,
    )

    assert result["status"] == "staging_ready"
    assert captured_stage["externalized_shared_receipts"] == {child: archive_result}
    assert captured_receipt["expected_binding_context"] == {
        "source_role": "analysis_case_externalized_shared_child",
        "externalized_shared_reference_sha256": target.case_staging._canonical_sha256(
            reference
        ),
    }
