"""検体単位のprivate artifact分離とdatastore handoffを検証する。"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import archive_analysis_datastore as archive  # noqa: E402
import stage_case_analysis_datastore as target  # noqa: E402


def _json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _recommit_selection(document: dict[str, object]) -> None:
    """人工selection変更後のcommitmentを本番関数で再計算する。"""

    document["selection_commitment_sha256"] = (
        target.partitioner.compute_selection_commitment(document)
    )


def _fixture(
    tmp_path: Path,
    *,
    pe_payloads: tuple[bytes, bytes] = (b"MZ-case-one", b"MZ-case-two"),
) -> dict[str, object]:
    repository = tmp_path / "repository"
    source = tmp_path / "private" / "source"
    one_shot = tmp_path / "work" / "analysis"
    ghidra = tmp_path / "private" / "ghidra"
    output = tmp_path / "staging"
    for directory in (
        repository,
        source,
        one_shot / "cases",
        ghidra / "objects",
        ghidra / "import-staging",
    ):
        directory.mkdir(parents=True)

    cases = [hashlib.sha256(value).hexdigest() for value in pe_payloads]
    items = []
    selected_metadata = []
    relationships = []
    validation_programs = []
    totals = {
        "characteristic_native_decompilations": 0,
        "exports_items": 0,
        "functions_items": 0,
        "imports_items": 0,
        "managed_method_bodies": 0,
        "managed_methods": 0,
        "native_functions": 0,
        "programs": len(cases),
        "segments_items": 0,
        "strings_items": 0,
    }
    for index, (case_sha256, pe_payload) in enumerate(
        zip(cases, pe_payloads, strict=True),
        start=1,
    ):
        source_case = source / case_sha256
        source_case.mkdir()
        archive_path = source_case / f"{case_sha256}.zip"
        archive_payload = f"encrypted-source-{index}".encode("ascii")
        archive_path.write_bytes(archive_payload)
        metadata = {
            "sha256_hash": case_sha256,
            "file_name": f"case-{index}.exe",
        }
        items.append(
            {
                "sha256": case_sha256,
                "zip_path": str(archive_path.resolve()),
                "zip_sha256": hashlib.sha256(archive_payload).hexdigest(),
                "zip_size": len(archive_payload),
                "metadata": metadata,
            }
        )
        selected_metadata.append(dict(metadata))
        case_result = one_shot / "cases" / case_sha256
        case_result.mkdir()
        _json(
            case_result / "report.json",
            {
                "sha256": case_sha256,
                "executed_sample": False,
                "network_contacted": False,
                "ai_used": False,
            },
        )

        import_path = ghidra / "import-staging" / f"{case_sha256}.quarantine.bin"
        import_path.write_bytes(pe_payload)
        object_root = ghidra / "objects" / case_sha256
        object_root.mkdir()
        root_relationship = {
            "case_sha256": case_sha256,
            "depth": 0,
            "format": "pe",
            "is_pe": True,
            "layer_sha256": case_sha256,
            "parent_sha256": None,
            "reconstruction_mode": "authenticated_root_only",
            "size": len(pe_payload),
            "source_archive_sha256": hashlib.sha256(archive_payload).hexdigest(),
            "source_archive_size": len(archive_payload),
            "transform": "submission",
        }
        program_result = {
            "schema_version": 1,
            "sha256": case_sha256,
            "status": "complete",
            "functions": [],
            "imports": [],
            "exports": [],
            "segments": [],
            "relationships": [root_relationship],
            "retrieval_coverage": {"strings": {"item_count": 0}},
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "arbitrary_ghidra_scripts_enabled": False,
                "raw_results_private": True,
            },
        }
        _json(object_root / "program-result.json", program_result)
        (object_root / "decompilations.raw.jsonl").write_text("", encoding="utf-8")
        _json(object_root / "ghidra-raw-index.json", {"sha256": case_sha256})
        relationships.append(root_relationship)
        validation_programs.append(
            {
                "artifacts": {
                    "cil_instructions": None,
                    "decompilations": str((object_root / "decompilations.raw.jsonl").resolve()),
                    "ghidra_raw_index": str((object_root / "ghidra-raw-index.json").resolve()),
                    "program_result": str((object_root / "program-result.json").resolve()),
                },
                "characteristic_native_decompilation_count": 0,
                "errors": [],
                "managed_method_body_count": 0,
                "managed_method_count": 0,
                "native_function_count": 0,
                "sha256": case_sha256,
                "valid": True,
            }
        )

    source_manifest = {
        "schema_version": 1,
        "source": "fixture",
        "selection_mode": "windows_pe_newest",
        "file_types": ["exe", "dll"],
        "query_limit": 1000,
        "selected_at": "2026-09-03T00:00:00Z",
        "selection_provenance": {"method": "fixture"},
        "requested": len(cases),
        "excluded_hashes": 0,
        "excluded_hashes_sha256": "f" * 64,
        "excluded_tags": [],
        "selected_hashes": cases,
        "selected_metadata": selected_metadata,
        "items": items,
        "max_download_bytes": 1024,
        "max_total_download_bytes": 4096,
        "minimum_free_bytes": 1024,
        "complete": True,
        "archives_remain_encrypted": True,
        "samples_executed": False,
    }
    source_manifest["selection_commitment_sha256"] = (
        target.partitioner.compute_selection_commitment(source_manifest)
    )
    _json(source / "manifest.json", source_manifest)
    _json(
        ghidra / "input-relationships.json",
        {
            "schema_version": 1,
            "collection_id": "daily-fixture",
            "sample_executed": False,
            "network_contacted": False,
            "static_tools": {"sevenzip": None},
            "unique_pe_objects": len(cases),
            "relationships": relationships,
        },
    )
    _json(
        ghidra / "private-artifact-validation.json",
        {
            "schema_version": 1,
            "complete": True,
            "global_errors": [],
            "invalid_programs": 0,
            "valid_programs": len(cases),
            "programs": validation_programs,
            "totals": totals,
        },
    )
    safety = {
        "arbitrary_ghidra_scripts_enabled": False,
        "mcp_localhost_only": True,
        "network_contacted": False,
        "sample_executed": False,
    }
    _json(
        ghidra / "run-progress.json",
        {
            "schema_version": 1,
            "collection_id": "daily-fixture",
            "status": "complete",
            "safety": safety,
        },
    )
    _json(
        ghidra / "run-summary.json",
        {
            "schema_version": 1,
            "collection_id": "daily-fixture",
            "status": "complete",
            "safety": safety,
        },
    )
    return {
        "repository": repository,
        "source": source,
        "one_shot": one_shot,
        "ghidra": ghidra,
        "output": output,
        "cases": cases,
    }


def _stage(fixture: dict[str, object], *, cases: list[str] | None = None) -> dict:
    selected = cases if cases is not None else [fixture["cases"][0]]
    return target.stage_cases(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        ghidra_root=fixture["ghidra"],
        output_root=fixture["output"],
        case_sha256s=selected,
    )


def _stage_without_ghidra(fixture: dict[str, object]) -> dict:
    return target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        case_sha256s=[fixture["cases"][0]],
    )


def _recommit_staged_follow_on_lineage(
    staged_root: Path,
    document: dict[str, object],
) -> None:
    """改ざんlineageと自己申告inventoryを同時更新する負例用helper。"""

    lineage_path = staged_root / "derived" / "follow-on-lineage.case.json"
    _json(lineage_path, document)
    payload = archive._extended_length_path(lineage_path).read_bytes()
    manifest_path = staged_root / target.STAGING_MANIFEST_NAME
    manifest = json.loads(
        archive._extended_length_path(manifest_path).read_text(encoding="utf-8")
    )
    record = next(
        item
        for item in manifest["files"]
        if item["path"] == "derived/follow-on-lineage.case.json"
    )
    record["size"] = len(payload)
    record["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest["follow_on_lineage_sha256"] = target._canonical_sha256(document)
    lineage_safety = document["safety"]
    manifest["safety"]["incomplete_follow_on_evidence_present"] = (
        lineage_safety["incomplete_follow_on_evidence_present"]
    )
    manifest["safety"]["derived_case_state_counts"] = document[
        "derived_case_state_counts"
    ]
    manifest["safety"]["derived_case_count"] = len(
        document["derived_case_sha256s"]
    )
    manifest["safety"]["derived_cases_complete"] = (
        document["derived_case_state_counts"]["partial"] == 0
    )
    manifest["total_size_excluding_this_manifest"] = sum(
        int(item["size"]) for item in manifest["files"]
    )
    manifest["file_inventory_sha256"] = target._inventory_sha256(
        manifest["files"]
    )
    roles: dict[str, dict[str, int]] = {}
    for item in manifest["files"]:
        role = str(item["role"])
        summary = roles.setdefault(role, {"file_count": 0, "total_size": 0})
        summary["file_count"] += 1
        summary["total_size"] += int(item["size"])
    manifest["roles"] = dict(sorted(roles.items()))
    _json(manifest_path, manifest)


def _add_exclusion_set(
    fixture: dict[str, object],
    *,
    identities: list[str] | None = None,
) -> list[str]:
    identities = sorted(
        identities
        if identities is not None
        else {
            hashlib.sha256(b"excluded-one").hexdigest(),
            hashlib.sha256(b"excluded-two").hexdigest(),
        }
    )
    manifest_path = fixture["source"] / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    excluded_hashes_sha256 = target._canonical_sha256(identities)
    manifest["excluded_hashes"] = len(identities)
    manifest["excluded_hashes_sha256"] = excluded_hashes_sha256
    _recommit_selection(manifest)
    _json(manifest_path, manifest)
    _json(
        fixture["source"] / "exclusion-set.json",
        {
            "schema_version": 1,
            "identity_type": "sha256",
            "identity_count": len(identities),
            "identities": identities,
            "excluded_hashes_sha256": excluded_hashes_sha256,
            "selection_commitment_sha256": manifest["selection_commitment_sha256"],
            "classification": "private",
            "contains_sample_sha256": True,
            "publishable": False,
        },
    )
    return identities


def _add_follow_on_child(
    fixture: dict[str, object],
    *,
    root_index: int = 0,
    status: str = "child_complete",
) -> str:
    root = fixture["cases"][root_index]
    child_payload = b"MZ-derived-complete"
    child = hashlib.sha256(child_payload).hexdigest()
    parent_directory = fixture["one_shot"] / "cases" / root
    payload_path = parent_directory / "p" / f"{child}.exe"
    payload_io = archive._extended_length_path(payload_path)
    payload_io.parent.mkdir()
    payload_io.write_bytes(child_payload)
    child_directory = fixture["one_shot"] / "cases" / child
    child_directory.mkdir()
    complete = status == "child_complete"
    _json(
        child_directory / "report.json",
        {
            "sample": {"sha256": child},
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
            "case_state": {
                "status": "complete" if complete else "partial",
                "complete": complete,
                "blockers": [] if complete else ["fixture_incomplete"],
            },
        },
    )
    roots = list(fixture["cases"])
    _json(
        fixture["one_shot"] / "follow-on-analysis.json",
        {
            "schema_version": 1,
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
            "status": "complete" if complete else "partial",
            "roots": roots,
            "nodes": [
                *({"sha256": digest, "depth": 0, "state": "root"} for digest in roots),
                {
                    "sha256": child,
                    "depth": 1,
                    "state": "analyzed",
                    "case_state": "complete" if complete else "partial",
                },
            ],
            "edges": [
                {
                    "parent_sha256": root,
                    "child_sha256": child,
                    "depth": 1,
                    "path": f"p/{child}.exe",
                    "role": "recovered_payload",
                    "kind": "pe",
                    "size": len(child_payload),
                    "status": status,
                }
            ],
            "errors": [],
            "omitted_metadata": [],
            "omitted_metadata_commitments": [],
            "wall_clock_exhausted": False,
        },
    )
    return child


def _add_shared_follow_on_child(
    fixture: dict[str, object],
    *,
    status: str = "child_complete",
) -> str:
    """2 rootが同一derived leafを保持するfollow-on graphを作る。"""

    child = _add_follow_on_child(fixture, status=status)
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    second = fixture["cases"][1]
    first_payload = fixture["one_shot"] / "cases" / fixture["cases"][0] / "p" / f"{child}.exe"
    second_payload = fixture["one_shot"] / "cases" / second / "p" / f"{child}.exe"
    second_payload_io = archive._extended_length_path(second_payload)
    second_payload_io.parent.mkdir()
    second_payload_io.write_bytes(
        archive._extended_length_path(first_payload).read_bytes()
    )
    shared = dict(graph["edges"][0])
    shared["parent_sha256"] = second
    shared["status"] = (
        "shared_sha256_reused_complete"
        if status == "child_complete"
        else "shared_sha256_reused_incomplete"
    )
    graph["edges"].append(shared)
    _json(graph_path, graph)
    return child


def _add_runtime_request_sidecar(fixture: dict[str, object]) -> Path:
    path = fixture["source"] / "request-improved.json"
    _json(
        path,
        {
            "schema_version": 1,
            "job_id": "fixture-improved",
            "inputs": list(reversed(fixture["cases"])),
            "family_hint_manifest": None,
            "options": {
                "archive_mode": "malwarebazaar",
                "assessment_only": False,
                "family": None,
                "force_container_probe": False,
                "max_file_size": 1024,
                "max_files": 2,
                "max_static_layers": 64,
                "minimum_confidence": "medium",
                "retry_max_static_layers": 128,
                "string_scan_limit": 1000,
            },
        },
    )
    return path


def test_stage_case_without_ghidra_keeps_source_and_one_shot_only(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]

    result = target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        case_sha256s=[digest],
    )

    assert result["case_count"] == 1
    case = result["cases"][0]
    root = Path(case["source_path"])
    assert archive._extended_length_path(root / "source" / f"{digest}.zip").is_file()
    assert archive._extended_length_path(root / "one-shot-private" / "report.json").is_file()
    assert not (root / "ghidra").exists()
    manifest = json.loads((root / target.STAGING_MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["ghidra"] == {"status": "not_requested", "files_included": False}
    assert manifest["safety"]["sample_executed"] is False
    assert manifest["safety"]["network_contacted"] is False
    assert manifest["safety"]["ai_used"] is False
    assert manifest["safety"]["one_shot_report_safety_validated"] is True
    assert "externalized_shared_reference_sha256" not in manifest
    for key in (
        "physically_included_derived_case_count",
        "externalized_shared_child_count",
        "externalized_shared_child_sha256s",
        "externalized_lineage_derived_case_count",
        "shared_payload_bytes_included",
        "shared_derived_analysis_included",
        "shared_archives_remote_reverified",
    ):
        assert key not in manifest["safety"]
    assert "externalized_shared_reference_sha256" not in case
    assert "externalized_shared_child_sha256s" not in case

    reused = target.reuse_case_staging(
        output_root=fixture["output"],
        collection_id="daily-fixture",
        case_sha256=digest,
    )
    assert "externalized_shared_reference_sha256" not in reused["cases"][0]


def test_output_root_creation_failure_removes_only_new_owned_components(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    first = tmp_path / "owned-output-a"
    requested = first / "owned-output-b" / "owned-output-c"
    original_mkdir = target.os.mkdir

    def controlled_mkdir(path: object, mode: int = 0o777) -> None:
        if Path(path).name == "owned-output-b":
            raise OSError("fixture mkdir failure")
        original_mkdir(path, mode)

    monkeypatch.setattr(target.os, "mkdir", controlled_mkdir)
    with pytest.raises(target.CaseStagingError, match="作成できません"):
        target._prepare_output_root(
            requested,
            repository=fixture["repository"],
            inputs=(fixture["source"], fixture["one_shot"]),
        )

    assert not first.exists()
    assert (fixture["source"] / "manifest.json").is_file()
    assert (
        fixture["one_shot"]
        / "cases"
        / fixture["cases"][0]
        / "report.json"
    ).is_file()


def test_partitioned_run_stages_one_case_against_complete_source_manifest(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    source_manifest = json.loads((fixture["source"] / "manifest.json").read_text(encoding="utf-8"))
    source_item = next(item for item in source_manifest["items"] if item["sha256"] == digest)
    partition = tmp_path / "partition-job" / "analysis"
    (partition / "cases").mkdir(parents=True)
    (fixture["one_shot"] / "cases" / digest).rename(partition / "cases" / digest)
    _json(
        partition / "cases" / digest / "report.json",
        {
            "sample": {
                "sha256": digest,
                "input_kind": "authenticated_single_member_zip",
                "outer_sha256": source_item["zip_sha256"],
                "outer_size": source_item["zip_size"],
                "member_name": f"{digest}.exe",
            },
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        },
    )

    result = target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=partition,
        output_root=fixture["output"],
        case_sha256s=[digest],
        source_requested_sha256=digest,
        expected_run_root_sha256s=[digest],
    )

    staged = Path(result["cases"][0]["source_path"])
    assert result["case_count"] == 1
    assert archive._extended_length_path(staged / "source" / f"{digest}.zip").is_file()
    assert not archive._extended_length_path(
        staged / "source" / f"{fixture['cases'][1]}.zip"
    ).exists()
    acquisition = json.loads(
        (staged / "derived" / "source-acquisition.case.json").read_text(encoding="utf-8")
    )
    assert acquisition["source_manifest_sha256"] == hashlib.sha256(
        (fixture["source"] / "manifest.json").read_bytes()
    ).hexdigest()


def test_partitioned_run_rejects_unbound_source_archive(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    partition = tmp_path / "partition-job" / "analysis"
    (partition / "cases").mkdir(parents=True)
    (fixture["one_shot"] / "cases" / digest).rename(partition / "cases" / digest)
    _json(
        partition / "cases" / digest / "report.json",
        {
            "sample": {
                "sha256": digest,
                "input_kind": "authenticated_single_member_zip",
                "outer_sha256": "f" * 64,
                "outer_size": 1,
                "member_name": f"{digest}.exe",
            },
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        },
    )

    with pytest.raises(target.CaseStagingError, match="取得archiveへ一意"):
        target.stage_cases_without_ghidra(
            repository=fixture["repository"],
            collection_id="daily-fixture",
            source_root=fixture["source"],
            one_shot_root=partition,
            output_root=fixture["output"],
            case_sha256s=[digest],
            source_requested_sha256=digest,
            expected_run_root_sha256s=[digest],
        )


def test_source_manifest_rejects_uncommitted_provider_metadata(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    manifest_path = fixture["source"] / "manifest.json"
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    document["items"][0]["metadata"]["signature"] = "mutated-after-selection"
    _json(manifest_path, document)

    with pytest.raises(target.CaseStagingError, match="安全投影"):
        target._validate_source_manifest(fixture["source"])


def test_partitioned_run_binds_provider_hash_alias_without_public_manifest(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    actual = fixture["cases"][0]
    requested = hashlib.sha256(b"partition-provider-request").hexdigest()
    source = fixture["source"]
    (source / actual).rename(source / requested)
    (source / requested / f"{actual}.zip").rename(source / requested / f"{requested}.zip")
    source_document = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    source_document["selected_hashes"][0] = requested
    source_document["selected_metadata"][0]["sha256_hash"] = requested
    source_item = source_document["items"][0]
    source_item["sha256"] = requested
    source_item["metadata"]["sha256_hash"] = requested
    source_item["zip_path"] = str((source / requested / f"{requested}.zip").resolve())
    _recommit_selection(source_document)
    _json(source / "manifest.json", source_document)
    partition = tmp_path / "partition-job" / "analysis"
    (partition / "cases").mkdir(parents=True)
    (fixture["one_shot"] / "cases" / actual).rename(partition / "cases" / actual)
    _json(
        partition / "cases" / actual / "report.json",
        {
            "sample": {
                "sha256": actual,
                "input_kind": "authenticated_single_member_zip",
                "outer_sha256": source_item["zip_sha256"],
                "outer_size": source_item["zip_size"],
                "member_name": f"{requested}.exe",
            },
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        },
    )

    result = target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=source,
        one_shot_root=partition,
        output_root=fixture["output"],
        case_sha256s=[actual],
        source_requested_sha256=requested,
        expected_run_root_sha256s=[actual],
    )

    staged = Path(result["cases"][0]["source_path"])
    acquisition = json.loads(
        (staged / "derived" / "source-acquisition.case.json").read_text(encoding="utf-8")
    )
    assert result["cases"][0]["provider_requested_sha256"] == requested
    assert acquisition["case_sha256"] == actual
    assert acquisition["provider_requested_sha256"] == requested
    assert archive._extended_length_path(staged / "source" / f"{requested}.zip").is_file()


def test_complete_derived_lineage_is_staged_only_with_its_root(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    root = fixture["cases"][0]
    child = _add_follow_on_child(fixture)

    result = _stage_without_ghidra(fixture)

    case = result["cases"][0]
    assert case["derived_case_sha256s"] == [child]
    staged = Path(case["source_path"])
    assert (staged / "one-shot-private" / "report.json").is_file()
    assert archive._extended_length_path(staged / "one-shot-derived" / child / "report.json").is_file()
    assert not (staged / "one-shot-private" / fixture["cases"][1]).exists()
    projection = json.loads((staged / "derived" / "follow-on-lineage.case.json").read_text(encoding="utf-8"))
    assert projection["case_sha256"] == root
    assert projection["derived_case_sha256s"] == [child]
    assert projection["edges"][0]["status"] == "child_complete"
    assert "--expected-source-tree-sha256" in case["archive_arguments"]


def test_incomplete_derived_lineage_rejects_only_affected_root(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _add_follow_on_child(fixture, status="child_incomplete")

    with pytest.raises(target.CaseStagingError, match="derived_child_incomplete"):
        _stage_without_ghidra(fixture)

    unaffected = target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        case_sha256s=[fixture["cases"][1]],
    )
    assert unaffected["cases"][0]["derived_case_sha256s"] == []


def test_sealed_partial_derived_lineage_requires_explicit_flag(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture, status="child_incomplete")

    with pytest.raises(target.CaseStagingError, match="derived_child_incomplete"):
        _stage_without_ghidra(fixture)

    result = target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        case_sha256s=[fixture["cases"][0]],
        allow_partial_derived_cases=True,
        expected_analysis_output_sha256="d" * 64,
    )

    case = result["cases"][0]
    assert case["derived_case_sha256s"] == [child]
    assert case["derived_case_state_counts"] == {"complete": 0, "partial": 1}
    staged = Path(case["source_path"])
    manifest = json.loads(
        (staged / target.STAGING_MANIFEST_NAME).read_text(encoding="utf-8")
    )
    assert manifest["analysis_output_sha256"] == "d" * 64
    assert manifest["safety"]["derived_cases_complete"] is False
    assert manifest["safety"]["derived_case_state_counts"] == {
        "complete": 0,
        "partial": 1,
    }


def test_unmaterialized_timeout_is_staged_as_evidence_only_with_explicit_flag(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture, status="child_incomplete")
    child_directory = fixture["one_shot"] / "cases" / child
    for path in child_directory.iterdir():
        path.unlink()
    child_directory.rmdir()
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    child_node = next(item for item in graph["nodes"] if item["sha256"] == child)
    child_node["state"] = "timeout"
    child_node.pop("case_state")
    _json(graph_path, graph)
    live_lineage = target._validate_one_shot_lineage(
        fixture["one_shot"],
        source_case_sha256s=set(fixture["cases"]),
    )
    expected_lineage = target.build_follow_on_lineage_case_document(
        live_lineage,
        collection_id="daily-fixture",
        case_sha256=fixture["cases"][0],
    )

    with pytest.raises(target.CaseStagingError, match="derived_child_incomplete"):
        _stage_without_ghidra(fixture)

    result = target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        case_sha256s=[fixture["cases"][0]],
        allow_partial_derived_cases=True,
        expected_follow_on_lineage_document=expected_lineage,
    )

    case = result["cases"][0]
    assert case["derived_case_sha256s"] == []
    assert case["incomplete_derived_case_sha256s"] == [child]
    staged = Path(case["source_path"])
    assert not (staged / "one-shot-derived").exists()
    projection = json.loads(
        (staged / "derived" / "follow-on-lineage.case.json").read_text(
            encoding="utf-8"
        )
    )
    assert projection["incomplete_derived_case_sha256s"] == [child]
    assert projection["incomplete_derived_case_states"] == {child: "timeout"}
    assert projection["safety"]["incomplete_derived_cases_included"] is False
    assert projection["safety"]["incomplete_follow_on_evidence_present"] is True
    with pytest.raises(target.CaseStagingError, match="明示的な許可"):
        target.reuse_case_staging(
            output_root=fixture["output"],
            collection_id="daily-fixture",
            case_sha256=fixture["cases"][0],
        )
    resumed = target.reuse_case_staging(
        output_root=fixture["output"],
        collection_id="daily-fixture",
        case_sha256=fixture["cases"][0],
        allow_partial_derived_cases=True,
        expected_follow_on_lineage_document=expected_lineage,
    )
    assert resumed["cases"][0]["derived_case_state_counts"] == {
        "complete": 0,
        "partial": 0,
    }


@pytest.mark.parametrize("mutation", ["remove_timeout", "change_edge"])
def test_live_lineage_rejects_self_consistently_recommitted_stale_staging(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture, status="child_incomplete")
    child_directory = fixture["one_shot"] / "cases" / child
    for path in child_directory.iterdir():
        path.unlink()
    child_directory.rmdir()
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    child_node = next(item for item in graph["nodes"] if item["sha256"] == child)
    child_node["state"] = "timeout"
    child_node.pop("case_state")
    _json(graph_path, graph)
    live_lineage = target._validate_one_shot_lineage(
        fixture["one_shot"],
        source_case_sha256s=set(fixture["cases"]),
    )
    expected_lineage = target.build_follow_on_lineage_case_document(
        live_lineage,
        collection_id="daily-fixture",
        case_sha256=fixture["cases"][0],
    )
    staged_result = target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        case_sha256s=[fixture["cases"][0]],
        allow_partial_derived_cases=True,
        expected_follow_on_lineage_document=expected_lineage,
    )
    case_result = staged_result["cases"][0]
    staged = Path(case_result["source_path"])
    lineage_path = staged / "derived" / "follow-on-lineage.case.json"
    stale_lineage = json.loads(
        archive._extended_length_path(lineage_path).read_text(encoding="utf-8")
    )
    if mutation == "remove_timeout":
        stale_lineage["incomplete_derived_case_sha256s"] = []
        stale_lineage["incomplete_derived_case_states"] = {}
        stale_lineage["edges"] = []
        stale_lineage["safety"]["incomplete_follow_on_evidence_present"] = False
    else:
        stale_lineage["edges"][0]["role"] = "recommitted_stale_role"
    _recommit_staged_follow_on_lineage(staged, stale_lineage)

    with pytest.raises(target.CaseStagingError, match="live graph"):
        target.reuse_case_staging(
            output_root=fixture["output"],
            collection_id="daily-fixture",
            case_sha256=fixture["cases"][0],
            allow_partial_derived_cases=True,
            expected_follow_on_lineage_document=expected_lineage,
        )
    with pytest.raises(target.CaseStagingError, match="live graph"):
        target.remove_case_staging_after_verified_archive(
            output_root=fixture["output"],
            source_path=staged,
            collection_id="daily-fixture",
            case_sha256=fixture["cases"][0],
            archive_result=_verified_archive_result(case_result),
            allow_partial_derived_cases=True,
            expected_follow_on_lineage_document=expected_lineage,
        )
    assert staged.is_dir()


@pytest.mark.parametrize("graph_status", ["complete", "no_retained_payloads"])
def test_timeout_evidence_requires_partial_graph_status(
    tmp_path: Path,
    graph_status: str,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture, status="child_incomplete")
    child_directory = fixture["one_shot"] / "cases" / child
    for path in child_directory.iterdir():
        path.unlink()
    child_directory.rmdir()
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    child_node = next(item for item in graph["nodes"] if item["sha256"] == child)
    child_node["state"] = "timeout"
    child_node.pop("case_state")
    graph["status"] = graph_status
    _json(graph_path, graph)

    with pytest.raises(target.CaseStagingError, match="partial follow-on graph"):
        target.stage_cases_without_ghidra(
            repository=fixture["repository"],
            collection_id="daily-fixture",
            source_root=fixture["source"],
            one_shot_root=fixture["one_shot"],
            output_root=fixture["output"],
            case_sha256s=[fixture["cases"][0]],
            allow_partial_derived_cases=True,
        )


def test_materialized_partial_derived_requires_partial_graph_status(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _add_follow_on_child(fixture, status="child_incomplete")
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph["status"] = "complete"
    _json(graph_path, graph)

    with pytest.raises(target.CaseStagingError, match="partial follow-on graph"):
        target.stage_cases_without_ghidra(
            repository=fixture["repository"],
            collection_id="daily-fixture",
            source_root=fixture["source"],
            one_shot_root=fixture["one_shot"],
            output_root=fixture["output"],
            case_sha256s=[fixture["cases"][0]],
            allow_partial_derived_cases=True,
        )


def test_complete_follow_on_graph_requires_at_least_one_complete_edge(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture)
    child_directory = fixture["one_shot"] / "cases" / child
    for path in child_directory.iterdir():
        path.unlink()
    child_directory.rmdir()
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph["nodes"] = [item for item in graph["nodes"] if item["sha256"] != child]
    graph["edges"] = []
    _json(graph_path, graph)

    with pytest.raises(target.CaseStagingError, match="未完了edge"):
        target._validate_one_shot_lineage(
            fixture["one_shot"],
            source_case_sha256s=set(fixture["cases"]),
        )


@pytest.mark.parametrize(
    "node_state",
    ["queued", "failed", "wall_clock_limit", "incomplete_case_omitted"],
)
def test_non_timeout_unmaterialized_node_is_rejected_even_with_partial_flag(
    tmp_path: Path,
    node_state: str,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture, status="child_incomplete")
    child_directory = fixture["one_shot"] / "cases" / child
    for path in child_directory.iterdir():
        path.unlink()
    child_directory.rmdir()
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    child_node = next(item for item in graph["nodes"] if item["sha256"] == child)
    child_node["state"] = node_state
    child_node.pop("case_state")
    _json(graph_path, graph)

    with pytest.raises(target.CaseStagingError, match="timeout状態だけ"):
        target.stage_cases_without_ghidra(
            repository=fixture["repository"],
            collection_id="daily-fixture",
            source_root=fixture["source"],
            one_shot_root=fixture["one_shot"],
            output_root=fixture["output"],
            case_sha256s=[fixture["cases"][0]],
            allow_partial_derived_cases=True,
        )


def test_unmaterialized_timeout_node_rejects_case_state(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture, status="child_incomplete")
    child_directory = fixture["one_shot"] / "cases" / child
    for path in child_directory.iterdir():
        path.unlink()
    child_directory.rmdir()
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    child_node = next(item for item in graph["nodes"] if item["sha256"] == child)
    child_node["state"] = "timeout"
    child_node["case_state"] = "partial"
    _json(graph_path, graph)

    with pytest.raises(target.CaseStagingError, match="case_stateは許可しません"):
        target.stage_cases_without_ghidra(
            repository=fixture["repository"],
            collection_id="daily-fixture",
            source_root=fixture["source"],
            one_shot_root=fixture["one_shot"],
            output_root=fixture["output"],
            case_sha256s=[fixture["cases"][0]],
            allow_partial_derived_cases=True,
        )


@pytest.mark.parametrize(
    ("node_state", "directory_present"),
    [("timeout", True), ("analyzed", False)],
)
def test_follow_on_materialized_node_and_directory_sets_must_match(
    tmp_path: Path,
    node_state: str,
    directory_present: bool,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture)
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    child_node = next(item for item in graph["nodes"] if item["sha256"] == child)
    child_node["state"] = node_state
    if node_state == "timeout":
        child_node.pop("case_state")
        graph["edges"][0]["status"] = "child_incomplete"
    if not directory_present:
        child_directory = fixture["one_shot"] / "cases" / child
        for path in child_directory.iterdir():
            path.unlink()
        child_directory.rmdir()
    _json(graph_path, graph)

    with pytest.raises(target.CaseStagingError, match="materialized node集合"):
        target._validate_one_shot_lineage(
            fixture["one_shot"],
            source_case_sha256s=set(fixture["cases"]),
        )


def test_failed_follow_on_graph_is_not_a_sealed_staging_source(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    _add_follow_on_child(fixture)
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph["status"] = "failed"
    _json(graph_path, graph)

    with pytest.raises(target.CaseStagingError, match="schemaまたは安全契約"):
        target._validate_one_shot_lineage(
            fixture["one_shot"],
            source_case_sha256s=set(fixture["cases"]),
        )


def test_shared_child_lineage_is_rejected_for_all_involved_roots(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture)
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    second = fixture["cases"][1]
    second_payload = fixture["one_shot"] / "cases" / second / "p" / f"{child}.exe"
    second_payload_io = archive._extended_length_path(second_payload)
    second_payload_io.parent.mkdir()
    first_payload = fixture["one_shot"] / "cases" / fixture["cases"][0] / "p" / f"{child}.exe"
    second_payload_io.write_bytes(archive._extended_length_path(first_payload).read_bytes())
    shared = dict(graph["edges"][0])
    shared["parent_sha256"] = second
    shared["status"] = "shared_sha256_reused_complete"
    graph["edges"].append(shared)
    _json(graph_path, graph)

    for digest in fixture["cases"]:
        with pytest.raises(target.CaseStagingError, match="shared_or_cross_root_child"):
            target.stage_cases_without_ghidra(
                repository=fixture["repository"],
                collection_id="daily-fixture",
                source_root=fixture["source"],
                one_shot_root=fixture["one_shot"],
                output_root=fixture["output"],
                case_sha256s=[digest],
            )


def test_shared_child_is_staged_once_then_referenced_without_root_bytes(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    fixture["output"] = (
        tmp_path
        / ("shared-stage-a-" + "a" * 80)
        / ("shared-stage-b-" + "b" * 80)
        / ("shared-stage-c-" + "c" * 80)
    )
    assert len(os.fspath(fixture["output"])) > 260
    assert not os.path.lexists(
        archive._extended_length_path(fixture["output"])
    )
    child = _add_shared_follow_on_child(fixture)
    lineage = target._validate_one_shot_lineage(
        fixture["one_shot"],
        source_case_sha256s=set(fixture["cases"]),
    )
    document = target.build_shared_derived_externalization_documents(
        lineage,
        collection_id="daily-fixture",
        allow_partial_derived_cases=False,
    )[child]
    analysis_sha256 = "a" * 64
    shared = target.stage_externalized_shared_derived_case(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        expected_run_root_sha256s=fixture["cases"],
        child_sha256=child,
        allow_partial_derived_cases=False,
        expected_analysis_output_sha256=analysis_sha256,
        expected_externalization_document=document,
    )
    shared_root = Path(shared["source_path"])
    shared_root_io = archive._extended_length_path(shared_root)
    assert not os.path.lexists(shared_root_io / "source")
    assert not os.path.lexists(shared_root_io / "one-shot-private")
    assert os.path.isfile(
        shared_root_io / "one-shot-derived" / child / "report.json"
    )
    assert sum(
        archive._hash_source_snapshot(path)[0] == child
        for path, _relative in target._walk_files(
            shared_root,
            role="test shared staging",
        )
    ) == 1
    reused_shared = target.reuse_externalized_shared_derived_staging(
        output_root=fixture["output"],
        collection_id="daily-fixture",
        child_sha256=child,
        allow_partial_derived_cases=False,
        expected_analysis_output_sha256=analysis_sha256,
        expected_externalization_document=document,
    )
    assert reused_shared["source_tree_sha256"] == shared["source_tree_sha256"]

    receipt = {
        "target": shared["target"],
        "archive_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "source_tree_sha256": shared["source_tree_sha256"],
        "provenance_sha256": shared["provenance_sha256"],
        "archive_report_sha256": "d" * 64,
        "externalization_document_sha256": target._canonical_sha256(document),
        "source_follow_on_sha256": document["source_follow_on_sha256"],
        "owner_set_commitment_sha256": document["owner_set_commitment_sha256"],
        "edge_set_commitment_sha256": document["edge_set_commitment_sha256"],
        "child_case_state": document["child_case_state"],
        "remote_reverified": True,
    }
    root = fixture["cases"][0]
    lineage_document = target.build_follow_on_lineage_case_document(
        lineage,
        collection_id="daily-fixture",
        case_sha256=root,
    )
    staged_result = target._stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        case_sha256s=[root],
        expected_run_root_sha256s=fixture["cases"],
        expected_analysis_output_sha256=analysis_sha256,
        expected_follow_on_lineage_document=lineage_document,
        externalized_shared_receipts={child: receipt},
    )
    staged_root = Path(staged_result["cases"][0]["source_path"])
    staged_root_io = archive._extended_length_path(staged_root)
    assert not os.path.lexists(
        staged_root_io / "one-shot-private" / "p" / f"{child}.exe"
    )
    assert not os.path.lexists(staged_root_io / "one-shot-derived" / child)
    reference, _reference_sha256 = target._read_json(
        staged_root / "derived" / "shared-derived-reference.case.json",
        label="test shared reference",
    )
    assert reference["items"][0]["shared_archive"]["archive_sha256"] == "b" * 64
    assert "object_uri" not in reference["items"][0]["shared_archive"]
    assert not any(
        archive._hash_source_snapshot(path)[0] == child
        for path, _relative in target._walk_files(
            staged_root,
            role="test root staging",
        )
    )
    reused_root = target.reuse_case_staging(
        output_root=fixture["output"],
        collection_id="daily-fixture",
        case_sha256=root,
        expected_analysis_output_sha256=analysis_sha256,
        expected_follow_on_lineage_document=lineage_document,
        expected_externalized_shared_reference_document=reference,
    )
    assert (
        reused_root["cases"][0]["externalized_shared_reference_sha256"]
        == target._canonical_sha256(reference)
    )
    cleanup_result = target.remove_externalized_shared_staging_after_verified_archive(
        output_root=fixture["output"],
        source_path=shared_root,
        collection_id="daily-fixture",
        child_sha256=child,
        archive_result={
            **receipt,
            "status": "verified_reused",
            "file_count": shared["file_count"],
            "total_size": shared["total_size"],
        },
        allow_partial_derived_cases=False,
        expected_analysis_output_sha256=analysis_sha256,
        expected_externalization_document=document,
    )
    assert cleanup_result["removed"] is True
    assert not os.path.lexists(archive._extended_length_path(shared_root))
    root_case = staged_result["cases"][0]
    root_cleanup = target.remove_case_staging_after_verified_archive(
        output_root=fixture["output"],
        source_path=staged_root,
        collection_id="daily-fixture",
        case_sha256=root,
        archive_result={
            "target": root_case["target"],
            "status": "verified_reused",
            "archive_sha256": "e" * 64,
            "manifest_sha256": "f" * 64,
            "source_tree_sha256": root_case["source_tree_sha256"],
            "file_count": root_case["file_count"],
            "total_size": root_case["total_size"],
        },
        expected_analysis_output_sha256=analysis_sha256,
        expected_follow_on_lineage_document=lineage_document,
        expected_externalized_shared_reference_document=reference,
    )
    assert root_cleanup["removed"] is True
    assert not os.path.lexists(archive._extended_length_path(staged_root))
    assert (fixture["source"] / "manifest.json").is_file()
    assert (fixture["one_shot"] / "follow-on-analysis.json").is_file()


def test_partial_shared_child_externalization_requires_matching_policy(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    child = _add_shared_follow_on_child(
        fixture,
        status="child_incomplete",
    )
    lineage = target._validate_one_shot_lineage(
        fixture["one_shot"],
        source_case_sha256s=set(fixture["cases"]),
    )

    with pytest.raises(target.CaseStagingError, match="明示的な許可"):
        target.build_shared_derived_externalization_documents(
            lineage,
            collection_id="daily-fixture",
            allow_partial_derived_cases=False,
        )
    document = target.build_shared_derived_externalization_documents(
        lineage,
        collection_id="daily-fixture",
        allow_partial_derived_cases=True,
    )[child]
    assert document["partial_policy"]["allow_partial_derived_cases"] is True
    assert document["child_case_state"] == "partial"


def test_non_leaf_shared_child_is_not_externalized(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    child = _add_shared_follow_on_child(fixture)
    grand_payload = b"MZ-derived-grandchild"
    grandchild = hashlib.sha256(grand_payload).hexdigest()
    child_payload = fixture["one_shot"] / "cases" / child / "p" / f"{grandchild}.exe"
    child_payload_io = archive._extended_length_path(child_payload)
    child_payload_io.parent.mkdir()
    child_payload_io.write_bytes(grand_payload)
    grand_directory = fixture["one_shot"] / "cases" / grandchild
    grand_directory_io = archive._extended_length_path(grand_directory)
    grand_directory_io.mkdir()
    grand_report = {
        "sample": {"sha256": grandchild},
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
        "case_state": {"status": "complete", "complete": True, "blockers": []},
    }
    (grand_directory_io / "report.json").write_text(
        json.dumps(grand_report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph["nodes"].append(
        {
            "sha256": grandchild,
            "depth": 2,
            "state": "analyzed",
            "case_state": "complete",
        }
    )
    graph["edges"].append(
        {
            "parent_sha256": child,
            "child_sha256": grandchild,
            "depth": 2,
            "path": f"p/{grandchild}.exe",
            "role": "recovered_payload",
            "kind": "pe",
            "size": len(grand_payload),
            "status": "child_complete",
        }
    )
    _json(graph_path, graph)
    lineage = target._validate_one_shot_lineage(
        fixture["one_shot"],
        source_case_sha256s=set(fixture["cases"]),
    )

    with pytest.raises(target.CaseStagingError, match="leafではない"):
        target.build_shared_derived_externalization_documents(
            lineage,
            collection_id="daily-fixture",
            allow_partial_derived_cases=False,
        )


def test_orphan_derived_case_is_rejected_globally(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    child = _add_follow_on_child(fixture)
    graph_path = fixture["one_shot"] / "follow-on-analysis.json"
    graph = json.loads(graph_path.read_text(encoding="utf-8"))
    graph["edges"] = []
    _json(graph_path, graph)

    with pytest.raises(target.CaseStagingError, match="active parent"):
        _stage_without_ghidra(fixture)

    assert child in {path.name for path in (fixture["one_shot"] / "cases").iterdir()}


def test_runtime_request_sidecar_is_validated_but_not_staged(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    request = _add_runtime_request_sidecar(fixture)

    result = _stage_without_ghidra(fixture)

    staged = Path(result["cases"][0]["source_path"])
    assert request.is_file()
    assert not any(path.name == request.name for path in staged.rglob("*"))


def test_runtime_request_sidecar_with_unknown_option_is_rejected(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    request = _add_runtime_request_sidecar(fixture)
    document = json.loads(request.read_text(encoding="utf-8"))
    document["options"]["allow_network"] = True
    _json(request, document)

    with pytest.raises(target.CaseStagingError, match="runtime request"):
        _stage_without_ghidra(fixture)


def test_exclusion_set_is_validated_and_only_its_commitment_is_staged(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    identities = _add_exclusion_set(fixture)

    result = _stage_without_ghidra(fixture)

    root = Path(result["cases"][0]["source_path"])
    assert not (root / "exclusion-set.json").exists()
    assert not (root / "source" / "exclusion-set.json").exists()
    acquisition = json.loads((root / "derived" / "source-acquisition.case.json").read_text(encoding="utf-8"))
    assert acquisition["source_sidecars"] == [
        {
            "name": "exclusion-set.json",
            "size": (fixture["source"] / "exclusion-set.json").stat().st_size,
            "sha256": hashlib.sha256((fixture["source"] / "exclusion-set.json").read_bytes()).hexdigest(),
            "raw_content_included": False,
        }
    ]
    assert acquisition["safety"]["raw_source_sidecars_included"] is False
    staged_bytes = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
    assert all(identity.encode("ascii") not in staged_bytes for identity in identities)


def test_invalid_exclusion_set_commitment_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _add_exclusion_set(fixture)
    sidecar_path = fixture["source"] / "exclusion-set.json"
    sidecar = json.loads(sidecar_path.read_text(encoding="utf-8"))
    sidecar["excluded_hashes_sha256"] = "f" * 64
    _json(sidecar_path, sidecar)

    with pytest.raises(target.CaseStagingError, match="commitment"):
        _stage_without_ghidra(fixture)

    assert list(fixture["output"].iterdir()) == []


def test_empty_exclusion_set_is_valid_and_stages_only_its_commitment(
    tmp_path: Path,
) -> None:
    """正規producerが出す空の除外baselineも同じ非公開契約で扱う。"""

    fixture = _fixture(tmp_path)
    assert _add_exclusion_set(fixture, identities=[]) == []

    result = _stage_without_ghidra(fixture)

    root = Path(result["cases"][0]["source_path"])
    acquisition = json.loads((root / "derived" / "source-acquisition.case.json").read_text(encoding="utf-8"))
    assert [item["name"] for item in acquisition["source_sidecars"]] == ["exclusion-set.json"]
    assert acquisition["safety"]["raw_source_sidecars_included"] is False


@pytest.mark.parametrize(
    ("report_updates", "removed_fields", "message"),
    [
        ({"executed_sample": True}, (), "sample非実行"),
        ({"network_contacted": True}, (), "network非接触"),
        ({"ai_used": True}, (), "AI利用"),
        ({}, ("executed_sample",), "sample非実行"),
    ],
)
def test_without_ghidra_rejects_unsafe_or_ambiguous_one_shot_safety(
    tmp_path: Path,
    report_updates: dict[str, object],
    removed_fields: tuple[str, ...],
    message: str,
) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    report_path = fixture["one_shot"] / "cases" / digest / "report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report.update(report_updates)
    for field in removed_fields:
        report.pop(field, None)
    _json(report_path, report)

    with pytest.raises(target.CaseStagingError, match=message):
        _stage_without_ghidra(fixture)

    assert list(fixture["output"].iterdir()) == []


def test_without_ghidra_accepts_legacy_execution_field_and_null_ai(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    report_path = fixture["one_shot"] / "cases" / digest / "report.json"
    _json(
        report_path,
        {
            "sha256": digest,
            "sample_executed": False,
            "network_contacted": False,
            "ai_used": None,
        },
    )

    result = _stage_without_ghidra(fixture)

    assert result["safety"]["ai_used"] is None
    assert result["safety"]["one_shot_report_safety_validated"] is True


def test_cli_requires_exactly_one_ghidra_mode() -> None:
    base = [
        "--repository",
        "repository",
        "--collection-id",
        "daily-fixture",
        "--source-root",
        "source",
        "--one-shot-root",
        "one-shot",
        "--output-root",
        "output",
        "--case-sha256",
        "a" * 64,
    ]

    with pytest.raises(SystemExit):
        target.build_parser().parse_args(base)
    with pytest.raises(SystemExit):
        target.build_parser().parse_args([*base, "--ghidra-root", "ghidra", "--ghidra-not-requested"])


def test_cli_ghidra_not_requested_dispatches_without_ghidra_root(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def fake_stage(**arguments: object) -> dict[str, object]:
        observed.update(arguments)
        return {"schema_version": target.SCHEMA_VERSION, "case_count": 1}

    monkeypatch.setattr(target, "stage_cases_without_ghidra", fake_stage)
    digest = "a" * 64

    exit_code = target.main(
        [
            "--repository",
            "repository",
            "--collection-id",
            "daily-fixture",
            "--source-root",
            "source",
            "--one-shot-root",
            "one-shot",
            "--ghidra-not-requested",
            "--output-root",
            "output",
            "--case-sha256",
            digest,
        ]
    )

    assert exit_code == 0
    assert "ghidra_root" not in observed
    assert observed["case_sha256s"] == [digest]
    assert json.loads(capsys.readouterr().out)["case_count"] == 1


def _add_shared_program(fixture: dict[str, object]) -> str:
    ghidra = fixture["ghidra"]
    payload = b"MZ-shared-component"
    digest = hashlib.sha256(payload).hexdigest()
    (ghidra / "import-staging" / f"{digest}.quarantine.bin").write_bytes(payload)
    object_root = ghidra / "objects" / digest
    object_root.mkdir()
    relationship_document = json.loads((ghidra / "input-relationships.json").read_text(encoding="utf-8"))
    shared_relationships = []
    for case_sha256 in fixture["cases"]:
        root = next(item for item in relationship_document["relationships"] if item["case_sha256"] == case_sha256)
        shared_relationships.append(
            {
                "case_sha256": case_sha256,
                "depth": 1,
                "format": "pe",
                "is_pe": True,
                "layer_sha256": digest,
                "parent_sha256": case_sha256,
                "reconstruction_mode": "authenticated_static_child",
                "size": len(payload),
                "source_archive_sha256": root["source_archive_sha256"],
                "source_archive_size": root["source_archive_size"],
                "transform": "embedded_shared_fixture",
            }
        )
    _json(
        object_root / "program-result.json",
        {
            "schema_version": 1,
            "sha256": digest,
            "status": "complete",
            "functions": [],
            "imports": [],
            "exports": [],
            "segments": [],
            "relationships": shared_relationships,
            "retrieval_coverage": {"strings": {"item_count": 0}},
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "arbitrary_ghidra_scripts_enabled": False,
                "raw_results_private": True,
            },
        },
    )
    (object_root / "decompilations.raw.jsonl").write_text("", encoding="utf-8")
    _json(object_root / "ghidra-raw-index.json", {"sha256": digest})
    relationship_document["relationships"].extend(shared_relationships)
    relationship_document["unique_pe_objects"] += 1
    _json(ghidra / "input-relationships.json", relationship_document)

    validation_path = ghidra / "private-artifact-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    validation["programs"].append(
        {
            "artifacts": {
                "cil_instructions": None,
                "decompilations": str((object_root / "decompilations.raw.jsonl").resolve()),
                "ghidra_raw_index": str((object_root / "ghidra-raw-index.json").resolve()),
                "program_result": str((object_root / "program-result.json").resolve()),
            },
            "characteristic_native_decompilation_count": 0,
            "errors": [],
            "managed_method_body_count": 0,
            "managed_method_count": 0,
            "native_function_count": 0,
            "sha256": digest,
            "valid": True,
        }
    )
    validation["valid_programs"] += 1
    validation["totals"]["programs"] += 1
    _json(validation_path, validation)
    return digest


def test_single_case_is_physically_separated_and_archive_compatible(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected, excluded = fixture["cases"]

    result = _stage(fixture, cases=[selected])

    assert result["case_count"] == 1
    assert result["safety"]["s3_upload_performed"] is False
    staged = Path(result["cases"][0]["source_path"])
    manifest = json.loads((staged / target.STAGING_MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["case_sha256"] == selected
    assert manifest["safety"]["different_cases_included"] is False
    assert manifest["archive_handoff"]["datastore_upload_json_created"] is False
    relationship = json.loads((staged / "derived" / "input-relationships.case.json").read_text(encoding="utf-8"))
    assert {item["case_sha256"] for item in relationship["relationships"]} == {selected}
    validation = json.loads((staged / "derived" / "private-artifact-validation.case.json").read_text(encoding="utf-8"))
    assert [item["sha256"] for item in validation["programs"]] == [selected]
    assert all(
        value is None or value.startswith(f"ghidra/objects/{selected}/")
        for value in validation["programs"][0]["artifacts"].values()
    )
    assert not (staged / "ghidra" / "objects" / excluded).exists()
    assert not (staged / "ghidra" / "import-staging" / f"{excluded}.quarantine.bin").exists()
    assert not any(path.name == "datastore-upload.json" for path in staged.rglob("*"))
    files = archive.collect_source_files([staged])
    assert len(files) == result["cases"][0]["file_count"]
    assert all(path.lstat().st_nlink == 1 for path in staged.rglob("*") if path.is_file())


def test_collection_session_validates_once_and_stages_one_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    calls = 0
    original = target._validate_private_validation

    def count_validation(*args: object, **kwargs: object) -> object:
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(target, "_validate_private_validation", count_validation)
    session = target.prepare_case_staging_session(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        ghidra_root=fixture["ghidra"],
        output_root=fixture["output"],
        case_sha256s=fixture["cases"],
    )
    result = target.stage_case_from_session(
        session,
        case_sha256=fixture["cases"][0],
    )

    assert calls == 1
    assert len(session.inputs.cases) == 2
    assert result["case_count"] == 1
    assert result["cases"][0]["case_sha256"] == fixture["cases"][0]
    assert result["safety"]["case_separated"] is True


def test_collection_session_accepts_strict_provider_hash_alias(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    actual = fixture["cases"][0]
    requested = hashlib.sha256(b"provider-requested-identity").hexdigest()
    source = fixture["source"]
    source_case = source / actual
    requested_case = source / requested
    source_case.rename(requested_case)
    (requested_case / f"{actual}.zip").rename(requested_case / f"{requested}.zip")
    source_document = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    source_document["selected_hashes"][0] = requested
    source_document["selected_metadata"][0]["sha256_hash"] = requested
    source_item = source_document["items"][0]
    source_item["sha256"] = requested
    source_item["metadata"]["sha256_hash"] = requested
    source_item["zip_path"] = str((requested_case / f"{requested}.zip").resolve())
    _recommit_selection(source_document)
    _json(source / "manifest.json", source_document)

    one_shot_report = fixture["one_shot"] / "cases" / actual / "report.json"
    _json(
        one_shot_report,
        {
            "sample": {
                "sha256": actual,
                "input_kind": "authenticated_single_member_zip",
                "outer_sha256": source_item["zip_sha256"],
                "outer_size": source_item["zip_size"],
                "member_name": f"{requested}.exe",
            }
        },
    )
    _json(
        fixture["repository"] / "analysis-results" / "collections" / "daily-fixture" / "manifest.json",
        {
            "collection_id": "daily-fixture",
            "acquisition_items": [
                {
                    "sha256": actual,
                    "provider_requested_sha256": requested,
                    "zip_sha256": source_item["zip_sha256"],
                    "zip_size": source_item["zip_size"],
                    "metadata": {"sha256_hash": actual},
                    "provider_reported_metadata": {"sha256_hash": requested},
                    "source_integrity": {
                        "status": "provider_requested_sha256_mismatch",
                        "provider_requested_sha256": requested,
                        "analyzed_member_sha256": actual,
                        "archive_sha256": source_item["zip_sha256"],
                        "archive_size": source_item["zip_size"],
                        "member_name": f"{requested}.exe",
                        "provider_metadata_used_for_family_attribution": False,
                    },
                }
            ],
        },
    )

    session = target.prepare_case_staging_session(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=source,
        one_shot_root=fixture["one_shot"],
        ghidra_root=fixture["ghidra"],
        output_root=fixture["output"],
        case_sha256s=[requested, fixture["cases"][1]],
    )
    result = target.stage_case_from_session(session, case_sha256=requested)

    assert set(session.inputs.cases) == set(fixture["cases"])
    assert session.inputs.cases[actual].source_requested_sha256 == requested
    staged = Path(result["cases"][0]["source_path"])
    assert archive._extended_length_path(staged / "source" / f"{requested}.zip").is_file()
    provenance = json.loads((staged / "derived" / "source-acquisition.case.json").read_text(encoding="utf-8"))
    assert provenance["case_sha256"] == actual
    assert provenance["provider_requested_sha256"] == requested


def test_collection_session_rejects_tampered_provider_hash_alias(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    actual = fixture["cases"][0]
    requested = hashlib.sha256(b"provider-requested-identity").hexdigest()
    source = fixture["source"]
    (source / actual).rename(source / requested)
    (source / requested / f"{actual}.zip").rename(source / requested / f"{requested}.zip")
    source_document = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
    source_document["selected_hashes"][0] = requested
    source_document["selected_metadata"][0]["sha256_hash"] = requested
    source_document["items"][0]["sha256"] = requested
    source_document["items"][0]["metadata"]["sha256_hash"] = requested
    source_document["items"][0]["zip_path"] = str((source / requested / f"{requested}.zip").resolve())
    _recommit_selection(source_document)
    _json(source / "manifest.json", source_document)

    with pytest.raises(target.CaseStagingError, match="公開collection"):
        target.prepare_case_staging_session(
            repository=fixture["repository"],
            collection_id="daily-fixture",
            source_root=source,
            one_shot_root=fixture["one_shot"],
            ghidra_root=fixture["ghidra"],
            output_root=fixture["output"],
            case_sha256s=[requested, fixture["cases"][1]],
        )


def test_collection_session_rejects_case_tree_changed_after_preflight(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][1]
    session = target.prepare_case_staging_session(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        ghidra_root=fixture["ghidra"],
        output_root=fixture["output"],
        case_sha256s=fixture["cases"],
    )
    (fixture["source"] / selected / "late-added.bin").write_bytes(b"not committed")

    with pytest.raises(target.CaseStagingError, match="preflight commitment"):
        target.stage_case_from_session(session, case_sha256=selected)

    assert not (fixture["output"] / f"daily-fixture-{selected}").exists()


def test_host_path_scan_keeps_malware_build_path_but_rejects_analysis_root() -> None:
    home = os.fspath(Path.home()).encode("utf-8")
    target._scan_sensitive_content(
        home + rb"\Desktop\builder\go\src\runtime",
        relative="ghidra/import-staging/sample.quarantine.bin",
    )

    with pytest.raises(target.CaseStagingError, match="current_host_analysis_path"):
        target._scan_sensitive_content(
            os.fspath(Path.cwd().resolve()).encode("utf-8"),
            relative="derived/provenance.json",
        )


def test_exactly_one_case_is_required_per_invocation(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    with pytest.raises(target.CaseStagingError, match="1回につき1件"):
        _stage(fixture, cases=[])
    with pytest.raises(target.CaseStagingError, match="1回につき1件"):
        _stage(fixture, cases=list(fixture["cases"]))

    assert not fixture["output"].exists()


def test_shared_program_result_is_filtered_to_the_selected_case(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    shared = _add_shared_program(fixture)
    selected, excluded = fixture["cases"]

    result = _stage(fixture, cases=[selected])

    staged = Path(result["cases"][0]["source_path"])
    program_result_path = staged / "ghidra" / "objects" / shared / "program-result.json"
    raw = archive._extended_length_path(program_result_path).read_bytes()
    program = json.loads(raw)
    assert {item["case_sha256"] for item in program["relationships"]} == {selected}
    assert excluded.encode("ascii") not in raw


def test_explicit_other_case_reference_is_rejected_after_copy(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected, excluded = fixture["cases"]
    (fixture["one_shot"] / "cases" / selected / "report.json").write_text(
        json.dumps({"case_sha256": excluded}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(target.CaseStagingError, match="他case"):
        _stage(fixture, cases=[selected])

    assert list(fixture["output"].iterdir()) == []


@pytest.mark.parametrize("identity_field", ["sample.sha256", "sample_sha256"])
def test_one_shot_report_identity_aliases_are_bound_to_selected_case(
    tmp_path: Path,
    identity_field: str,
) -> None:
    """reportの別identity表現に他caseが混在した場合も公開前に拒否する。"""

    fixture = _fixture(tmp_path)
    selected, excluded = fixture["cases"]
    report: dict[str, object] = {"sha256": selected}
    if identity_field == "sample.sha256":
        report["sample"] = {"sha256": excluded}
    else:
        report["sample_sha256"] = excluded
    _json(
        fixture["one_shot"] / "cases" / selected / "report.json",
        report,
    )

    with pytest.raises(target.CaseStagingError, match="他case"):
        _stage(fixture, cases=[selected])

    assert list(fixture["output"].iterdir()) == []


def test_secret_content_is_rejected_and_partial_stage_is_removed(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    (fixture["one_shot"] / "cases" / selected / "report.json").write_text(
        '{"token":"github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}\n',
        encoding="utf-8",
    )

    with pytest.raises(target.CaseStagingError, match="秘密値"):
        _stage(fixture, cases=[selected])

    output = fixture["output"]
    assert output.is_dir()
    assert list(output.iterdir()) == []


def test_secret_content_split_across_scan_chunks_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    token = b"github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    report = fixture["one_shot"] / "cases" / selected / "report.json"
    report.write_bytes(b"x" * (target.COPY_CHUNK_BYTES - 12) + token)

    with pytest.raises(target.CaseStagingError, match="秘密値"):
        _stage(fixture, cases=[selected])

    assert list(fixture["output"].iterdir()) == []


def test_verified_malware_binary_is_hash_bound_without_text_secret_scan(
    tmp_path: Path,
) -> None:
    """検体内の攻撃者制御文字列をhost秘密値と誤認せず、SHA-256で拘束する。"""

    marker = b"-----BEGIN PRIVATE KEY-----"
    fixture = _fixture(
        tmp_path,
        pe_payloads=(b"MZ-malware" + marker, b"MZ-case-two"),
    )
    selected = fixture["cases"][0]

    result = _stage(fixture, cases=[selected])

    staged = Path(result["cases"][0]["source_path"])
    imported = staged / "ghidra" / "import-staging" / f"{selected}.quarantine.bin"
    assert archive._extended_length_path(imported).read_bytes() == b"MZ-malware" + marker
    assert result["preflight_verified_malware_binaries_excluded"] == 1
    manifest = json.loads((staged / target.STAGING_MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["safety"]["host_secret_content_scan_scope"] == ("non_sample_content_only")
    assert manifest["safety"]["verified_malware_binary_count"] == 1


def test_sensitive_filename_is_rejected_before_copy(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    (fixture["one_shot"] / "cases" / selected / "datastore-upload.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    with pytest.raises(target.CaseStagingError, match="資格情報"):
        _stage(fixture, cases=[selected])


def test_import_content_must_match_layer_sha256(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    (fixture["ghidra"] / "import-staging" / f"{selected}.quarantine.bin").write_bytes(b"MZ-replaced")

    with pytest.raises(target.CaseStagingError, match="内容SHA-256"):
        _stage(fixture, cases=[selected])


def test_copy_rejects_source_replacement_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """preflight後に同名sourceを差し替えてもidentity／SHA拘束でfail-closedにする。"""

    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    archive_path = fixture["source"] / selected / f"{selected}.zip"
    original_copy_file = target._copy_file
    replaced = False

    def replace_then_copy(
        source: Path,
        destination: Path,
        *,
        staging_root: Path,
        role: str,
        commitments: dict[str, target.SourceCommitment],
    ) -> target.CopiedFile:
        nonlocal replaced
        if source.name == archive_path.name and role == "source" and not replaced:
            replacement = source.with_name(f".{source.name}.replacement")
            replacement.write_bytes(b"X" * source.stat().st_size)
            os.replace(replacement, source)
            replaced = True
        return original_copy_file(
            source,
            destination,
            staging_root=staging_root,
            role=role,
            commitments=commitments,
        )

    monkeypatch.setattr(target, "_copy_file", replace_then_copy)

    with pytest.raises(
        target.CaseStagingError,
        match="単一handle|commitment",
    ):
        _stage(fixture, cases=[selected])

    assert replaced is True
    assert list(fixture["output"].iterdir()) == []


def test_promoted_staging_rejects_same_size_content_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """final rename直後の同サイズ改変もcountだけで受理しない。"""

    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    real_replace = target.os.replace
    changed = False

    def replace_then_change(source: Path, destination: Path) -> None:
        nonlocal changed
        real_replace(source, destination)
        if Path(destination).name.startswith("daily-fixture-"):
            report = Path(destination) / "one-shot-private" / "report.json"
            payload = bytearray(report.read_bytes())
            payload[0] ^= 1
            report.write_bytes(payload)
            changed = True

    monkeypatch.setattr(target.os, "replace", replace_then_change)

    with pytest.raises(target.CaseStagingError, match="copy commitment"):
        _stage(fixture, cases=[selected])

    assert changed is True


def test_validation_artifact_cannot_escape_its_object(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    validation_path = fixture["ghidra"] / "private-artifact-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    external = fixture["ghidra"] / "objects" / fixture["cases"][1] / "program-result.json"
    validation["programs"][0]["artifacts"]["program_result"] = str(external.resolve())
    _json(validation_path, validation)

    with pytest.raises(target.CaseStagingError, match="対応object外"):
        _stage(fixture, cases=[selected])


def test_missing_decompilation_file_is_allowed_when_no_characteristic_function_was_selected(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    validation_path = fixture["ghidra"] / "private-artifact-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    program = next(item for item in validation["programs"] if item["sha256"] == selected)
    program["native_function_count"] = 5
    validation["totals"]["native_functions"] = 5
    validation["totals"]["functions_items"] = 5
    _json(validation_path, validation)
    decompilations = fixture["ghidra"] / "objects" / selected / "decompilations.raw.jsonl"
    decompilations.unlink()

    staged = _stage(fixture, cases=[selected])

    source = Path(staged["cases"][0]["source_path"])
    derived = json.loads((source / "derived" / "private-artifact-validation.case.json").read_text(encoding="utf-8"))
    assert derived["programs"][0]["artifacts"]["decompilations"] is None


def test_missing_decompilation_file_is_rejected_when_characteristic_function_was_selected(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    validation_path = fixture["ghidra"] / "private-artifact-validation.json"
    validation = json.loads(validation_path.read_text(encoding="utf-8"))
    program = next(item for item in validation["programs"] if item["sha256"] == selected)
    program["native_function_count"] = 5
    program["characteristic_native_decompilation_count"] = 1
    validation["totals"]["native_functions"] = 5
    validation["totals"]["functions_items"] = 5
    validation["totals"]["characteristic_native_decompilations"] = 1
    _json(validation_path, validation)
    (fixture["ghidra"] / "objects" / selected / "decompilations.raw.jsonl").unlink()

    with pytest.raises(target.CaseStagingError, match="必須artifact"):
        _stage(fixture, cases=[selected])


def test_output_inside_repository_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)

    with pytest.raises(target.CaseStagingError, match="repository内"):
        target.stage_cases(
            repository=fixture["repository"],
            collection_id="daily-fixture",
            source_root=fixture["source"],
            one_shot_root=fixture["one_shot"],
            ghidra_root=fixture["ghidra"],
            output_root=fixture["repository"] / ".work" / "case-staging",
            case_sha256s=[fixture["cases"][0]],
        )


def test_source_hardlink_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    source_file = fixture["one_shot"] / "cases" / selected / "report.json"
    alias = fixture["one_shot"] / "cases" / selected / "alias.json"
    try:
        os.link(source_file, alias)
    except OSError as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")

    with pytest.raises(target.CaseStagingError, match="hardlink"):
        _stage(fixture, cases=[selected])


def test_incomplete_ghidra_run_is_rejected(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    progress = fixture["ghidra"] / "run-progress.json"
    document = json.loads(progress.read_text(encoding="utf-8"))
    document["status"] = "ghidra_chunk_pending"
    _json(progress, document)

    with pytest.raises(target.CaseStagingError, match="未完"):
        _stage(fixture, cases=[fixture["cases"][0]])


def test_existing_case_staging_is_fully_revalidated_for_resume(
    tmp_path: Path,
) -> None:
    """一時upload失敗後に残した正規stagingを同じcase/targetで再利用できる。"""

    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    staged = _stage(fixture, cases=[selected])
    original = staged["cases"][0]

    resumed = target.reuse_case_staging(
        output_root=fixture["output"],
        collection_id="daily-fixture",
        case_sha256=selected,
    )

    assert resumed["reused_existing_staging"] is True
    assert resumed["case_count"] == 1
    assert resumed["cases"][0]["case_sha256"] == selected
    assert resumed["cases"][0]["target"] == original["target"]
    assert Path(resumed["cases"][0]["source_path"]) == Path(original["source_path"])
    assert resumed["safety"]["existing_staging_fully_revalidated"] is True


def test_complete_derived_staging_can_be_reused_and_cleaned_up(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    child = _add_follow_on_child(fixture)
    staged = _stage_without_ghidra(fixture)
    case_result = staged["cases"][0]

    resumed = target.reuse_case_staging(
        output_root=fixture["output"],
        collection_id="daily-fixture",
        case_sha256=selected,
    )

    assert resumed["cases"][0]["derived_case_state_counts"] == {
        "complete": 1,
        "partial": 0,
    }
    assert archive._extended_length_path(
        Path(resumed["cases"][0]["source_path"])
        / "one-shot-derived"
        / child
        / "report.json"
    ).is_file()
    cleanup = target.remove_case_staging_after_verified_archive(
        output_root=fixture["output"],
        source_path=Path(case_result["source_path"]),
        collection_id="daily-fixture",
        case_sha256=selected,
        archive_result=_verified_archive_result(case_result),
    )
    assert cleanup["removed"] is True


def test_partial_derived_staging_reuse_and_cleanup_require_explicit_policy(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    _add_follow_on_child(fixture, status="child_incomplete")
    staged = target.stage_cases_without_ghidra(
        repository=fixture["repository"],
        collection_id="daily-fixture",
        source_root=fixture["source"],
        one_shot_root=fixture["one_shot"],
        output_root=fixture["output"],
        case_sha256s=[selected],
        allow_partial_derived_cases=True,
        expected_analysis_output_sha256="d" * 64,
    )
    case_result = staged["cases"][0]

    with pytest.raises(target.CaseStagingError, match="明示的な許可"):
        target.reuse_case_staging(
            output_root=fixture["output"],
            collection_id="daily-fixture",
            case_sha256=selected,
        )
    with pytest.raises(target.CaseStagingError, match="analysis tree commitment"):
        target.reuse_case_staging(
            output_root=fixture["output"],
            collection_id="daily-fixture",
            case_sha256=selected,
            allow_partial_derived_cases=True,
            expected_analysis_output_sha256="e" * 64,
        )

    resumed = target.reuse_case_staging(
        output_root=fixture["output"],
        collection_id="daily-fixture",
        case_sha256=selected,
        allow_partial_derived_cases=True,
        expected_analysis_output_sha256="d" * 64,
    )
    assert resumed["cases"][0]["derived_case_state_counts"]["partial"] == 1

    with pytest.raises(target.CaseStagingError, match="明示的な許可"):
        target.remove_case_staging_after_verified_archive(
            output_root=fixture["output"],
            source_path=Path(case_result["source_path"]),
            collection_id="daily-fixture",
            case_sha256=selected,
            archive_result=_verified_archive_result(case_result),
        )
    cleanup = target.remove_case_staging_after_verified_archive(
        output_root=fixture["output"],
        source_path=Path(case_result["source_path"]),
        collection_id="daily-fixture",
        case_sha256=selected,
        archive_result=_verified_archive_result(case_result),
        allow_partial_derived_cases=True,
        expected_analysis_output_sha256="d" * 64,
    )
    assert cleanup["removed"] is True


def test_existing_case_staging_tamper_is_rejected_on_resume(
    tmp_path: Path,
) -> None:
    """保持stagingの1 byte変更を再開時inventory照合で拒否する。"""

    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    staged = _stage(fixture, cases=[selected])
    source = Path(staged["cases"][0]["source_path"])
    report = source / "one-shot-private" / "report.json"
    report.write_bytes(report.read_bytes() + b" ")

    with pytest.raises(target.CaseStagingError, match="SHA-256"):
        target.reuse_case_staging(
            output_root=fixture["output"],
            collection_id="daily-fixture",
            case_sha256=selected,
        )

    assert source.is_dir()


def test_existing_ghidra_import_requires_filename_sha256_on_resume(
    tmp_path: Path,
) -> None:
    """inventoryを再作成されても検体名と実データのSHA-256不一致を拒否する。"""

    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    staged = _stage(fixture, cases=[selected])
    source = Path(staged["cases"][0]["source_path"])
    imported = source / "ghidra" / "import-staging" / f"{selected}.quarantine.bin"
    imported_io = archive._extended_length_path(imported)
    imported_io.write_bytes(b"NZ" + imported_io.read_bytes()[2:])

    manifest_path = source / target.STAGING_MANIFEST_NAME
    manifest_io = archive._extended_length_path(manifest_path)
    manifest = json.loads(manifest_io.read_text(encoding="utf-8"))
    record = next(
        item for item in manifest["files"] if item["path"] == f"ghidra/import-staging/{selected}.quarantine.bin"
    )
    record["sha256"] = hashlib.sha256(imported_io.read_bytes()).hexdigest()
    manifest["file_inventory_sha256"] = target._inventory_sha256(manifest["files"])
    manifest_io.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(target.CaseStagingError, match="ファイル名SHA-256"):
        target.reuse_case_staging(
            output_root=fixture["output"],
            collection_id="daily-fixture",
            case_sha256=selected,
        )

    assert source.is_dir()


def _verified_archive_result(case_result: dict) -> dict[str, object]:
    files = archive.collect_source_files([Path(case_result["source_path"])])
    records = [{"path": item.archive_name, "size": item.size, "sha256": item.sha256} for item in files]
    commitment = hashlib.sha256(
        json.dumps(
            records,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return {
        "target": case_result["target"],
        "status": "verified",
        "archive_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "source_tree_sha256": commitment,
        "file_count": len(files),
        "total_size": sum(item.size for item in files),
    }


def test_verified_archive_cleanup_removes_only_owned_case_staging(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    result = _stage(fixture, cases=[selected])
    case_result = result["cases"][0]
    staged = Path(case_result["source_path"])
    source_archive = fixture["source"] / selected / f"{selected}.zip"

    cleanup = target.remove_case_staging_after_verified_archive(
        output_root=fixture["output"],
        source_path=staged,
        collection_id="daily-fixture",
        case_sha256=selected,
        archive_result=_verified_archive_result(case_result),
    )

    assert cleanup == {
        "target": case_result["target"],
        "case_sha256": selected,
        "removed": True,
        "source_deleted": False,
    }
    assert not staged.exists()
    assert source_archive.is_file()
    assert list(fixture["output"].iterdir()) == []


def test_cleanup_rejects_unverified_archive_and_preserves_staging(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    result = _stage(fixture, cases=[selected])
    case_result = result["cases"][0]
    staged = Path(case_result["source_path"])
    archive_result = _verified_archive_result(case_result)
    archive_result["status"] = "upload_pending"

    with pytest.raises(target.CaseStagingError, match="remote検証済み"):
        target.remove_case_staging_after_verified_archive(
            output_root=fixture["output"],
            source_path=staged,
            collection_id="daily-fixture",
            case_sha256=selected,
            archive_result=archive_result,
        )

    assert staged.is_dir()


def test_cleanup_rejects_changed_inventory_and_preserves_staging(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    result = _stage(fixture, cases=[selected])
    case_result = result["cases"][0]
    staged = Path(case_result["source_path"])
    archive_result = _verified_archive_result(case_result)
    (staged / "one-shot-private" / "report.json").write_text(
        '{"changed":true}\n',
        encoding="utf-8",
    )

    with pytest.raises(target.CaseStagingError, match="source tree commitment"):
        target.remove_case_staging_after_verified_archive(
            output_root=fixture["output"],
            source_path=staged,
            collection_id="daily-fixture",
            case_sha256=selected,
            archive_result=archive_result,
        )

    assert staged.is_dir()


def test_cleanup_rejects_directory_swap_at_rename_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """事前検証後のdirectory差し替えをidentity固定で拒否する。"""

    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    result = _stage(fixture, cases=[selected])
    case_result = result["cases"][0]
    staged = Path(case_result["source_path"])
    archive_result = _verified_archive_result(case_result)
    saved = staged.with_name(f".{staged.name}.original")
    real_replace = target.os.replace
    swapped = False

    def swap_then_replace(source: Path, destination: Path) -> None:
        nonlocal swapped
        source_path = Path(source)
        if (
            source_path
            == archive._extended_length_path(staged)
            and not swapped
        ):
            source_path.rename(archive._extended_length_path(saved))
            source_path.mkdir()
            (source_path / "attacker.bin").write_bytes(b"same-name-different-tree")
            swapped = True
        real_replace(source, destination)

    monkeypatch.setattr(target.os, "replace", swap_then_replace)

    with pytest.raises(target.CaseStagingError, match="directory identity"):
        target.remove_case_staging_after_verified_archive(
            output_root=fixture["output"],
            source_path=staged,
            collection_id="daily-fixture",
            case_sha256=selected,
            archive_result=archive_result,
        )

    assert swapped is True
    assert saved.is_dir()
    assert any(path.name.endswith(".verified-delete") for path in fixture["output"].iterdir())


def test_verified_cleanup_accepts_case_bound_supplement_target(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    selected = fixture["cases"][0]
    result = _stage(fixture, cases=[selected])
    original = Path(result["cases"][0]["source_path"])
    supplement_target = f"vidar-{selected}-passive-capture"
    supplement = original.parent / supplement_target
    original.rename(supplement)
    manifest_path = supplement / target.STAGING_MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["target"] = supplement_target
    _json(manifest_path, manifest)
    case_result = {
        **result["cases"][0],
        "target": supplement_target,
        "source_path": str(supplement),
    }

    cleanup = target.remove_case_staging_after_verified_archive(
        output_root=fixture["output"],
        source_path=supplement,
        collection_id="daily-fixture",
        case_sha256=selected,
        archive_target=supplement_target,
        archive_result=_verified_archive_result(case_result),
    )

    assert cleanup["removed"] is True
    assert cleanup["target"] == supplement_target
    assert not supplement.exists()
