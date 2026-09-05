"""検体単位のprivate artifact分離とdatastore handoffを検証する。"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

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


def _fixture(tmp_path: Path) -> dict[str, object]:
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

    pe_payloads = (b"MZ-case-one", b"MZ-case-two")
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
        _json(case_result / "report.json", {"sha256": case_sha256})

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

    _json(
        source / "manifest.json",
        {
            "schema_version": 1,
            "source": "fixture",
            "selection_mode": "windows_pe_newest",
            "selected_at": "2026-09-03T00:00:00Z",
            "selected_hashes": cases,
            "selected_metadata": selected_metadata,
            "items": items,
            "complete": True,
            "archives_remain_encrypted": True,
            "samples_executed": False,
            "selection_commitment_sha256": "c" * 64,
        },
    )
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
    archive_path = (
        fixture["source"]
        / selected
        / f"{selected}.zip"
    )
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
    derived = json.loads(
        (source / "derived" / "private-artifact-validation.case.json").read_text(encoding="utf-8")
    )
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
    assert Path(resumed["cases"][0]["source_path"]) == Path(
        original["source_path"]
    )
    assert resumed["safety"]["existing_staging_fully_revalidated"] is True


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
        if source_path == staged and not swapped:
            source_path.rename(saved)
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
