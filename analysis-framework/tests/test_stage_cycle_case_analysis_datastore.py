"""自動解析cycleのcase別datastore stagingを検証する。"""

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

import archive_analysis_datastore as archive
import stage_case_analysis_datastore as base
import stage_cycle_case_analysis_datastore as target
import terminal_payload_acquisition


def _json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _report(digest: str, *, complete: bool = True) -> dict[str, object]:
    return {
        "sha256": digest,
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
        "case_state": {
            "status": "complete" if complete else "partial",
            "complete": complete,
            "blockers": [] if complete else ["fixture_blocker"],
        },
    }


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _refresh_terminal_and_summary(fixture: dict[str, object]) -> None:
    run = fixture["run"]
    cases = fixture["cases"]
    follow_path = run / "follow-on-analysis.json"
    follow = json.loads(follow_path.read_text(encoding="utf-8"))
    terminal = terminal_payload_acquisition.build_terminal_payload_acquisition(
        follow,
        root_case_states={digest: "complete" for digest in cases},
    )
    terminal_path = run / "terminal-payload-acquisition.json"
    _json(terminal_path, terminal)
    summary_path = run / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["follow_on_analysis"] = {
        "artifact": "follow-on-analysis.json",
        "sha256": _sha256_file(follow_path),
        "status": follow["status"],
        "node_count": len(follow["nodes"]),
        "edge_count": len(follow["edges"]),
        "error_count": len(follow["errors"]),
    }
    summary["terminal_payload_acquisition"] = {
        "artifact": "terminal-payload-acquisition.json",
        "sha256": _sha256_file(terminal_path),
        "status": terminal["status"],
        "frontier_count": len(terminal["frontier"]),
        "selected_count": len(terminal["selected_sha256"]),
        "pending_count": len(terminal["pending_sha256"]),
    }
    _json(summary_path, summary)


def _fixture(tmp_path: Path) -> dict[str, object]:
    repository = tmp_path / "repository"
    source = tmp_path / "private" / "source"
    run = tmp_path / "private" / "run"
    output = tmp_path / "private" / "staging"
    repository.mkdir()
    source.mkdir(parents=True)
    (run / "cases").mkdir(parents=True)
    cases = sorted(hashlib.sha256(value).hexdigest() for value in (b"root-one", b"root-two"))

    items: list[dict[str, object]] = []
    metadata: list[dict[str, object]] = []
    summary_cases: list[dict[str, object]] = []
    for index, digest in enumerate(cases, start=1):
        payload = f"encrypted-archive-{index}".encode("ascii")
        source_case = source / digest
        source_case.mkdir()
        archive_path = source_case / f"{digest}.zip"
        archive_path.write_bytes(payload)
        item_metadata = {
            "sha256_hash": digest,
            "file_name": f"fixture-{index}.exe",
        }
        items.append(
            {
                "sha256": digest,
                "zip_path": str(archive_path),
                "zip_sha256": hashlib.sha256(payload).hexdigest(),
                "zip_size": len(payload),
                "metadata": item_metadata,
            }
        )
        metadata.append(dict(item_metadata))
        case = run / "cases" / digest
        case.mkdir()
        _json(case / "report.json", _report(digest))
        (case / "evidence.txt").write_text(
            f"静的解析済み: {digest[:12]}\n",
            encoding="utf-8",
        )
        summary_cases.append(
            {
                "sha256": digest,
                "case_state": "complete",
                "automation_state": "resolved",
                "report": f"cases/{digest}/report.json",
            }
        )

    _json(
        source / "manifest.json",
        {
            "schema_version": 1,
            "source": "fixture",
            "selected_hashes": cases,
            "selected_metadata": metadata,
            "items": items,
            "complete": True,
            "archives_remain_encrypted": True,
            "samples_executed": False,
            "selection_commitment_sha256": "c" * 64,
        },
    )
    _json(
        source / "exclusion-set.json",
        {
            "schema_version": 1,
            "excluded_hashes_sha256": "e" * 64,
            "excluded_count": 100,
        },
    )
    _json(
        run / "follow-on-analysis.json",
        {
            "schema_version": 1,
            "status": "no_retained_payloads",
            "roots": cases,
            "nodes": [{"sha256": digest, "depth": 0, "state": "root"} for digest in cases],
            "edges": [],
            "omitted_metadata": [],
            "omitted_metadata_commitments": [],
            "errors": [],
            "wall_clock_exhausted": False,
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        },
    )
    _json(
        run / "summary.json",
        {
            "schema_version": 1,
            "counts": {
                "input_files": len(cases),
                "analyzed": len(cases),
                "complete": len(cases),
                "partial": 0,
                "failed": 0,
                "errors": 0,
            },
            "cases": summary_cases,
            "derived_cases": [],
            "executed_sample": False,
            "network_contacted": False,
            "ai_used": False,
        },
    )
    fixture = {
        "repository": repository,
        "source": source,
        "run": run,
        "output": output,
        "cases": cases,
    }
    _refresh_terminal_and_summary(fixture)
    return fixture


def _stage(fixture: dict[str, object], *, digest: str | None = None) -> dict:
    selected = digest or fixture["cases"][0]
    return target.stage_cycle_case(
        repository=fixture["repository"],
        collection_id="valleyrat-auto-cycle-fixture",
        source_root=fixture["source"],
        run_root=fixture["run"],
        output_root=fixture["output"],
        case_sha256=selected,
    )


def test_stage_cycle_case_is_case_scoped_and_archive_ready(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    other = fixture["cases"][1]

    result = _stage(fixture)

    assert result["case_count"] == 1
    assert result["safety"]["s3_upload_performed"] is False
    case = result["cases"][0]
    root = Path(case["source_path"])
    root_io = archive._extended_length_path(root)
    source_archive = root_io / "source" / digest / f"{digest}.zip"
    assert source_archive.is_file()
    assert (root_io / "cycle-analysis" / digest / "report.json").is_file()
    assert not (root_io / "source" / "exclusion-set.json").exists()
    assert not (root_io / "cycle-analysis" / other).exists()
    sidecar_projection = json.loads((root_io / "derived" / "source-sidecars.case.json").read_text(encoding="utf-8"))
    assert sidecar_projection["source_sidecars"] == [
        {
            "name": "exclusion-set.json",
            "raw_content_included": False,
            "sha256": _sha256_file(fixture["source"] / "exclusion-set.json"),
            "size": (fixture["source"] / "exclusion-set.json").stat().st_size,
        }
    ]
    for path in root_io.rglob("*.json"):
        text = path.read_text(encoding="utf-8")
        assert other not in path.read_text(encoding="utf-8")
        assert "e" * 64 not in text
    files = archive.collect_source_files([root])
    records = [{"path": item.archive_name, "size": item.size, "sha256": item.sha256} for item in files]
    assert case["source_tree_sha256"] == base._inventory_sha256(records)
    assert (fixture["source"] / digest / f"{digest}.zip").is_file()
    assert not os.path.samefile(
        fixture["source"] / digest / f"{digest}.zip",
        source_archive,
    )


def test_stage_cycle_case_rejects_partial_run(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    _json(fixture["run"] / "cases" / digest / "report.json", _report(digest, complete=False))
    summary_path = fixture["run"] / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["cases"][0]["case_state"] = "partial"
    summary["counts"]["complete"] = 1
    summary["counts"]["partial"] = 1
    _json(summary_path, summary)

    with pytest.raises(target.CycleCaseStagingError, match="partial|未完了"):
        _stage(fixture)


def test_stage_cycle_case_rejects_aborted_marker(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    (fixture["run"] / "ABORTED-UNUSABLE.txt").write_text(
        "中断済み",
        encoding="utf-8",
    )

    with pytest.raises(target.CycleCaseStagingError, match="ABORTED|未束縛"):
        _stage(fixture)


def test_stage_cycle_case_rejects_unbound_case_directory(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    extra = hashlib.sha256(b"unbound-case").hexdigest()
    directory = fixture["run"] / "cases" / extra
    directory.mkdir()
    _json(directory / "report.json", _report(extra))

    with pytest.raises(target.CycleCaseStagingError, match="未束縛case"):
        _stage(fixture)


def test_stage_cycle_case_rejects_partial_subset_run(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    other = fixture["cases"][1]
    for path in (fixture["run"] / "cases" / other).iterdir():
        path.unlink()
    (fixture["run"] / "cases" / other).rmdir()

    with pytest.raises(target.CycleCaseStagingError, match="case集合|未束縛case"):
        _stage(fixture)


def test_stage_cycle_case_rejects_secret_content(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    (fixture["run"] / "cases" / digest / "operator-note.txt").write_text(
        "github_pat_" + "A" * 40,
        encoding="utf-8",
    )

    with pytest.raises(target.CycleCaseStagingError, match="秘密値"):
        _stage(fixture)


def test_stage_cycle_case_rejects_current_repository_path(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    (fixture["run"] / "cases" / digest / "operator-note.txt").write_text(
        str(Path.cwd()),
        encoding="utf-8",
    )

    with pytest.raises(target.CycleCaseStagingError, match="host path"):
        _stage(fixture)


def test_stage_cycle_case_rejects_foreign_case_reference(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest, foreign = fixture["cases"]
    _json(
        fixture["run"] / "cases" / digest / "foreign.json",
        {"case_sha256": foreign},
    )

    with pytest.raises(target.CycleCaseStagingError, match="安全に渡せません"):
        _stage(fixture)


def test_stage_cycle_case_rejects_hardlink(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    external = tmp_path / "external-note.txt"
    external.write_text("private", encoding="utf-8")
    linked = fixture["run"] / "cases" / digest / "linked-note.txt"
    try:
        os.link(external, linked)
    except OSError as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")

    with pytest.raises(target.CycleCaseStagingError, match="hardlink"):
        _stage(fixture)


def test_stage_cycle_case_rejects_sidecar_changed_after_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    original = base._copy_tree
    changed = False

    def mutate_after_first_copy(*args: object, **kwargs: object) -> list[base.CopiedFile]:
        nonlocal changed
        copied = original(*args, **kwargs)
        if not changed:
            changed = True
            _json(
                fixture["source"] / "exclusion-set.json",
                {"schema_version": 1, "excluded_count": 101},
            )
        return copied

    monkeypatch.setattr(base, "_copy_tree", mutate_after_first_copy)

    with pytest.raises(target.CycleCaseStagingError, match="preflight"):
        _stage(fixture)

    assert not any(fixture["output"].iterdir())


def test_stage_cycle_case_refuses_existing_target(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _stage(fixture)

    with pytest.raises(target.CycleCaseStagingError, match="上書きしません"):
        _stage(fixture)


def test_stage_cycle_case_keeps_reachable_payload_relationship(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    child_payload = b"derived-fixture"
    child = hashlib.sha256(child_payload).hexdigest()
    child_directory = fixture["run"] / "cases" / child
    child_directory.mkdir()
    _json(child_directory / "report.json", _report(child))
    payload_path = fixture["run"] / "cases" / digest / "p" / f"{child}.bin"
    payload_path.parent.mkdir(parents=True)
    archive._extended_length_path(payload_path).write_bytes(child_payload)

    summary_path = fixture["run"] / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["derived_cases"] = [
        {
            "sha256": child,
            "case_state": "complete",
            "automation_state": "resolved",
            "ai_used": False,
            "report": f"cases/{child}/report.json",
        }
    ]
    _json(summary_path, summary)
    follow_path = fixture["run"] / "follow-on-analysis.json"
    follow = json.loads(follow_path.read_text(encoding="utf-8"))
    follow["status"] = "complete"
    follow["nodes"].append(
        {
            "sha256": child,
            "depth": 1,
            "size": len(child_payload),
            "state": "analyzed",
            "case_state": "complete",
            "family_hint_count": 0,
            "family_hint_root_sha256": None,
            "family_hint_lineage_depth": None,
        }
    )
    follow["edges"] = [
        {
            "parent_sha256": digest,
            "child_sha256": child,
            "depth": 1,
            "path": f"p/{child}.bin",
            "role": "terminal_payload",
            "kind": "binary",
            "size": len(child_payload),
            "status": "child_complete",
        }
    ]
    _json(follow_path, follow)
    _refresh_terminal_and_summary(fixture)

    result = _stage(fixture)

    root = archive._extended_length_path(Path(result["cases"][0]["source_path"]))
    assert (root / "cycle-analysis" / digest / "p" / f"{child}.bin").read_bytes() == child_payload
    assert (root / "recovered-payloads" / digest / "p" / f"{child}.bin").read_bytes() == child_payload
    assert not (root / "cycle-analysis" / child).exists()
    projection = json.loads((root / "derived" / "follow-on.case.json").read_text(encoding="utf-8"))
    assert projection["descendant_sha256"] == [child]


def test_stage_cycle_case_rejects_recovered_payload_hash_mismatch(
    tmp_path: Path,
) -> None:
    fixture = _fixture(tmp_path)
    digest = fixture["cases"][0]
    expected_payload = b"derived-fixture"
    observed_payload = b"derived-fixturE"
    child = hashlib.sha256(expected_payload).hexdigest()
    child_directory = fixture["run"] / "cases" / child
    child_directory.mkdir()
    _json(child_directory / "report.json", _report(child))
    payload_path = fixture["run"] / "cases" / digest / "p" / f"{child}.bin"
    payload_path.parent.mkdir(parents=True)
    archive._extended_length_path(payload_path).write_bytes(observed_payload)

    summary_path = fixture["run"] / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["derived_cases"] = [
        {
            "sha256": child,
            "case_state": "complete",
            "automation_state": "resolved",
            "ai_used": False,
            "report": f"cases/{child}/report.json",
        }
    ]
    _json(summary_path, summary)
    follow_path = fixture["run"] / "follow-on-analysis.json"
    follow = json.loads(follow_path.read_text(encoding="utf-8"))
    follow["status"] = "complete"
    follow["nodes"].append(
        {
            "sha256": child,
            "depth": 1,
            "size": len(expected_payload),
            "state": "analyzed",
            "case_state": "complete",
            "family_hint_count": 0,
            "family_hint_root_sha256": None,
            "family_hint_lineage_depth": None,
        }
    )
    follow["edges"] = [
        {
            "parent_sha256": digest,
            "child_sha256": child,
            "depth": 1,
            "path": f"p/{child}.bin",
            "role": "terminal_payload",
            "kind": "binary",
            "size": len(expected_payload),
            "status": "child_complete",
        }
    ]
    _json(follow_path, follow)
    _refresh_terminal_and_summary(fixture)

    with pytest.raises(target.CycleCaseStagingError, match="SHA-256"):
        _stage(fixture)


def test_stage_cycle_case_rejects_shared_derived_case(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    first, second = fixture["cases"]
    child = hashlib.sha256(b"shared-derived").hexdigest()
    child_directory = fixture["run"] / "cases" / child
    child_directory.mkdir()
    _json(child_directory / "report.json", _report(child))
    summary_path = fixture["run"] / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["derived_cases"] = [
        {
            "sha256": child,
            "case_state": "complete",
            "automation_state": "resolved",
            "ai_used": False,
            "report": f"cases/{child}/report.json",
        }
    ]
    _json(summary_path, summary)
    follow_path = fixture["run"] / "follow-on-analysis.json"
    follow = json.loads(follow_path.read_text(encoding="utf-8"))
    follow["status"] = "complete"
    follow["nodes"].append(
        {
            "sha256": child,
            "depth": 1,
            "size": 1,
            "state": "analyzed",
            "case_state": "complete",
            "family_hint_count": 0,
            "family_hint_root_sha256": None,
            "family_hint_lineage_depth": None,
        }
    )
    follow["edges"] = [
        {
            "parent_sha256": parent,
            "child_sha256": child,
            "depth": 1,
            "path": f"p/{child}.bin",
            "role": "terminal_payload",
            "kind": "binary",
            "size": 1,
            "status": ("child_complete" if parent == first else "shared_sha256_reused_complete"),
        }
        for parent in (first, second)
    ]
    _json(follow_path, follow)

    with pytest.raises(target.CycleCaseStagingError, match="複数root"):
        _stage(fixture)
