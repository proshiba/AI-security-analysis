"""終端ギャップの元archive照合とfail-closed分類を検証する。"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
import terminal_gap_source_queue as queue  # noqa: E402


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def _case(root: Path, marker: str, *, family: str = "asyncrat", state: str = "explicit_unrecovered") -> dict:
    digest = marker * 64
    canonical = f"analysis-results/malware/{family}/versions/unknown/cases/{digest}"
    case_dir = root.joinpath(*canonical.split("/"))
    case_dir.mkdir(parents=True)
    _write_json(case_dir / "metadata.json", {"sha256": digest, "collections": []})
    return {
        "sha256": digest,
        "family": family,
        "version_key": "unknown",
        "canonical_path": canonical,
        "priority": "P0",
        "state": state,
        "gap_types": ["terminal_payload_unrecovered"],
    }


def _inventory(*cases: dict) -> dict:
    return {"schema_version": 1, "cases": list(cases)}


def test_report_and_collection_binding_verify_same_private_archive(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    case = _case(root, "a")
    archive = b"harmless synthetic ZIP stand-in"
    archive_sha = hashlib.sha256(archive).hexdigest()
    (private / f"{case['sha256']}.zip").write_bytes(archive)
    case_dir = root.joinpath(*case["canonical_path"].split("/"))
    _write_json(case_dir / "report.json", {
        "sample": {"sha256": case["sha256"], "input_kind": "authenticated_single_member_zip", "outer_sha256": archive_sha, "outer_size": len(archive)}
    })
    _write_json(case_dir / "metadata.json", {"sha256": case["sha256"], "collections": ["batch-1"]})
    manifest = root / "analysis-results/collections/batch-1/sources/asyncrat/malwarebazaar-manifest.json"
    _write_json(manifest, {"items": [{
        "sha256": case["sha256"], "zip_sha256": archive_sha, "zip_size": len(archive),
        "metadata": {"sha256_hash": case["sha256"]},
    }]})

    result = queue.build_queue(root, _inventory(case), input_root=private)
    source = result["cases"][0]["source"]
    assert source["status"] == "verified"
    assert source["archive_sha256"] == archive_sha
    assert source["binding_sources"] == ["case_report", "collection:batch-1"]
    assert result["cases"][0]["automatic_dispatch_allowed"] is False
    assert result["safety"]["sample_executed"] is False


def test_conflicting_bindings_are_not_dispatched(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    case = _case(root, "b")
    case_dir = root.joinpath(*case["canonical_path"].split("/"))
    _write_json(case_dir / "report.json", {
        "sample": {"sha256": case["sha256"], "input_kind": "authenticated_single_member_zip", "outer_sha256": "1" * 64, "outer_size": 50}
    })
    _write_json(case_dir / "metadata.json", {"sha256": case["sha256"], "collections": ["batch-2"]})
    _write_json(
        root / "analysis-results/collections/batch-2/sources/asyncrat/malwarebazaar-manifest.json",
        {"items": [{"sha256": case["sha256"], "zip_sha256": "2" * 64, "zip_size": 50}]},
    )
    source = queue.build_queue(root, _inventory(case))["cases"][0]["source"]
    assert source == {
        "status": "conflicting_source_bindings", "action": "review_source_integrity_conflict"
    }


def test_missing_binding_and_required_bytes_absent_are_separate(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    unbound = _case(root, "c")
    absent = _case(root, "d", state="source_material_absent")
    rows = {item["sha256"]: item for item in queue.build_queue(root, _inventory(unbound, absent))["cases"]}
    assert rows[unbound["sha256"]]["source"]["status"] == "source_integrity_unbound"
    assert rows[absent["sha256"]]["source"]["status"] == "required_terminal_bytes_absent"


def test_same_name_wrong_archive_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    case = _case(root, "e")
    case_dir = root.joinpath(*case["canonical_path"].split("/"))
    _write_json(case_dir / "report.json", {
        "sample": {"sha256": case["sha256"], "input_kind": "authenticated_single_member_zip", "outer_sha256": "0" * 64, "outer_size": 5}
    })
    (private / f"{case['sha256']}.zip").write_bytes(b"wrong")
    source = queue.build_queue(root, _inventory(case), input_root=private)["cases"][0]["source"]
    assert source["status"] == "archive_mismatch"


def test_invalid_case_path_or_report_identity_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    case = _case(root, "f")
    changed = dict(case, canonical_path="../../outside")
    with pytest.raises(queue.TerminalGapQueueError, match="case path"):
        queue.build_queue(root, _inventory(changed))
    case_dir = root.joinpath(*case["canonical_path"].split("/"))
    _write_json(case_dir / "report.json", {
        "sample": {"sha256": "0" * 64, "input_kind": "authenticated_single_member_zip", "outer_sha256": "1" * 64, "outer_size": 50}
    })
    with pytest.raises(queue.TerminalGapQueueError, match="report.sample.sha256"):
        queue.build_queue(root, _inventory(case))


def test_duplicate_archive_name_blocks_verification(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    case = _case(root, "9")
    case_dir = root.joinpath(*case["canonical_path"].split("/"))
    _write_json(case_dir / "report.json", {
        "sample": {"sha256": case["sha256"], "input_kind": "authenticated_single_member_zip", "outer_sha256": "1" * 64, "outer_size": 5}
    })
    for child in (private / "one", private / "two"):
        child.mkdir()
        (child / f"{case['sha256']}.zip").write_bytes(b"wrong")
    source = queue.build_queue(root, _inventory(case), input_root=private)["cases"][0]["source"]
    assert source["status"] == "duplicate_archive_name"


def test_cli_writes_and_checks_deterministic_public_queue(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    case = _case(root, "8")
    inventory = root / "intelligence/terminal-payload-recovery/inventory.json"
    _write_json(inventory, _inventory(case))
    output = root / "analysis-results/research/terminal-queue/queue.json"
    arguments = ["--repository", str(root), "--output", str(output)]
    assert queue.main([*arguments, "--write"]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["scope"]["case_count"] == 1
    assert queue.main([*arguments, "--check"]) == 0
    output.write_text("{}\n", encoding="utf-8")
    assert queue.main([*arguments, "--check"]) == 1
    assert "stale" in capsys.readouterr().out
