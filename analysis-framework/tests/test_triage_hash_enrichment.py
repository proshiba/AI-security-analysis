from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import triage_hash_enrichment as module  # noqa: E402


def test_collection_partial_hashes_returns_only_partial(tmp_path: Path) -> None:
    collection = tmp_path / "collection"
    collection.mkdir()
    digest_a = "a" * 64
    digest_b = "b" * 64
    (collection / "publication-summary.json").write_text(
        json.dumps(
            {
                "cases": [
                    {"sha256": digest_a, "case_state": "partial"},
                    {"sha256": digest_b, "case_state": "complete"},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert module.collection_partial_hashes(collection) == [digest_a]


def test_collection_hashes_returns_all_publication_cases(tmp_path: Path) -> None:
    collection = tmp_path / "collection"
    collection.mkdir()
    digest_a = "a" * 64
    digest_b = "b" * 64
    (collection / "publication-summary.json").write_text(
        json.dumps(
            {
                "cases": [
                    {"sha256": digest_a, "publication_stage": "analysis_followup_pending"},
                    {"sha256": digest_b, "case_state": "complete"},
                ]
            }
        ),
        encoding="utf-8",
    )
    assert module.collection_hashes(collection) == [digest_a, digest_b]


def test_collection_hashes_falls_back_to_manifest_case_id(tmp_path: Path) -> None:
    collection = tmp_path / "collection"
    collection.mkdir()
    digest = "c" * 64
    (collection / "publication-summary.json").write_text(
        json.dumps({"cases": []}),
        encoding="utf-8",
    )
    (collection / "manifest.json").write_text(
        json.dumps({"cases": [{"case_id": f"sha256:{digest}"}]}),
        encoding="utf-8",
    )
    assert module.collection_hashes(collection) == [digest]


def test_run_rejects_invalid_hash() -> None:
    try:
        module.run(["invalid"], "key", 1.0)
    except ValueError as error:
        assert "SHA-256" in str(error)
    else:
        raise AssertionError("無効なhashを拒否しませんでした")


def test_enrich_hash_accepts_exact_extracted_analysis_target(monkeypatch) -> None:
    query_hash = "d" * 64
    root_hash = "e" * 64

    def fake_api(path: str, _key: str, _timeout: float) -> dict:
        if path.startswith("/search?"):
            return {"data": [{"id": "260804-abcdefghij"}]}
        if path == "/samples/260804-abcdefghij":
            return {"sha256": root_hash, "private": False}
        if path.endswith("/overview.json"):
            return {
                "sample": {"id": "260804-abcdefghij", "sha256": root_hash},
                "targets": [{"sha256": query_hash, "target": "inner.dll", "tasks": []}],
            }
        raise AssertionError(path)

    monkeypatch.setattr(module.triage, "_api_json", fake_api)
    monkeypatch.setattr(
        module.triage,
        "summarize_overview",
        lambda _value: {"behavioral_tasks": []},
    )

    result = module.enrich_hash(query_hash, "key", 1.0)

    assert result["matches"][0]["matched_object"] == "analysis_target"
    assert result["errors"] == []
