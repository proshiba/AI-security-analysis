from __future__ import annotations

import json
from pathlib import Path
import sys


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
