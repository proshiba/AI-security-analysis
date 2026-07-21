"""batch collection登録の固定レイアウト境界を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
sys.path.insert(0, str(COMMON))

import register_batch_collection as register  # noqa: E402


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def test_register_batch_writes_metadata_and_manifest(tmp_path: Path) -> None:
    digest = "a" * 64
    case = (
        tmp_path
        / "analysis-results/malware/test-family/versions/unknown/cases"
        / digest
    )
    case.mkdir(parents=True)
    classification = tmp_path / "classification.json"
    _write_json(
        classification,
        {
            "samples": [
                {
                    "sha256": digest,
                    "family": "test-family",
                    "version": "unknown",
                }
            ]
        },
    )
    result = register.register_batch(
        tmp_path, classification, "test-collection", write=True
    )
    assert result["cases"] == 1
    metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["collections"] == ["test-collection"]
    manifest = json.loads(
        (
            tmp_path
            / "analysis-results/collections/test-collection/manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert manifest["cases"] == [{"case_id": f"sha256:{digest}"}]


def test_register_batch_rejects_missing_case(tmp_path: Path) -> None:
    classification = tmp_path / "classification.json"
    _write_json(
        classification,
        {
            "samples": [
                {
                    "sha256": "b" * 64,
                    "family": "test-family",
                    "version": "unknown",
                }
            ]
        },
    )
    with pytest.raises(register.BatchRegistrationError, match="missing"):
        register.register_batch(
            tmp_path, classification, "test-collection", write=False
        )

def test_register_batch_accepts_unclassified_case_kind(tmp_path: Path) -> None:
    digest = "c" * 64
    case = (
        tmp_path
        / "analysis-results/malware/unclassified/versions/unknown/cases"
        / digest
    )
    case.mkdir(parents=True)
    _write_json(
        case / "metadata.json",
        {
            "case_id": f"sha256:{digest}",
            "sha256": digest,
            "case_kind": "unclassified",
            "family": "unclassified",
            "canonical_path": case.relative_to(tmp_path).as_posix(),
            "malware_version": {
                "normalized_key": "unknown",
                "status": "unknown",
                "reported": None,
                "confidence": "none",
                "reason": "終端家族が未解決",
                "evidence": [],
            },
        },
    )
    classification = tmp_path / "classification.json"
    _write_json(
        classification,
        {
            "samples": [
                {
                    "sha256": digest,
                    "family": "unclassified",
                    "version": "unknown",
                }
            ]
        },
    )
    result = register.register_batch(
        tmp_path, classification, "test-collection", write=True
    )
    assert result["cases"] == 1
    metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["case_kind"] == "unclassified"
    assert metadata["collections"] == ["test-collection"]
