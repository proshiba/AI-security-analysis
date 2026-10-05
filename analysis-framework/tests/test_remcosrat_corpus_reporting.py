from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
FAMILY_DIR = ROOT / "analysis-framework" / "malware" / "remcosrat"
COMMON_DIR = ROOT / "analysis-framework" / "common"


def load(name: str, filename: str):
    path = FAMILY_DIR / filename
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.path[:0] = [str(FAMILY_DIR), str(COMMON_DIR)]
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(FAMILY_DIR))
        sys.path.remove(str(COMMON_DIR))
    return module


def test_publication_redacts_private_material_and_local_paths(tmp_path: Path) -> None:
    module = load("remcos_publish_test", "publish_corpus_report.py")
    parent = "1" * 64
    peer = "2" * 64
    analysis = {
        "schema_version": 2,
        "selection": {
            "signature": "RemcosRAT",
            "selected_at": "2026-10-04T14:07:10Z",
            "requested": 1,
            "newest_first": True,
        },
        "counts": {
            "selected": 1,
            "archive_verified": 1,
            "root_pe": 1,
            "root_non_pe_delivery": 0,
            "static_family_confirmed": 1,
            "confirmed_unique_c2": 1,
            "external_public_analysis_matched": 1,
            "external_config_reported": 1,
            "external_unique_config_endpoints": 1,
        },
        "confirmed_unique_c2": ["c2.example:2404"],
        "external_reported_unique_config_endpoints": ["c2.example:2404"],
        "c2_hunting": {
            "endpoints": [{"endpoint": "c2.example:2404", "sources": ["confirmed_static_configuration"]}],
            "configured_certificate_pivots": [{"sha256": peer}],
        },
        "samples": [
            {
                "sha256": parent,
                "first_seen": "2026-10-04 07:16:05",
                "provider_file_type": "exe",
                "inner_size": 4096,
                "input_role": "terminal_pe",
                "static_family_confirmed": True,
                "config_status": "recovered",
                "version_candidates": ["7.3.1 Pro"],
                "c2": [{"endpoint": "c2.example:2404", "tls_enabled": True}],
                "config": {
                    "botnet": "reviewed",
                    "connect_interval_seconds": 1,
                    "initial_connect_delay_seconds": 0,
                    "field_count": 57,
                    "schema_profile": "published_56_field_or_later",
                    "tls_material": {
                        "peer_certificate_sha256": peer,
                        "private_key_present": True,
                        "private_key": "private-secret-must-not-be-published",
                    },
                    "source_path": r"C:\Users\Example\private\sample.exe",
                },
                "terminal_artifacts": [],
                "external_analysis": {
                    "public_analysis_match_count": 1,
                    "reported_config_endpoints": ["c2.example:2404"],
                },
            }
        ],
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_published": False,
            "credentials_published": False,
            "private_key_published": False,
        },
    }
    source = tmp_path / "analysis.json"
    source.write_text(json.dumps(analysis), encoding="utf-8")
    output = tmp_path / "public"

    result = module.publish(source, output)

    assert result == {"files": 5, "samples": 1, "validated_configs": 1}
    combined = "\n".join(path.read_text(encoding="utf-8") for path in output.iterdir())
    assert "private-secret-must-not-be-published" not in combined
    assert r"C:\Users\Example" not in combined
    validated = json.loads((output / "validated-configs.json").read_text(encoding="utf-8"))
    assert validated["configs"][0]["private_key_present"] is True
    assert validated["configs"][0]["private_key_published"] is False


def test_triage_result_merge_rejects_duplicate_parent_artifact_pair() -> None:
    module = load("remcos_triage_merge_test", "analyze_triage_artifacts.py")
    artifact = {
        "parent_sha256": "1" * 64,
        "artifact_sha256": "2" * 64,
        "status": "remcos_config_recovered",
        "archive_verified": True,
        "artifact_verified": True,
    }
    result = {
        "artifacts": [artifact],
        "confirmed_static_c2": ["c2.example:2404"],
        "configured_peer_certificate_sha256": ["3" * 64],
    }

    with pytest.raises(ValueError, match="重複"):
        module.merge_results([result, result])


def test_triage_result_merge_keeps_evidence_counts_and_safety_boundary() -> None:
    module = load("remcos_triage_merge_count_test", "analyze_triage_artifacts.py")
    results = []
    for index, endpoint in enumerate(("first.example:2404", "second.example:4489"), start=1):
        results.append(
            {
                "artifacts": [
                    {
                        "parent_sha256": str(index) * 64,
                        "artifact_sha256": str(index + 2) * 64,
                        "status": "remcos_config_recovered",
                        "archive_verified": True,
                        "artifact_verified": True,
                    }
                ],
                "confirmed_static_c2": [endpoint],
                "configured_peer_certificate_sha256": [str(index + 4) * 64],
            }
        )

    merged = module.merge_results(results)

    assert merged["counts"] == {
        "artifact_batches": 2,
        "artifacts": 2,
        "archive_verified": 2,
        "artifact_verified": 2,
        "config_recovered": 2,
        "unique_c2": 2,
        "unique_peer_certificate_sha256": 2,
    }
    assert merged["safety"]["sample_executed"] is False
    assert merged["safety"]["network_contacted"] is False
    assert merged["safety"]["plaintext_artifact_written"] is False
