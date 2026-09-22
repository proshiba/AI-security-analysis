"""検体別C2横断監査の網羅・証拠境界・IOC非公開を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import audit_c2_inventory as auditor  # noqa: E402


def _write(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")


def test_all_records_and_strict_stix_overlap_without_raw_values(tmp_path: Path) -> None:
    first = tmp_path / "analysis-results/malware/rat-a/versions/unknown/cases" / ("a" * 64) / "iocs.json"
    second = tmp_path / "analysis-results/malware/rat-b/versions/unknown/cases" / ("b" * 64) / "iocs.json"
    _write(first, {"network": [
        {"host": "c2.example.test", "port": 443, "role": "configured_c2",
         "confidence": "confirmed_static_configuration", "source": "handler:rat-a:extract",
         "evidence": {"kind": "verified_config"}, "reachability": "not_tested"},
        {"value": "https://secret.example.test/?key=do-not-publish", "role": "configured_c2",
         "confidence": "confirmed_static"},
        {"value": "https://sandbox.example.test", "role": "c2_candidate_external_sandbox_config",
         "confidence": "medium_external_sandbox_exact_hash"},
        {"value": "https://kill.example.test", "role": "kill_switch_not_c2",
         "confidence": "confirmed_static"},
        "malformed",
    ]})
    _write(second, {"network": [
        {"value": "c2.example.test:443", "role": "c2", "confidence": "confirmed_static"},
        {"value": "another.example.test:8443", "role": "c2", "confidence": "confirmed_static"},
        {"value": "https://candidate.example.test", "role": "c2_candidate", "confidence": "medium"},
    ]})
    curated_path = tmp_path / "curated.json"
    _write(curated_path, {"endpoints": [
        {"id": "one", "domain": "c2.example.test", "port": 443,
         "classification": "confirmed-c2", "family_id": "rat-a"},
        {"id": "two", "domain": "other.example.test", "port": 8443,
         "classification": "reported-c2"},
    ]})

    result = auditor.audit(tmp_path, curated_path, "2026-09-21")
    assert result["counts"]["malware_ioc_files"] == 2
    assert result["counts"]["network_records"] == 8
    assert result["counts"]["static_config_ioc_files"] == 2
    assert result["counts"]["static_config_classification_file_missing"] == 2
    assert result["counts"]["invalid_network_record"] == 1
    assert result["evidence_tiers"]["static_config_supported_c2"] == 3
    assert result["evidence_tiers"]["excluded_unsafe_or_shared_value"] == 1
    assert result["evidence_tiers"]["external_sandbox_candidate"] == 1
    assert result["evidence_tiers"]["excluded_non_c2"] == 1
    assert result["evidence_tiers"]["c2_candidate_not_confirmed"] == 1
    assert result["counts"]["unique_public_static_config_c2_values"] == 2
    assert result["counts"]["static_config_values_shared_across_families"] == 1
    assert result["counts"]["static_config_item_source_missing"] == 2
    assert result["counts"]["static_config_case_path_sha256_present"] == 3
    assert "static_config_sample_identity_not_resolved" not in result["counts"]
    assert result["curated_stix"]["strict_value_overlap_with_static_config"] == 1
    assert result["curated_stix"]["strict_family_and_value_overlap_with_static_config"] == 1
    assert "confirmed_c2_with_observation_time" not in result["curated_stix"]["quality"]
    serialized = json.dumps(result)
    assert "c2.example.test" not in serialized
    assert "do-not-publish" not in serialized
    assert "another.example.test" not in serialized
    assert result["assessment_boundary"]["raw_ioc_values_published"] is False


def test_invalid_network_and_curated_classification_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "analysis-results/malware/rat-a/iocs.json"
    curated_path = tmp_path / "curated.json"
    _write(path, {"network": "bad"})
    _write(curated_path, {"endpoints": []})
    with pytest.raises(ValueError, match="network"):
        auditor.audit(tmp_path, curated_path, "2026-09-21")

    _write(path, {"network": []})
    _write(curated_path, {"endpoints": [{"classification": "invented"}]})
    with pytest.raises(ValueError, match="分類"):
        auditor.audit(tmp_path, curated_path, "2026-09-21")


def test_unknown_role_not_echoed(tmp_path: Path) -> None:
    _write(tmp_path / "analysis-results/malware/rat-a/iocs.json", {
        "network": [{"value": "https://example.test", "role": "secret-role-do-not-publish"}],
    })
    curated_path = tmp_path / "curated.json"
    _write(curated_path, {"endpoints": []})
    result = auditor.audit(tmp_path, curated_path, "2026-09-21")
    assert result["network_roles"] == {"other_role": 1}
    assert "secret-role-do-not-publish" not in json.dumps(result)


def test_initial_family_classification_is_not_final_adjudication(tmp_path: Path) -> None:
    path = tmp_path / "analysis-results/malware/nanocore/versions/unknown/cases" / ("c" * 64) / "iocs.json"
    _write(path, {"network": [
        {"host": "c2.example.test", "port": 443, "role": "configured_c2",
         "confidence": "confirmed_static_configuration", "source": "handler:nanocore:extract"},
    ]})
    _write(path.parent / "classification.json", {"malware_type": "unknown"})
    curated_path = tmp_path / "curated.json"
    _write(curated_path, {"endpoints": []})
    result = auditor.audit(tmp_path, curated_path, "2026-09-21")
    assert result["counts"]["static_config_initial_classification_unknown"] == 1
    assert "static_config_initial_classification_other_mismatch" not in result["counts"]
