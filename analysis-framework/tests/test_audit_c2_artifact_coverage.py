"""C2成果物の横断監査が値を公開せず、証拠水準を混同しないことを確認する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import audit_c2_artifact_coverage as auditor  # noqa: E402


def _write(path: Path, document: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")


def test_artifact_counts_and_empty_ioc_boundary(tmp_path: Path) -> None:
    first = tmp_path / "analysis-results/malware/rat/versions/v1/cases" / ("a" * 64)
    second = tmp_path / "analysis-results/malware/rat/versions/v1/cases" / ("b" * 64)
    third = tmp_path / "analysis-results/malware/rat/versions/v1/cases" / ("c" * 64)
    _write(first / "config.json", {
        "config_endpoints": [{"host": "secret-c2.example.test", "port": 443}, {"port": 80}],
        "config": {"network_candidates": [{"value": "candidate.example.test"}]},
    })
    _write(first / "communication-patterns.json", {"communication": {
        "confirmed_static_endpoints": [{"value": "secret-c2.example.test:443"}],
        "candidate_patterns": [{"value": "candidate.example.test"}],
    }})
    _write(first / "iocs.json", {"network": []})
    _write(second / "c2-observation-plan.json", {"targets": ["planned.example.test"]})
    _write(second / "c2-analysis.json", {"c2": {"endpoints": ["reported.example.test"]}})
    _write(second / "network-evidence.json", {"stage_flow": {"endpoint": "observed.example.test:443"}})
    _write(third / "config.json", {"config": {"network_candidates": []}})
    _write(third / "iocs.json", {"network": [{"value": "present.example.test"}]})

    result = auditor.audit(tmp_path, "2026-09-21")
    assert result["artifact_files"]["config.json"] == 2
    assert result["artifact_files"]["c2-analysis.json"] == 1
    assert result["artifact_files"]["indicators.json"] == 0
    assert result["artifact_files"]["protocol-observations.json"] == 0
    assert result["artifact_files_with_explicit_endpoint_records"]["config.json"] == 1
    assert result["endpoint_record_claims_by_tier"] == {
        "analysis_endpoint_claim": 1,
        "candidate_literal": 2,
        "configuration_claim": 1,
        "indicator_c2_claim": 0,
        "monitoring_claim": 0,
        "network_evidence_claim": 1,
        "planned_target": 1,
        "protocol_observation_claim": 0,
        "static_endpoint_claim": 1,
    }
    assert result["case_counts"]["cases_with_target_artifacts"] == 3
    assert result["case_counts"]["iocs_json_state"] == {
        "empty": 1, "invalid": 0, "missing": 1, "nonempty": 1,
    }
    assert result["case_counts"]["iocs_json_state_when_other_artifact_has_endpoint"] == {
        "empty": 1, "invalid": 0, "missing": 1, "nonempty": 0,
    }
    serialized = json.dumps(result)
    assert "secret-c2.example.test" not in serialized
    assert "candidate.example.test" not in serialized
    assert "planned.example.test" not in serialized
    assert "rat/versions" not in serialized
    assert result["assessment_boundary"]["candidate_or_plan_is_c2_confirmation"] is False


def test_invalid_json_and_unrelated_file_are_not_endpoint_evidence(tmp_path: Path) -> None:
    case = tmp_path / "analysis-results/malware/rat/versions/v1/cases" / ("d" * 64)
    _write(case / "c2-analysis.json", {"c2": {"evidence": "secret.example.test", "endpoints": []}})
    _write(case / "config.json", {"c2": [{"port": 443}, {}]})
    (case / "network-evidence.json").write_text("{broken", encoding="utf-8")
    _write(tmp_path / "analysis-results/malware/rat/extra/config.json", {
        "c2": [{"host": "outside-case.example.test"}],
    })
    _write(case / "iocs.json", {"network": "not-a-list"})

    result = auditor.audit(tmp_path, "2026-09-21")
    assert result["artifact_files"]["config.json"] == 1
    assert result["invalid_json_files"]["network-evidence.json"] == 1
    assert sum(result["endpoint_record_claims_by_tier"].values()) == 0
    assert result["case_counts"]["iocs_json_state"]["invalid"] == 1


def test_scalar_and_nested_config_are_counted_without_liveness_inference(tmp_path: Path) -> None:
    case = tmp_path / "analysis-results/malware/rat/versions/v1/cases" / ("e" * 64)
    _write(case / "config.json", {"config": {
        "c2_ip": "192.0.2.5",
        "c2": {"primary": {"host": "primary.example.test"},
               "backup": {"domain": "backup.example.test"}},
    }})
    result = auditor.audit(tmp_path, "2026-09-21")
    assert result["endpoint_record_claims_by_tier"]["configuration_claim"] == 3
    assert result["assessment_boundary"]["static_config_is_live_c2_confirmation"] is False


def test_indicators_without_iocs_are_kept_separate_from_confirmation(tmp_path: Path) -> None:
    case = tmp_path / "analysis-results/malware/rat/versions/v1/cases" / ("f" * 64)
    _write(case / "indicators.json", {
        "c2": ["claimed.example.test"],
        "c2_assessment": {"targets": [{"host": "plan.example.test"}]},
        "detection_inputs": {"network_candidates": [{"value": "literal.example.test"}]},
        "indicators": [
            {"role": "redline_c2", "value": "redline.example.test"},
            {"role": "c2_candidate_static_config", "value": "maybe.example.test"},
            {"role": "submitted_sample", "value": "do-not-count"},
        ],
    })
    result = auditor.audit(tmp_path, "2026-09-21")
    tiers = result["endpoint_record_claims_by_tier"]
    assert tiers["indicator_c2_claim"] == 2
    assert tiers["planned_target"] == 1
    assert tiers["candidate_literal"] == 2
    assert result["case_counts"]["iocs_json_state_when_other_artifact_has_endpoint"]["missing"] == 1
    assert "claimed.example.test" not in json.dumps(result)
    assert result["assessment_boundary"]["indicator_c2_claim_independently_verified"] is False
