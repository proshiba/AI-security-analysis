"""認証済み設定とfamily帰属の分離を検証する。"""

from __future__ import annotations

import copy
import importlib
import sys
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
for location in (REPOSITORY, COMMON):
    if str(location) not in sys.path:
        sys.path.insert(0, str(location))

lineage = importlib.import_module("handler_profile_lineage")
orchestration = importlib.import_module("orchestration_outcome")
contract = importlib.import_module("analysis_contract")

ROOT_SHA = "a" * 64
TERMINAL_SHA = "b" * 64


def _record(version: str = "BwRat  1.0.0") -> dict:
    handler_id = "dcrat:extractors.dcrat.extractor.py:extract"
    result = {
        "family": "dcrat",
        "sample_sha256": TERMINAL_SHA,
        "static_config_recovered": True,
        "executed": False,
        "network_contacted": False,
        "static_evidence": {
            "authentication": "hmac_sha256",
            "all_expected_fields_validated": True,
        },
        "config": {
            "static_config_recovered": True,
            "version": version,
            "crypto_profile": {"authentication": "HMAC-SHA256"},
            "endpoints": [{"host": "c2.example.test", "port": 1217}],
        },
        "config_endpoints": [{"host": "c2.example.test", "port": 1217}],
    }
    quality = contract.handler_result_quality(result)
    return {
        "source": "selected_family_analysis",
        "family": "dcrat",
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": quality,
        "selected_layer_sha256": TERMINAL_SHA,
        "result": {
            "executed_sample": False,
            "network_contacted": False,
            "handler": {"id": handler_id, "family": "dcrat"},
            "selected_layer": {"sha256": TERMINAL_SHA},
            "result": result,
        },
    }


def _detector_candidate() -> dict:
    return {
        "family": "dcrat",
        "evidence": [
            {
                "kind": "type_detector_structure",
                "layer_sha256": TERMINAL_SHA,
                "supports_attribution": True,
                "confidence": "high",
            }
        ],
        "routing_eligibility": {
            "mode": "selected_family_analysis",
            "selected_family_analysis": True,
            "family_attribution": True,
        },
    }


def test_hmac_config_candidate_keeps_lineage_and_family_separate() -> None:
    record = _record()
    assert orchestration.assess_handler_record(record)["succeeded"] is True
    document = lineage.build_document(sha256=ROOT_SHA, handler_records=[record])
    assert document["candidate_count"] == 1
    assert document["conflicting_profiles"] == ["dcrat"]
    candidate = document["candidates"][0]
    assert candidate["self_declared_product"] == "bwrat"
    assert candidate["configured_network_candidates"] == [
        {"host": "c2.example.test", "port": 1217, "role": "static_config_candidate", "contacted": False}
    ]
    assert candidate["family_attribution_confirmed"] is False
    assert candidate["used_for_c2_confirmation"] is False
    assert "secret" not in repr(document)
    assert document["safety"]["network_contacted"] is False


def test_cross_lineage_claim_vetoes_only_detector_family_resolution() -> None:
    record = _record()
    document = lineage.build_document(sha256=ROOT_SHA, handler_records=[record])
    candidate = _detector_candidate()
    assert orchestration.resolve_family([candidate], [record])["status"] == "resolved"
    restricted = lineage.restrict_detector_candidates([candidate], document)
    assert restricted == []
    assert orchestration.resolve_family(restricted, [record])["status"] == "unresolved"
    known_hash = copy.deepcopy(candidate)
    known_hash["evidence"].append(
        {"kind": "known_inner_sha256", "layer_sha256": TERMINAL_SHA, "supports_attribution": True, "confidence": "high"}
    )
    assert lineage.restrict_detector_candidates([known_hash], document) == [known_hash]


def test_same_self_description_does_not_veto_family() -> None:
    record = _record("DCRat 1.0.7")
    document = lineage.build_document(sha256=ROOT_SHA, handler_records=[record])
    assert document["conflicting_profiles"] == []
    assert lineage.restrict_detector_candidates([_detector_candidate()], document)


def test_unverified_or_mismatched_handler_config_is_rejected() -> None:
    valid = _record()
    malformed = []
    for field, value in (("static_evidence", {"authentication": "none"}), ("config", {"endpoints": []})):
        record = copy.deepcopy(valid)
        record["result"]["result"][field] = value
        malformed.append(record)
    wrong_layer = copy.deepcopy(valid)
    wrong_layer["result"]["result"]["sample_sha256"] = "c" * 64
    malformed.append(wrong_layer)
    unsafe = copy.deepcopy(valid)
    unsafe["result"]["network_contacted"] = True
    malformed.append(unsafe)
    for record in malformed:
        assert lineage.build_document(sha256=ROOT_SHA, handler_records=[record])["candidate_count"] == 0
