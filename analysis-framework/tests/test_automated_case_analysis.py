from __future__ import annotations

import importlib
from pathlib import Path
import sys


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

case_automation = importlib.import_module("automated_case_analysis")
c2_contract = importlib.import_module("c2_analysis_contract")
handler_evidence = importlib.import_module("handler_evidence")

DIGEST = "a" * 64
REPOSITORY = Path(__file__).resolve().parents[2]
HANDLER_ID = "fixture:extract_config.py:extract_config"


def _execution(**updates: object) -> dict:
    return {
        "handler_id": HANDLER_ID,
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
        **updates,
    }


def _artifact(result: dict, **updates: object) -> dict:
    return {
        "handler": {"id": HANDLER_ID},
        "result": result,
        "selected_evidence": {"sufficient": True},
        "executed_sample": False,
        "network_contacted": False,
        **updates,
    }


def test_trusted_handler_result_requires_matching_static_evidence() -> None:
    artifact = _artifact({"static_config_recovered": True})
    assert handler_evidence.trusted_handler_result(_execution(), artifact) is True
    assert handler_evidence.trusted_handler_result(
        _execution(handler_id="fixture:other"), artifact
    ) is False
    assert handler_evidence.trusted_handler_result(
        _execution(), {**artifact, "network_contacted": True}
    ) is False
    assert handler_evidence.trusted_handler_result(
        _execution(selected_evidence={"sufficient": False}), artifact
    ) is False


def test_pattern_document_separates_confirmed_and_candidate_endpoints() -> None:
    result = {
        "static_config_recovered": True,
        "c2": [
            {
                "url": "https://user:pass@confirmed.example/gate?token=secret",
                "role": "tasking",
                "confidence": "confirmed_static_configuration",
                "evidence": {"kind": "decoded_config", "token": "secret"},
            }
        ],
        "config": {
            "static_config_recovered": True,
            "network_candidates": [
                "https://user:pass@candidate.example/stage?token=secret"
            ],
        },
    }
    document = handler_evidence.build_communication_pattern_document(
        sha256=DIGEST,
        family="fixture",
        handler_results=[(_execution(), _artifact(result))],
    )
    encoded = repr(document)
    assert document["status"] == "confirmed_static_configuration_patterns"
    assert document["config"]["static_config_recovered"] is True
    assert len(document["communication"]["confirmed_static_endpoints"]) == 1
    assert len(document["communication"]["candidate_patterns"]) == 1
    assert document["communication"]["protocol_confirmed"] is False
    assert "user:pass" not in encoded
    assert "token=secret" not in encoded


def test_untrusted_handler_cannot_supply_config_or_patterns() -> None:
    artifact = _artifact(
        {
            "static_config_recovered": True,
            "config": {"endpoints": ["https://untrusted.example/gate"]},
        },
        executed_sample=True,
    )
    document = handler_evidence.build_communication_pattern_document(
        sha256=DIGEST,
        family="fixture",
        handler_results=[(_execution(), artifact)],
    )
    assert document["status"] == "unresolved"
    assert document["config"]["static_config_recovered"] is False
    assert document["communication"]["confirmed_static_endpoints"] == []
    assert document["communication"]["candidate_patterns"] == []


def test_case_automation_records_all_c2_phases_without_overpromotion() -> None:
    artifact = _artifact(
        {
            "static_config_recovered": True,
            "c2": [
                {
                    "host": "c2.example",
                    "port": 443,
                    "transport": "tls",
                    "role": "c2",
                    "confidence": "confirmed_static_configuration",
                    "evidence": {"kind": "decoded_config"},
                }
            ],
        }
    )
    patterns, contract = case_automation.build_case_automation_artifacts(
        sha256=DIGEST,
        family="fixture",
        layer_report={"counts": {"recovered_layers": 2}},
        handler_results=[(_execution(), artifact)],
    )
    phases = {item["phase"]: item for item in contract["phase_evidence"]}
    assert patterns["communication"]["confirmed_static_endpoints"]
    assert phases["embedded_layer_recovery"]["status"] == "completed"
    assert phases["family_config_extraction"]["status"] == "completed"
    assert phases["c2_endpoint_extraction"]["status"] == "completed"
    assert phases["c2_protocol_analysis"]["status"] == "blocked"
    assert contract["c2"]["outcome"] == "unresolved"
    assert contract["c2"]["protocol"]["status"] == "unresolved"
    assert contract["c2"]["endpoints"][0]["value"] == "c2.example:443"
    validation = c2_contract.validate_contract(
        contract,
        DIGEST,
        repository=REPOSITORY,
    )
    assert validation["complete"] is False
    assert validation["daily_ready"] is True
    assert validation["deferred"] is True


def test_case_automation_is_explicit_when_no_config_was_recovered() -> None:
    patterns, contract = case_automation.build_case_automation_artifacts(
        sha256=DIGEST,
        family="unclassified",
        layer_report={"counts": {"recovered_layers": 0}},
        handler_results=[],
    )
    phases = {item["phase"]: item for item in contract["phase_evidence"]}
    assert patterns["status"] == "unresolved"
    assert phases["embedded_layer_recovery"]["status"] == "not_applicable"
    assert phases["family_config_extraction"]["status"] == "blocked"
    assert phases["c2_endpoint_extraction"]["status"] == "blocked"
    assert contract["deep_analysis"]["next_minimum_step"]
