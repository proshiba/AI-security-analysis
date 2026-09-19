"""route-only handlerの静的候補を独立成果物へ射影する回帰テスト。"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))

from analysis_contract import handler_result_quality
from component_static_findings import build_component_static_findings

ROOT_SHA = "a" * 64
LAYER_SHA = "b" * 64


def _assessment(component: str, result: dict) -> dict:
    handler_id = f"{component}:analysis-framework.malware.{component}.extract.config:extract_config"
    minimum = 1
    quality = handler_result_quality(result, minimum_score=minimum)
    return {
        "executed_sample": False,
        "network_contacted": False,
        "families": [{
            "family": component,
            "confirmed": False,
            "status": "handler_evidence_route_only",
            "attempts": [{
                "status": "handler_evidence_route_only",
                "handler_id": handler_id,
                "layer": {"sha256": LAYER_SHA},
                "handler_evidence": quality,
                "handler_family_attribution": {
                    "route_only": True,
                    "supports_family_confirmation": False,
                },
                "result": {
                    "handler": {
                        "id": handler_id,
                        "family": component,
                        "minimum_evidence_score": minimum,
                    },
                    "result": result,
                    "result_quota": {"truncated": False},
                    "executed_sample": False,
                    "network_contacted": False,
                },
            }],
        }],
    }


def _result(component: str) -> dict:
    return {
        "family": component,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "attribution_scope": "component_handler_route",
        "sample": {"sha256": LAYER_SHA},
        "artifact_role": "component_candidate",
    }


def test_network_candidate_is_bounded_and_not_promoted_to_c2() -> None:
    result = _result("ror13_network_loader")
    result["network_candidates"] = [{
        "host": "8.8.8.8",
        "port": 8080,
        "transport": "tcp",
        "confidence": "static_candidate_dataflow_review_required",
        "evidence": {"stack_fragments": ["UNVERIFIED_PRIVATE_TEXT"]},
    }]
    result["secret"] = "DO_NOT_PUBLISH"
    document = build_component_static_findings(
        sha256=ROOT_SHA, assessment=_assessment("ror13_network_loader", result)
    )
    assert document["status"] == "route_only_component_findings"
    assert document["finding_count"] == 1
    finding = document["findings"][0]
    assert finding["observations"]["network_endpoint_candidates"] == [{
        "host": "8.8.8.8",
        "port": 8080,
        "transport": "tcp",
        "confidence": "static_candidate_dataflow_review_required",
        "c2_confirmed": False,
        "liveness_confirmed": False,
    }]
    assert document["evidence_boundary"]["c2_confirmed"] is False
    assert "DO_NOT_PUBLISH" not in str(document)
    assert "UNVERIFIED_PRIVATE_TEXT" not in str(document)


def test_clipboard_literals_are_counted_but_never_published() -> None:
    result = _result("clipboard_replacement_dll")
    result["clipboard_imports"] = sorted({
        "OpenClipboard", "CloseClipboard", "GetClipboardSequenceNumber",
        "GetClipboardData", "EmptyClipboard", "SetClipboardData",
    })
    result["address_literal_candidates"] = [
        {"value": "SECRET_UNVERIFIED_ADDRESS_ONE"},
        {"value": "SECRET_UNVERIFIED_ADDRESS_TWO"},
    ]
    document = build_component_static_findings(
        sha256=ROOT_SHA, assessment=_assessment("clipboard_replacement_dll", result)
    )
    assert document["findings"][0]["observations"] == {
        "clipboard_api_correlation": True,
        "xor_address_literal_candidate_count": 2,
        "raw_address_literals_published": False,
    }
    assert "SECRET_UNVERIFIED_ADDRESS" not in str(document)


def test_fail_closed_on_missing_route_contract_or_layer_mismatch() -> None:
    result = _result("ror13_network_loader")
    result["network_candidates"] = [{"host": "8.8.8.8", "port": 8080}]
    assessment = _assessment("ror13_network_loader", result)
    attempt = assessment["families"][0]["attempts"][0]
    invalid = copy.deepcopy(assessment)
    invalid["families"][0]["attempts"][0]["result"]["result"].pop("supports_family_attribution")
    assert build_component_static_findings(sha256=ROOT_SHA, assessment=invalid)["findings"] == []
    invalid = copy.deepcopy(assessment)
    invalid["families"][0]["attempts"][0]["layer"]["sha256"] = "c" * 64
    assert build_component_static_findings(sha256=ROOT_SHA, assessment=invalid)["findings"] == []
    invalid = copy.deepcopy(assessment)
    invalid["families"][0]["attempts"][0]["result"]["result_quota"]["truncated"] = True
    assert build_component_static_findings(sha256=ROOT_SHA, assessment=invalid)["findings"] == []
    assert attempt["status"] == "handler_evidence_route_only"


def test_rejects_confirmed_family_and_unsafe_assessment() -> None:
    result = _result("ror13_network_loader")
    result["network_candidates"] = [{"host": "8.8.8.8", "port": 8080}]
    assessment = _assessment("ror13_network_loader", result)
    assessment["families"][0]["confirmed"] = True
    assert build_component_static_findings(sha256=ROOT_SHA, assessment=assessment)["finding_count"] == 0
    assessment["families"][0]["confirmed"] = False
    assessment["network_contacted"] = True
    assert build_component_static_findings(sha256=ROOT_SHA, assessment=assessment)["finding_count"] == 0
