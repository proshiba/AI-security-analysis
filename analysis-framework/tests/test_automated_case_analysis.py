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


def _artifact(
    result: dict,
    *,
    handler_family: str = "fixture",
    **updates: object,
) -> dict:
    return {
        "handler": {"id": HANDLER_ID, "family": handler_family},
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
    assert handler_evidence.trusted_handler_result(
        _execution(selected_evidence={"sufficient": True, "score": 2}),
        {**artifact, "selected_evidence": {"sufficient": True, "score": 1}},
    ) is False
    assert handler_evidence.trusted_handler_result(
        _execution(selected_layer_sha256="b" * 64),
        {
            **artifact,
            "result": {
                "static_config_recovered": True,
                "sample_sha256": "c" * 64,
            },
        },
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


def test_nested_unvalidated_dual_use_config_is_not_treated_as_management() -> None:
    result = {
        "relay": {
            "tenant_key_sha256": "a" * 64,
            "tenant_key_length": 64,
        },
        "config": {
            "static_config_recovered": True,
            "config_endpoints": [
                {
                    "host": "192.0.2.10",
                    "port": 8041,
                    "transport": "tcp_tls",
                    "role": "remote_management_relay",
                    "confidence": "confirmed_static_configuration",
                    "evidence": {
                        "kind": "screenconnect_embedded_management_endpoint",
                        "c2_classification": "dual_use_not_c2_by_itself",
                        "malicious_use_confirmed": False,
                    },
                    "tenant_key": "must-not-be-published",
                }
            ],
            "static_evidence": {
                "all_expected_fields_validated": True,
                "source": "screenconnect_embedded_management_configuration",
                "dual_use_endpoint": True,
            },
        },
    }
    document = handler_evidence.build_communication_pattern_document(
        sha256=DIGEST,
        family="screenconnect_rmm",
        handler_results=[(_execution(), _artifact(result))],
    )

    endpoints = document["communication"]["confirmed_static_endpoints"]
    assert endpoints == [
        {
            "host": "192.0.2.10",
            "port": 8041,
            "transport": "tcp_tls",
            "role": "remote_management_relay",
            "confidence": "confirmed_static_configuration",
            "evidence": {
                "kind": "screenconnect_embedded_management_endpoint",
                "c2_classification": "dual_use_not_c2_by_itself",
                "malicious_use_confirmed": False,
            },
            "source": f"handler:{HANDLER_ID}",
        }
    ]
    assert "tenant_key" not in repr(endpoints).casefold()
    assert document["communication"]["confirmed_static_management_endpoints"] == []
    assert document["communication"]["confirmed_static_c2_endpoints"] == endpoints


def test_nested_config_endpoint_requires_complete_static_validation() -> None:
    config = {
        "static_config_recovered": True,
        "config_endpoints": [
            {
                "host": "192.0.2.11",
                "port": 443,
                "role": "remote_management_relay",
                "confidence": "confirmed_static_configuration",
                "evidence": {"kind": "fixture"},
            }
        ],
        "static_evidence": {"all_expected_fields_validated": False},
    }
    document = handler_evidence.build_communication_pattern_document(
        sha256=DIGEST,
        family="screenconnect_rmm",
        handler_results=[(_execution(), _artifact({"config": config}))],
    )

    assert document["config"]["static_config_recovered"] is True
    assert document["communication"]["confirmed_static_endpoints"] == []


def test_legacy_screenconnect_result_is_projected_fail_closed() -> None:
    legacy = {
        "schema_version": 1,
        "family": "ScreenConnect RMM",
        "classification": "commercial_rmm_dual_use",
        "malware_by_itself": False,
        "abuse_attribution": "not_established",
        "artifact_role": "access_agent_installer",
        "network_contacted": False,
        "sample_executed": False,
        "malicious_use_context": {
            "assessment": "requires_incident_context",
            "malicious_use_confirmed": False,
            "unauthorized_installation_observed": False,
            "embedded_management_endpoint_observed": True,
            "requires_authorization_and_delivery_context": True,
        },
        "relay": {
            "host": "192.0.2.12",
            "port": 8041,
            "transport": "tcp_tls",
            "role": "remote_management_relay",
            "c2_classification": "dual_use_not_c2_by_itself",
            "tenant_key_sha256": "b" * 64,
            "tenant_key_length": 407,
            "redacted_query": "?h=192.0.2.12&p=8041&k=<redacted>",
        },
    }
    document = handler_evidence.build_communication_pattern_document(
        sha256=DIGEST,
        family="screenconnect_rmm",
        handler_results=[
            (_execution(), _artifact(legacy, handler_family="screenconnect_rmm"))
        ],
    )

    endpoint = document["communication"]["confirmed_static_endpoints"][0]
    assert endpoint["host"] == "192.0.2.12"
    assert endpoint["role"] == "remote_management_relay"
    assert endpoint["evidence"]["legacy_projection"] is True
    assert document["config"]["static_config_recovered"] is True
    assert "tenant_key" not in repr(endpoint).casefold()

    legacy["malicious_use_context"]["malicious_use_confirmed"] = True
    rejected = handler_evidence.build_communication_pattern_document(
        sha256=DIGEST,
        family="screenconnect_rmm",
        handler_results=[
            (_execution(), _artifact(legacy, handler_family="screenconnect_rmm"))
        ],
    )
    assert rejected["communication"]["confirmed_static_endpoints"] == []


def test_dual_use_management_endpoint_is_excluded_from_c2_contract() -> None:
    legacy = {
        "schema_version": 1,
        "family": "ScreenConnect RMM",
        "classification": "commercial_rmm_dual_use",
        "malware_by_itself": False,
        "abuse_attribution": "not_established",
        "artifact_role": "access_agent_installer",
        "network_contacted": False,
        "sample_executed": False,
        "malicious_use_context": {
            "assessment": "requires_incident_context",
            "malicious_use_confirmed": False,
            "unauthorized_installation_observed": False,
            "embedded_management_endpoint_observed": True,
            "requires_authorization_and_delivery_context": True,
        },
        "relay": {
            "host": "192.0.2.12",
            "port": 8041,
            "transport": "tcp_tls",
            "role": "remote_management_relay",
            "c2_classification": "dual_use_not_c2_by_itself",
            "tenant_key_sha256": "b" * 64,
            "tenant_key_length": 407,
            "redacted_query": "?h=192.0.2.12&p=8041&k=<redacted>",
        },
    }
    patterns, contract = case_automation.build_case_automation_artifacts(
        sha256=DIGEST,
        family="screenconnect_rmm",
        layer_report={"counts": {"recovered_layers": 1}},
        handler_results=[
            (_execution(), _artifact(legacy, handler_family="screenconnect_rmm"))
        ],
    )

    communication = patterns["communication"]
    assert len(communication["confirmed_static_management_endpoints"]) == 1
    assert communication["confirmed_static_c2_endpoints"] == []
    assert contract["c2"]["endpoints"] == []
    assert contract["c2"]["outcome"] == "unresolved"
    assert contract["c2"]["protocol"]["status"] == "unresolved"
    assert contract["deep_analysis"]["blockers"]
    phases = {item["phase"]: item for item in contract["phase_evidence"]}
    assert phases["c2_endpoint_extraction"]["status"] == "not_applicable"
    assert phases["c2_protocol_analysis"]["status"] == "blocked"
    assert any(
        "双用途管理endpoint" in evidence
        for evidence in phases["c2_endpoint_extraction"]["evidence"]
    )
    patterns, contract = case_automation.build_case_automation_artifacts(
        sha256=DIGEST,
        family="screenconnect_rmm",
        layer_report={"counts": {"recovered_layers": 1}},
        handler_results=[
            (_execution(), _artifact(legacy, handler_family="screenconnect_rmm"))
        ],
        screenconnect_no_c2_completion_verified=True,
    )
    assert contract["c2"]["outcome"] == "no_c2_capability_verified"
    assert contract["c2"]["protocol"]["status"] == "not_applicable"
    assert contract["deep_analysis"]["blockers"] == []
    phases = {item["phase"]: item for item in contract["phase_evidence"]}
    assert all(item["status"] != "blocked" for item in phases.values())
    validation = c2_contract.validate_contract(
        contract,
        DIGEST,
        repository=REPOSITORY,
    )
    assert validation["complete"] is True

    legacy["artifact_role"] = "unknown"
    rejected_patterns, rejected_contract = case_automation.build_case_automation_artifacts(
        sha256=DIGEST,
        family="screenconnect_rmm",
        layer_report={"counts": {"recovered_layers": 1}},
        handler_results=[
            (_execution(), _artifact(legacy, handler_family="screenconnect_rmm"))
        ],
        screenconnect_no_c2_completion_verified=True,
    )
    assert rejected_patterns["config"]["terminal_managed_client"] is False
    assert rejected_contract["c2"]["outcome"] == "unresolved"
    rejected_phases = {
        item["phase"]: item for item in rejected_contract["phase_evidence"]
    }
    assert rejected_phases["c2_protocol_analysis"]["status"] == "blocked"
    assert rejected_contract["deep_analysis"]["blockers"]


def test_malformed_screenconnect_cannot_fallback_to_generic_terminal_flag() -> None:
    endpoint = {
        "host": "192.0.2.20",
        "port": 8041,
        "transport": "tcp_tls",
        "role": "remote_management_relay",
        "confidence": "confirmed_static_configuration",
        "evidence": {
            "kind": "screenconnect_embedded_management_endpoint",
            "c2_classification": "dual_use_not_c2_by_itself",
            "malicious_use_confirmed": False,
        },
    }
    result = {
        "schema_version": 1,
        "family": "ScreenConnect RMM",
        "classification": "commercial_rmm_dual_use",
        "malware_by_itself": False,
        "abuse_attribution": "not_established",
        "artifact_role": "access_agent_installer",
        "network_contacted": False,
        "sample_executed": False,
        "malicious_use_context": {
            "assessment": "requires_incident_context",
            "malicious_use_confirmed": False,
            "unauthorized_installation_observed": False,
            "embedded_management_endpoint_observed": True,
            "requires_authorization_and_delivery_context": True,
        },
        "config": {
            "terminal_managed_client": True,
            "static_config_recovered": True,
            "config_endpoints": [endpoint],
            "static_evidence": {"all_expected_fields_validated": True},
        },
    }

    patterns, contract = case_automation.build_case_automation_artifacts(
        sha256=DIGEST,
        family="screenconnect_rmm",
        layer_report={"counts": {"recovered_layers": 1}},
        handler_results=[
            (_execution(), _artifact(result, handler_family="screenconnect_rmm"))
        ],
        screenconnect_no_c2_completion_verified=True,
    )

    assert patterns["config"]["terminal_managed_client"] is False
    assert patterns["communication"]["confirmed_static_management_endpoints"] == []
    assert patterns["communication"]["confirmed_static_c2_endpoints"]
    assert contract["c2"]["outcome"] == "unresolved"


def test_non_screenconnect_cannot_self_label_management_endpoint() -> None:
    result = {
        "c2": [
            {
                "host": "c2.example.test",
                "port": 443,
                "transport": "tls",
                "role": "remote_management_relay",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "screenconnect_embedded_management_endpoint",
                    "c2_classification": "dual_use_not_c2_by_itself",
                    "malicious_use_confirmed": False,
                },
            }
        ],
        "config": {
            "static_config_recovered": True,
            "terminal_managed_client": True,
        },
    }

    patterns, contract = case_automation.build_case_automation_artifacts(
        sha256=DIGEST,
        family="fixture",
        layer_report={"counts": {"recovered_layers": 0}},
        handler_results=[(_execution(), _artifact(result))],
        screenconnect_no_c2_completion_verified=True,
    )

    assert patterns["communication"]["confirmed_static_management_endpoints"] == []
    assert len(patterns["communication"]["confirmed_static_c2_endpoints"]) == 1
    assert contract["c2"]["outcome"] == "unresolved"


def test_screenconnect_protocol_evidence_prevents_no_c2_completion() -> None:
    endpoint = {
        "host": "192.0.2.30",
        "port": 8041,
        "transport": "tcp_tls",
        "role": "remote_management_relay",
        "confidence": "confirmed_static_configuration",
        "evidence": {
            "kind": "screenconnect_embedded_management_endpoint",
            "c2_classification": "dual_use_not_c2_by_itself",
            "malicious_use_confirmed": False,
        },
    }
    result = {
        "schema_version": 1,
        "family": "ScreenConnect RMM",
        "sample_sha256": DIGEST,
        "classification": "commercial_rmm_dual_use",
        "malware_by_itself": False,
        "abuse_attribution": "not_established",
        "artifact_role": "access_agent_installer",
        "network_contacted": False,
        "sample_executed": False,
        "malicious_use_context": {
            "assessment": "requires_incident_context",
            "malicious_use_confirmed": False,
            "unauthorized_installation_observed": False,
            "embedded_management_endpoint_observed": True,
            "requires_authorization_and_delivery_context": True,
        },
        "config": {
            "static_config_recovered": True,
            "config_endpoints": [endpoint],
            "static_evidence": {
                "all_expected_fields_validated": True,
                "source": "screenconnect_embedded_management_configuration",
                "dual_use_endpoint": True,
            },
        },
        "protocol_evidence": {
            "analysis_status": "complete",
            "family": "ScreenConnect RMM",
            "sample_sha256": DIGEST,
            "registration": {
                "method": "fixture.registration",
                "missing_required_fields": [],
            },
            "dispatcher": {
                "method": "fixture.dispatch",
                "missing_command_markers": [],
                "observed_command_markers": ["command"],
                "file_or_plugin_transfer_markers": [],
                "heartbeat_request": None,
                "heartbeat_response_markers": [],
            },
            "emulator_readiness": {
                "heartbeat_required": False,
                "heartbeat_request_response_confirmed": False,
                "registration_schema_confirmed": True,
                "command_dispatcher_confirmed": True,
                "live_operation_fake_result_allowed": False,
            },
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "raw_cil_published": False,
                "unreviewed_literals_published": False,
            },
        },
        "static_protocol": {
            "status": "confirmed",
            "method": "fixture_method",
            "transport": "tcp_tls",
            "framing": "fixture_frame",
            "serialization": "fixture_serialization",
            "confidence": "high",
            "tcp_open_only": False,
            "live_verified": False,
        },
    }

    patterns, contract = case_automation.build_case_automation_artifacts(
        sha256=DIGEST,
        family="screenconnect_rmm",
        layer_report={"counts": {"recovered_layers": 1}},
        handler_results=[
            (_execution(), _artifact(result, handler_family="screenconnect_rmm"))
        ],
        screenconnect_no_c2_completion_verified=True,
    )

    phases = {item["phase"]: item for item in contract["phase_evidence"]}
    assert patterns["communication"]["protocol_confirmed"] is True
    assert phases["c2_protocol_analysis"]["status"] == "completed"
    assert contract["c2"]["protocol"]["status"] == "static_confirmed_live_unverified"
    assert contract["c2"]["outcome"] == "unresolved"
    assert contract["deep_analysis"]["blockers"]


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
