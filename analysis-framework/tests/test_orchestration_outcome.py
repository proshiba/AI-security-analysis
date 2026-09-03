"""AI非依存オーケストレーションの証拠解決と公開品質ゲートを検証する。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import orchestration_outcome as outcome  # noqa: E402
from analysis_contract import handler_result_quality  # noqa: E402
from orchestration_outcome import (  # noqa: E402
    build_outcome,
    resolve_family,
    summarize_handler_outputs,
)

SHA256 = "a" * 64
DETECTOR_SHA256 = "d" * 64


def _candidate(
    family: str,
    kind: str,
    *,
    requirements: dict[str, bool] | None = None,
    source_claim: str = "forged",
) -> dict[str, object]:
    if kind == "known_hash":
        evidence = {
            "kind": "known_outer_sha256",
            "confidence": "high",
            "layer_sha256": SHA256,
            "supports_attribution": True,
        }
        routing = {"mode": "blocked"}
    elif kind == "detector_selected":
        evidence = {
            "kind": "type_detector_structure",
            "confidence": "medium",
            "layer_sha256": SHA256,
            "supports_attribution": True,
        }
        routing = {
            "mode": "selected_family_analysis",
            "selected_family_analysis": True,
            "family_attribution": True,
        }
    elif kind == "detector_candidate":
        evidence = {
            "kind": "type_detector_structure",
            "confidence": "medium",
            "layer_sha256": DETECTOR_SHA256,
            "supports_attribution": True,
        }
        routing = {
            "mode": "candidate_verification",
            "candidate_verification": True,
            "family_attribution": False,
        }
    else:
        evidence = {
            "kind": "external_metadata_hint",
            "confidence": "unverified",
            "supports_attribution": False,
        }
        routing = {
            "mode": "candidate_verification",
            "candidate_verification": True,
            "family_attribution": False,
        }
    return {
        "family": family,
        "source": source_claim,
        "source_strength": 4,
        "evidence": [evidence],
        "routing_eligibility": routing,
        "requirements": requirements or {},
    }


def _record(
    family: str,
    payload: dict[str, object],
    *,
    status: str = "succeeded",
    verified_binary_outputs: list[dict[str, object]] | None = None,
    verified_binary_output_audit: dict[str, object] | None = None,
) -> dict[str, object]:
    enriched = {"capabilities": ["fixture"], **payload}
    quality = handler_result_quality(enriched)
    record: dict[str, object] = {
        "family": family,
        "handler_id": f"{family}:extract",
        "status": status,
        "result": {"result": enriched},
        "selected_layer_sha256": SHA256,
    }
    if status == "corroborated":
        record.update(
            {
                "source": "candidate_verification",
                "handler_evidence": quality,
                "detector_corroboration": {
                    "corroborated": True,
                    "basis": "detector_structural_evidence",
                    "layer_sha256": DETECTOR_SHA256,
                    "lineage_distance": 1,
                },
            }
        )
    else:
        record.update(
            {
                "source": "selected_family_analysis",
                "selected_evidence": quality,
            }
        )
    if verified_binary_outputs is not None:
        record["verified_binary_outputs"] = verified_binary_outputs
    if verified_binary_output_audit is not None:
        record["verified_binary_output_audit"] = verified_binary_output_audit
    return record


def _verified_output(*, matches: bool = True) -> dict[str, object]:
    return {
        "role": "terminal_payload",
        "kind": "pe",
        "path": "result.terminal_payload",
        "sha256": "b" * 64,
        "size": 1_234,
        "verification": {
            "status": "artifact_hash_verified",
            "sha256_matches": matches,
            "size_matches": True,
        },
    }


def _retention_audit(*, analysis_complete: bool) -> dict[str, object]:
    return {
        "schema_version": 1,
        "maximum_outputs": 64,
        "maximum_total_size": 256 * 1024 * 1024,
        "binary_values_seen": 1,
        "binary_bytes_seen": 1_234,
        "traversal_items": 4,
        "observed_output_count": 1,
        "retained_output_count": 1,
        "retained_for_follow_on_analysis": True,
        "follow_on_analysis_complete": analysis_complete,
        "observation_scope": "parent_rehashed_case_artifact",
        "truncated": False,
        "reasons": [],
    }


def test_forged_strength_and_operator_source_do_not_resolve() -> None:
    candidate = _candidate("nanocore", "external_metadata", source_claim="known_hash")
    candidate["basis"] = "explicit_operator_selection"
    result = resolve_family([candidate], [])

    assert result["status"] == "unresolved"
    assert result["candidates"][0]["source"] == "external_metadata"
    assert result["candidates"][0]["source_strength"] == 1


def test_known_hash_requires_canonical_evidence_kind() -> None:
    valid = resolve_family([_candidate("valleyrat", "known_hash")], [])
    forged = resolve_family(
        [{"family": "valleyrat", "source": "known_hash", "source_strength": 4}],
        [],
    )

    assert valid["family"] == "valleyrat"
    assert forged["status"] == "unresolved"


def test_external_metadata_never_confirms_with_selected_handler_status() -> None:
    candidate = _candidate("nanocore", "external_metadata")
    strong = _record(
        "nanocore",
        {"decoded_config_recovered": True, "config": {"campaign": "fixture"}},
    )
    assert resolve_family([candidate], [strong])["status"] == "unresolved"


def test_detector_candidate_requires_revalidated_corroboration() -> None:
    candidate = _candidate("quasarrat", "detector_candidate")
    succeeded = _record("quasarrat", {"capabilities": ["file_manager"]})
    corroborated = _record("quasarrat", {"capabilities": ["file_manager"]}, status="corroborated")

    assert resolve_family([candidate], [succeeded])["status"] == "unresolved"
    assert resolve_family([candidate], [corroborated])["family"] == "quasarrat"


def test_forged_corroborated_status_is_rejected() -> None:
    candidate = _candidate("quasarrat", "detector_candidate")
    forged = _record("quasarrat", {"capabilities": ["x"]}, status="corroborated")
    forged.pop("detector_corroboration")

    assert resolve_family([candidate], [forged])["status"] == "unresolved"


def test_equal_best_families_remain_ambiguous() -> None:
    result = resolve_family(
        [
            _candidate("family-a", "detector_candidate"),
            _candidate("family-b", "detector_candidate"),
        ],
        [
            _record("family-a", {"capabilities": ["x"]}, status="corroborated"),
            _record("family-b", {"capabilities": ["x"]}, status="corroborated"),
        ],
    )
    assert result["status"] == "ambiguous"
    assert result["winning_families"] == ["family-a", "family-b"]


def test_network_output_redacts_credentials_query_and_token_path() -> None:
    second = _record(
        "agenttesla",
        {"c2_candidates": ["ftp://another:credential@example.test:2121/token/0123456789abcdef"]},
    )
    second["handler_id"] = "agenttesla:secondary"
    records = [
        _record(
            "agenttesla",
            {
                "c2_candidates": [
                    "  ftp://operator:secret@example.test:2121/token/0123456789abcdef?id=query-secret",
                    "192.0.2.10:8080",
                ]
            },
        ),
        second,
    ]
    outputs = summarize_handler_outputs(records)
    rendered = repr(outputs["network_endpoints"])

    for secret in ("operator", "secret", "another", "credential", "query-secret", "0123456789abcdef"):
        assert secret not in rendered
    assert "example.test" in rendered
    assert "[redacted]" in rendered
    matching = [item for item in outputs["network_endpoints"] if item["host"] == "example.test"]
    assert len(matching[0]["provenance"]) == 2


def test_network_structural_labels_are_not_parsed_as_endpoints() -> None:
    outputs = summarize_handler_outputs(
        [
            _record(
                "vidar",
                {
                    "findings": [
                        {
                            "kind": "network.url",
                            "status": "candidate",
                            "value": "https://example.test/bootstrap",
                        }
                    ]
                },
            )
        ]
    )

    assert [item["host"] for item in outputs["network_endpoints"]] == ["example.test"]


def test_evidence_walk_terminates_on_cycle_and_huge_sequence() -> None:
    cycle: dict[str, object] = {}
    cycle["self"] = cycle
    assert list(outcome._walk_evidence(cycle)) == [(("self",), cycle)]

    huge = list(range(outcome.MAX_EVIDENCE_NODES * 2))
    assert list(outcome._walk_evidence(huge)) == []


def test_hash_only_terminal_payload_is_claimed_but_not_reached() -> None:
    record = _record(
        "loader",
        {"terminal_payload": {"sha256": "b" * 64, "size": 1_234}},
    )
    outputs = summarize_handler_outputs([record])

    assert outputs["terminal_payload"]["status"] == "claimed"
    assert outputs["terminal_payload"]["claimed_sha256"] == ["b" * 64]
    assert outputs["terminal_payload_sha256"] == []


def test_verified_binary_manifest_marks_terminal_reached() -> None:
    record = _record(
        "loader",
        {},
        verified_binary_outputs=[_verified_output()],
        verified_binary_output_audit=_retention_audit(analysis_complete=True),
    )
    outputs = summarize_handler_outputs([record])

    assert outputs["terminal_payload"]["status"] == "verified"
    assert outputs["terminal_payload_sha256"] == ["b" * 64]
    assert outputs["verified_binary_outputs"][0]["size"] == 1_234


def test_retained_payload_without_follow_on_analysis_remains_incomplete() -> None:
    record = _record(
        "loader",
        {},
        verified_binary_outputs=[_verified_output()],
        verified_binary_output_audit=_retention_audit(analysis_complete=False),
    )
    outputs = summarize_handler_outputs([record])

    assert outputs["terminal_payload"]["status"] == "retained_pending_analysis"
    assert outputs["retained_terminal_payload_sha256"] == ["b" * 64]
    assert outputs["terminal_payload_sha256"] == []
    built = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate(
                "loader",
                "known_hash",
                requirements={"terminal_payload_required": True},
            )
        ],
        handler_records=[record],
        function_analysis_available=True,
    )
    assert built["status"] == "partial"
    assert built["quality_gates"]["terminal_payload"]["status"] == "required_missing"
    assert "terminal_payload" in built["blockers"]


def test_forged_retention_audit_does_not_upgrade_terminal_payload() -> None:
    forged = _retention_audit(analysis_complete=True)
    forged["observation_scope"] = "handler_self_report"
    record = _record(
        "loader",
        {},
        verified_binary_outputs=[_verified_output()],
        verified_binary_output_audit=forged,
    )
    outputs = summarize_handler_outputs([record])

    assert outputs["terminal_payload"]["status"] == "candidate"
    assert outputs["retained_binary_outputs"] == []
    assert outputs["terminal_payload_sha256"] == []


def test_invalid_verified_binary_manifest_remains_unresolved() -> None:
    record = _record(
        "loader",
        {},
        verified_binary_outputs=[_verified_output(matches=False)],
    )
    outputs = summarize_handler_outputs([record])

    assert outputs["terminal_payload"]["status"] == "unresolved"
    assert outputs["terminal_payload_sha256"] == []


def test_other_family_success_cannot_satisfy_handler_or_network_gate() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[_candidate("valleyrat", "known_hash", requirements={"network_required": True})],
        handler_records=[_record("formbook", {"c2_candidates": ["formbook.example:443"]})],
        function_analysis_available=True,
    )

    assert result["outputs"]["network_endpoints"] == []
    assert result["quality_gates"]["handler_evidence"]["status"] == "required_missing"
    assert result["candidate_outputs"]["network_endpoints"]


def test_config_gate_rejects_boolean_self_report_without_correlated_value() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate("valleyrat", "known_hash", requirements={"config_required": True})
        ],
        handler_records=[
            _record(
                "valleyrat",
                {
                    "configuration_recovered": True,
                    "static_config_recovered": True,
                    "validated": True,
                },
            )
        ],
        function_analysis_available=True,
    )

    assert result["outputs"]["config_recovered"] is False
    assert result["outputs"]["config_evidence"] == []
    assert result["quality_gates"]["config"]["status"] == "required_missing"
    assert result["status"] == "partial"


def test_generic_url_and_candidate_endpoint_do_not_satisfy_network_gate() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate("valleyrat", "known_hash", requirements={"network_required": True})
        ],
        handler_records=[
            _record(
                "valleyrat",
                {
                    "static_config_recovered": True,
                    "config": {"campaign": "fixture"},
                    "urls": ["https://download.example/payload.bin"],
                    "c2_candidates": ["candidate.example:443"],
                },
            )
        ],
        function_analysis_available=True,
    )

    assert len(result["outputs"]["network_endpoints"]) == 2
    assert result["outputs"]["qualified_network_endpoints"] == []
    assert result["quality_gates"]["network"] == {
        "required": True,
        "satisfied": False,
        "observed": True,
        "status": "required_missing",
    }
    assert result["status"] == "partial"


def test_static_config_correlated_c2_satisfies_network_and_config_gates() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate(
                "valleyrat",
                "known_hash",
                requirements={"config_required": True, "network_required": True},
            )
        ],
        handler_records=[
            _record(
                "valleyrat",
                {
                    "static_config_recovered": True,
                    "config": {"campaign": "fixture"},
                    "findings": [
                        {
                            "role": "primary_c2",
                            "endpoint": "rat.example:443",
                            "transport": "tcp",
                        }
                    ],
                },
            )
        ],
        function_analysis_available=True,
    )

    endpoint = result["outputs"]["qualified_network_endpoints"][0]
    assert endpoint["role"] == "c2"
    assert endpoint["protocol"] == "tcp"
    assert endpoint["evidence_basis"] == ["static_config_correlation"]
    assert endpoint["provenance"][0]["handler_id"] == "valleyrat:extract"
    assert result["outputs"]["config_evidence"][0]["correlated_keys"] == ["config", "findings"]
    assert result["status"] == "complete"


@pytest.mark.parametrize(
    "role",
    ["remote_management_relay", "screenconnect_clickonce_bootstrap"],
)
def test_exact_dual_use_management_role_satisfies_network_without_becoming_c2(
    role: str,
) -> None:
    classification = (
        "dual_use_not_c2_by_itself"
        if role == "remote_management_relay"
        else "dual_use_management_endpoint_not_c2_by_itself"
    )
    endpoint = {
        "role": role,
        "host": "192.0.2.10",
        "port": 8041,
        "transport": "tcp_tls",
        "confidence": "confirmed_static_configuration",
        "evidence": {
            "kind": "screenconnect_embedded_management_endpoint",
            "c2_classification": classification,
            "malicious_use_confirmed": False,
        },
    }
    if role == "screenconnect_clickonce_bootstrap":
        endpoint.update(
            {
                "url": "https://192.0.2.10:8041/Bin/ScreenConnect.Client.application",
                "path": "/Bin/ScreenConnect.Client.application",
            }
        )
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate(
                "screenconnect_rmm",
                "known_hash",
                requirements={"config_required": True, "network_required": True},
            )
        ],
        handler_records=[
            _record(
                "screenconnect_rmm",
                {
                    "schema_version": 1,
                    "family": "ScreenConnect RMM",
                    "classification": "commercial_rmm_dual_use",
                    "malware_by_itself": False,
                    "abuse_attribution": "not_established",
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
                    }
                },
            )
        ],
        function_analysis_available=True,
    )

    endpoint = result["outputs"]["qualified_network_endpoints"][0]
    assert endpoint["role"] == role
    assert endpoint["role"] != "c2"
    assert endpoint["evidence_basis"] == ["static_config_correlation"]
    assert result["status"] == "complete"


def test_structured_host_and_port_are_one_qualified_endpoint() -> None:
    """同一mappingのhostをportなしscalarへ二重資格化せず1件へ結合する。"""

    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate(
                "ghostdesk",
                "known_hash",
                requirements={"config_required": True, "network_required": True},
            )
        ],
        handler_records=[
            _record(
                "ghostdesk",
                {
                    "decoded_config_recovered": True,
                    "c2": [
                        {
                            "host": "node.example",
                            "port": 4444,
                            "role": "configured_external_c2",
                            "transport": "websocket_over_raw_tcp",
                        }
                    ],
                },
            )
        ],
        function_analysis_available=True,
    )

    assert len(result["outputs"]["qualified_network_endpoints"]) == 1
    endpoint = result["outputs"]["qualified_network_endpoints"][0]
    assert endpoint["host"] == "node.example"
    assert endpoint["port"] == 4444
    assert endpoint["contacted"] is False


def test_unlisted_remote_management_role_remains_unqualified() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate(
                "screenconnect_rmm",
                "known_hash",
                requirements={"config_required": True, "network_required": True},
            )
        ],
        handler_records=[
            _record(
                "screenconnect_rmm",
                {
                    "config": {
                        "static_config_recovered": True,
                        "config_endpoints": [
                            {
                                "role": "remote_management_gateway",
                                "host": "192.0.2.11",
                                "port": 443,
                            }
                        ],
                    }
                },
            )
        ],
        function_analysis_available=True,
    )

    assert result["outputs"]["qualified_network_endpoints"] == []
    assert result["quality_gates"]["network"]["status"] == "required_missing"
    assert result["status"] == "partial"


def test_legacy_screenconnect_result_satisfies_config_and_network_as_dual_use() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate(
                "screenconnect_rmm",
                "known_hash",
                requirements={"config_required": True, "network_required": True},
            )
        ],
        handler_records=[
            _record(
                "screenconnect_rmm",
                {
                    "schema_version": 1,
                    "family": "ScreenConnect RMM",
                    "classification": "commercial_rmm_dual_use",
                    "malware_by_itself": False,
                    "abuse_attribution": "not_established",
                    "artifact_role": "access_agent_installer",
                    "logic": ["埋め込み管理先を静的に回収"],
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
                },
            )
        ],
        function_analysis_available=True,
    )

    endpoint = result["outputs"]["qualified_network_endpoints"][0]
    assert endpoint["role"] == "remote_management_relay"
    assert endpoint["role"] != "c2"
    assert result["outputs"]["config_recovered"] is True
    assert result["status"] == "complete"


def test_reviewed_protocol_control_endpoint_satisfies_network_without_config() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate("rat", "known_hash", requirements={"network_required": True})
        ],
        handler_records=[
            _record(
                "rat",
                {
                    "findings": [
                        {
                            "role": "control_endpoint",
                            "endpoint": "control.example:8443",
                            "transport": "tls",
                            "protocol_reviewed": True,
                            "source": "reviewed_static_protocol",
                        }
                    ]
                },
            )
        ],
        function_analysis_available=True,
    )

    assert result["outputs"]["config_recovered"] is False
    assert result["outputs"]["qualified_network_endpoints"][0]["evidence_basis"] == [
        "reviewed_protocol_evidence"
    ]
    assert result["status"] == "complete"


def test_delivery_role_or_unreviewed_protocol_does_not_satisfy_network_gate() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[
            _candidate("rat", "known_hash", requirements={"network_required": True})
        ],
        handler_records=[
            _record(
                "rat",
                {
                    "findings": [
                        {
                            "role": "delivery",
                            "endpoint": "download.example:443",
                            "transport": "https",
                            "protocol_reviewed": True,
                            "source": "reviewed_static_protocol",
                        },
                        {
                            "role": "c2",
                            "endpoint": "unreviewed.example:443",
                            "transport": "tcp",
                        },
                    ]
                },
            )
        ],
        function_analysis_available=True,
    )

    assert result["outputs"]["qualified_network_endpoints"] == []
    assert result["status"] == "partial"


def test_required_capability_has_only_its_missing_blocker() -> None:
    result = build_outcome(
        sample_sha256=SHA256,
        generic_status="complete",
        layer_status="complete",
        candidates=[_candidate("valleyrat", "known_hash", requirements={"network_required": True})],
        handler_records=[_record("valleyrat", {"capabilities": ["remote_shell"]})],
        function_analysis_available=False,
    )
    assert result["blockers"] == ["network"]


def test_output_is_deterministic_across_record_order() -> None:
    records = [
        _record("family", {"c2_candidates": ["same.example", "same.example:443"]}),
        _record("family", {"c2_candidates": ["same.example:443"]}),
    ]
    first = summarize_handler_outputs(records)
    second = summarize_handler_outputs(list(reversed(records)))

    assert first == second
    assert [item["port"] for item in first["network_endpoints"]] == [None, 443]
