"""XLoader/FormBook native loader lineageの複合証拠契約を検証する。"""

from __future__ import annotations

import sys
from copy import deepcopy
from pathlib import Path

FRAMEWORK = Path(__file__).parents[1]
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from malware.formbook_loader.native_lineage_evidence import (
    evaluate_native_xloader_lineage,
)

ANALYSIS_SHA256 = "a" * 64


def _reports() -> tuple[dict[str, object], dict[str, object]]:
    stage0 = {
        "analysis_type": "formbook_native_stage0_static_recovery",
        "status": "recovered",
        "analysis_pe_sha256": ANALYSIS_SHA256,
        "profile": {
            "dispatcher_call_count": 25,
            "block_count": 16,
            "code_score": 102,
            "xor_constant_count": 3,
            "first_key_sha256": "1" * 64,
            "second_key_sha256": "2" * 64,
        },
        "candidate_evaluation": {
            "attempt_count": 24,
            "accepted_distinct_stage_count": 1,
            "selected_unique": True,
        },
        "safety": {
            "sample_executed": False,
            "cpu_emulation_used": False,
            "network_contacted": False,
        },
    }
    follow_on = {
        "matched": True,
        "variant": "native_xloader_encrypted_c2_seed_pool",
        "matched_patterns": [
            "dominant_stack_string_decrypt_call_target",
            "statically_recovered_20_byte_base_key",
            "canonical_base64_candidate_inventory",
            "unique_64_entry_primary_candidate_cluster",
        ],
        "static_config_recovered": False,
        "c2": [],
        "terminal_payload_recovered": False,
        "native_string_recovery": {
            "automation_status": "decoded",
            "key_status": "statically_recovered",
            "call_target_selection_method": "dominant",
            "builder_count": 175,
            "base_key_recovery": {
                "status": "recovered",
                "scanned_callee_count": 8,
            },
        },
        "encrypted_network_inventory": {
            "status": "primary_pool_confirmed",
            "reason": "unique_64_candidate_cluster",
            "candidate_set_complete": True,
            "builder_count": 175,
            "primary_pool_candidate_count": 64,
            "cluster_evidence": {
                "largest_cluster_size": 64,
                "dominance_margin": 55,
                "required_dominance_margin": 16,
                "required_boundary_gap": 0x800,
                "observed_minimum_boundary_gap": 0x1800,
            },
        },
        "safety": {
            "sample_executed": False,
            "cpu_emulation_used": False,
            "network_contacted": False,
            "raw_decoded_values_included": False,
            "raw_key_material_included": False,
            "c2_endpoint_confirmed": False,
        },
    }
    return stage0, follow_on


def test_two_independent_axes_confirm_loader_lineage_only():
    stage0, follow_on = _reports()
    result = evaluate_native_xloader_lineage(
        stage0,
        follow_on,
        follow_on_input_sha256=ANALYSIS_SHA256,
    )
    assert result["status"] == "confirmed"
    assert result["supports_family_attribution"] is True
    assert result["attribution_scope"] == "native_loader_lineage_not_terminal_payload"
    assert result["terminal_family_confirmed"] is False
    assert result["c2_endpoint_confirmed"] is False
    assert len(result["independent_evidence_axes"]) == 2


def test_reports_from_different_inputs_cannot_be_combined():
    stage0, follow_on = _reports()
    result = evaluate_native_xloader_lineage(
        stage0,
        follow_on,
        follow_on_input_sha256="b" * 64,
    )
    assert result["status"] == "not_confirmed"
    assert "analysis_pe_sha256_binding_missing_or_mismatched" in result["reason_codes"]


def test_stage0_packer_axis_alone_is_not_family_evidence():
    stage0, follow_on = _reports()
    follow_on["matched"] = False
    follow_on["encrypted_network_inventory"] = {}
    result = evaluate_native_xloader_lineage(
        stage0,
        follow_on,
        follow_on_input_sha256=ANALYSIS_SHA256,
    )
    assert result["supports_family_attribution"] is False


def test_seed_pool_axis_alone_is_not_family_evidence():
    stage0, follow_on = _reports()
    stage0["status"] = "not_candidate"
    stage0["candidate_evaluation"] = {}
    result = evaluate_native_xloader_lineage(
        stage0,
        follow_on,
        follow_on_input_sha256=ANALYSIS_SHA256,
    )
    assert result["supports_family_attribution"] is False


def test_builder_count_and_pool_size_must_match_exact_contract():
    for path, value in (
        (("native_string_recovery", "builder_count"), 174),
        (("encrypted_network_inventory", "builder_count"), 176),
        (("encrypted_network_inventory", "primary_pool_candidate_count"), 63),
        (("encrypted_network_inventory", "cluster_evidence", "largest_cluster_size"), 65),
    ):
        stage0, follow_on = _reports()
        target = follow_on
        for name in path[:-1]:
            target = target[name]
        target[path[-1]] = value
        result = evaluate_native_xloader_lineage(
            stage0,
            follow_on,
            follow_on_input_sha256=ANALYSIS_SHA256,
        )
        assert result["status"] == "not_confirmed"
        assert "unique_64_seed_pool_structure_incomplete" in result["reason_codes"] or (
            "builder_or_base_key_structure_incomplete" in result["reason_codes"]
        )


def test_ambiguous_stage_or_cluster_margin_fails_closed():
    stage0, follow_on = _reports()
    stage0["candidate_evaluation"]["accepted_distinct_stage_count"] = 2
    follow_on["encrypted_network_inventory"]["cluster_evidence"][
        "dominance_margin"
    ] = 15
    result = evaluate_native_xloader_lineage(
        stage0,
        follow_on,
        follow_on_input_sha256=ANALYSIS_SHA256,
    )
    assert set(result["reason_codes"]) >= {
        "stage0_candidate_not_unique_or_bounded",
        "unique_64_seed_pool_structure_incomplete",
    }


def test_mutating_source_reports_after_copy_does_not_change_prior_result():
    stage0, follow_on = _reports()
    stage0_copy, follow_on_copy = deepcopy(stage0), deepcopy(follow_on)
    result = evaluate_native_xloader_lineage(
        stage0_copy,
        follow_on_copy,
        follow_on_input_sha256=ANALYSIS_SHA256,
    )
    stage0["status"] = "changed"
    follow_on["matched"] = False
    assert result["status"] == "confirmed"
