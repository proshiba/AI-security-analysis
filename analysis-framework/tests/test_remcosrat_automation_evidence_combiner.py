"""Remcos盲検・exact-hash終端artifact統合の信頼境界を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "analysis-framework" / "malware" / "remcosrat" / "combine_automation_evidence.py"
SPEC = importlib.util.spec_from_file_location("remcos_automation_combiner", MODULE_PATH)
assert SPEC and SPEC.loader
combiner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(combiner)

ROOTS = ("a" * 64, "b" * 64, "c" * 64)
MANIFEST_SHA256 = "f" * 64
SETTINGS_SHA256 = "9" * 64
CONFIGURATION_SHA256 = "4" * 64
KEY_SHA256 = "3" * 64
ENDPOINT_SHA256 = hashlib.sha256(b"example.com:2404").hexdigest()


def _identity(endpoints: list[str]) -> str:
    raw = json.dumps(
        [SETTINGS_SHA256, sorted(endpoints)],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _blind() -> dict:
    cases = []
    for index, root in enumerate(ROOTS):
        success = index == 0
        cases.append(
            {
                "root_sha256": root,
                "strict_joint": success,
                "family_confirmed": success,
                "static_config_recovered": success,
                "qualified_c2": success,
                "configuration_conflict": False,
                "evaluation_error_count": 0,
                "analysis_status": "complete",
                "truncated": False,
                "sample_executed": False,
                "network_contacted": False,
                "archive_authenticated_in_memory": True,
                "inner_sha256_verified": True,
                "static_layer_count": 1,
                "static_layer_sha256": [root],
                "strict_evidence_layers": (
                    [
                        {
                            "layer_sha256": root,
                            "depth": 0,
                            "transform": "submission",
                            "configuration_sha256": CONFIGURATION_SHA256,
                            "settings_resource_sha256": SETTINGS_SHA256,
                            "rc4_key_sha256": KEY_SHA256,
                            "configured_endpoint_count": 1,
                            "configured_endpoint_sha256": [ENDPOINT_SHA256],
                            "qualified_endpoint_count": 1,
                            "qualified_c2": True,
                            "raw_endpoint_published": False,
                            "raw_key_published": False,
                            "raw_config_published": False,
                        }
                    ]
                    if success
                    else []
                ),
            }
        )
    return {
        "schema_version": 1,
        "evaluation": "remcos_family_config_c2_strict_static_automation",
        "cohort": {
            "selection_mode": "signature_newest",
            "signature": "RemcosRAT",
            "provider_label_role": "denominator_selection_only_not_family_confirmation",
            "manifest_sha256": MANIFEST_SHA256,
            "root_case_count": 3,
            "expected_case_count": 3,
            "target_cohort_case_count": 3,
        },
        "strict_contract": {
            "strict_detector_required": True,
            "strict_extractor_required": True,
            "non_production_test_hook_used": False,
            "same_layer_family_config_c2_required_for_joint": True,
            "cross_layer_configuration_conflict_rejected": True,
            "all_static_layers_required_for_success": True,
            "all_static_layers_evaluated": True,
            "provider_label_used_for_confirmation": False,
            "triage_or_external_config_used_for_confirmation": False,
        },
        "current": {
            "root_case_count": 3,
            "complete_evaluation_case_count": 3,
            "partial_case_count": 0,
            "truncated_case_count": 0,
            "configuration_conflict_case_count": 0,
            "case_evaluation_failure_count": 0,
            "case_deadline_exceeded_count": 0,
            "cohort_deadline_exceeded_case_count": 0,
            "evaluation_status": "complete",
            "evaluation_completed_without_deadline": True,
            "implementation_stable_during_evaluation": True,
            "strict_joint_case_count": 1,
            "family_confirmed_case_count": 1,
            "static_config_recovered_case_count": 1,
            "qualified_c2_case_count": 1,
        },
        "cases": cases,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "persistent_plaintext_sample_written": False,
            "raw_endpoint_published": False,
            "raw_key_published": False,
            "raw_config_published": False,
            "arbitrary_external_tool_path_accepted": False,
        },
    }


def _artifact_retrieval() -> dict:
    return {
        "manifest_sha256": "8" * 64,
        "manifest_sha256_pinned": True,
        "manifest_profile": "canonical_triage_artifact_retrieval_v1_verified",
        "download_record_binding_sha256": "7" * 64,
        "endpoint_path_sha256": "6" * 64,
        "reference_sha256": "5" * 64,
        "selection": "reviewed_report_memory",
        "provider_parent_binding": ("metadata_sha256_and_public_analysis_verified_by_retrieval_tool"),
        "http_status": 200,
        "redirects_followed": False,
        "metadata_sha256_verified_by_retrieval_tool": True,
        "public_analysis_verified_by_retrieval_tool": True,
    }


def _terminal(*, parent: str = ROOTS[1], identity: str | None = None) -> dict:
    endpoints = ["example.com:2404"]
    return {
        "schema_version": 2,
        "analysis": "remcosrat_triage_terminal_artifacts",
        "counts": {
            "artifacts": 1,
            "archive_verified": 1,
            "artifact_verified": 1,
            "config_recovered": 1,
            "config_recovered_parent": 1,
            "configuration_conflict_parent": 0,
            "invalid_configuration_evidence": 0,
            "unique_c2": 1,
            "unique_peer_certificate_sha256": 0,
        },
        "retrieval_evidence": {
            "manifest_count": 1,
            "manifest_sha256": ["8" * 64],
            "all_manifests_sha256_pinned": True,
            "manifest_profiles": ["canonical_triage_artifact_retrieval_v1_verified"],
            "download_record_binding_validated": True,
            "parent_sha256_provider_authenticated_offline": False,
        },
        "confirmed_static_c2": endpoints,
        "configuration_conflict_parent_sha256": [],
        "artifacts": [
            {
                "parent_sha256": parent,
                "artifact_sha256": "e" * 64,
                "archive_verified": True,
                "artifact_verified": True,
                "retrieval_evidence": _artifact_retrieval(),
                "status": "remcos_config_recovered",
                "family": "remcosrat",
                "accepted_for_parent": True,
                "parent_configuration_identity_sha256": identity or _identity(endpoints),
                "c2": [
                    {
                        "endpoint": endpoints[0],
                        "host": "example.com",
                        "host_kind": "dns",
                        "port": 2404,
                        "tls_enabled": True,
                        "third_field_kind": "tls_flag",
                        "monitor_eligible": True,
                        "role": "interactive_c2",
                        "confidence": "confirmed_static_configuration",
                        "contacted": False,
                        "liveness_confirmed": False,
                        "evidence": {
                            "kind": "rc4_decrypted_rcdata_settings",
                            "resource_type": "RT_RCDATA",
                            "resource_name": "SETTINGS",
                            "config_field_index": 0,
                            "all_expected_fields_validated": True,
                            "validated_field_indices": [0, 1, 2, 14, 41],
                            "complete_c2_record_set_validated": True,
                            "family_specific_mutex_prefix_validated": True,
                        },
                    }
                ],
                "config": {
                    "static_config_recovered": True,
                    "decoded_config_recovered": True,
                    "family_attribution_confirmed": True,
                    "validated_field_indices": [0, 1, 2, 14, 41],
                    "complete_c2_record_set_validated": True,
                    "family_specific_mutex_prefix_validated": True,
                    "credential_value_published": False,
                    "rc4_key_published": False,
                    "decoded_settings_published": False,
                    "decoded_settings_sha256": SETTINGS_SHA256,
                    "endpoints": endpoints,
                },
            }
        ],
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "plaintext_artifact_written": False,
            "raw_config_published": False,
            "credentials_published": False,
            "private_key_published": False,
        },
    }


def _combine(blind: dict, terminal: dict, **kwargs: object) -> dict:
    return combiner.combine(
        blind,
        terminal,
        blind_sha256="1" * 64,
        terminal_sha256="2" * 64,
        expected_cohort_manifest_sha256=MANIFEST_SHA256,
        expected_case_count=3,
        **kwargs,
    )


def test_union_is_recomputed_without_double_counting() -> None:
    result = _combine(_blind(), _terminal(), target_rate=0.5)
    assert result["blind_root_static"]["case_count"] == 1
    assert result["exact_hash_terminal_artifact"]["case_count"] == 1
    assert result["two_stage_union"]["case_count"] == 2
    assert result["two_stage_union"]["overlap_case_count"] == 0
    assert result["two_stage_union"]["rate"] == pytest.approx(2 / 3)
    assert result["two_stage_union"]["target_met"] is False
    assert result["safety"]["c2_network_contacted"] is False
    assert result["safety"]["external_provider_artifact_retrieval_recorded"] is True
    assert result["safety"]["raw_endpoint_published"] is False
    assert all(":" not in value for value in result["two_stage_union"]["root_sha256"])


def test_overlap_is_counted_once() -> None:
    result = _combine(_blind(), _terminal(parent=ROOTS[0]))
    assert result["two_stage_union"]["case_count"] == 1
    assert result["two_stage_union"]["overlap_case_count"] == 1


def test_terminal_parent_outside_blind_cohort_is_rejected() -> None:
    with pytest.raises(ValueError, match="cohort"):
        _combine(_blind(), _terminal(parent="0" * 64))


def test_terminal_conflict_record_is_excluded() -> None:
    terminal = _terminal()
    terminal["artifacts"][0] = {
        "parent_sha256": ROOTS[1],
        "artifact_sha256": "e" * 64,
        "archive_verified": True,
        "artifact_verified": True,
        "retrieval_evidence": _artifact_retrieval(),
        "status": "configuration_conflict_rejected",
        "accepted_for_parent": False,
    }
    terminal["configuration_conflict_parent_sha256"] = [ROOTS[1]]
    terminal["confirmed_static_c2"] = []
    terminal["counts"].update(
        {
            "config_recovered": 0,
            "config_recovered_parent": 0,
            "configuration_conflict_parent": 1,
            "unique_c2": 0,
        }
    )
    result = _combine(_blind(), terminal)
    assert result["exact_hash_terminal_artifact"]["case_count"] == 0
    assert result["two_stage_union"]["case_count"] == 1


def test_terminal_conflict_also_excludes_prior_blind_success() -> None:
    terminal = _terminal(parent=ROOTS[0])
    terminal["artifacts"][0] = {
        "parent_sha256": ROOTS[0],
        "artifact_sha256": "e" * 64,
        "archive_verified": True,
        "artifact_verified": True,
        "retrieval_evidence": _artifact_retrieval(),
        "status": "configuration_conflict_rejected",
        "accepted_for_parent": False,
    }
    terminal["configuration_conflict_parent_sha256"] = [ROOTS[0]]
    terminal["confirmed_static_c2"] = []
    terminal["counts"].update(
        {
            "config_recovered": 0,
            "config_recovered_parent": 0,
            "configuration_conflict_parent": 1,
            "unique_c2": 0,
        }
    )

    result = _combine(_blind(), terminal)

    assert result["blind_root_static"]["case_count"] == 0
    assert result["blind_root_static"]["terminal_conflict_excluded_case_count"] == 1
    assert result["two_stage_union"]["case_count"] == 0


def test_terminal_conflict_parent_cannot_retain_success_artifact() -> None:
    terminal = _terminal()
    terminal["artifacts"].append(
        {
            "parent_sha256": ROOTS[1],
            "artifact_sha256": "d" * 64,
            "archive_verified": True,
            "artifact_verified": True,
            "retrieval_evidence": _artifact_retrieval(),
            "status": "configuration_conflict_rejected",
            "accepted_for_parent": False,
        }
    )
    terminal["configuration_conflict_parent_sha256"] = [ROOTS[1]]
    terminal["counts"].update(
        {
            "artifacts": 2,
            "archive_verified": 2,
            "artifact_verified": 2,
            "config_recovered_parent": 0,
            "configuration_conflict_parent": 1,
        }
    )

    with pytest.raises(ValueError, match="成功artifact"):
        _combine(_blind(), terminal)


@pytest.mark.parametrize(
    "field",
    ["all_static_layers_required_for_success", "all_static_layers_evaluated"],
)
def test_blind_static_completeness_contract_is_required(field: str) -> None:
    blind = _blind()
    blind["strict_contract"][field] = False

    with pytest.raises(ValueError, match="strict証拠契約"):
        _combine(blind, _terminal())


def test_blind_strict_evidence_empty_object_is_rejected() -> None:
    blind = _blind()
    blind["cases"][0]["strict_evidence_layers"] = [{}]

    with pytest.raises(ValueError, match="layer_sha256"):
        _combine(blind, _terminal())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("depth", 1, "layer depth"),
        ("transform", "", "transform"),
        ("configuration_sha256", "A" * 64, "lowercase SHA-256"),
        ("settings_resource_sha256", "short", "lowercase SHA-256"),
        ("rc4_key_sha256", None, "lowercase SHA-256"),
        ("configured_endpoint_count", 2, "endpoint SHA件数"),
        ("configured_endpoint_sha256", [ENDPOINT_SHA256, ENDPOINT_SHA256], "endpoint SHA件数"),
        ("qualified_endpoint_count", 0, "許可範囲内の整数"),
        ("qualified_c2", False, "qualified C2"),
        ("raw_endpoint_published", True, "安全境界"),
        ("raw_key_published", True, "安全境界"),
        ("raw_config_published", True, "安全境界"),
    ],
)
def test_blind_strict_evidence_fields_are_revalidated(
    field: str,
    value: object,
    message: str,
) -> None:
    blind = _blind()
    blind["cases"][0]["strict_evidence_layers"][0][field] = value

    with pytest.raises(ValueError, match=message):
        _combine(blind, _terminal())


def test_blind_static_layer_set_and_evidence_binding_are_revalidated() -> None:
    blind = _blind()
    blind["cases"][0]["static_layer_count"] = 2
    with pytest.raises(ValueError, match="static layer件数"):
        _combine(blind, _terminal())

    blind = _blind()
    blind["cases"][0]["static_layer_sha256"] = ["d" * 64]
    with pytest.raises(ValueError, match="static layer集合"):
        _combine(blind, _terminal())

    blind = _blind()
    blind["cases"][0]["strict_evidence_layers"][0]["layer_sha256"] = "d" * 64
    with pytest.raises(ValueError, match="layer対応"):
        _combine(blind, _terminal())


def test_blind_non_strict_case_cannot_retain_strict_evidence() -> None:
    blind = _blind()
    blind["cases"][1]["strict_evidence_layers"] = blind["cases"][0]["strict_evidence_layers"]

    with pytest.raises(ValueError, match="strict証拠件数"):
        _combine(blind, _terminal())


def test_safety_violation_and_partial_blind_evaluation_are_rejected() -> None:
    terminal = _terminal()
    terminal["safety"]["network_contacted"] = True
    with pytest.raises(ValueError, match="安全境界"):
        _combine(_blind(), terminal)
    blind = _blind()
    blind["current"]["partial_case_count"] = 1
    with pytest.raises(ValueError, match="完全な固定集合"):
        _combine(blind, _terminal())


def test_terminal_config_identity_is_recomputed() -> None:
    with pytest.raises(ValueError, match="再計算"):
        _combine(_blind(), _terminal(identity="d" * 64))


def test_terminal_c2_noncommunication_evidence_is_required() -> None:
    terminal = _terminal()
    terminal["artifacts"][0]["c2"][0]["liveness_confirmed"] = True
    with pytest.raises(ValueError, match="strict証拠契約"):
        _combine(_blind(), terminal)


@pytest.mark.parametrize("third_field_kind", ["absent", "withheld_unknown_or_credential"])
def test_terminal_legacy_c2_with_unknown_tls_is_supported(
    third_field_kind: str,
) -> None:
    terminal = _terminal()
    record = terminal["artifacts"][0]["c2"][0]
    record["tls_enabled"] = None
    record["third_field_kind"] = third_field_kind
    result = _combine(_blind(), terminal)
    assert result["exact_hash_terminal_artifact"]["case_count"] == 1


def test_terminal_c2_tls_and_third_field_contract_must_match() -> None:
    terminal = _terminal()
    terminal["artifacts"][0]["c2"][0]["third_field_kind"] = "absent"
    with pytest.raises(ValueError, match="strict証拠契約"):
        _combine(_blind(), terminal)


@pytest.mark.parametrize(
    ("endpoint", "host", "host_kind", "monitor_eligible"),
    [
        ("0.0.0.0:2404", "0.0.0.0", "ipv4", True),
        ("localhost:2404", "localhost", "dns", True),
        ("8.8.8.8:2404", "8.8.8.8", "ipv4", False),
    ],
)
def test_terminal_c2_host_and_monitor_eligibility_are_recomputed(
    endpoint: str,
    host: str,
    host_kind: str,
    monitor_eligible: bool,
) -> None:
    terminal = _terminal()
    record = terminal["artifacts"][0]["c2"][0]
    record.update(
        {
            "endpoint": endpoint,
            "host": host,
            "host_kind": host_kind,
            "monitor_eligible": monitor_eligible,
        }
    )
    terminal["artifacts"][0]["config"]["endpoints"] = [endpoint]
    terminal["artifacts"][0]["parent_configuration_identity_sha256"] = _identity([endpoint])
    terminal["confirmed_static_c2"] = [endpoint]

    with pytest.raises(ValueError, match="C2 record"):
        _combine(_blind(), terminal)


def test_legacy_retrieval_evidence_is_not_counted_as_verified() -> None:
    terminal = _terminal()
    terminal["retrieval_evidence"]["manifest_profiles"] = ["legacy_bounded_subset_v1"]
    terminal["artifacts"][0]["retrieval_evidence"]["manifest_profile"] = "legacy_bounded_subset_v1"
    with pytest.raises(ValueError, match="verified contract"):
        _combine(_blind(), terminal)


def test_self_asserted_bounded_subset_is_not_strict_verified_evidence() -> None:
    terminal = _terminal()
    terminal["retrieval_evidence"]["manifest_profiles"] = ["verified_bounded_subset_v1"]
    terminal["artifacts"][0]["retrieval_evidence"]["manifest_profile"] = "verified_bounded_subset_v1"
    with pytest.raises(ValueError, match="verified contract"):
        _combine(_blind(), terminal)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("selection", "arbitrary_selection"),
        ("provider_parent_binding", "self_asserted_binding"),
    ],
)
def test_terminal_retrieval_binding_claim_is_exact(field: str, value: str) -> None:
    terminal = _terminal()
    terminal["artifacts"][0]["retrieval_evidence"][field] = value
    with pytest.raises(ValueError, match="verified取得証跡"):
        _combine(_blind(), terminal)


def test_manifest_provider_role_and_boolean_counts_are_pinned() -> None:
    blind = _blind()
    blind["cohort"]["provider_label_role"] = "family_confirmation"
    with pytest.raises(ValueError, match="固定集合"):
        _combine(blind, _terminal())
    blind = _blind()
    blind["current"]["strict_joint_case_count"] = True
    with pytest.raises(ValueError, match="整数"):
        _combine(blind, _terminal())
    with pytest.raises(ValueError, match="固定集合"):
        combiner.combine(
            _blind(),
            _terminal(),
            blind_sha256="1" * 64,
            terminal_sha256="2" * 64,
            expected_cohort_manifest_sha256="0" * 64,
            expected_case_count=3,
        )


def _write_json(path: Path, value: dict) -> str:
    raw = (json.dumps(value, ensure_ascii=False) + "\n").encode()
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def test_cli_requires_pins_and_rejects_output_alias(tmp_path: Path) -> None:
    blind_path = tmp_path / "blind.json"
    terminal_path = tmp_path / "terminal.json"
    blind_sha = _write_json(blind_path, _blind())
    terminal_sha = _write_json(terminal_path, _terminal())
    with pytest.raises(ValueError, match="pin"):
        combiner.main(
            [
                "--blind-evaluation",
                str(blind_path),
                "--blind-evaluation-sha256",
                "0" * 64,
                "--terminal-analysis",
                str(terminal_path),
                "--terminal-analysis-sha256",
                terminal_sha,
                "--expected-cohort-manifest-sha256",
                MANIFEST_SHA256,
                "--expected-case-count",
                "3",
                "--output",
                str(tmp_path / "out.json"),
            ]
        )
    with pytest.raises(ValueError, match="同じpath"):
        combiner.main(
            [
                "--blind-evaluation",
                str(blind_path),
                "--blind-evaluation-sha256",
                blind_sha,
                "--terminal-analysis",
                str(terminal_path),
                "--terminal-analysis-sha256",
                terminal_sha,
                "--expected-cohort-manifest-sha256",
                MANIFEST_SHA256,
                "--expected-case-count",
                "3",
                "--output",
                str(blind_path),
            ]
        )


def test_cli_rejects_symlink_input_before_resolution(tmp_path: Path) -> None:
    blind_path = tmp_path / "blind.json"
    terminal_path = tmp_path / "terminal.json"
    blind_sha = _write_json(blind_path, _blind())
    terminal_sha = _write_json(terminal_path, _terminal())
    alias = tmp_path / "blind-link.json"
    try:
        alias.symlink_to(blind_path)
    except OSError:
        pytest.skip("この環境ではsymlinkを作成できません")
    with pytest.raises(ValueError, match="single-link"):
        combiner.main(
            [
                "--blind-evaluation",
                str(alias),
                "--blind-evaluation-sha256",
                blind_sha,
                "--terminal-analysis",
                str(terminal_path),
                "--terminal-analysis-sha256",
                terminal_sha,
                "--expected-cohort-manifest-sha256",
                MANIFEST_SHA256,
                "--expected-case-count",
                "3",
                "--output",
                str(tmp_path / "out.json"),
            ]
        )


@pytest.mark.skipif(not hasattr(os, "link"), reason="hardlink未対応環境")
def test_cli_rejects_existing_output_hardlink(tmp_path: Path) -> None:
    blind_path = tmp_path / "blind.json"
    terminal_path = tmp_path / "terminal.json"
    blind_sha = _write_json(blind_path, _blind())
    terminal_sha = _write_json(terminal_path, _terminal())
    alias = tmp_path / "alias.json"
    os.link(blind_path, alias)
    with pytest.raises(ValueError, match="single-link|hardlink"):
        combiner.main(
            [
                "--blind-evaluation",
                str(blind_path),
                "--blind-evaluation-sha256",
                blind_sha,
                "--terminal-analysis",
                str(terminal_path),
                "--terminal-analysis-sha256",
                terminal_sha,
                "--expected-cohort-manifest-sha256",
                MANIFEST_SHA256,
                "--expected-case-count",
                "3",
                "--output",
                str(alias),
            ]
        )
