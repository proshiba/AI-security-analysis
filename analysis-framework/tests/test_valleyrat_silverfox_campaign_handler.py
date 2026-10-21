"""SilverFox-style ValleyRAT route-only campaign handlerを検証する。"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest
from extractors.valleyrat.silverfox_loader_lineage import SilverFoxLoaderLineage

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import handler_catalog as catalog
from analysis_contract import handler_result_quality

MODULE_PATH = FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "silverfox_style_infection_loader" / "analyze.py"
SPEC = importlib.util.spec_from_file_location(
    "valleyrat_silverfox_style_campaign_handler",
    MODULE_PATH,
)
assert SPEC is not None and SPEC.loader is not None
HANDLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HANDLER)


def _observation(*, status: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "matched": True,
        "component_profile": (
            "silverfox_style_infection_loader" if status == HANDLER.VALIDATED_STATUS else "native_loader_candidate"
        ),
        "outer_stage_candidate_count": 1,
        "outer_stage": {
            "size": 4096,
            "virtualalloc_exact_copy_jump_proven": True,
            "source_rva_included": False,
        },
        "route_config": {
            "record_count": 1,
            "marker_to_xor_record_structure_proven": True,
            "endpoint_values_included": False,
            "used_for_valleyrat_c2_confirmation": False,
        },
        "decoders": {
            "tail_patch_operation_count": 4,
            "reverse_feedback_count": 4096,
            "repeating_xor_key_length": 16,
            "decoded_component_size": 128,
            "decoded_component_hash_included": False,
            "key_included": False,
        },
        "downstream": {
            "profile": "silverfox_style_infection_downloader_component",
            "wininet_get_read_retry_lineage_proven": True,
            "file_write_and_process_capability_proven": True,
            "registry_handoff_structure_proven": True,
            "endpoint_values_included": False,
            "raw_command_values_included": False,
        },
        "missing_proof_codes": [
            "valleyrat_terminal_component_unproven",
            "valleyrat_terminal_protocol_unproven",
        ],
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "terminal_network_lineage_proven": False,
        "terminal_protocol_lineage_proven": False,
        "candidate_only": True,
        "hash_or_filename_rule_used": False,
        "external_label_used": False,
        "endpoint_values_included": False,
        "raw_payload_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def test_validated_loader_returns_only_nonterminal_follow_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """完全なloader lineageでもfamily/C2を確定せず、次段だけを返す。"""

    component = b"MZ" + bytes(126)
    monkeypatch.setattr(
        HANDLER,
        "analyze_silverfox_loader_lineage",
        lambda _data: SilverFoxLoaderLineage(
            observation=_observation(status=HANDLER.VALIDATED_STATUS),
            recovered_component=component,
        ),
    )

    result = HANDLER.analyze(b"MZ outer loader")

    assert result["campaign_type"] == "silverfox_style_infection_loader"
    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["attribution_scope"] == "component_handler_route"
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert result["findings"] == []
    assert result["recovered_payload"] == {
        "role": "recovered_payload",
        "kind": "pe",
        "name": f"{hashlib.sha256(component).hexdigest()}.bin",
        "data": component,
    }
    quality = handler_result_quality(
        result,
        minimum_score=HANDLER.HANDLER_CONTRACT["minimum_evidence_score"],
    )
    assert quality["tier_name"] == "structural_corroboration"
    assert quality["sufficient"] is True


def test_incomplete_lineage_returns_codes_without_payload_or_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """不完全lineageは許可形式の不足codeだけを返し、bytesと秘密値を捨てる。"""

    observation = _observation(status=HANDLER.INCOMPLETE_STATUS)
    observation["missing_proof_codes"] = [
        "route_record_unproven",
        "password=do-not-publish",
    ]
    monkeypatch.setattr(
        HANDLER,
        "analyze_silverfox_loader_lineage",
        lambda _data: SilverFoxLoaderLineage(
            observation=observation,
            recovered_component=b"MZ must not escape",
        ),
    )

    result = HANDLER.analyze(b"MZ incomplete loader")

    assert result["silverfox_loader_lineage"]["status"] == (HANDLER.INCOMPLETE_STATUS)
    assert result["silverfox_loader_lineage"]["missing_proof_codes"] == ["route_record_unproven"]
    assert "recovered_payload" not in result
    assert result["config"]["endpoints"] == []
    assert "do-not-publish" not in repr(result)
    assert "must not escape" not in repr(result)


def test_validated_status_without_component_fails_closed_as_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """statusだけがvalidatedでも復元bytesがなければfollow-onへ昇格しない。"""

    monkeypatch.setattr(
        HANDLER,
        "analyze_silverfox_loader_lineage",
        lambda _data: SilverFoxLoaderLineage(
            observation=_observation(status=HANDLER.VALIDATED_STATUS),
            recovered_component=None,
        ),
    )

    result = HANDLER.analyze(b"MZ inconsistent loader")

    lineage = result["silverfox_loader_lineage"]
    assert lineage["status"] == HANDLER.INCOMPLETE_STATUS
    assert lineage["component_profile"] == "native_loader_candidate"
    assert "recovered_component_unavailable" in lineage["missing_proof_codes"]
    assert "recovered_payload" not in result
    assert result["terminal_family_confirmed"] is False


def test_validated_status_with_component_size_mismatch_does_not_return_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """宣言サイズと一致しない復元bytesをfixed-pointへ渡さない。"""

    monkeypatch.setattr(
        HANDLER,
        "analyze_silverfox_loader_lineage",
        lambda _data: SilverFoxLoaderLineage(
            observation=_observation(status=HANDLER.VALIDATED_STATUS),
            recovered_component=b"MZ short",
        ),
    )

    result = HANDLER.analyze(b"MZ inconsistent loader")
    lineage = result["silverfox_loader_lineage"]

    assert lineage["status"] == HANDLER.INCOMPLETE_STATUS
    assert lineage["component_profile"] == "native_loader_candidate"
    assert "recovered_component_size_mismatch" in lineage["missing_proof_codes"]
    assert "recovered_payload" not in result


@pytest.mark.parametrize(
    ("path", "invalid_value"),
    [
        (("component_profile",), "native_loader_candidate"),
        (("supports_family_attribution",), True),
        (("terminal_family_confirmed",), True),
        (("terminal_network_lineage_proven",), True),
        (("terminal_protocol_lineage_proven",), True),
        (("candidate_only",), False),
        (("hash_or_filename_rule_used",), True),
        (("external_label_used",), True),
        (("endpoint_values_included",), True),
        (("raw_payload_included",), True),
        (("sample_executed",), True),
        (("network_contacted",), True),
        (("outer_stage_candidate_count",), 2),
        (("outer_stage", "virtualalloc_exact_copy_jump_proven"), False),
        (("outer_stage", "source_rva_included"), True),
        (("decoders", "tail_patch_operation_count"), 0),
        (("decoders", "reverse_feedback_count"), 0),
        (("decoders", "repeating_xor_key_length"), 0),
        (("decoders", "decoded_component_size"), 0),
        (("decoders", "decoded_component_hash_included"), True),
        (("decoders", "key_included"), True),
        (("route_config", "record_count"), 2),
        (("route_config", "marker_to_xor_record_structure_proven"), False),
        (("route_config", "endpoint_values_included"), True),
        (("route_config", "used_for_valleyrat_c2_confirmation"), True),
        (("downstream", "wininet_get_read_retry_lineage_proven"), False),
        (("downstream", "file_write_and_process_capability_proven"), False),
        (("downstream", "registry_handoff_structure_proven"), False),
        (("downstream", "endpoint_values_included"), True),
        (("downstream", "raw_command_values_included"), True),
    ],
    ids=[
        "status-profile-mismatch",
        "family-attribution-promoted",
        "terminal-family-promoted",
        "terminal-network-promoted",
        "terminal-protocol-promoted",
        "candidate-only-cleared",
        "hash-rule-used",
        "external-label-used",
        "endpoint-value-published",
        "raw-payload-published",
        "sample-executed",
        "network-contacted",
        "validated-outer-count-not-unique",
        "outer-copy-jump-unproven",
        "outer-source-rva-published",
        "decoder-patch-count-not-positive",
        "decoder-feedback-count-not-positive",
        "decoder-key-length-not-positive",
        "decoded-component-size-not-positive",
        "decoded-component-hash-published",
        "decoder-key-published",
        "route-record-count-not-unique",
        "route-record-structure-unproven",
        "route-endpoint-published",
        "route-config-promoted-to-c2",
        "downstream-wininet-unproven",
        "downstream-file-process-unproven",
        "downstream-registry-unproven",
        "downstream-endpoint-published",
        "raw-downstream-command-published",
    ],
)
def test_inconsistent_upstream_lineage_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, ...],
    invalid_value: object,
) -> None:
    """上流analyzerの構造証拠を信頼せず、各境界をhandlerで再検証する。"""

    observation = copy.deepcopy(_observation(status=HANDLER.VALIDATED_STATUS))
    target: dict[str, object] = observation
    for field in path[:-1]:
        child = target[field]
        assert isinstance(child, dict)
        target = child
    target[path[-1]] = invalid_value
    monkeypatch.setattr(
        HANDLER,
        "analyze_silverfox_loader_lineage",
        lambda _data: SilverFoxLoaderLineage(
            observation=observation,
            recovered_component=b"MZ component",
        ),
    )

    with pytest.raises(catalog.HandlerNoEvidenceError):
        HANDLER.analyze(b"MZ inconsistent loader")


def test_incomplete_lineage_accepts_absent_unproven_stages_without_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """曖昧な外層では未証明stageを捏造せず、不足codeだけを返す。"""

    observation = _observation(status=HANDLER.INCOMPLETE_STATUS)
    observation["outer_stage_candidate_count"] = 2
    observation["outer_stage"] = None
    observation["route_config"] = {
        "record_count": 0,
        "marker_to_xor_record_structure_proven": False,
        "endpoint_values_included": False,
        "used_for_valleyrat_c2_confirmation": False,
    }
    observation["decoders"] = None
    observation["downstream"] = None
    observation["missing_proof_codes"] = [
        "multiple_outer_stage_interpretations_ambiguous",
        "route_record_unproven",
    ]
    monkeypatch.setattr(
        HANDLER,
        "analyze_silverfox_loader_lineage",
        lambda _data: SilverFoxLoaderLineage(
            observation=observation,
            recovered_component=b"MZ must not escape",
        ),
    )

    result = HANDLER.analyze(b"MZ incomplete loader")

    assert result["silverfox_loader_lineage"]["decoder_lineage_proven"] is False
    assert result["silverfox_loader_lineage"]["outer_virtualalloc_copy_jump_lineage_proven"] is False
    assert "recovered_payload" not in result
    assert result["config"]["endpoints"] == []
    assert "must not escape" not in repr(result)


def test_no_lineage_is_handler_no_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """構造不一致を空の成功結果へ変換しない。"""

    monkeypatch.setattr(
        HANDLER,
        "analyze_silverfox_loader_lineage",
        lambda _data: None,
    )

    with pytest.raises(catalog.HandlerNoEvidenceError):
        HANDLER.analyze(b"MZ unrelated")


def test_campaign_handler_is_bytes_only_and_passes_static_preflight() -> None:
    """専用handlerはPE bytes入力だけを隔離workerで受理する。"""

    catalog.clear_handler_caches()
    try:
        spec = next(
            item
            for item in catalog.discover_handlers()
            if item.relative_path.endswith("valleyrat/campaigns/silverfox_style_infection_loader/analyze.py")
        )
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format="pe",
            input_size=1024 * 1024,
        )
    finally:
        catalog.clear_handler_caches()

    assert spec.automatic is True
    assert spec.invocation == "bytes"
    assert spec.campaign == "silverfox_style_infection_loader"
    assert spec.input_formats == ("pe",)
    assert preflight["eligible"] is True
    assert preflight["blockers"] == []
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False
