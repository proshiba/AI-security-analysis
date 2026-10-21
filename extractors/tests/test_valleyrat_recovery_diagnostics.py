"""ValleyRAT静的復元診断の証拠境界を検証する。"""

from __future__ import annotations

import json

import pytest

from extractors.valleyrat import extractor


def _string_scan(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "status": "complete",
        "completed": True,
        "skipped": False,
        "truncated": False,
    }
    result.update(overrides)
    return result


def test_unresolved_profile_has_actionable_machine_readable_blocker() -> None:
    """適合profileがない場合を曖昧なno evidenceだけで終わらせない。"""

    result = extractor._recovery_diagnostics(
        variant="unresolved_variant",
        static_config_confirmed=False,
        candidate_config_recovered=False,
        string_scan=_string_scan(),
        vvas_recovery={"status": "not_found"},
        native_loader_observations={},
    )

    assert result["status"] == "unsupported_profile"
    assert result["blocker_codes"] == ["no_supported_terminal_profile"]
    assert result["next_action_codes"] == ["add_or_refine_static_variant_profile"]


def test_loader_missing_proofs_are_normalized_without_secret_values() -> None:
    """loader候補は不足proofだけを公開し、設定値やendpointを複写しない。"""

    result = extractor._recovery_diagnostics(
        variant="silverfox_style_infection_loader",
        static_config_confirmed=False,
        candidate_config_recovered=False,
        string_scan=_string_scan(
            status="not_attempted",
            completed=False,
            skipped=True,
            skip_reason="large_pe_marker_first_only",
        ),
        vvas_recovery={"status": "not_found"},
        native_loader_observations={
            "silverfox_loader_lineage": {
                "status": "silverfox_style_loader_candidate_incomplete_lineage",
                "candidate_only": True,
                "missing_proof_codes": [
                    "feedback_decoder_lineage_unproven",
                    "infection_downloader_sink_lineage_unproven",
                    "not allowed: 203.0.113.9:443",
                ],
                "endpoint": "203.0.113.9:443",
            }
        },
    )

    assert result["status"] == "route_only"
    assert result["blocker_codes"] == [
        "feedback_decoder_lineage_unproven",
        "infection_downloader_sink_lineage_unproven",
        "large_pe_marker_first_only",
    ]
    encoded = json.dumps(result, ensure_ascii=False)
    assert "203.0.113.9" not in encoded
    assert result["raw_configuration_included"] is False
    assert result["raw_network_values_included"] is False


def test_incomplete_mapped_scan_is_distinct_from_unsupported_profile() -> None:
    """上限到達はdecoder未対応と分離し、再解析可能な理由を残す。"""

    result = extractor._recovery_diagnostics(
        variant="unresolved_variant",
        static_config_confirmed=False,
        candidate_config_recovered=False,
        string_scan=_string_scan(
            status="not_attempted",
            completed=False,
            skipped=True,
            skip_reason="mapped_config_scan_incomplete",
        ),
        vvas_recovery={
            "status": "mapped_config_scan_incomplete_rejected",
            "mapped_config_scan": {
                "status": "incomplete",
                "candidate_count": 2,
                "unique_configuration_count": 0,
                "candidate_set_complete": False,
            },
        },
        native_loader_observations={},
    )

    assert result["status"] == "limit_exhausted"
    assert "mapped_config_scan_incomplete" in result["blocker_codes"]
    assert result["next_action_codes"] == ["review_or_extend_bounded_scan"]
    assert result["metrics"]["mapped_candidate_count"] == 2


def test_input_size_limit_is_reported_without_starting_recovery(monkeypatch) -> None:
    """入力上限拒否にも共通診断を付け、検体実行や通信を示さない。"""

    monkeypatch.setattr(extractor, "MAXIMUM_INPUT_SIZE", 4)
    result = extractor.extract(b"12345", "oversize.bin")
    diagnostics = result["config"]["recovery_diagnostics"]

    assert diagnostics["status"] == "limit_exhausted"
    assert diagnostics["blocker_codes"] == ["input_size_limit"]
    assert diagnostics["sample_executed"] is False
    assert diagnostics["network_contacted"] is False


@pytest.mark.parametrize(
    "route_name",
    ["onyx", "raw_vvas", "xor_b1", "wide_pipe", "export_funnel"],
)
def test_profile_specific_early_returns_always_include_safe_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    route_name: str,
) -> None:
    """profile固有の早期returnでも未確定理由と安全境界を必ず残す。"""

    early_extractors = {
        "onyx": "_extract_onyx_terminal",
        "raw_vvas": "_extract_raw_vvas_transport_shellcode",
        "xor_b1": "_extract_xor_b1_downloader",
        "wide_pipe": "_extract_wide_pipe_config",
    }
    for function_name in (
        "_reviewed_pdfcore8_result",
        "_extract_ca01_sideload",
        "_extract_onyx_terminal",
        "_extract_run_dll_native_core",
        "_extract_x86_codemark_resource",
        "_extract_bin101",
        "_extract_codemark_stage",
        "_extract_raw_vvas_transport_shellcode",
        "_extract_n520",
        "_extract_xor_b1_downloader",
        "_extract_wide_pipe_config",
    ):
        monkeypatch.setattr(extractor, function_name, lambda *_args: None)
    monkeypatch.setattr(
        extractor,
        "_extract_native_loader_lineage",
        lambda *_args: (None, {}, ()),
    )
    monkeypatch.setattr(
        extractor,
        "_decode_vvas_mapped_pe_config",
        lambda _data: ({}, {}, ()),
    )
    monkeypatch.setattr(
        extractor,
        "probe_export_funnel_route",
        lambda _data: {"matched": False},
    )

    if route_name == "export_funnel":
        monkeypatch.setattr(
            extractor,
            "probe_export_funnel_route",
            lambda _data: {
                "matched": True,
                "variant": "export_funnel_route",
                "recovery_status": "not_recovered",
                "encoded_config_candidate_observed": True,
            },
        )
    else:
        result = extractor.build_result(
            "valleyrat",
            b"MZ fixture",
            {
                "variant": f"{route_name}_profile",
                "recovery_status": "not_recovered",
                "static_config_recovered": False,
                "candidate_config_recovered": route_name in {"raw_vvas", "wide_pipe"},
                "terminal_family_confirmed": route_name == "wide_pipe",
                "endpoints": [],
                "ipv4": [],
                "urls": [],
            },
            [],
            ["検体実行と外部通信は行っていません。"],
        )
        monkeypatch.setattr(
            extractor,
            early_extractors[route_name],
            lambda *_args: result,
        )

    extracted = extractor.extract(b"MZ fixture", "fixture.exe")
    diagnostics = extracted["config"]["recovery_diagnostics"]

    assert diagnostics["schema_version"] == 1
    assert diagnostics["status"] in {"route_only", "rejected"}
    assert diagnostics["blocker_codes"]
    assert diagnostics["raw_configuration_included"] is False
    assert diagnostics["raw_network_values_included"] is False
    assert diagnostics["sample_executed"] is False
    assert diagnostics["network_contacted"] is False
