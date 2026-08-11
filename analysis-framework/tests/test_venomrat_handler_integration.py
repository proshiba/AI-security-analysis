from __future__ import annotations

import sys
from pathlib import Path

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import handler_catalog  # noqa: E402
from analysis_contract import handler_result_quality  # noqa: E402
from extractors.venomrat import integrated as venom_integrated  # noqa: E402


def _venom_structural_fixture() -> bytes:
    fields = {
        "Key",
        "Por_ts",
        "Hos_ts",
        "Ver_sion",
        "In_stall",
        "Paste_bin",
        "An_ti",
        "Group",
        "Certifi_cate",
        "Pac_ket",
        "Po_ng",
    }
    return b"MZ" + b"\x00" * 64 + b"BSJB\x00" + "\x00".join(sorted(fields)).encode()


def _venom_handler() -> handler_catalog.HandlerSpec:
    return next(
        item
        for item in handler_catalog.discover_handlers()
        if item.family == "venomrat"
        and item.relative_path == "extractors/venomrat/extractor.py"
    )


def test_venomrat_handler_pins_hmac_verified_common_recovery() -> None:
    spec = _venom_handler()
    assert spec.automatic is True
    assert spec.input_formats == ("pe",)
    assert spec.input_contract_source == "module_declaration"
    assert spec.minimum_evidence_score == 20_000

    preflight = handler_catalog.preflight_handler_for_assessment(
        spec,
        actual_format="pe",
        input_size=75_776,
    )
    assert preflight["eligible"] is True
    assert preflight["blockers"] == []
    audited_paths = {
        item["path"] for item in preflight["dependency_audit"]["files"]
    }
    assert "extractors/venomrat/integrated.py" in audited_paths
    assert "analysis-framework/common/dotnet_rat_config.py" in audited_paths
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False

    incompatible = handler_catalog.preflight_handler_for_assessment(
        spec,
        actual_format="data",
        input_size=75_776,
    )
    assert incompatible["eligible"] is False
    assert "incompatible_input_format:data" in incompatible["blockers"]


def test_venomrat_validated_config_is_sufficient_handler_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """強いCIL構造と検証済み設定をone-shotのtier 3へ接続する。"""

    spec = _venom_handler()
    monkeypatch.setattr(
        venom_integrated,
        "_validated_recovery",
        lambda _data: {
            "version": "Venom RAT v6.0.3",
            "install": "true",
            "group": "start",
            "anti_analysis": "false",
            "endpoints": [{"host": "c2.example.test", "port": 2794}],
            "dynamic_config_url": "https://resolver.example.test/raw/config",
            "certificate": {
                "sha256": "a" * 64,
                "size": 573,
                "certificate_mismatch_excludes_c2": False,
            },
        },
    )

    result = venom_integrated.extract(_venom_structural_fixture(), "fixture.exe")
    quality = handler_result_quality(
        result,
        minimum_score=spec.minimum_evidence_score,
    )

    assert result["config"]["recovery_status"] == "recovered_hmac_verified"
    assert result["config"]["version"] == "Venom RAT v6.0.3"
    assert {item["role"] for item in result["findings"]} == {
        "configured_c2",
        "dynamic_config_resolver",
        "tls_certificate_pin",
    }
    assert quality["tier"] == 3
    assert quality["tier_name"] == "validated_static_configuration"
    assert quality["score"] >= spec.minimum_evidence_score
    assert quality["sufficient"] is True


def test_venomrat_single_marker_is_not_handler_evidence() -> None:
    """共有由来の単一markerを設定候補や帰属証拠へ昇格しない。"""

    spec = _venom_handler()
    result = venom_integrated.extract(b"MZ BSJB mutex c2.example.test:2794")
    quality = handler_result_quality(
        result,
        minimum_score=spec.minimum_evidence_score,
    )

    assert result["config"]["recovery_status"] == "not_attempted_structural_mismatch"
    assert result["config"]["static_config_recovered"] is False
    assert result["findings"] == []
    assert quality["tier"] == 0
    assert quality["score"] == 0
    assert quality["sufficient"] is False
