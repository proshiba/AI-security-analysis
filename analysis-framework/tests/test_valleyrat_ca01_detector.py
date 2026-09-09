"""CA01設定probeのdetector優先順とfamily帰属境界を検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
)
SPEC = importlib.util.spec_from_file_location("valleyrat_ca01_detect", MODULE_PATH)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)

def _probe(
    *,
    reviewed_exact: bool,
    outer_profile: str = "vulkan_export_create_thread",
) -> dict[str, object]:
    cef_profile = outer_profile == "cef_alias_export_beginthreadex"
    return {
        "matched": True,
        "family": "valleyrat" if reviewed_exact else None,
        "variant": "ca01_x64_double_base64_sideload_terminal",
        "outer_profile": outer_profile,
        "supports_family_attribution": reviewed_exact,
        "attribution_scope": (
            "reviewed_exact_cef_alias_loader_linked_config_and_memory_stage_consumer"
            if cef_profile and reviewed_exact
            else "reviewed_exact_loader_linked_config_and_memory_stage_consumer"
            if reviewed_exact
            else "component_handler_route"
        ),
        "terminal_family_confirmed": reviewed_exact,
        "classification_confidence": (
            "high_structural_decoded_config"
            if reviewed_exact
            else "medium_structural_config_route"
        ),
        "static_config_recovered": True,
        "evidence": {
            "status": "validated_ca01_x64_double_base64_sideload_config",
            "slot_count": 3,
            "endpoint_count": 2,
            "raw_network_values_included": False,
            "raw_encoded_token_included": False,
            "raw_addresses_included": False,
        },
        "config": {
            "endpoint_count": 2,
            "slot_count": 3,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def test_reviewed_ca01_precedes_raw_codemark_and_confirms_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CA01成功時はraw codemark routeへ進まず、既知完全一致を高確度化する。"""

    monkeypatch.setattr(DETECT, "probe_ca01_config", lambda _data: _probe(reviewed_exact=True))
    monkeypatch.setattr(
        DETECT,
        "_codemark_stage_observation",
        lambda *_args, **_kwargs: pytest.fail("CA01成功後にraw codemarkを評価してはならない"),
    )

    result = DETECT.detect(b"MZ reviewed-ca01", Path("vulkan-1.dll"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is True
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "ca01_x64_double_base64_sideload_terminal"
    assert campaign["confidence"] == "high"
    assert campaign["terminal_family_confirmed"] is True


def test_unknown_ca01_is_route_only_and_probe_output_remains_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未知hashは設定件数を保持するがfamily確定や生network値を公開しない。"""

    monkeypatch.setattr(DETECT, "probe_ca01_config", lambda _data: _probe(reviewed_exact=False))
    monkeypatch.setattr(
        DETECT,
        "_codemark_stage_observation",
        lambda *_args, **_kwargs: pytest.fail("CA01 route一致後に別probeを評価してはならない"),
    )

    result = DETECT.detect(b"MZ unknown-ca01", Path("unknown.dll"))
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["confidence"] == "medium"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["terminal_family_confirmed"] is False
    assert "198.51.100.24" not in serialized
    assert "UEVSSU9ESUM=" not in serialized
    assert "0x1800" not in serialized


def test_reviewed_cef_ca01_uses_beginthreadex_lineage_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CEF型は_beginthreadex根拠で確定し、Vulkan経路を混在させない。"""

    monkeypatch.setattr(
        DETECT,
        "probe_ca01_config",
        lambda _data: _probe(
            reviewed_exact=True,
            outer_profile="cef_alias_export_beginthreadex",
        ),
    )

    result = DETECT.detect(b"MZ reviewed-cef-ca01", Path("libcef.dll"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is True
    reasons = result["campaigns"][0]["reasons"]
    assert any("_beginthreadex" in reason for reason in reasons)
    assert not any("Vulkan export" in reason for reason in reasons)


def test_unknown_cef_ca01_remains_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じCEF構造でも未レビューhashはfamily確定へ昇格しない。"""

    monkeypatch.setattr(
        DETECT,
        "probe_ca01_config",
        lambda _data: _probe(
            reviewed_exact=False,
            outer_profile="cef_alias_export_beginthreadex",
        ),
    )

    result = DETECT.detect(b"MZ unknown-cef-ca01", Path("libcef.dll"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    assert result["campaigns"][0]["terminal_family_confirmed"] is False
    assert result["campaigns"][0]["attribution_scope"] == "component_handler_route"
