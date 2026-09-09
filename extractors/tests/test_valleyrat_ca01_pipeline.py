"""CA01設定復元をValleyRAT共通extract入口へ統合する契約を検証する。"""

from __future__ import annotations

import hashlib
import json

import pytest

from extractors.valleyrat import ca01_sideload as ca01
from extractors.valleyrat import extractor


def _recovery(outer_sha256: str) -> ca01.Ca01SideloadRecovery:
    slots = [
        {
            "index": 1,
            "host": "198.51.100.24",
            "port": 449,
            "transport": "tcp",
            "transport_selector": 1,
            "role": "primary",
            "enabled": True,
            "raw_label": "private-primary",
        },
        {
            "index": 2,
            "host": "198.51.100.24",
            "port": 449,
            "transport": "tcp",
            "transport_selector": 1,
            "role": "primary_duplicate",
            "enabled": True,
        },
        {
            "index": 3,
            "host": "198.51.100.24",
            "port": 443,
            "transport": "tcp",
            "transport_selector": 1,
            "role": "alternate",
            "enabled": True,
        },
    ]
    identity_material = "\n".join(
        f"{slot['index']}|{slot['host']}|{slot['port']}|"
        f"{slot['transport_selector']}|{slot['role']}"
        for slot in slots
    ).encode("utf-8")
    return ca01.Ca01SideloadRecovery(
        outer_sha256=outer_sha256,
        config={
            "variant": "ca01_x64_double_base64_sideload_terminal",
            "slots": slots,
            "endpoints": [
                {
                    "host": "198.51.100.24",
                    "port": 449,
                    "transport": "tcp",
                    "role": "primary",
                },
                {
                    "host": "198.51.100.24",
                    "port": 443,
                    "transport": "tcp",
                    "role": "alternate",
                },
            ],
            "configuration_identity_sha256": hashlib.sha256(
                identity_material
            ).hexdigest(),
            "raw_token": "UEVSSU9ESUM=",
        },
        structural_evidence={
            "architecture": "x64",
            "vulkan_export_count": 1,
            "producer_candidate_count": 1,
            "export_reachable_thread_config_lineage_present": True,
            "create_thread_wrapper_reachable": True,
            "lineage_counts": {
                "export_to_main_direct_call_count": 1,
                "main_to_thread_factory_direct_call_count": 1,
                "thread_factory_to_create_thread_wrapper_count": 1,
            },
            "producer": {
                "double_base64_decode_depth": 2,
                "slot_count": 3,
                "unique_endpoint_count": 2,
                "primary_slot_count": 2,
                "alternate_slot_count": 1,
                "explicit_transport_selector_count": 3,
                "periodic_wait_after_consumer_present": True,
                "raw_encoded_token_included": False,
                "raw_network_values_included": False,
                "raw_labels_included": False,
                "raw_addresses_included": False,
            },
            "sample_executed": False,
            "recovered_stage_executed": False,
            "network_contacted": False,
        },
    )


def test_extract_projects_known_ca01_config_without_private_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """既知CA01は通常化endpoint／slotを返し、生token・identityを公開しない。"""

    recovery = _recovery(ca01._REVIEWED_CA01_OUTER_SHA256)
    monkeypatch.setattr(extractor, "recover_ca01_config", lambda _data: recovery)

    result = extractor._extract_ca01_sideload(b"MZ-ca01", "unsafe/path.dll")

    assert result is not None
    config = result["config"]
    assert config["variant"] == "ca01_x64_double_base64_sideload_terminal"
    assert config["static_config_recovered"] is True
    assert config["terminal_family_confirmed"] is True
    assert config["endpoints"] == ["198.51.100.24:449", "198.51.100.24:443"]
    assert config["decoded_ca01_slots"] == [
        {
            "slot": 1,
            "endpoint": "198.51.100.24:449",
            "transport": "tcp",
            "transport_selector": 1,
            "role": "primary",
            "enabled": True,
        },
        {
            "slot": 2,
            "endpoint": "198.51.100.24:449",
            "transport": "tcp",
            "transport_selector": 1,
            "role": "primary_duplicate",
            "enabled": True,
        },
        {
            "slot": 3,
            "endpoint": "198.51.100.24:443",
            "transport": "tcp",
            "transport_selector": 1,
            "role": "alternate",
            "enabled": True,
        },
    ]
    serialized = json.dumps(result, ensure_ascii=False)
    assert "private-primary" not in serialized
    assert "UEVSSU9ESUM=" not in serialized
    private_identity = recovery.config["configuration_identity_sha256"]
    assert isinstance(private_identity, str)
    assert private_identity not in serialized


def test_ca01_precedes_weaker_extractors_and_falls_back_cleanly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CA01成功時は弱い経路を呼ばず、不一致時だけ既存経路へ進む。"""

    monkeypatch.setattr(extractor, "_reviewed_pdfcore8_result", lambda *_args: None)
    monkeypatch.setattr(
        extractor,
        "recover_ca01_config",
        lambda _data: _recovery(ca01._REVIEWED_CA01_OUTER_SHA256),
    )
    monkeypatch.setattr(
        extractor,
        "_extract_onyx_terminal",
        lambda *_args: pytest.fail("CA01成功後にOnyxへ進んではならない"),
    )

    result = extractor.extract(b"MZ-ca01")
    assert result["config"]["variant"] == "ca01_x64_double_base64_sideload_terminal"

    expected = {"fallback": True}
    monkeypatch.setattr(extractor, "recover_ca01_config", lambda _data: None)
    monkeypatch.setattr(extractor, "_extract_onyx_terminal", lambda *_args: expected)
    assert extractor.extract(b"MZ-not-ca01") is expected


def test_unknown_ca01_hash_keeps_config_but_not_family_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未知hashの同型configは抽出しつつ終端family確定を抑止する。"""

    monkeypatch.setattr(
        extractor,
        "recover_ca01_config",
        lambda _data: _recovery("a" * 64),
    )

    result = extractor._extract_ca01_sideload(b"MZ-unknown-ca01", "sample.dll")

    assert result is not None
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["attribution_scope"] == "component_handler_route"


@pytest.mark.parametrize(
    "malformation",
    [
        "boolean_selector",
        "transport_selector_mismatch",
        "wrong_slot_order",
        "wrong_role_order",
        "missing_primary_duplicate",
        "alternate_duplicates_primary",
        "alternate_uses_different_host",
        "endpoint_projection_mismatch",
        "duplicate_raw_endpoint",
        "endpoint_transport_mismatch",
        "endpoint_role_mismatch",
        "disabled_slot",
        "wrong_variant",
        "missing_structural_evidence",
        "configuration_identity_mismatch",
        "invalid_outer_hash",
    ],
)
def test_ca01_projection_rejects_noncanonical_three_slot_config(
    monkeypatch: pytest.MonkeyPatch,
    malformation: str,
) -> None:
    """復元器境界後に壊れたslot構造を受けても公開設定へ昇格しない。"""

    recovery = _recovery(ca01._REVIEWED_CA01_OUTER_SHA256)
    slots = recovery.config["slots"]
    endpoints = recovery.config["endpoints"]
    assert isinstance(slots, list)
    assert isinstance(endpoints, list)

    if malformation == "boolean_selector":
        slots[0]["transport_selector"] = True
    elif malformation == "transport_selector_mismatch":
        slots[2]["transport_selector"] = 0
    elif malformation == "wrong_slot_order":
        slots[0]["index"], slots[1]["index"] = 2, 1
    elif malformation == "wrong_role_order":
        slots[1]["role"] = "alternate"
    elif malformation == "missing_primary_duplicate":
        slots[1]["port"] = 448
    elif malformation == "alternate_duplicates_primary":
        slots[2]["port"] = 449
    elif malformation == "alternate_uses_different_host":
        slots[2]["host"] = "198.51.100.25"
        endpoints[1]["host"] = "198.51.100.25"
    elif malformation == "endpoint_projection_mismatch":
        endpoints.reverse()
    elif malformation == "duplicate_raw_endpoint":
        endpoints.append(dict(endpoints[0]))
    elif malformation == "endpoint_transport_mismatch":
        endpoints[1]["transport"] = "udp"
    elif malformation == "endpoint_role_mismatch":
        endpoints[1]["role"] = "primary"
    elif malformation == "disabled_slot":
        slots[2]["enabled"] = False
    elif malformation == "wrong_variant":
        recovery.config["variant"] = "unrelated"
    elif malformation == "missing_structural_evidence":
        recovery.structural_evidence.clear()
    elif malformation == "configuration_identity_mismatch":
        recovery.config["configuration_identity_sha256"] = "0" * 64
    elif malformation == "invalid_outer_hash":
        recovery = ca01.Ca01SideloadRecovery(
            outer_sha256="A" * 64,
            config=recovery.config,
            structural_evidence=recovery.structural_evidence,
        )
    else:  # pragma: no cover - parametrizationを増やす際のfail-closed保険
        pytest.fail(f"未処理の負例: {malformation}")

    monkeypatch.setattr(extractor, "recover_ca01_config", lambda _data: recovery)

    assert extractor._extract_ca01_sideload(b"MZ-malformed-ca01", "sample.dll") is None
