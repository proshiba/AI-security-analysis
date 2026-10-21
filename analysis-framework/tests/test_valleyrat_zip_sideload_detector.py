"""ZIP side-load終端とraw vvaS候補のdetector境界を検証する。"""

from __future__ import annotations

import importlib.util
import io
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"


def _load_detector():
    spec = importlib.util.spec_from_file_location("valleyrat_zip_lineage_detect", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _zip_fixture() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("host.exe", b"MZ-host")
        archive.writestr("proxy.dll", b"MZ-proxy")
        archive.writestr("carrier.dat", b"carrier")
    return stream.getvalue()


def _terminal_probe() -> dict[str, object]:
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "zip_sideload_shellcode_vvas_terminal",
        "supports_family_attribution": True,
        "terminal_family_confirmed": True,
        "attribution_scope": "validated_terminal_component_structure",
        "static_config_recovered": True,
        "evidence": {
            "source_transform_sink_lineage": True,
            "raw_network_values_included": False,
        },
        "config": {
            "endpoint_count": 1,
            "raw_network_values_included": False,
        },
    }


def _route_probe() -> dict[str, object]:
    return {
        "matched": True,
        "family": None,
        "variant": "zip_sideload_uniform_xor_vvas_command_c2_candidate",
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "attribution_scope": "component_handler_route",
        "static_config_recovered": False,
        "candidate_config_recovered": True,
        "used_for_family_resolution": False,
        "used_for_c2_confirmation": False,
        "command_c2_confirmed": False,
        "final_rat_confirmed": False,
        "c2_liveness_confirmed": False,
        "evidence": {
            "status": "validated_zip_sideload_command_c2_route_candidate",
            "lineage_profile": "sideload_loader_uniform_xor_route_candidate",
            "source_transform_sink_lineage": False,
            "sibling_import_export_edge": True,
            "loader_exact_key_uniform_xor_injection_path": True,
            "carrier_file_read_handoff_confirmed": False,
            "vvas_transport_shellcode_candidate": True,
            "missing_proof_codes": [
                "zip_loader_carrier_file_read_dataflow_unproven"
            ],
            "configuration_identity_included": False,
            "component_hashes_included": False,
            "member_names_included": False,
            "raw_payload_included": False,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "config": {
            "endpoint_count": 1,
            "endpoint_role": "command_c2_candidate",
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "endpoints": ["198.51.100.27:443"],
        "c2_candidates": [
            {
                "endpoint": "198.51.100.27:443",
                "role": "command_c2_candidate",
                "contacted": False,
                "liveness_confirmed": False,
                "qualified": False,
            }
        ],
        "sample_executed": False,
        "network_contacted": False,
    }


def test_zip_terminal_campaign_supports_family_without_raw_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector = _load_detector()
    members = [
        SimpleNamespace(name="host.exe", data=b"MZ-host"),
        SimpleNamespace(name="proxy.dll", data=b"MZ-proxy"),
        SimpleNamespace(name="carrier.dat", data=b"carrier"),
    ]
    monkeypatch.setattr(detector, "read_aes_zip_members", lambda *_args, **_kwargs: members)
    monkeypatch.setattr(detector, "probe_zip_sideload_shellcode", lambda _data: _terminal_probe())

    observations, campaigns = detector.inspect_zip(_zip_fixture())

    assert campaigns == [
        {
            "campaign_type": "zip_sideload_shellcode_vvas_terminal",
            "confidence": "high",
            "reasons": campaigns[0]["reasons"],
            "attribution_scope": "validated_terminal_component_structure",
            "supports_family_attribution": True,
            "terminal_family_confirmed": True,
        }
    ]
    assert observations["zip_sideload_shellcode_terminal"]["config"] == {
        "endpoint_count": 1,
        "raw_network_values_included": False,
    }


def test_zip_direct_xor_route_is_not_family_or_qualified_c2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector = _load_detector()
    members = [
        SimpleNamespace(name="host.exe", data=b"MZ-host"),
        SimpleNamespace(name="loader.dll", data=b"MZ-loader"),
        SimpleNamespace(name="carrier.bin", data=b"carrier"),
    ]
    monkeypatch.setattr(detector, "read_aes_zip_members", lambda *_args, **_kwargs: members)
    monkeypatch.setattr(detector, "probe_zip_sideload_shellcode", lambda _data: _route_probe())

    observations, campaigns = detector.inspect_zip(_zip_fixture())

    assert len(campaigns) == 1
    campaign = campaigns[0]
    assert campaign["campaign_type"] == (
        "zip_sideload_uniform_xor_vvas_command_c2_candidate"
    )
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False
    assert campaign["command_c2_confirmed"] is False
    assert campaign["final_rat_confirmed"] is False
    assert "zip_sideload_shellcode_terminal" not in observations
    route = observations["zip_sideload_command_c2_candidate"]
    assert route["used_for_family_resolution"] is False
    assert route["used_for_c2_confirmation"] is False
    assert route["config"]["endpoint_role"] == "command_c2_candidate"
    assert route["c2_candidates"] == _route_probe()["c2_candidates"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("static_config_recovered", True),
        ("supports_family_attribution", True),
        ("terminal_family_confirmed", True),
        ("used_for_c2_confirmation", True),
    ],
)
def test_zip_route_rejects_confirmation_flag_escalation(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: bool,
) -> None:
    detector = _load_detector()
    members = [
        SimpleNamespace(name="host.exe", data=b"MZ-host"),
        SimpleNamespace(name="loader.dll", data=b"MZ-loader"),
        SimpleNamespace(name="carrier.bin", data=b"carrier"),
    ]
    probe = _route_probe()
    probe[field] = value
    monkeypatch.setattr(detector, "read_aes_zip_members", lambda *_args, **_kwargs: members)
    monkeypatch.setattr(detector, "probe_zip_sideload_shellcode", lambda _data: probe)

    observations, campaigns = detector.inspect_zip(_zip_fixture())

    assert "zip_sideload_command_c2_candidate" not in observations
    assert all(
        item.get("campaign_type")
        != "zip_sideload_uniform_xor_vvas_command_c2_candidate"
        for item in campaigns
    )


def test_raw_shellcode_detector_remains_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector = _load_detector()
    raw = b"raw-vvas-transport-fixture"
    monkeypatch.setattr(detector, "_terminal_configuration_detection", lambda *_args: None)
    monkeypatch.setattr(
        detector,
        "probe_raw_vvas_shellcode",
        lambda _data: {
            "matched": True,
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "evidence": {"raw_network_values_included": False},
            "config": {"endpoint_count": 1, "raw_network_values_included": False},
        },
    )

    result = detector.detect(raw, Path("anonymous.bin"))

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "raw_vvas_codemark_transport_candidate"
    assert campaign["terminal_family_confirmed"] is False
    assert campaign["supports_family_attribution"] is False
