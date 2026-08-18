from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
for candidate in (REPOSITORY, COMMON):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

analysis_contract = importlib.import_module("analysis_contract")
integrated = importlib.import_module("extractors.asyncrat.integrated")
protocol = importlib.import_module("dotnet_rat_protocol_evidence")
DETECT_SPEC = importlib.util.spec_from_file_location(
    "asyncrat_detect_for_test",
    REPOSITORY / "analysis-framework" / "malware" / "asyncrat" / "detect.py",
)
assert DETECT_SPEC and DETECT_SPEC.loader
detector = importlib.util.module_from_spec(DETECT_SPEC)
DETECT_SPEC.loader.exec_module(detector)

REVIEWED_SHA256 = "ff8235089a02e71d422a0c227f177f14052b58d1558324a6001ded65418bb498"


def _structural_fixture() -> bytes:
    return b"\x00".join(
        [
            b"MZ",
            b"BSJB",
            *(value.encode() for value in sorted(integrated._SETTINGS)),
            *(value.encode() for value in sorted(integrated._PROTOCOL)),
        ]
    )


def test_structural_route_requires_settings_and_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    complete = {
        "settings_fields": sorted(integrated._SETTINGS),
        "settings_fields_complete": True,
        "missing_types": [],
        "missing_methods": {},
        "methods_complete": True,
    }
    monkeypatch.setattr(integrated, "_managed_structure", lambda _data: complete)
    data = _structural_fixture()
    assert integrated.structural_evidence(data)["matched"] is True
    assert integrated.structural_evidence(data.replace(b"savePlugin", b"missing"))["matched"] is False
    incomplete = {**complete, "settings_fields_complete": False}
    monkeypatch.setattr(integrated, "_managed_structure", lambda _data: incomplete)
    assert integrated.structural_evidence(data)["matched"] is False


def test_handler_result_reaches_validated_static_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integrated,
        "_managed_structure",
        lambda _data: {
            "settings_fields": sorted(integrated._SETTINGS),
            "settings_fields_complete": True,
            "missing_types": [],
            "missing_methods": {},
            "methods_complete": True,
        },
    )
    monkeypatch.setattr(
        integrated,
        "_validated_recovery",
        lambda _data: {
            "version": "0.5.8",
            "install": "true",
            "group": "Default",
            "anti_analysis": "false",
            "endpoints": [{"host": "c2.example.test", "port": 443}],
            "dynamic_config_present": False,
            "certificate": {
                "sha256": "9" * 64,
                "size": 1_270,
                "certificate_mismatch_excludes_c2": False,
            },
            "crypto_profile": {
                "salt_source": "reviewed_family_profile",
                "salt_published": False,
            },
        },
    )
    monkeypatch.setattr(
        integrated,
        "_validated_protocol",
        lambda _data, _digest: {
            "analysis_status": "complete",
            "registration": {"missing_required_fields": []},
            "dispatcher": {"missing_command_markers": []},
        },
    )
    monkeypatch.setattr(integrated, "_managed_inventory", lambda *_args: [])

    result = integrated.extract(_structural_fixture(), "fixture.exe")
    quality = analysis_contract.handler_result_quality(result, 20_000)

    assert result["config"]["recovery_status"] == "recovered_hmac_and_protocol_verified"
    assert result["config_endpoints"] == [
        {
            "host": "c2.example.test",
            "port": 443,
            "transport": "tls",
            "role": "configured_c2",
            "confidence": "confirmed_static_configuration",
            "evidence": {
                "kind": "hmac_verified_dotnet_settings",
                "all_expected_fields_validated": True,
            },
        }
    ]
    assert quality["tier"] == 3
    assert quality["sufficient"] is True
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_exact_review_has_meaningful_functions() -> None:
    functions = integrated._reviewed_functions(REVIEWED_SHA256)
    assert len(functions) == 12
    assert {item["role"] for item in functions} >= {
        "command_control",
        "config_authentication",
        "config_decoder",
        "defense_evasion",
        "persistence",
        "plugin_loader",
    }
    assert all(item["logic_steps_ja"] for item in functions)
    assert all(item["program_selector"] == f"sha256:{REVIEWED_SHA256}" for item in functions)


def test_unreviewed_hash_does_not_receive_reviewed_function_claims() -> None:
    assert integrated._reviewed_functions("a" * 64) == []


def test_async_protocol_accepts_variant_without_optional_winupdate() -> None:
    profile = protocol.FAMILY_PROFILES["asyncrat"]
    records = [
        {
            "token": "0x06000001",
            "owner": profile["registration_method"][0],
            "name": profile["registration_method"][1],
            "literals": list(profile["required_registration_fields"]),
            "path_keys": list(profile["required_registration_fields"]),
            "calls": [],
            "cil_semantic_sha256": "1" * 64,
        },
        {
            "token": "0x06000002",
            "owner": profile["dispatcher_method"][0],
            "name": profile["dispatcher_method"][1],
            "literals": list(profile["command_markers"]),
            "path_keys": [],
            "calls": [],
            "cil_semantic_sha256": "2" * 64,
        },
        {
            "token": "0x06000003",
            "owner": profile["heartbeat_method"][0],
            "name": profile["heartbeat_method"][1],
            "literals": ["Packet", "Ping", "Message"],
            "path_keys": [],
            "calls": ["GetActiveWindowTitle", "Encode2Bytes", "Send"],
            "cil_semantic_sha256": "3" * 64,
        },
    ]
    result = protocol.summarize_records(records, "asyncrat", "a" * 64)
    assert result["analysis_status"] == "complete"
    assert result["dispatcher"]["observed_optional_command_markers"] == []


def test_detector_routes_reviewed_managed_structure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        detector,
        "structural_evidence",
        lambda _data: {"matched": True, "rule": "fixture"},
    )
    result = detector.detect(b"fixture", Path("fixture.exe"))
    assert result["matched"] is True
    assert result["observations"]["family"] == "asyncrat"
    assert result["campaigns"][0]["confidence"] == "high"
    assert result["observations"]["executed"] is False
    assert result["observations"]["network_contacted"] is False


def test_detector_falls_back_without_managed_structure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        detector,
        "structural_evidence",
        lambda _data: {"matched": False, "rule": "fixture"},
    )
    monkeypatch.setattr(detector, "detect_family", lambda *_args: {"matched": False, "observations": {}})
    result = detector.detect(b"fixture", Path("fixture.exe"))
    assert result["matched"] is False
    assert result["observations"]["reviewed_managed_structure"]["matched"] is False
