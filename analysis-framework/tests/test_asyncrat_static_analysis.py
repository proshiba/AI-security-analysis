from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

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


def test_structural_route_accepts_strict_obfuscated_config_protocol_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integrated,
        "_managed_structure",
        lambda _data: {
            "settings_fields": [],
            "settings_fields_complete": False,
            "missing_types": ["Client.Settings"],
            "missing_methods": {},
            "methods_complete": False,
        },
    )
    monkeypatch.setattr(
        integrated,
        "_validated_recovery",
        lambda _data: {"config_mode": "chacha20_obfuscated_v058"},
    )
    monkeypatch.setattr(
        integrated,
        "_validated_protocol",
        lambda _data, _digest: {
            "protocol_variant": "compact_v058_chacha20"
        },
    )

    result = integrated.structural_evidence(b"MZ\0BSJB\0obfuscated")

    assert result["matched"] is True
    assert result["obfuscated_profile_confirmed"] is True
    assert result["rule"] == "asyncrat_obfuscated_chacha20_compact_v058"


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
            "config_mode": "hmac_encrypted",
            "version": "0.5.8",
            "install": "true",
            "group": "Default",
            "anti_analysis": "false",
            "endpoints": [{"host": "c2.example.test", "port": 443}],
            "dynamic_config_present": False,
            "certificate": {
                "sha256": "9" * 64,
                "size": 1_270,
                "validation": "embedded_certificate_present",
                "certificate_mismatch_excludes_c2": False,
            },
            "crypto_profile": {
                "salt_source": "reviewed_family_profile",
                "salt_published": False,
            },
            "static_shape_evidence": None,
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


def test_plaintext_handler_result_preserves_accept_all_tls_evidence(
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
            "config_mode": "plaintext_static_v057b",
            "version": "0.5.7B",
            "install": "false",
            "group": "Debug",
            "anti_analysis": "false",
            "endpoints": [{"host": "c2.example.test", "port": 443}],
            "dynamic_config_present": False,
            "certificate": {
                "sha256": None,
                "size": None,
                "validation": "accept_all",
                "certificate_mismatch_excludes_c2": False,
            },
            "crypto_profile": {
                "settings_storage": "plaintext",
                "salt_source": "not_applicable",
                "salt_published": False,
            },
            "static_shape_evidence": {
                "settings_initializer": "trivial_return_true",
                "tls_certificate_validation": "accept_all",
                "placeholder_fields_validated": True,
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

    assert result["config"]["recovery_status"] == "recovered_plaintext_and_protocol_verified"
    assert result["config_endpoints"][0]["evidence"]["kind"] == "reviewed_plaintext_dotnet_settings"
    assert result["static_evidence"]["config_mode"] == "plaintext_static_v057b"
    assert result["static_evidence"]["authentication"] == "not_applicable"
    assert result["static_evidence"]["tls_certificate_validation"] == "accept_all"
    assert all(item["kind"] != "certificate.sha256" for item in result["findings"])


def test_obfuscated_chacha_handler_recovers_after_name_based_route_miss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integrated,
        "structural_evidence",
        lambda _data: {
            "matched": False,
            "managed_pe": True,
            "rule": "name_based_rule_missed",
        },
    )
    monkeypatch.setattr(
        integrated,
        "_validated_recovery",
        lambda _data: {
            "config_mode": "chacha20_obfuscated_v058",
            "version": "0.5.8",
            "install": "false",
            "group": "Default",
            "anti_analysis": "false",
            "endpoints": [{"host": "c2.example.test", "port": 1533}],
            "dynamic_config_present": False,
            "certificate": {
                "sha256": "8" * 64,
                "size": 1_252,
                "validation": "embedded_certificate_present",
                "certificate_mismatch_excludes_c2": False,
            },
            "crypto_profile": {
                "settings_storage": "encrypted",
                "key_derivation": "reviewed_xor_add_32_byte_mixing",
                "authentication": "none_per_setting",
                "cipher": "ChaCha20-IETF",
                "nonce_size": 12,
                "initial_counter": 1,
                "salt_source": "not_applicable",
                "salt_published": False,
            },
            "static_shape_evidence": {"chacha_core_token": "0x0600007d"},
        },
    )
    monkeypatch.setattr(
        integrated,
        "_validated_protocol",
        lambda _data, _digest: {
            "analysis_status": "complete",
            "protocol_variant": "compact_v058_chacha20",
        },
    )
    monkeypatch.setattr(integrated, "_managed_inventory", lambda *_args: [])

    result = integrated.extract(b"MZ\0BSJB\0fixture", "fixture.exe")

    assert result["config"]["recovery_status"] == (
        "recovered_chacha20_and_protocol_verified"
    )
    assert result["config"]["structural_assessment"]["matched"] is True
    assert result["config"]["structural_assessment"][
        "obfuscated_profile_confirmed"
    ] is True
    assert result["config_endpoints"][0]["evidence"]["kind"] == (
        "reviewed_chacha20_dotnet_settings"
    )
    assert result["static_evidence"]["authentication"] == "none_per_setting"
    assert result["static_evidence"]["decryption"] == "chacha20_ietf"


def test_protocol_rejection_does_not_publish_recovered_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integrated,
        "structural_evidence",
        lambda _data: {"matched": True, "managed_pe": True, "rule": "fixture"},
    )
    monkeypatch.setattr(
        integrated,
        "_validated_recovery",
        lambda _data: {
            "config_mode": "hmac_encrypted",
            "endpoints": [{"host": "c2.example.test", "port": 443}],
            "certificate": {
                "sha256": "8" * 64,
                "validation": "embedded_certificate_present",
            },
        },
    )

    def reject_protocol(*_args: object) -> dict[str, object]:
        raise ValueError("raw parser detail")

    monkeypatch.setattr(integrated, "_validated_protocol", reject_protocol)

    result = integrated.extract(b"MZ\0BSJB\0fixture", "fixture.exe")

    assert result["static_config_recovered"] is False
    assert result["config_endpoints"] == []
    assert result["protocol_evidence"] is None
    assert result["config"]["recovery_status"] == "rejected_or_not_recovered"
    assert result["config"]["recovery_diagnostics"] == {
        "stage": "protocol_evidence",
        "error_type": "ValueError",
        "exception_message_published": False,
    }
    assert "raw parser detail" not in repr(result)


def test_plaintext_recovery_miss_uses_mode_specific_structural_rule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integrated,
        "structural_evidence",
        lambda _data: {"matched": False, "managed_pe": True, "rule": "name_miss"},
    )
    monkeypatch.setattr(
        integrated,
        "_validated_recovery",
        lambda _data: {
            "config_mode": "plaintext_static_v057b",
            "version": "0.5.7B",
            "install": "false",
            "group": "Debug",
            "anti_analysis": "false",
            "endpoints": [{"host": "c2.example.test", "port": 443}],
            "dynamic_config_present": False,
            "certificate": {"sha256": None, "validation": "accept_all"},
            "crypto_profile": {},
            "static_shape_evidence": {},
        },
    )
    monkeypatch.setattr(
        integrated,
        "_validated_protocol",
        lambda *_args: {"analysis_status": "complete"},
    )
    monkeypatch.setattr(integrated, "_managed_inventory", lambda *_args: [])
    monkeypatch.setattr(
        integrated, "_reviewed_functions", lambda *_args, **_kwargs: []
    )

    result = integrated.extract(b"MZ\0BSJB\0fixture", "fixture.exe")
    evidence = result["config"]["structural_assessment"]

    assert evidence["matched"] is True
    assert evidence["recovered_profile_confirmed"] is True
    assert evidence["plaintext_profile_confirmed"] is True
    assert "obfuscated_profile_confirmed" not in evidence
    assert evidence["rule"] == "asyncrat_plaintext_v057b_protocol_verified"


def test_managed_inventory_records_unrelated_malformed_body_without_losing_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    method = SimpleNamespace(Rva=1, Name="Main")
    metadata = SimpleNamespace(
        MethodDef=SimpleNamespace(rows=[method]),
        TypeDef=SimpleNamespace(rows=[SimpleNamespace()]),
    )
    pe = SimpleNamespace(net=SimpleNamespace(mdtables=metadata))
    monkeypatch.setattr(integrated.dnfile, "dnPE", lambda **_kwargs: pe)
    monkeypatch.setattr(
        integrated,
        "_read_bounded_method_body",
        lambda *_args: (_ for _ in ()).throw(ValueError("malformed")),
    )

    result = integrated._managed_inventory(b"MZfixture", "a" * 64)
    coverage = result[0]["retrieval_coverage"]

    assert coverage["malformed_method_bodies"] == 1
    assert coverage["inventory_complete"] is False
    assert result[0]["confidence"] == "partial_program_structure_inventory"


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


def test_chacha_review_requires_exact_hash_mode_and_data(monkeypatch) -> None:
    expected = [{"role": "config_decoder"}]
    monkeypatch.setattr(
        integrated,
        "_reviewed_chacha_functions",
        lambda _digest, _data: expected,
    )

    assert (
        integrated._reviewed_functions(
            integrated._CHACHA_REVIEWED_SHA256,
            data=b"managed-fixture",
            config_mode="chacha20_obfuscated_v058",
        )
        is expected
    )
    assert (
        integrated._reviewed_functions(
            integrated._CHACHA_REVIEWED_SHA256,
            data=b"managed-fixture",
            config_mode="hmac_encrypted",
        )
        == []
    )


def test_plaintext_profile_receives_mode_specific_function_claims(monkeypatch) -> None:
    monkeypatch.setattr(integrated, "_plaintext_v057b_profile_matches", lambda _data: True)

    functions = integrated._reviewed_functions(
        "a" * 64,
        data=b"managed-fixture",
        config_mode="plaintext_static_v057b",
    )

    assert len(functions) == 12
    assert all(item["confidence"] == "confirmed_static_profile_match" for item in functions)
    initialize = next(item for item in functions if item["name"] == "Client.Settings.InitializeSettings")
    assert initialize["callees"] == []
    assert initialize["api_calls"] == []
    assert "追加復号を行わず" in initialize["summary_ja"]
    connection = next(item for item in functions if item["name"].endswith("InitializeClient"))
    assert "常にtrueを返す検証callback" in connection["logic_steps_ja"][1]


def test_plaintext_profile_requires_exact_structural_match(monkeypatch) -> None:
    monkeypatch.setattr(integrated, "_plaintext_v057b_profile_matches", lambda _data: False)

    assert (
        integrated._reviewed_functions(
            "a" * 64,
            data=b"managed-fixture",
            config_mode="plaintext_static_v057b",
        )
        == []
    )


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
