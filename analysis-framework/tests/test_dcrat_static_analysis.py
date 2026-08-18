from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
for candidate in (REPOSITORY, COMMON):
    if str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))

analyze_sample = importlib.import_module("analyze_sample")
analysis_contract = importlib.import_module("analysis_contract")
case_automation = importlib.import_module("automated_case_analysis")
config_recovery = importlib.import_module("dotnet_rat_config")
protocol_recovery = importlib.import_module("dotnet_rat_protocol_evidence")
integrated = importlib.import_module("extractors.dcrat.integrated")

REVIEWED_SHA256 = "85cd6c3229f9ab547cc54f2cbdcf6ef2937987c0181e5ffa3c4205105df8e8fe"
FIXTURE_SALT = b"fixture-dcrat-static-salt"


def _encrypt(value: str, master_key: str) -> str:
    material = hashlib.pbkdf2_hmac("sha1", master_key.encode(), FIXTURE_SALT, 50_000, 96)
    encryption_key, authentication_key = material[:32], material[32:]
    iv = bytes(range(16))
    padder = PKCS7(128).padder()
    padded = padder.update(value.encode()) + padder.finalize()
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    body = iv + ciphertext
    mac = hmac.new(authentication_key, body, hashlib.sha256).digest()
    return base64.b64encode(mac + body).decode()


def _settings_literals() -> dict[str, str]:
    profile = config_recovery.PROFILES["dcrat"]
    names = profile["fields"]
    master_key = "fixture-master-key"
    plain = {
        "ports": "5552",
        "hosts": "c2.example.test,",
        "version": "1.0.7",
        "install": "true",
        "pastebin": "null",
        "anti": "false",
        "group": "Default",
        "certificate": base64.b64encode(b"fixture-certificate").decode(),
    }
    values = {"Key": base64.b64encode(master_key.encode()).decode()}
    values.update({names[key]: _encrypt(value, master_key) for key, value in plain.items()})
    return values


def _protocol_records() -> list[dict[str, object]]:
    profile = protocol_recovery.FAMILY_PROFILES["dcrat"]
    return [
        {
            "token": "0x06000054",
            "owner": profile["registration_method"][0],
            "name": profile["registration_method"][1],
            "literals": list(profile["required_registration_fields"]),
            "path_keys": list(profile["required_registration_fields"]),
            "calls": ["ForcePathObject"],
            "cil_semantic_sha256": "1" * 64,
        },
        {
            "token": "0x06000023",
            "owner": profile["dispatcher_method"][0],
            "name": profile["dispatcher_method"][1],
            "literals": list(profile["command_markers"]),
            "path_keys": [],
            "calls": [],
            "cil_semantic_sha256": "2" * 64,
        },
        {
            "token": "0x06000021",
            "owner": profile["heartbeat_method"][0],
            "name": profile["heartbeat_method"][1],
            "literals": [profile["packet_key"], "Ping", "Message"],
            "path_keys": [],
            "calls": ["GetActiveWindowTitle", "Encode2Bytes", "Send"],
            "cil_semantic_sha256": "3" * 64,
        },
    ]


_STRUCTURAL_SALT = bytes.fromhex("4463526174427971777164616e6368756e")


def _structural_fixture() -> bytes:
    markers = [
        b"MZ",
        b"BSJB",
        b"Por_ts",
        b"Hos_ts",
        b"Ver_sion",
        b"In_stall",
        b"Certifi_cate",
        b"Pac_ket",
        b"Po_ng",
        b"plu_gin",
        b"save_Plugin",
        _STRUCTURAL_SALT,
    ]
    return b"\x00".join(markers)


def test_dcrat_config_uses_static_initializer_salt_without_publishing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config_recovery, "settings_literals", lambda *_args: _settings_literals())
    monkeypatch.setattr(config_recovery, "static_salt", lambda *_args: FIXTURE_SALT)

    result = config_recovery.recover(b"fixture-managed-client", "dcrat")

    assert result["config_endpoints"] == [{"host": "c2.example.test", "port": 5552}]
    assert result["version"] == "1.0.7"
    assert result["crypto_profile"]["salt_source"] == "reviewed_static_initializer"
    assert result["crypto_profile"]["salt_published"] is False
    assert FIXTURE_SALT.hex() not in repr(result)
    assert result["secret_fields_published"] is False


def test_dcrat_protocol_schema_is_complete_and_bounded() -> None:
    result = protocol_recovery.summarize_records(_protocol_records(), "dcrat", "a" * 64)

    assert result["analysis_status"] == "complete"
    assert result["registration"]["missing_required_fields"] == []
    assert result["dispatcher"]["missing_command_markers"] == []
    assert result["dispatcher"]["heartbeat_response_markers"] == ["Po_ng"]
    assert result["emulator_readiness"]["registration_schema_confirmed"] is True
    assert result["emulator_readiness"]["live_operation_fake_result_allowed"] is False


def test_dcrat_structural_route_requires_settings_protocol_and_crypto() -> None:
    data = _structural_fixture()
    assert integrated.structural_evidence(data)["matched"] is True
    assert integrated.structural_evidence(data.replace(b"save_Plugin", b"missing"))["matched"] is False
    assert integrated.structural_evidence(data.replace(_STRUCTURAL_SALT, b"missing"))["matched"] is False


def test_handler_result_reaches_validated_static_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        integrated,
        "_validated_recovery",
        lambda _data: {
            "version": "1.0.7",
            "install": True,
            "group": "Default",
            "anti_analysis": False,
            "endpoints": [{"host": "c2.example.test", "port": 5552}],
            "dynamic_config_url": None,
            "certificate": {
                "sha256": "9" * 64,
                "size": 564,
                "certificate_mismatch_excludes_c2": False,
            },
            "crypto_profile": {
                "salt_source": "reviewed_static_initializer",
                "salt_published": False,
            },
        },
    )
    monkeypatch.setattr(
        integrated,
        "_validated_protocol",
        lambda _data, _digest: {
            "analysis_status": "complete",
            "registration": {"required_fields": ["Pac_ket", "HWID"]},
        },
    )

    result = integrated.extract(_structural_fixture(), "fixture.exe")
    quality = analysis_contract.handler_result_quality(result, 20_000)

    assert result["config"]["recovery_status"] == "recovered_hmac_and_protocol_verified"
    assert quality["tier"] == 3
    assert quality["sufficient"] is True
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_exact_review_has_meaningful_functions_and_program_inventory() -> None:
    functions = integrated._reviewed_functions(REVIEWED_SHA256)
    programs = integrated._program_evidence(REVIEWED_SHA256)

    assert len(functions) == 14
    assert {item["role"] for item in functions} >= {
        "command_control",
        "config_authentication",
        "config_decoder",
        "defense_evasion",
        "persistence",
        "plugin_loader",
    }
    assert all(item["logic_steps_ja"] for item in functions)
    assert all(item["summary_ja"] for item in functions)
    assert programs[0]["managed_method_count"] == 194
    assert programs[0]["retrieval_coverage"] == {
        "managed_methods_declared": 194,
        "managed_methods_with_body": 175,
        "managed_methods_without_body": 19,
        "malformed_method_bodies": 0,
        "ghidra_native_decompilation_used_for_cil_semantics": False,
    }


def test_analyze_sample_collects_handler_program_evidence(tmp_path: Path) -> None:
    handler_dir = tmp_path / "handlers"
    handler_dir.mkdir()
    artifact = handler_dir / "result.json"
    artifact.write_text(
        json.dumps({"result": {"program_evidence": [{"managed_method_count": 194}]}}),
        encoding="utf-8",
    )

    records = analyze_sample._handler_static_logic_program_evidence(
        tmp_path,
        [{"status": "succeeded", "result": "handlers/result.json"}],
    )

    assert records == [{"managed_method_count": 194}]

def test_static_protocol_is_confirmed_without_live_overpromotion() -> None:
    handler_id = "dcrat:extractors.dcrat.extractor.py:extract"
    protocol = {
        "schema_version": 1,
        "family": "dcrat",
        "sample_sha256": "a" * 64,
        "analysis_status": "complete",
        "registration": {
            "method": "Client.Helper.IdSender.SendInfo",
            "missing_required_fields": [],
        },
        "dispatcher": {
            "method": "Client.Connection.ClientSocket.Read",
            "missing_command_markers": [],
            "observed_command_markers": ["Po_ng", "plu_gin", "save_Plugin"],
            "file_or_plugin_transfer_markers": ["plu_gin", "save_Plugin"],
            "heartbeat_response_markers": ["Po_ng"],
            "heartbeat_request": {
                "method": "Client.Connection.ClientSocket.KeepAlivePacket",
                "schema_confirmed": True,
            },
        },
        "emulator_readiness": {
            "registration_schema_confirmed": True,
            "command_dispatcher_confirmed": True,
            "heartbeat_request_response_confirmed": True,
            "live_operation_fake_result_allowed": False,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_cil_published": False,
            "unreviewed_literals_published": False,
        },
    }
    result = {
        "family": "dcrat",
        "sample_sha256": "a" * 64,
        "config": {"static_config_recovered": True, "terminal_managed_client": True},
        "static_config_recovered": True,
        "config_endpoints": [
            {
                "host": "c2.example.test",
                "port": 5552,
                "transport": "tls",
                "role": "configured_c2",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "hmac_verified_dotnet_settings",
                    "all_expected_fields_validated": True,
                },
            }
        ],
        "static_evidence": {"all_expected_fields_validated": True},
        "protocol_evidence": protocol,
        "static_protocol": {
            "status": "confirmed",
            "method": "managed_cil_tls_le32_messagepack",
            "transport": "tls",
            "framing": "little_endian_uint32_length_prefix",
            "serialization": "messagepack",
            "confidence": "high",
            "tcp_open_only": False,
            "live_verified": False,
        },
    }
    execution = {
        "handler_id": handler_id,
        "status": "succeeded",
        "selected_evidence": {"sufficient": True},
    }
    artifact = {
        "handler": {"id": handler_id},
        "result": result,
        "selected_evidence": {"sufficient": True},
        "executed_sample": False,
        "network_contacted": False,
    }

    patterns, contract = case_automation.build_case_automation_artifacts(
        sha256="a" * 64,
        family="dcrat",
        layer_report={"counts": {"recovered_layers": 0}},
        handler_results=[(execution, artifact)],
    )
    phases = {item["phase"]: item for item in contract["phase_evidence"]}

    assert len(patterns["communication"]["confirmed_static_endpoints"]) == 1
    assert patterns["communication"]["candidate_patterns"] == []
    assert patterns["communication"]["protocol_confirmed"] is True
    assert patterns["communication"]["liveness_confirmed"] is False
    assert patterns["config"]["terminal_managed_client"] is True
    assert phases["terminal_payload_analysis"]["status"] == "completed"
    assert phases["c2_protocol_analysis"]["status"] == "completed"
    assert contract["terminal_payload"]["reached"] is True
    assert contract["c2"]["outcome"] == "unresolved"
    assert contract["c2"]["protocol"] == {
        "status": "static_confirmed_live_unverified",
        "method": "managed_cil_tls_le32_messagepack",
        "confidence": "high",
        "tcp_open_only": False,
        "static_hints": ["managed_cil_tls_le32_messagepack", "tls"],
        "live_verified": False,
    }
    assert contract["c2"]["live_check"] == {
        "status": "pending",
        "target_registered": False,
    }
