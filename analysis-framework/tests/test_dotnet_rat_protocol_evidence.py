from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "common" / "dotnet_rat_protocol_evidence.py"
)
SPEC = importlib.util.spec_from_file_location("dotnet_rat_protocol_evidence", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _records(
    family: str,
    *,
    missing_field: str | None = None,
    missing_heartbeat_literal: str | None = None,
) -> list[dict]:
    profile = MODULE.FAMILY_PROFILES[family]
    fields = [
        value
        for value in profile["required_registration_fields"]
        if value != missing_field
    ]
    return [
        {
            "token": "0x06000001",
            "owner": profile["registration_method"][0],
            "name": profile["registration_method"][1],
            "literals": [*fields, "秘密の未review文字列"],
            "path_keys": fields,
            "calls": ["ForcePathObject"],
            "cil_semantic_sha256": "1" * 64,
        },
        {
            "token": "0x06000002",
            "owner": profile["dispatcher_method"][0],
            "name": profile["dispatcher_method"][1],
            "literals": [*profile["command_markers"], "秘密のoperator値"],
            "path_keys": [],
            "calls": [],
            "cil_semantic_sha256": "2" * 64,
        },
        {
            "token": "0x06000003",
            "owner": profile["heartbeat_method"][0],
            "name": profile["heartbeat_method"][1],
            "literals": [
                value
                for value in (profile["packet_key"], "Ping", "Message")
                if value != missing_heartbeat_literal
            ],
            "path_keys": [],
            "calls": ["GetActiveWindowTitle", "Encode2Bytes", "Send"],
            "cil_semantic_sha256": "3" * 64,
        },
    ]


@pytest.mark.parametrize("family", ["asyncrat", "venomrat"])
def test_complete_exact_schema_without_unreviewed_literal_leak(family: str) -> None:
    result = MODULE.summarize_records(_records(family), family, "a" * 64)
    assert result["analysis_status"] == "complete"
    assert result["registration"]["missing_required_fields"] == []
    assert result["dispatcher"]["missing_command_markers"] == []
    assert result["dispatcher"]["heartbeat_request"] == {
        "method": "Client.Connection.ClientSocket.KeepAlivePacket",
        "method_token": "0x06000003",
        "cil_semantic_sha256": "3" * 64,
        "packet_key": MODULE.FAMILY_PROFILES[family]["packet_key"],
        "packet_value": "Ping",
        "message_key": "Message",
        "message_source": "active_window_title",
        "emulator_message_value": "",
        "sanitized_for_privacy": True,
        "schema_confirmed": True,
    }
    assert result["dispatcher"]["heartbeat_response_markers"] == list(
        MODULE.FAMILY_PROFILES[family]["heartbeat_response_markers"]
    )
    assert result["emulator_readiness"]["heartbeat_request_response_confirmed"] is True
    assert "heartbeat_reply_only" not in result["emulator_readiness"]
    assert result["emulator_readiness"]["live_operation_fake_result_allowed"] is False
    assert "秘密の未review文字列" not in repr(result)
    assert "秘密のoperator値" not in repr(result)


def test_missing_registration_field_is_partial_and_fail_closed() -> None:
    result = MODULE.summarize_records(
        _records("asyncrat", missing_field="HWID"), "asyncrat", "b" * 64
    )
    assert result["analysis_status"] == "partial"
    assert result["registration"]["missing_required_fields"] == ["HWID"]
    assert result["emulator_readiness"]["registration_schema_confirmed"] is False


def test_missing_keepalive_marker_is_partial_and_fail_closed() -> None:
    result = MODULE.summarize_records(
        _records("asyncrat", missing_heartbeat_literal="Message"),
        "asyncrat",
        "b" * 64,
    )
    assert result["analysis_status"] == "partial"
    assert result["dispatcher"]["heartbeat_request"]["schema_confirmed"] is False
    assert result["emulator_readiness"]["heartbeat_request_response_confirmed"] is False


def test_missing_review_method_is_rejected() -> None:
    with pytest.raises(MODULE.ProtocolEvidenceError, match="review対象method"):
        MODULE.summarize_records([], "asyncrat", "c" * 64)


def test_invalid_family_and_hash_are_rejected() -> None:
    with pytest.raises(MODULE.ProtocolEvidenceError, match="未対応family"):
        MODULE.summarize_records(_records("asyncrat"), "unknown", "d" * 64)
    with pytest.raises(MODULE.ProtocolEvidenceError, match="SHA-256"):
        MODULE.summarize_records(_records("asyncrat"), "asyncrat", "bad")
