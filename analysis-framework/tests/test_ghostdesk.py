from __future__ import annotations

import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK = ROOT / "analysis-framework"
COMMON = FRAMEWORK / "common"
for trusted in (FRAMEWORK, COMMON):
    if str(trusted) not in sys.path:
        sys.path.insert(0, str(trusted))

import handler_evidence  # noqa: E402


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DETECT = load("analysis-framework/malware/ghostdesk/detect.py", "ghostdesk_detect_test")
EXTRACT = load("analysis-framework/malware/ghostdesk/extract_config.py", "ghostdesk_extract_test")
CONTRACT = load(
    "analysis-framework/common/analysis_contract.py",
    "ghostdesk_analysis_contract_test",
)


def _minimal_amd64_pe() -> bytearray:
    data = bytearray(0x200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, 0x8664)
    struct.pack_into("<H", data, 0x86, 3)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    return data


def _record(prefix: bytes, plaintext: bytes, key: int) -> bytes:
    assert len(plaintext) <= 255
    return prefix + bytes([len(plaintext)]) + bytes(value ^ key for value in plaintext)


def _sample(
    *,
    key: int = 0x5A,
    token_key: int | None = None,
    host: bytes = b"node.example:4444",
) -> tuple[bytes, bytes]:
    token = b"gd_" + b"a" * 40
    markers = (
        list(DETECT.IDENTITY_MARKERS)
        + list(DETECT.TRANSPORT_MARKERS)
        + list(DETECT.COMMAND_MARKERS)
        + list(DETECT.PERSISTENCE_MARKERS)
        + list(DETECT.WORKER_MARKERS)
        + list(EXTRACT.OPERATOR_COMMANDS)
        + list(EXTRACT.REALTIME_CONTROL_TYPES)
    )
    data = _minimal_amd64_pe()
    data.extend(b"\0".join(value.encode("ascii") if isinstance(value, str) else value for value in markers))
    data.extend(b"\0")
    data.extend(_record(EXTRACT.C2_RECORD_PREFIX, host, key))
    data.extend(b"\0" * 32)
    data.extend(
        _record(
            EXTRACT.TOKEN_RECORD_PREFIX,
            token,
            key if token_key is None else token_key,
        )
    )
    return bytes(data), token


def test_detector_requires_correlated_profile_and_unique_records() -> None:
    data, _ = _sample()
    result = DETECT.detect(data)
    assert result["matched"] is True
    assert result["observations"]["c2_record_count"] == 1
    assert result["observations"]["token_record_count"] == 1
    assert result["observations"]["unique_same_key_config_pair_decodable"] is True
    assert result["observations"]["sample_executed"] is False
    assert result["observations"]["network_contacted"] is False

    generic = _minimal_amd64_pe()
    generic.extend(b"WebSocket\0shell\0screenshot\0RuntimeBroker.exe")
    assert DETECT.detect(bytes(generic))["matched"] is False
    assert DETECT.detect(b"not-a-pe" + data)["matched"] is False


def test_extract_config_redacts_token_and_separates_listener() -> None:
    data, token = _sample()
    result = EXTRACT.extract_config(data)
    assert result["family"] == "ghostdesk"
    assert result["c2"] == result["config"]["endpoints"]
    assert result["c2"][0]["host"] == "node.example"
    assert result["c2"][0]["port"] == 4444
    assert result["c2"][0]["role"] == "configured_external_c2"
    assert result["projection_scope"] == "input_presence_only"
    assert "alternate_control_listener" not in result
    assert "network_flow" not in result
    token_record = result["configuration"]["records"]["token_record"]
    assert token_record["decoded_length"] == len(token)
    assert token_record["decoded_sha256"] == hashlib.sha256(token).hexdigest()
    assert token_record["raw_value_exported"] is False
    rendered = json.dumps(result, ensure_ascii=False)
    assert token.decode("ascii") not in rendered
    assert "/bot?token=<redacted>" in rendered
    assert result["sample_executed"] is False
    assert result["network_contacted"] is False
    assert result["decoded_config_recovered"] is True
    assert result["configuration"]["decoded_config_recovered"] is True
    assert result["config"]["decoded_config_recovered"] is True
    assert result["protocol"]["registration_type_marker_present"] is True
    quality = CONTRACT.handler_result_quality(
        result,
        minimum_score=EXTRACT.HANDLER_CONTRACT["minimum_evidence_score"],
    )
    assert quality["tier"] >= 4
    assert quality["score"] >= 40000
    assert quality["sufficient"] is True


def test_ghostdesk_strict_xor_config_is_one_confirmed_static_c2() -> None:
    """復号C2を1件に正規化し、token・接触・livenessを昇格しない。"""

    data, token = _sample()
    result = EXTRACT.extract_config(data)
    quality = CONTRACT.handler_result_quality(
        result,
        minimum_score=EXTRACT.HANDLER_CONTRACT["minimum_evidence_score"],
    )
    handler_id = "ghostdesk:extract_config.py:extract_config"
    records = handler_evidence.confirmed_static_handler_iocs(
        [
            (
                {
                    "handler_id": handler_id,
                    "status": "succeeded",
                    "selected_evidence": quality,
                },
                {
                    "handler": {"id": handler_id, "family": "ghostdesk"},
                    "result": result,
                    "selected_evidence": quality,
                    "executed_sample": False,
                    "network_contacted": False,
                },
            )
        ]
    )

    assert len(records) == 1
    assert records[0]["host"] == "node.example"
    assert records[0]["port"] == 4444
    assert records[0]["contacted"] is False
    assert records[0]["liveness_confirmed"] is False
    assert token.decode("ascii") not in json.dumps(records, ensure_ascii=False)


def test_reviewed_ghostdesk_protocol_is_static_confirmed_live_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """review済みsampleだけprotocolを確証し、live検証へは昇格しない。"""

    data, token = _sample()
    digest = hashlib.sha256(data).hexdigest()
    monkeypatch.setattr(EXTRACT, "REVIEWED_SHA256", digest)
    result = EXTRACT.extract_config(data)
    quality = CONTRACT.handler_result_quality(
        result,
        minimum_score=EXTRACT.HANDLER_CONTRACT["minimum_evidence_score"],
    )
    handler_id = "ghostdesk:extract_config.py:extract_config"
    pair = (
        {
            "handler_id": handler_id,
            "status": "succeeded",
            "selected_evidence": quality,
            "selected_layer_sha256": digest,
        },
        {
            "handler": {"id": handler_id, "family": "ghostdesk"},
            "result": result,
            "selected_evidence": quality,
            "executed_sample": False,
            "network_contacted": False,
        },
    )

    document = handler_evidence.build_communication_pattern_document(
        sha256=digest,
        family="ghostdesk",
        handler_results=[pair],
    )

    assert document["status"] == "confirmed_static_configuration_patterns"
    endpoints = document["communication"]["confirmed_static_c2_endpoints"]
    assert len(endpoints) == 1
    assert endpoints[0]["host"] == "node.example"
    assert endpoints[0]["port"] == 4444
    assert endpoints[0]["contacted"] is False
    assert endpoints[0]["liveness_confirmed"] is False
    assert document["communication"]["protocol_confirmed"] is True
    protocols = document["communication"]["protocol_evidence"]
    assert len(protocols) == 1
    assert protocols[0]["method"] == "websocket_ecdh_aes_gcm_json"
    assert protocols[0]["live_verified"] is False
    assert document["communication"]["liveness_confirmed"] is False
    assert document["safety"]["network_contacted"] is False
    assert token.decode("ascii") not in json.dumps(document, ensure_ascii=False)


def test_unreviewed_profile_is_presence_driven_without_case_projection() -> None:
    data, _ = _sample()
    result = EXTRACT.extract_config(data)
    assert result["command_dispatch"]["operator_commands_present"] == list(EXTRACT.OPERATOR_COMMANDS)
    assert "browser" not in result["command_dispatch"]["operator_commands_present"]
    assert "screenshot_ack" not in result["command_dispatch"]["operator_commands_present"]
    assert result["command_dispatch"]["realtime_control_types_present"] == list(EXTRACT.REALTIME_CONTROL_TYPES)
    assert result["command_dispatch"]["acknowledgement_types"] == []
    assert result["command_dispatch"]["parameter_fields"] == []
    assert result["process_behavior"]["fixed_process_templates"] == []
    assert result["persistence"]["write_paths_confirmed"] is False
    assert "run_key" not in result["persistence"]
    assert "reviewed_ghidra_evidence" not in result
    assert "self_installation" not in result
    assert result["embedded_decoy"]["gdpf_extraction_capability_present"] is False
    assert result["malicious_capabilities"]["reviewed_code_path_projection_applied"] is False


def test_reviewed_sha_projects_confirmed_case_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    data, _ = _sample()
    monkeypatch.setattr(EXTRACT, "REVIEWED_SHA256", hashlib.sha256(data).hexdigest())
    result = EXTRACT.extract_config(data)
    assert result["projection_scope"] == "confirmed_reviewed_sample"
    assert result["attribution"]["public_family_taxonomy_established"] is False
    assert result["alternate_control_listener"]["bind_address"] == "0.0.0.0"
    assert result["alternate_control_listener"]["port"] == 7788
    assert result["alternate_control_listener"]["outbound_c2"] is False
    assert result["alternate_control_listener"]["included_in_config_endpoints"] is False
    assert result["command_dispatch"]["parameter_fields"] == list(EXTRACT.PARAMETER_FIELDS)
    assert (
        result["protocol"]["registration"]["json_template"]
        == '{"t":"register","hwid":"%s","computer":"%s","username":"%s",'
        '"os":"%s","cpu":%d,"ram":%llu,"av":"%s","tz":"%s"}'
    )
    process_by_id = {item["id"]: item for item in result["process_behavior"]["fixed_process_templates"]}
    assert process_by_id["interactive_shell"]["command_line"] == "cmd.exe /K chcp 65001"
    assert process_by_id["delayed_self_delete"]["command_line_template"].startswith("cmd.exe /c ping -n 4")
    assert process_by_id["installed_copy"]["parent_process"] == "explorer.exe"
    assert process_by_id["installed_copy"]["preferred_creation_flags_hex"] == "0x08080000"
    assert "--remote-debugging-port=0" in process_by_id["chromium_hvnc"]["arguments_template"]
    assert result["persistence"]["service_entrypoint"]["service_installation_confirmed"] is False
    assert result["persistence"]["logon_script_value"]["evidence_level"] == "marker_only"
    assert result["persistence"]["logon_script_value"]["write_path_confirmed"] is False
    assert result["defense_evasion"]["defender_direct_write_path_confirmed"] is False
    assert result["defense_evasion"]["defender_changes_observed"] is False
    assert all(
        marker["call_path_confirmed"] is False for marker in result["defense_evasion"]["capability_markers"].values()
    )
    assert result["process_behavior"]["optional_gdpf_branch"]["taken_for_this_input"] is False


def test_command_names_require_complete_nul_terminated_literals() -> None:
    assert EXTRACT._present_names(b"\0shell_input\0ps_exec\0", ("shell", "exec")) == []
    assert EXTRACT._present_names(
        b'\0"shell"\0\0exec\0',
        ("shell", "exec"),
    ) == ["shell", "exec"]


def test_xor_inference_and_unique_pair_are_fail_closed() -> None:
    data, _ = _sample(key=0x31)
    assert EXTRACT.extract_config(data)["configuration"]["xor_key_hex"] == "0x31"

    mismatched, _ = _sample(key=0x31, token_key=0x32)
    assert DETECT.detect(mismatched)["matched"] is False
    with pytest.raises(ValueError, match="一意に復号"):
        EXTRACT.extract_config(mismatched)

    duplicate, _ = _sample()
    duplicate += _record(EXTRACT.C2_RECORD_PREFIX, b"second.example:443", 0x5A)
    with pytest.raises(ValueError, match="一意ではありません"):
        EXTRACT.extract_config(duplicate)

    local_host, _ = _sample(host=b"127.0.0.1:4444")
    with pytest.raises(ValueError, match="一意に復号"):
        EXTRACT.extract_config(local_host)


def test_gdpf_is_optional_validated_and_never_written(monkeypatch: pytest.MonkeyPatch) -> None:
    data, _ = _sample()
    monkeypatch.setattr(EXTRACT, "REVIEWED_SHA256", hashlib.sha256(data).hexdigest())
    absent = EXTRACT.extract_config(data)["embedded_decoy"]
    assert absent["gdpf_extraction_capability_present"] is True
    assert absent["embedded_payload_present"] is False
    assert absent["artifact_written_or_opened_by_this_handler"] is False
    assert absent["pe_overlay"]["ends_with_gdpf"] is False

    payload = b"%PDF-1.7\n" + b"A" * 128
    wrapped = data + payload + len(payload).to_bytes(4, "little") + b"GDPF"
    monkeypatch.setattr(EXTRACT, "REVIEWED_SHA256", hashlib.sha256(wrapped).hexdigest())
    present = EXTRACT.extract_config(wrapped)["embedded_decoy"]
    assert present["embedded_payload_present"] is True
    assert present["pdf_signature_present"] is True
    assert present["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert present["payload_bytes_exported"] is False
    assert present["pe_overlay"]["ends_with_gdpf"] is True

    malformed = data + (len(data) + 1).to_bytes(4, "little") + b"GDPF"
    with pytest.raises(ValueError, match="GDPF footer"):
        EXTRACT.extract_config(malformed)


def test_oversized_and_incomplete_inputs_are_rejected() -> None:
    oversized = b"MZ" + b"\0" * (EXTRACT.MAX_INPUT_BYTES - 1)
    assert len(oversized) == EXTRACT.MAX_INPUT_BYTES + 1
    assert DETECT.detect(oversized)["matched"] is False
    with pytest.raises(ValueError, match="上限"):
        EXTRACT.extract_config(oversized)

    data, _ = _sample()
    token_offset = data.index(EXTRACT.TOKEN_RECORD_PREFIX)
    missing_token = data[:token_offset]
    with pytest.raises(ValueError, match="一意ではありません"):
        EXTRACT.extract_config(missing_token)


def test_registry_and_handler_contract_enable_automatic_routing() -> None:
    registry = json.loads((FRAMEWORK / "registry" / "malware_types.json").read_text(encoding="utf-8-sig"))[
        "malware_types"
    ]
    assert registry["ghostdesk"]["detector"] == "malware/ghostdesk/detect.py"
    assert (
        "b01168b6a5517bc4491a2f0420def87e8ad4267c3662c498016eca1e37dca80a"
        in registry["ghostdesk"]["known_sample_sha256"]
    )
    assert EXTRACT.HANDLER_CONTRACT == {
        "input_formats": ["pe"],
        "minimum_evidence_score": 40000,
    }
    policies = json.loads(
        (FRAMEWORK / "registry" / "family_analysis_requirements.json").read_text(encoding="utf-8-sig")
    )["policies"]
    assert policies["ghostdesk"] == {
        "category": "rat",
        "config_required": True,
        "network_required": True,
        "terminal_payload_required": False,
    }
