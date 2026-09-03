from __future__ import annotations

import importlib
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

DETECT = importlib.import_module("malware.sliver.detect")
EXTRACT = importlib.import_module("malware.sliver.extract_config")
CONTRACT = importlib.import_module("analysis_contract")
HANDLER_CATALOG = importlib.import_module("handler_catalog")


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


def _sample(
    *,
    omit_cluster: str | None = None,
    include_go: bool = True,
    build_version: bytes = b"unknown",
    concatenate_markers: bool = False,
) -> bytes:
    data = _minimal_amd64_pe()
    if include_go:
        data.extend(DETECT.GO_BUILD_INFO_MAGIC)
        data.extend(bytes((8, 2)))
        data.extend(b"\0" * 16)
        data.extend(bytes((len(build_version),)))
        data.extend(build_version)
        data.extend(b"\0")
        data.extend(b"runtime.buildVersion\0")
    data.extend(b"github.com/bishopfox/sliver/protobuf/sliverpb\0")
    for name, markers in DETECT.PROTOBUF_CLUSTERS.items():
        if name == omit_cluster:
            continue
        separator = b"" if concatenate_markers else b"\0"
        data.extend(separator.join(marker.encode("ascii") for marker in markers))
        data.extend(b"\0")
    return bytes(data)


def test_detector_requires_all_independent_clusters_and_go_pe_structure() -> None:
    result = DETECT.detect(_sample())
    assert result["matched"] is True
    observations = result["observations"]
    assert observations["pe"]["amd64_pe32_plus"] is True
    assert observations["go"]["structure_confirmed"] is True
    assert observations["go"]["version_status"] == "unknown_linker_value"
    assert observations["complete_cluster_count"] == 8
    assert observations["required_cluster_count"] == 8
    assert observations["sample_executed"] is False
    assert observations["network_contacted"] is False
    assert result["campaigns"][0]["artifact_role"] == "server_operator_or_implant_role_unresolved"
    assert result["campaigns"][0]["malicious_use_confirmed"] is False


def test_detector_rejects_single_marker_go_only_and_missing_cluster() -> None:
    generic = _minimal_amd64_pe()
    generic.extend(DETECT.GO_BUILD_INFO_MAGIC)
    generic.extend(bytes((8, 2)) + b"\0" * 16 + b"\x08go1.24.3\0runtime.main\0BeaconRegister\0")
    assert DETECT.detect(bytes(generic), Path("sliver.exe"))["matched"] is False
    assert DETECT.detect(_sample(omit_cluster="pivot"))["matched"] is False
    assert DETECT.detect(_sample(include_go=False))["matched"] is False


def test_detector_requires_amd64_pe32_plus() -> None:
    data = bytearray(_sample())
    struct.pack_into("<H", data, 0x84, 0x14C)
    struct.pack_into("<H", data, 0x98, 0x10B)
    assert DETECT.detect(bytes(data))["matched"] is False
    assert DETECT.detect(b"not-a-pe" + _sample())["matched"] is False


def test_detector_supports_go_concatenated_string_table() -> None:
    result = DETECT.detect(_sample(concatenate_markers=True))
    assert result["matched"] is True
    assert result["observations"]["complete_cluster_count"] == 8


def test_go_build_info_rejects_arbitrary_version_record() -> None:
    assert DETECT.detect(_sample(build_version=b"not-go"))["matched"] is False


def test_extractor_reports_capabilities_without_inventing_runtime_values() -> None:
    result = EXTRACT.extract_config(_sample())
    assert result["family"] == "sliver"
    assert result["classification"] == "sliver_framework_binary"
    assert result["artifact_role"] == "sliver_framework_binary"
    assert result["role_resolution"] == {
        "status": "server_operator_or_implant_role_unresolved",
        "implant_compatible": True,
        "implant_role_confirmed": False,
        "server_or_operator_role_confirmed": False,
        "reason_ja": (
            "共有protobuf型はserver、operator client、implantの複数roleへ組み込まれ得るため、"
            "message名の共起だけでは実行roleを確定しない"
        ),
    }
    assert result["dual_use_context"]["operator_intent"] == "not_established"
    assert result["dual_use_context"]["malicious_use_confirmed"] is False
    assert len(result["capabilities"]) == 8
    assert all(item["runtime_invocation_observed"] is False for item in result["capabilities"])

    command_names = {item["protobuf_message"] for item in result["commands"]}
    assert {
        "BeaconTasks",
        "ExecuteAssemblyReq",
        "InvokeExecuteAssemblyReq",
        "ExecWasmExtensionReq",
        "RegisterWasmExtensionReq",
        "PivotPeerEnvelope",
        "WGSocksStartReq",
        "WGSocksStopReq",
        "MemfilesListReq",
        "MemfilesAddReq",
        "MemfilesRmReq",
        "ProcessDumpReq",
        "SpawnDllReq",
        "ShellReq",
    } == command_names
    assert all(item["command_received_or_executed"] is False for item in result["commands"])
    assert all(item["arguments_recovered"] is False for item in result["commands"])


def test_extractor_keeps_c2_and_registration_runtime_values_unresolved() -> None:
    result = EXTRACT.extract_config(_sample())
    assert result["c2"] == []
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["config_endpoints"] == []
    evidence = result["config"]["static_evidence"]
    assert evidence["endpoint_recovery_status"] == "not_recovered"
    assert evidence["active_c2_value_recovered"] is False
    assert evidence["proxy_url_value_recovered"] is False
    assert evidence["config_id_value_recovered"] is False

    protocol = result["protocol_schema"]
    assert protocol["envelope"]["reference_schema_fields"] == [
        "ID",
        "Type",
        "Data",
        "UnknownMessageType",
    ]
    assert protocol["envelope"]["runtime_field_values_recovered"] is False
    assert protocol["beacon_registration"]["runtime_registration_values_recovered"] is False
    assert protocol["transport"] == "not_resolved"
    assert protocol["runtime_message_observed"] is False
    assert result["static_protocol"]["status"] == "schema_markers_only"
    assert "protocol_evidence" not in result
    assert result["sample_executed"] is False
    assert result["executed_sample"] is False
    assert result["network_contacted"] is False
    assert result["safety"]["raw_secret_exported"] is False
    assert result["safety"]["runtime_values_invented"] is False


def test_handler_result_is_structural_tier_and_sufficient() -> None:
    result = EXTRACT.extract_config(_sample())
    quality = CONTRACT.handler_result_quality(
        result,
        minimum_score=EXTRACT.HANDLER_CONTRACT["minimum_evidence_score"],
    )
    assert quality["tier"] == 2
    assert quality["tier_name"] == "structural_corroboration"
    assert quality["score"] >= 20000
    assert quality["sufficient"] is True


def test_extractor_and_detector_fail_closed_on_incomplete_or_oversized_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="複数構造相関"):
        EXTRACT.extract_config(_sample(omit_cluster="memory_files"))

    monkeypatch.setattr(DETECT, "MAX_INPUT_BYTES", 128)
    monkeypatch.setattr(EXTRACT, "MAX_INPUT_BYTES", 128)
    oversized = b"MZ" + b"\0" * 127
    assert len(oversized) == 129
    detector_result = DETECT.detect(oversized)
    assert detector_result["matched"] is False
    assert detector_result["observations"]["input_within_limit"] is False
    with pytest.raises(ValueError, match="上限"):
        EXTRACT.extract_config(oversized)


def test_output_is_deterministic_and_json_serializable() -> None:
    first = EXTRACT.extract_config(_sample())
    second = EXTRACT.extract_config(_sample())
    assert first == second
    assert json.loads(json.dumps(first, ensure_ascii=False))["family"] == "sliver"


def test_registry_and_family_requirements_enable_automatic_routing() -> None:
    registry = json.loads((FRAMEWORK / "registry" / "malware_types.json").read_text(encoding="utf-8-sig"))[
        "malware_types"
    ]
    assert registry["sliver"] == {
        "description": (
            "AMD64 Go PEと8系統の独立protobuf messageクラスタを相関して識別する"
            "Sliver framework binary（実行role・悪性意図は未確定）"
        ),
        "detector": "malware/sliver/detect.py",
    }
    policies = json.loads(
        (FRAMEWORK / "registry" / "family_analysis_requirements.json").read_text(encoding="utf-8-sig")
    )["policies"]
    assert policies["sliver"] == {
        "category": "other",
        "config_required": True,
        "network_required": True,
        "terminal_payload_required": False,
    }
    assert EXTRACT.HANDLER_CONTRACT == {
        "input_formats": ["pe"],
        "minimum_evidence_score": 20000,
    }

    handlers = [
        item
        for item in HANDLER_CATALOG.discover_handlers()
        if item.family == "sliver" and item.relative_path == "analysis-framework/malware/sliver/extract_config.py"
    ]
    assert len(handlers) == 1
    assert handlers[0].automatic is True
    assert handlers[0].input_formats == ("pe",)
    assert handlers[0].input_contract_source == "module_declaration"
    assert handlers[0].minimum_evidence_score == 20000
    handler, invocation = HANDLER_CATALOG.load_handler(handlers[0])
    assert invocation == "bytes"
    assert handler(_sample())["classification"] == "sliver_framework_binary"
