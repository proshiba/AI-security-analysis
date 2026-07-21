"""200検体目標の補充分とNullnet PPC資材を回帰検証する。"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SHA256 = "f7fc5c3daba8d328b54ee98c69b1e28c78a7f3d7c25485db40f85b6fd49071b2"
HTA_SHA256 = "3dfe67edf7c21e9c73e8e0368d3afcbb6fd50ccf25cc93dab9c2775e03d97ab3"


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_ppc_sockaddr_instruction_extractor_recovers_reviewed_fallback() -> None:
    module = load("nullnet_ppc_extract", "analysis-framework/malware/mirai/nullnet_ppc.py")
    sequence = bytes.fromhex(
        "3d401001" "38000002" "3d60d920" "390a0350" "b00a0350"
        "616bb811" "38000050" "91680004" "3d201001" "b0080002"
    )
    result = module.extract_fallback_sockaddr(b"prefix" + sequence + b"suffix")
    assert result == {
        "host": "217.32.184.17",
        "port": 80,
        "role": "c2_fallback",
        "source": "PPC mainのsockaddr即値構築命令列",
    }


def test_nullnet_static_detector_requires_architecture_and_multiple_anchors() -> None:
    module = load("nullnet_static_detect", "analysis-framework/malware/mirai/nullnet_detect.py")
    header = b"\x7fELF\x01\x02" + b"\x00" * 12 + b"\x00\x14"
    data = header + b"\x00".join(module.ANCHORS[:4])
    result = module.detect(data)
    assert result["matched"] is True
    assert result["architecture_match"] is True
    assert result["confidence"] == "high_static_correlation"


def test_nullnet_network_detector_separates_candidate_and_protocol_confirmation() -> None:
    module = load("nullnet_network_detect", "analysis-framework/malware/mirai/nullnet_network_detector.py")
    assert module.detect([{"host": "example.invalid", "port": 1420}])["matched"] is False
    candidate = module.detect([{"host": "botnet.b5m.co.uk", "port": 1420}])
    assert candidate["matched"] is True
    assert candidate["c2_confirmed"] is False
    correlated = module.detect([
        {"host": "botnet.b5m.co.uk", "port": 1420},
        {
            "event": "c2_frame",
            "length_prefix": "uint16_be",
            "maximum_length": 0x400,
            "parser_validated": True,
        },
    ])
    assert correlated["protocol_correlated"] is True
    assert correlated["c2_confirmed"] is True


def test_nullnet_emulator_round_trip_is_non_networking() -> None:
    module = load("nullnet_emulator", "analysis-framework/malware/mirai/nullnet_emulator.py")
    frame = module.build_command(
        duration=60,
        vector=4,
        targets=[("192.0.2.10", 32)],
        options=[(1, b"review")],
    )
    parsed = module.parse_command(frame)
    assert parsed["duration"] == 60
    assert parsed["vector"] == 4
    assert parsed["targets"] == [{"address": "192.0.2.10", "prefix": 32}]
    assert parsed["options"] == [{"key": 1, "value_hex": "726576696577"}]
    assert parsed["network_contacted"] is False
    assert parsed["attack_executed"] is False
    with pytest.raises(ValueError):
        module.parse_command(frame[:-1])


def test_recovered_hta_profile_and_case_are_published() -> None:
    module = load(
        "recovered_hta_profile",
        "analysis-framework/malware/windows_script_stager/javascript_unicode_separator_stager.py",
    )
    profile = module.PROFILES[HTA_SHA256]
    assert profile["url"].endswith("/mHmNJ")
    assert profile["argument_variable"] == "moonbat"
    case = (
        ROOT / "analysis-results/malware/windows-script-stager/versions"
        / "2026-07-javascript-unicode-separator/cases" / HTA_SHA256
    )
    config = json.loads((case / "config.json").read_text(encoding="utf-8"))
    assert config["powershell"]["fragment_count"] == 18
    assert config["reflection"]["argument_count"] == 19


def test_supplement_publication_and_safety_boundary() -> None:
    research = ROOT / "analysis-results/research/malwarebazaar/supplements/supplement-0001"
    case = ROOT / "analysis-results/malware/mirai/versions/unknown/cases" / SHA256
    for name in (
        "README.md", "STATIC-ANALYSIS.md", "OSINT.md", "manifest.json",
        "classification.json", "c2-targets.json", "c2-validation.json", "shodan-hunt.json",
    ):
        assert (research / name).is_file()
    for name in ("README.md", "metadata.json", "config.json", "iocs.json", "IOC-LIST.md"):
        assert (case / name).is_file()

    validation = json.loads((research / "c2-validation.json").read_text(encoding="utf-8"))
    policy = validation["policy"]
    assert policy["tcp_connect_only"] is True
    assert policy["maximum_response_bytes"] == 0
    for key in ("application_data_sent", "server_data_read", "tls_handshake", "banner_read", "port_scanning"):
        assert policy[key] is False
    assert len(validation["results"]) == 3
    assert all(item["c2_confirmed"] is False for item in validation["results"])
    assert all(item["application_data_sent"] is False for item in validation["results"])
    assert all(item["server_data_read"] is False for item in validation["results"])


def test_supplement_json_and_yara_assets_are_valid_at_rest() -> None:
    roots = [
        ROOT / "analysis-results/research/malwarebazaar/supplements/supplement-0001",
        ROOT / "analysis-results/malware/mirai/versions/unknown/cases" / SHA256,
        ROOT / "analysis-results/collections/malwarebazaar-supplement-0001",
    ]
    for root in roots:
        for path in root.glob("*.json"):
            json.loads(path.read_text(encoding="utf-8"))
    rule = (ROOT / "analysis-framework/malware/mirai/rules/nullnet_ppc.yar").read_text(encoding="utf-8")
    assert "botnet.b5m.co.uk" in rule
    assert "POST /ctrlt/DeviceUpgrade_1" in rule
