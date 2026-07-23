"""Gh0st RATの受動検出器と非通信エミュレータのテスト。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "analysis-framework" / "malware" / "gh0strat"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DETECTOR = _load("gh0strat_c2_detector", BASE / "c2_detector.py")
EMULATOR = _load("gh0strat_emulator", BASE / "emulator.py")


def test_hunt_requires_profile_correlation_and_does_not_scan() -> None:
    assert DETECTOR.build_hunt({"network_candidates": ["node.example.org:443"]})["targets"] == []
    result = DETECTOR.build_hunt(
        {
            "profile_literal_correlation": True,
            "network_candidates": ["node.example.org:443"],
        }
    )
    assert result["targets"][0]["shodan_query"] == "hostname:node.example.org port:443"
    assert result["active_scan_performed"] is False
    assert result["network_contacted"] is False


def test_passive_detector_requires_endpoint_hash_and_frame() -> None:
    digest = "a" * 64
    config = {
        "profile_literal_correlation": True,
        "network_candidates": ["node.example.org:443"],
        "corroborated_sample_sha256": [digest],
    }
    event = {
        "host": "node.example.org",
        "port": 443,
        "process_sha256": digest,
        "first_five_bytes_hex": b"Gh0st".hex(),
        "packet_total_size": 128,
        "uncompressed_size": 256,
    }
    result = DETECTOR.detect([event], config)
    assert result["matched"] is True
    assert result["c2_confirmed"] is True
    assert result["network_contacted"] is False
    assert DETECTOR.detect([{**event, "process_sha256": "b" * 64}], config)["matched"] is False
    assert DETECTOR.detect([{**event, "packet_total_size": 1}], config)["matched"] is False


def test_emulator_generates_no_traffic_or_commands() -> None:
    result = EMULATOR.emulate({"network_candidates": ["node.example.org:443"]})
    assert result["packets_generated"] == 0
    assert result["commands_generated"] == 0
    assert result["network_contacted"] is False
    assert result["malware_protocol_compatible"] is False


def test_registry_does_not_promote_source_reported_hashes() -> None:
    registry = json.loads(
        (ROOT / "analysis-framework" / "registry" / "malware_types.json").read_text(
            encoding="utf-8-sig"
        )
    )
    entry = registry["malware_types"]["gh0strat"]
    assert entry["detector"] == "malware/gh0strat/detect.py"
    assert entry["known_sample_sha256"] == []
