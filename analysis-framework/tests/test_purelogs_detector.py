from __future__ import annotations

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "analysis-framework" / "malware" / "purelogs" / "detect.py"
REGISTRY_PATH = ROOT / "analysis-framework" / "registry" / "malware_types.json"
KNOWN_HASHES = {
    "070181f442b486e6bc3192434f99c19bff30441fdc069a2274987d742178c2ec",
    "0cf715d47bf25c5ca920110d091807c3fddb2bc14b45701fd2b36648e5463826",
    "247ccd7c34e6600d90b6e6d5dc82858fcf369da21d9a323db52a37ade981c62c",
    "3f95a86fb5a628574736c53ce3d4b54a9e039caae220c64b55f03d9490fffb9e",
    "4eac222c9b28ad1fcb44fe3a15a228632cce94333d6ca132f8e156d09adb8677",
}


def load_detector():
    spec = importlib.util.spec_from_file_location("purelogs_detect", DETECTOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_detector_requires_correlated_static_anchors() -> None:
    detector = load_detector()
    assert detector.detect(b"MZ generic /plugin")["matched"] is False
    result = detector.detect(
        b"MZ /plugin /userinfo /filesearch/req /finish unrelated.example"
    )
    assert result["matched"] is True
    assert result["sample_executed"] is False
    assert result["network_contacted"] is False


def test_registry_contains_reviewed_daily_hashes() -> None:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))["malware_types"]
    entry = registry["purelogs"]
    assert entry["detector"] == "malware/purelogs/detect.py"
    assert set(entry["known_sample_sha256"]) >= KNOWN_HASHES