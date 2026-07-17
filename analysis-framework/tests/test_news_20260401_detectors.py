"""Regression tests for the 2026-04-01 campaign detectors."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).parents[1] / "malware"


def load_module(name: str, path: Path):
    """Load one standalone detector module from its repository path."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_npm_and_atlascross_marker_clusters() -> None:
    """Require complete npm or multiple AtlasCross-specific markers."""
    npm = load_module("npm_news_detect", ROOT / "npm_supply_chain" / "detect.py")
    atlas = load_module("atlas_news_detect", ROOT / "atlascross" / "detect.py")
    npm_result = npm.detect(b"OrDeR_7077 6202033 _trans_2 package.md", Path("setup.js"))
    atlas_result = atlas.detect(b"AtlasInfo AtlasPro.ini", Path("sample.dll"))
    assert npm_result["matched"] and npm_result["campaigns"][0]["confidence"] == "medium"
    assert atlas_result["matched"] and atlas_result["campaigns"][0]["confidence"] == "medium"
    assert not npm.detect(b"generic package.md", Path("x.js"))["matched"]
    assert not atlas.detect(b"AtlasInfo", Path("x.dll"))["matched"]


def test_valleyrat_does_not_attribute_generic_pe() -> None:
    """Prevent the prior false positive where every PE matched ValleyRAT."""
    valley = load_module("valley_news_detect", ROOT / "valleyrat" / "detect.py")
    result = valley.detect(b"MZ" + b"\0" * 1024, Path("benign.exe"))
    assert result["matched"] is False
    assert result["campaigns"] == []


def test_shadowpad_detector_requires_exact_hash_or_decoded_config() -> None:
    """Match a structurally decoded config and reject a generic PE without one."""
    shadowpad = load_module("shadowpad_detect", ROOT / "shadowpad" / "detect.py")

    shadowpad.extract = lambda _data, _name: {
        "findings": [
            {
                "value": "https://goods.kankuedu.org",
                "role": "shadowpad_config_network",
                "confidence": "confirmed",
            }
        ],
        "config": {"legacy_payload_count": 1, "scatterbee_payload_count": 0},
    }
    result = shadowpad.detect(b"MZtosbtkbd.dll" + b"\0" * 128, Path("decoded.exe"))
    assert result["matched"] is True
    assert result["campaigns"][0]["campaign_type"] == "casper_goods_kankuedu"

    shadowpad.extract = lambda _data, _name: {
        "findings": [],
        "config": {"legacy_payload_count": 0, "scatterbee_payload_count": 0},
    }
    generic = shadowpad.detect(b"MZ" + b"\0" * 128, Path("generic.exe"))
    assert generic["matched"] is False
    assert generic["campaigns"] == []


def test_shadowpad_detector_skips_large_unmarked_inputs() -> None:
    """Avoid an expensive byte-by-byte config scan of unrelated large PEs."""
    shadowpad = load_module("shadowpad_large_detect", ROOT / "shadowpad" / "detect.py")

    def unexpected_extract(_data: bytes, _name: str) -> dict:
        raise AssertionError("large unmarked input should not be deep-scanned")

    shadowpad.extract = unexpected_extract
    result = shadowpad.detect(b"MZ" + b"\0" * 8_000_001, Path("large.exe"))
    assert result["matched"] is False
    assert result["observations"]["deep_scan"] == "skipped_unmarked_input"
