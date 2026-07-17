"""Tests for conservative Amadey and Latrodectus family detectors."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import runpy

ROOT = Path(__file__).parents[1] / "malware"


def test_detectors_reject_generic_pe() -> None:
    """Do not attribute generic PE-like bytes to either recent family."""
    for family in ("amadey", "latrodectus"):
        module = runpy.run_path(str(ROOT / family / "detect.py"))
        result = module["detect"](b"MZ" + bytes(1024), Path("generic.exe"))
        assert not result["matched"]
        assert result["observations"]["executed"] is False


def test_latrodectus_detector_uses_config_recovery(monkeypatch) -> None:
    """Attribute Latrodectus only after its characteristic config is decoded."""
    path = ROOT / "latrodectus" / "detect.py"
    spec = importlib.util.spec_from_file_location("latrodectus_config_detect", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(
        module,
        "recover_config",
        lambda _data: {
            "profile": "latrodectus_legacy_prng_strings",
            "version": "1.9.1",
            "group_id": 123,
        },
    )
    result = module.detect(b"MZ" + bytes(32), Path("fixture.dll"))
    assert result["matched"] is True
    assert result["campaigns"][0]["confidence"] == "high"
