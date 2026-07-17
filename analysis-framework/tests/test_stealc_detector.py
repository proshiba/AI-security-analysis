"""Tests for the StealC detector wrapper."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def test_detector_uses_structural_extraction(monkeypatch) -> None:
    path = Path(__file__).parents[1] / "malware" / "stealc" / "detect.py"
    spec = importlib.util.spec_from_file_location("stealc_detect", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "extract", lambda _data, _name: {"config": {"profile": {"c2_url": "http://example/gate.php"}}})
    result = module.detect(b"MZ" + bytes(100), Path("fixture.exe"))
    assert result["matched"] is True
    assert result["observations"]["network_contacted"] is False


def test_detector_skips_large_unmarked_inputs(monkeypatch) -> None:
    """Do not apply quadratic legacy decoding to unrelated large PEs."""
    path = Path(__file__).parents[1] / "malware" / "stealc" / "detect.py"
    spec = importlib.util.spec_from_file_location("stealc_large_detect", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "extract", lambda *_: (_ for _ in ()).throw(AssertionError("unexpected deep scan")))
    result = module.detect(b"MZgetprocaddress hwid build" + bytes(module.MAX_UNMARKED_DEEP_SCAN_BYTES), Path("large.exe"))
    assert result["matched"] is False
    assert result["observations"]["deep_scan"] == "skipped_large_unmarked_input"
