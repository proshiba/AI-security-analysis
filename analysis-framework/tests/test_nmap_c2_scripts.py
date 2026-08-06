from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil

import pytest


FRAMEWORK = Path(__file__).resolve().parents[1]
NMAP_ROOT = FRAMEWORK / "nmap"
CENTRAL_PROFILES = FRAMEWORK / "common" / "c2_protocol_probe_profiles.json"


def _load_validator():
    path = NMAP_ROOT / "verify_nse.py"
    spec = importlib.util.spec_from_file_location("nmap_verify_nse", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _nmap_executable() -> str | None:
    local = Path(r"C:\Users\Administrator\Tools\Nmap\nmap.exe")
    if local.is_file():
        return str(local)
    return shutil.which("nmap")


def test_profiles_cover_reviewed_active_families() -> None:
    mapping = json.loads((NMAP_ROOT / "profiles.json").read_text(encoding="utf-8"))
    central = json.loads(CENTRAL_PROFILES.read_text(encoding="utf-8"))
    mapped = {entry["family"] for entry in mapping["canonical_families"]}
    reviewed = {entry["family"] for entry in central["profiles"]}
    assert reviewed <= mapped
    assert "purehvnc" in mapped
    assert len(mapped) == 8


def test_all_declared_scripts_exist_and_are_utf8() -> None:
    mapping = json.loads((NMAP_ROOT / "profiles.json").read_text(encoding="utf-8"))
    scripts = {entry["script"] for entry in mapping["canonical_families"]}
    assert len(scripts) == 5
    for relative in scripts:
        path = NMAP_ROOT / relative
        assert path.is_file()
        text = path.read_text(encoding="utf-8")
        assert "categories" in text
        assert "c2_confirmed" in text


def test_nmap_loopback_protocol_validation() -> None:
    executable = _nmap_executable()
    if not executable:
        pytest.skip("Nmap executableがないためloopback統合試験を省略します")
    report = _load_validator().verify_all(executable)
    assert report["external_network_used"] is False
    assert report["case_count"] == 10
    assert report["passed_count"] == 10
