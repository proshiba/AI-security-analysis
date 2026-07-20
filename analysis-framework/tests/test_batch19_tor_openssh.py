from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_offline_forwarding_model_contains_no_network_action() -> None:
    module = load("analysis-framework/malware/tor_openssh_backdoor/emulator.py", "tor_backdoor_emulator")
    result = module.resolve_forwarding(13893)
    assert result["target_port"] == 3389
    assert result["network_enabled"] is False


def test_detector_requires_compound_event_evidence() -> None:
    module = load("analysis-framework/malware/tor_openssh_backdoor/network_detector.py", "tor_backdoor_detector")
    event = {
        "host": module.ONION_HOST,
        "path": "/Ozb",
        "proxy": "127.0.0.1:9050",
        "process": "unrealengine.exe",
    }
    assert module.inspect_event(event)["matched"] is True
    assert module.inspect_event({"host": module.ONION_HOST})["matched"] is False


def test_bundle_verifier_rejects_missing_files(tmp_path: Path) -> None:
    module = load("analysis-framework/malware/tor_openssh_backdoor/extract_config.py", "tor_backdoor_config")
    with pytest.raises(ValueError, match="ありません"):
        module.extract_config(tmp_path)
