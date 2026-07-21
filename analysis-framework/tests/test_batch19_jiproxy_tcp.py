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


def test_status_request_and_detector_agree_offline() -> None:
    emulator = load("analysis-framework/malware/jiproxy_relay/tcp_emulator.py", "jiproxy_tcp_emulator")
    detector = load("analysis-framework/malware/jiproxy_relay/tcp_network_detector.py", "jiproxy_tcp_detector")
    request = emulator.build_status_request(42)
    result = detector.inspect_http(request)
    assert result["matched"] is True
    assert result["indicators"]["integer_connections"] is True
    assert result["network_contacted"] is False


def test_tcp_extractor_rejects_unreviewed_hash() -> None:
    module = load("analysis-framework/malware/jiproxy_relay/tcp_variant.py", "jiproxy_tcp_config")
    with pytest.raises(ValueError, match="SHA-256"):
        module.extract_config(b"synthetic")
