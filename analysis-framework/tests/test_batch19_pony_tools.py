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


def test_emulator_and_detector_round_trip_without_network() -> None:
    emulator = load("analysis-framework/malware/pony/emulator.py", "pony_emulator")
    detector = load("analysis-framework/malware/pony/network_detector.py", "pony_detector")
    request = emulator.build_post_request(
        b"SYNTHETIC",
        host=detector.CAMPAIGN_HOST,
        path=detector.CAMPAIGN_PATH,
    )
    result = detector.detect_request(request)
    assert result["detected"] is True
    assert result["confidence"] == "high"
    assert result["campaign_host_match"] is True
    assert result["campaign_path_match"] is True
    assert result["content_length_valid"] is True
    assert result["body_decrypted"] is False
    assert result["network_contacted"] is False


def test_detector_rejects_plain_http_post() -> None:
    detector = load("analysis-framework/malware/pony/network_detector.py", "pony_detector_plain")
    request = b"POST /upload HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 0\r\n\r\n"
    result = detector.detect_request(request)
    assert result["detected"] is False
    assert result["campaign_host_match"] is False


def test_emulator_uses_inert_default_and_validates_inputs() -> None:
    emulator = load("analysis-framework/malware/pony/emulator.py", "pony_emulator_safe")
    request = emulator.build_post_request()
    assert b"Host: pony-sink.invalid\r\n" in request
    assert b"giftorcharden" not in request
    assert emulator.build_success_response().endswith(b"STATUS-IMPORT-OK")
    with pytest.raises(ValueError, match="host"):
        emulator.build_post_request(host="bad\r\nhost")


def test_extractors_fail_closed_for_unreviewed_hashes() -> None:
    extractor = load("analysis-framework/malware/pony/extract_config.py", "pony_extract_closed")
    normalizer = load(
        "analysis-framework/malware/pony/deobfuscate_push_ret.py",
        "pony_normalize_closed",
    )
    with pytest.raises(ValueError, match="SHA-256"):
        extractor.extract_config(b"synthetic")
    with pytest.raises(ValueError, match="SHA-256"):
        normalizer.normalize(b"synthetic")
