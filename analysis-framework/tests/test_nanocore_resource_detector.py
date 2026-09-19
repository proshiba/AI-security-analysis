"""NanoCore暗号化resource形式の静的検出に関する回帰テスト。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from malware.nanocore import detect as detector


def test_verified_resource_matches_without_plaintext_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "is_managed_pe", lambda _data, _lowered: True)
    monkeypatch.setattr(
        detector,
        "extract_config",
        lambda _data: {
            "config": {
                "Version": "1.2.2.0",
                "PrimaryConnectionHost": "controller.example",
                "ConnectionPort": 443,
            },
            "c2": [{"host": "controller.example", "port": 443}],
        },
    )
    result = detector.detect(b"MZ...NanoCore.ClientPluginHost...", Path("candidate.bin"))
    assert result["matched"] is True
    assert result["observations"]["encrypted_resource_config_verified"] is True
    assert result["observations"]["verified_endpoint_count"] == 1
    assert result["campaigns"][0]["confidence"] == "high"


def test_corrupt_resource_does_not_promote_family(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "is_managed_pe", lambda _data, _lowered: True)

    def reject(_data: bytes) -> dict[str, object]:
        raise ValueError("暗号文が不正")

    monkeypatch.setattr(detector, "extract_config", reject)
    result = detector.detect(b"MZ...NanoCore.ClientPluginHost...", Path("candidate.bin"))
    assert result["matched"] is False
    assert result["observations"]["encrypted_resource_config_verified"] is False


def test_resource_without_endpoint_does_not_promote_family(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(detector, "is_managed_pe", lambda _data, _lowered: True)
    monkeypatch.setattr(
        detector,
        "extract_config",
        lambda _data: {
            "config": {
                "Version": "1.2.2.0",
                "PrimaryConnectionHost": "controller.example",
                "ConnectionPort": 443,
            },
            "c2": [],
        },
    )
    result = detector.detect(b"MZ...NanoCore.ClientPluginHost...", Path("candidate.bin"))
    assert result["matched"] is False
