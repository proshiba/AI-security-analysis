"""Unit tests for shared profile-defined family extractors."""

from __future__ import annotations

import json

import pytest

from extractors import profiled_family


def test_profiles_normalization_and_validation(tmp_path) -> None:
    """Load the ten profiles, normalize aliases, and reject invalid documents."""
    profiles = profiled_family.load_profiles()
    assert len(profiles) == 10
    assert profiled_family.normalize_family("Quasar-RAT", profiles) == "quasarrat"
    assert profiled_family.profile_for("cloud eye")["family"] == "guloader"
    invalid = tmp_path / "invalid.json"
    invalid.write_text(json.dumps({"schema_version": 2}), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        profiled_family.load_profiles(invalid)


def test_bounded_strings_uses_three_windows(monkeypatch) -> None:
    """Keep first, middle, and last strings when the full scan bound is exceeded."""
    monkeypatch.setattr(profiled_family, "FULL_SCAN_LIMIT", 8)
    monkeypatch.setattr(profiled_family, "SAMPLE_WINDOW", 5)
    data = b"FIRST" + b"x" * 10 + b"MIDDLE" + b"y" * 10 + b"LAST"
    values = profiled_family.bounded_strings(data)
    text = " ".join(values)
    assert "FIRST" in text and "LAST" in text
    assert profiled_family.bounded_strings(data, 0) == []


def test_url_sanitization_and_profile_extraction() -> None:
    """Redact URL secrets and emit only candidate AsyncRAT infrastructure."""
    assert profiled_family.sanitize_network_url("https://user:pass@evil.example.org/a?q=secret#x") == "https://evil.example.org/a"
    assert profiled_family.sanitize_network_url("http://127.0.0.1/test") is None
    data = b"AsyncRAT Server HWID Hosts Ports https://evil.example.org/gate?token=redacted"
    result = profiled_family.extract_family("asyncrat", data, "fixture.exe")
    assert profiled_family.sanitize_network_url("http://schemas.microsoft.com/SMI") is None
    assert profiled_family.sanitize_network_url("https://discord.com/api/webhooks/123/SECRET") == "https://discord.com/api/webhooks/123"
    assert profiled_family.sanitize_network_url("https://api.telegram.org/bot123456789:SECRET/send") == "https://api.telegram.org/bot-REDACTED/send"
    assert profiled_family.sanitize_network_url("https://t.me/example") is None
    assert profiled_family.url_role("c2_candidate", "https://ipinfo.io/json") == "host_discovery_service"
    assert profiled_family.url_role("c2_candidate", "https://onedrive.live.com/download") == "stage_url_candidate"
    assert profiled_family.url_role("c2_candidate", "https://evil.example.org/payload.exe") == "stage_url_candidate"
    assert result["family"] == "asyncrat"
    assert result["config"]["static_config_recovered"] is True
    assert result["findings"][0]["value"] == "https://evil.example.org/gate"
    assert result["network_contacted"] is False


def test_extractor_factory_and_candidate_confidence() -> None:
    """Bind a profile and avoid claiming confirmation from an isolated literal."""
    extractor = profiled_family.extractor_for("idatloader")
    result = extractor(b"https://stage.example.org/a", "loader.js")
    assert result["family"] == "hijackloader"
    assert result["findings"][0]["confidence"] == "candidate"
    assert result["config"]["static_config_recovered"] is False
