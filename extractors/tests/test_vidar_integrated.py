from __future__ import annotations

from extractors.vidar import integrated


def test_integrated_extractor_relabels_dead_drops(monkeypatch) -> None:
    base = {
        "family": "vidar",
        "config": {
            "static_config_recovered": True,
            "c2_urls": [
                "https://t.me/gk6p2s",
                "https://steamcommunity.com/profiles/76561198667588759",
            ],
            "features": {"telegram_dead_drop": False},
        },
        "findings": [
            {
                "kind": "network.url",
                "value": "https://t.me/gk6p2s",
                "role": "c2",
                "confidence": "confirmed",
            },
            {
                "kind": "network.url",
                "value": "https://steamcommunity.com/profiles/76561198667588759",
                "role": "c2",
                "confidence": "confirmed",
            },
        ],
    }
    monkeypatch.setattr(integrated, "_extract_base", lambda data, name: base)
    result = integrated.extract(b"fixture", "fixture.bin")
    config = result["config"]
    assert config["config_record_urls"] == [
        "https://t.me/gk6p2s",
        "https://steamcommunity.com/profiles/76561198667588759",
    ]
    assert config["c2_urls"] == []
    assert config["dead_drop_urls"] == config["config_record_urls"]
    assert config["final_c2_recovered"] is False
    assert config["features"]["telegram_dead_drop"] is True
    assert [item["role"] for item in result["findings"]] == [
        "dead_drop.telegram",
        "dead_drop.steam_profile",
    ]


def test_integrated_extractor_preserves_unrecovered_result(monkeypatch) -> None:
    base = {"config": {"static_config_recovered": False}, "findings": []}
    monkeypatch.setattr(integrated, "_extract_base", lambda data, name: base)
    assert integrated.extract(b"fixture") is base
