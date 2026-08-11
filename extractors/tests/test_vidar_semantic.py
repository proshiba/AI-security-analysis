from __future__ import annotations

from extractors.vidar.semantic import classify_recovered_config


def test_social_urls_are_dead_drops_not_final_c2() -> None:
    result = classify_recovered_config(
        {
            "c2_urls": [
                "https://t.me/gk6p2s",
                "https://steamcommunity.com/profiles/76561198667588759",
            ]
        }
    )
    assert result["dead_drop_urls"] == [
        "https://t.me/gk6p2s",
        "https://steamcommunity.com/profiles/76561198667588759",
    ]
    assert result["final_c2_candidates"] == []
    assert result["final_c2_recovered"] is False
    assert result["requires_dead_drop_resolution"] is True
    assert [item["role"] for item in result["endpoints"]] == [
        "dead_drop.telegram",
        "dead_drop.steam_profile",
    ]


def test_unknown_http_record_remains_candidate() -> None:
    result = classify_recovered_config({"c2_urls": ["https://example.invalid/gate"]})
    assert result["dead_drop_urls"] == []
    assert result["final_c2_candidates"] == ["https://example.invalid/gate"]
    assert result["final_c2_recovered"] is False
