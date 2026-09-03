from __future__ import annotations

import hashlib

from extractors.vidar.semantic import classify_recovered_config


def test_social_urls_are_dead_drops_not_final_c2() -> None:
    result = classify_recovered_config(
        {
            "c2_urls": [
                "https://t.me/gk6p2s",
                "https://www.pinterest.com/m1duus",
                "https://steamcommunity.com/profiles/76561198667588759",
            ]
        }
    )
    assert result["dead_drop_urls"] == [
        "https://t.me/gk6p2s",
        "https://www.pinterest.com/m1duus",
        "https://steamcommunity.com/profiles/76561198667588759",
    ]
    assert result["final_c2_candidates"] == []
    assert result["final_c2_recovered"] is False
    assert result["requires_dead_drop_resolution"] is True
    assert [item["role"] for item in result["endpoints"]] == [
        "dead_drop.telegram",
        "dead_drop.pinterest_profile",
        "dead_drop.steam_profile",
    ]


def test_unknown_http_record_remains_candidate() -> None:
    result = classify_recovered_config({"c2_urls": ["https://example.invalid/gate"]})
    assert result["dead_drop_urls"] == []
    assert result["final_c2_candidates"] == ["https://example.invalid/gate"]
    assert result["final_c2_recovered"] is False


def test_exact_epic_profile_locator_is_dead_drop_and_query_is_described_by_hash() -> None:
    locator = "EMqJL"
    url = (
        "https://dev.epicgames.com/community/api/user_profiles/profile.json"
        f"?hash_id={locator}"
    )
    result = classify_recovered_config({"c2_urls": [url]})

    assert result["dead_drop_urls"] == [url]
    assert result["final_c2_candidates"] == []
    assert result["requires_dead_drop_resolution"] is True
    endpoint = result["endpoints"][0]
    assert endpoint["role"] == "dead_drop.epic_community_profile_candidate"
    assert endpoint["locator_query_parameter"] == "hash_id"
    assert endpoint["locator_query_value_sha256"] == hashlib.sha256(
        locator.encode("ascii")
    ).hexdigest()
    assert locator not in endpoint["locator_query_value_sha256"]


def test_epic_profile_without_exact_hash_id_remains_unresolved_candidate() -> None:
    for url in (
        "https://dev.epicgames.com/community/api/user_profiles/profile.json",
        "https://dev.epicgames.com/community/api/user_profiles/profile.json?user=EMqJL",
        "https://dev.epicgames.com/community/api/user_profiles/profile.json?hash_id=EMqJL&x=1",
    ):
        result = classify_recovered_config({"c2_urls": [url]})
        assert result["dead_drop_urls"] == []
        assert result["final_c2_candidates"] == [url]
