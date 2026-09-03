"""Vidar設定内URLをdead-drop、bootstrap、最終C2候補へ保守的に分類する。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


EPIC_COMMUNITY_PROFILE_PATH = "/community/api/user_profiles/profile.json"
EPIC_HASH_ID_QUERY = re.compile(r"hash_id=(?P<value>[A-Za-z0-9_-]{4,64})\Z")


@dataclass(frozen=True)
class VidarEndpointRole:
    url: str
    role: str
    confidence: str
    reason: str
    locator_query_present: bool = False
    locator_query_parameter: str | None = None
    locator_query_value_sha256: str | None = None


def _epic_profile_locator(url: str) -> tuple[bool, str | None]:
    """曖昧なquery解釈を許さず、Vidar用Epic profile locatorだけを認識する。"""

    try:
        parsed = urlsplit(url)
        explicit_port = parsed.port
    except ValueError:
        return False, None
    match = EPIC_HASH_ID_QUERY.fullmatch(parsed.query)
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").casefold() != "dev.epicgames.com"
        or parsed.path != EPIC_COMMUNITY_PROFILE_PATH
        or parsed.username
        or parsed.password
        or explicit_port is not None
        or parsed.fragment
        or match is None
    ):
        return False, None
    return True, match.group("value")


def classify_recovered_endpoint(url: str) -> VidarEndpointRole:
    """Vidar XOR設定由来URLを用途別に分類し、最終C2と早計に断定しない。"""

    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    epic_profile, epic_hash_id = _epic_profile_locator(url)
    if epic_profile and epic_hash_id is not None:
        return VidarEndpointRole(
            url,
            "dead_drop.epic_community_profile_candidate",
            "confirmed_static_config",
            "Epic Developer Communityのprofile lookupとhash_idは、最終C2を間接解決する共有service locator候補である",
            locator_query_present=True,
            locator_query_parameter="hash_id",
            locator_query_value_sha256=hashlib.sha256(epic_hash_id.encode("ascii")).hexdigest(),
        )
    if host in {"t.me", "telegram.me", "api.telegram.org"}:
        return VidarEndpointRole(
            url,
            "dead_drop.telegram",
            "confirmed_static_config",
            "Telegram上のprofileまたはchannelは、最終C2を間接解決するdead-dropである",
        )
    if host == "steamcommunity.com" and path.startswith(("/profiles/", "/id/")):
        return VidarEndpointRole(
            url,
            "dead_drop.steam_profile",
            "confirmed_static_config",
            "Steam community profileは、最終C2を間接解決するdead-dropである",
        )
    if host in {"pinterest.com", "www.pinterest.com"} and path not in {"", "/"}:
        return VidarEndpointRole(
            url,
            "dead_drop.pinterest_profile",
            "confirmed_static_config",
            "Pinterest profileは、最終C2を間接解決するdead-dropである",
        )
    return VidarEndpointRole(
        url,
        "c2_or_bootstrap_candidate",
        "requires_protocol_or_response_corroboration",
        "設定内URLだけでは最終C2と配布先またはbootstrapを区別できない",
    )


def classify_recovered_config(recovered: dict) -> dict:
    """recover_xor_configの出力へendpoint roleと未解決状態を付与する。"""

    values = recovered.get("c2_urls", [])
    endpoints = [
        classify_recovered_endpoint(value)
        for value in values
        if isinstance(value, str) and value.startswith(("http://", "https://"))
    ]
    dead_drop_urls = [item.url for item in endpoints if item.role.startswith("dead_drop.")]
    final_candidates = [
        item.url for item in endpoints if item.role == "c2_or_bootstrap_candidate"
    ]
    return {
        "endpoints": [
            {
                "url": item.url,
                "role": item.role,
                "confidence": item.confidence,
                "reason": item.reason,
                **(
                    {
                        "locator_query_present": True,
                        "locator_query_parameter": item.locator_query_parameter,
                        "locator_query_value_sha256": item.locator_query_value_sha256,
                    }
                    if item.locator_query_present
                    else {}
                ),
            }
            for item in endpoints
        ],
        "dead_drop_urls": dead_drop_urls,
        "final_c2_candidates": final_candidates,
        "final_c2_recovered": False,
        "requires_dead_drop_resolution": bool(dead_drop_urls),
    }


__all__ = [
    "VidarEndpointRole",
    "classify_recovered_config",
    "classify_recovered_endpoint",
]
