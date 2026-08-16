"""Vidar設定内URLをdead-drop、bootstrap、最終C2候補へ保守的に分類する。"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class VidarEndpointRole:
    url: str
    role: str
    confidence: str
    reason: str


def classify_recovered_endpoint(url: str) -> VidarEndpointRole:
    """Vidar XOR設定由来URLを用途別に分類し、最終C2と早計に断定しない。"""

    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path.lower()
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
