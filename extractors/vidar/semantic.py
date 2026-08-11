"""Vidar設定内URLをDDR/bootstrapと最終C2候補へ保守的に分類する。"""

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
    """Vidar XOR設定由来URLを用途別に分類し、DDRをC2と誤記しない。"""

    host = (urlsplit(url).hostname or "").lower()
    path = urlsplit(url).path.lower()
    if host in {"t.me", "telegram.me", "api.telegram.org"}:
        return VidarEndpointRole(
            url,
            "dead_drop.telegram",
            "confirmed_static_config",
            "Telegram上のprofile/channelは最終C2を間接解決するbootstrapである",
        )
    if host == "steamcommunity.com" and path.startswith(("/profiles/", "/id/")):
        return VidarEndpointRole(
            url,
            "dead_drop.steam_profile",
            "confirmed_static_config",
            "Steam community profileは最終C2を間接解決するbootstrapである",
        )
    return VidarEndpointRole(
        url,
        "c2_or_bootstrap_candidate",
        "requires_protocol_or_response_corroboration",
        "設定内URLだけでは最終C2と配布・bootstrapを区別できない",
    )


def classify_recovered_config(recovered: dict) -> dict:
    """既存recover_xor_config出力へendpoint roleと未解決状態を付与する。"""

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
        "endpoints": [item.__dict__ for item in endpoints],
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
