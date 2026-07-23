"""Extract Quasar/xClient-derived VenomRAT configuration candidates."""

from __future__ import annotations

from extractors.common import (
    build_result,
    endpoint_candidates,
    extract_strings,
)
from extractors.stealer_common import infrastructure_urls


def family_markers(strings: list[str]) -> list[str]:
    """Return observed VenomRAT/Quasar settings markers."""
    text = "\n".join(strings).lower()
    return [
        marker
        for marker in (
            "quasar.client",
            "xclient.core",
            "reconnectdelay",
            "installname",
            "mutex",
        )
        if marker in text
    ]


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract static endpoints and settings-field evidence from a VenomRAT candidate."""
    strings = extract_strings(data)
    markers = family_markers(strings)
    family_supported = len(markers) >= 2
    endpoints = endpoint_candidates(strings) if family_supported else []
    urls = infrastructure_urls(strings) if family_supported else []
    findings = [
        {
            "kind": "network.endpoint",
            "value": item,
            "role": "candidate_c2",
            "confidence": "inferred",
            "source": "static_string",
        }
        for item in endpoints
    ]
    return build_result(
        "venomrat",
        data,
        {
            "source_name": name,
            "markers": markers,
            "endpoints": endpoints,
            "urls": urls,
            "static_config_recovered": False,
            "c2_liveness_confirmed": False,
        },
        findings,
        [
            "暗号化リソースローダーでは、最終ペイロードを復元するまで設定を確定できません。",
            "単一の汎用マーカーだけではVenomRATに帰属せず、ネットワーク候補を公開しません。",
        ],
    )
