"""Extract Quasar/xClient-derived VenomRAT configuration candidates."""

from __future__ import annotations

from extractors.common import (
    build_result,
    endpoint_candidates,
    extract_strings,
    url_candidates,
)


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
    markers, endpoints, urls = (
        family_markers(strings),
        endpoint_candidates(strings),
        url_candidates(strings),
    )
    confidence = "inferred" if len(markers) >= 2 else "unverified"
    findings = [
        {
            "kind": "network.endpoint",
            "value": item,
            "role": "candidate_c2",
            "confidence": confidence,
            "source": "static_string",
        }
        for item in endpoints
    ]
    return build_result(
        "venomrat",
        data,
        {"source_name": name, "markers": markers, "endpoints": endpoints, "urls": urls},
        findings,
        [
            "Encrypted resource loaders require a recovered final payload before config can be confirmed."
        ],
    )
