"""Extract conservative RemcosRAT static configuration candidates."""

from __future__ import annotations

from extractors.common import build_result, endpoint_candidates, extract_strings


def marker_score(strings: list[str]) -> tuple[int, list[str]]:
    """Score family markers separately from endpoint extraction."""
    text = "\n".join(strings).lower()
    markers = [
        marker
        for marker in ("remcos agent", "rmc-", "remcos", "control remote")
        if marker in text
    ]
    return len(markers), markers


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract literal Remcos endpoint candidates without claiming decrypted config."""
    strings = extract_strings(data)
    score, markers = marker_score(strings)
    endpoints = endpoint_candidates(strings)
    confidence = "inferred" if score else "unverified"
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
        "remcosrat",
        data,
        {
            "source_name": name,
            "marker_score": score,
            "markers": markers,
            "endpoints": endpoints,
        },
        findings,
        [
            "Remcos configuration may be encrypted or resource-backed.",
            "Literal endpoints require config-reference or process-attributed validation.",
        ],
    )
