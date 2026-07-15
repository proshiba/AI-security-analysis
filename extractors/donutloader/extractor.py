"""Identify Donut/CHRD layers and delegate terminal PureRAT config extraction."""

from __future__ import annotations

from extractors.common import build_result
from extractors.purehvnc.extractor import extract as extract_purehvnc


def layer_markers(data: bytes) -> list[str]:
    """Return deterministic DonutLoader layer markers present in static bytes."""
    markers = []
    for label, marker in (("chrd_config", b"CHRD"), ("managed_payload_resource", b"PayloadSource.zip"), ("portable_executable", b"MZ")):
        if marker in data:
            markers.append(label)
    if data[:1] == b"\xe8" and len(data) >= 5:
        markers.append("donut_shellcode")
    return markers


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract delivery-layer markers or terminal PureRAT configuration."""
    markers = layer_markers(data)
    terminal = extract_purehvnc(data, name)
    endpoints = terminal["config"].get("endpoints", [])
    config = {
        "source_name": name,
        "layer_markers": markers,
        "terminal_family": "purehvnc" if terminal["config"].get("variant") != "unrecognized" else None,
        "terminal_config": terminal["config"] if endpoints else None,
        "endpoints": endpoints,
    }
    findings = [{**item, "source": "terminal_payload_static_config"} for item in terminal["findings"]]
    return build_result(
        "donutloader",
        data,
        config,
        findings,
        ["Run unpackers.chrd_donut_unpacker on the reviewed CHRD carrier before terminal extraction.", "Static extraction only; no payload execution or C2 contact was performed."],
    )
