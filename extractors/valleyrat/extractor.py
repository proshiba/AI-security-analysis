"""Extract ValleyRAT configuration indicators across reviewed campaign variants."""

from __future__ import annotations

from extractors.common import (
    build_result,
    endpoint_candidates,
    extract_strings,
    ipv4_candidates,
    url_candidates,
)


def identify_variant(strings: list[str]) -> str:
    """Identify a config representation without assuming all ValleyRAT builds match."""
    lower = "\n".join(strings).lower()
    if "odaktomk" in lower or all(
        item in lower for item in ("vvas.bin", "loggercollector.dll")
    ):
        return "dll_sideload_vvas_bundle"
    if "config.enc" in lower or "n520" in lower:
        return "single_pe_n520_managed"
    if "silverfox" in lower:
        return "silverfox_related"
    return "unresolved_variant"


def decode_vvas_reversed_config(strings: list[str]) -> dict[str, str]:
    """Decode the reviewed reversed key/value config used by vvaS shellcode."""
    for value in strings:
        if ":1p" not in value or ":1o" not in value:
            continue
        fields = {}
        for item in value[::-1].split("|"):
            if ":" in item:
                key, raw = item.split(":", 1)
                fields[key] = raw
        endpoints = {}
        for index in (1, 2, 3):
            host, port = fields.get(f"p{index}"), fields.get(f"o{index}")
            if host and port and port.isdigit() and host != "127.0.0.1":
                endpoints[f"endpoint_{index}"] = f"{host}:{int(port)}"
        return endpoints
    return {}


def extract(data: bytes, name: str = "sample") -> dict:
    """Return static ValleyRAT config candidates without contacting endpoints."""
    strings = extract_strings(data)
    variant = identify_variant(strings)
    decoded = decode_vvas_reversed_config(strings)
    endpoints, urls = endpoint_candidates(strings), url_candidates(strings)
    if decoded:
        endpoints = sorted(decoded.values())
    ips = (
        sorted({item.split(":", 1)[0] for item in endpoints})
        if decoded
        else (ipv4_candidates(strings) if variant == "dll_sideload_vvas_bundle" else [])
    )
    if ips and not decoded:
        endpoints = [item for item in endpoints if item.split(":", 1)[0] in ips]
    findings = [
        {
            "kind": "network.endpoint",
            "value": item,
            "role": "candidate_c2",
            "confidence": "confirmed" if decoded else "inferred",
            "source": "decoded_vvas_config" if decoded else "static_string",
        }
        for item in endpoints
    ]
    if not decoded:
        findings += [
            {
                "kind": "network.ip",
                "value": item,
                "role": "candidate_c2_host",
                "confidence": "inferred",
                "source": "decoded_static_string",
            }
            for item in ips
        ]
    findings += [
        {
            "kind": "network.url",
            "value": item,
            "role": "config_or_stage_url",
            "confidence": "inferred",
            "source": "static_string",
        }
        for item in urls
    ]
    return build_result(
        "valleyrat",
        data,
        {
            "variant": variant,
            "decoded_vvas": decoded,
            "source_name": name,
            "endpoints": endpoints,
            "ipv4": ips,
            "urls": urls,
        },
        findings,
        [
            "Static strings alone do not prove an endpoint is C2.",
            "Campaign-specific decoded config should supersede candidates when available.",
        ],
    )
