"""Extract redacted AgentTesla exfiltration configuration candidates."""

from __future__ import annotations

import re
import urllib.parse

from extractors.common import (
    build_result,
    endpoint_candidates,
    extract_strings,
    url_candidates,
)


def sanitize_url(value: str) -> tuple[str, bool]:
    """Remove credentials, query, fragment, and likely webhook/token paths."""
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https", "ftp"} or not parsed.hostname:
        return value, False
    secret = bool(parsed.username or parsed.password or parsed.query or parsed.fragment)
    path = parsed.path
    if "api.telegram.org" in parsed.hostname or "discord" in parsed.hostname:
        secret = secret or path not in {"", "/"}
        path = "/<redacted>" if path not in {"", "/"} else path
    port = f":{parsed.port}" if parsed.port else ""
    return urllib.parse.urlunsplit(
        (parsed.scheme.lower(), f"{parsed.hostname}{port}", path, "", "")
    ), secret


def protocol_for(value: str) -> str:
    """Map an endpoint or URL to the likely AgentTesla exfiltration protocol."""
    lower = value.lower()
    if lower.startswith("ftp://"):
        return "FTP"
    if "api.telegram.org" in lower:
        return "Telegram"
    if "discord" in lower:
        return "Discord"
    if re.search(r":(?:25|465|587)$", lower):
        return "SMTP"
    return "HTTP(S)" if lower.startswith("http") else "unknown"


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract AgentTesla endpoints while never publishing credential values."""
    strings = extract_strings(data)
    raw_values = [
        item
        for item in endpoint_candidates(strings) + url_candidates(strings)
        if item.lower().startswith("ftp://")
        or "api.telegram.org" in item.lower()
        or "discord" in item.lower()
        or re.search(r":(?:21|25|465|587)$", item.lower())
    ]
    values, credentials_present = [], False
    for raw in raw_values:
        value, secret = sanitize_url(raw) if "://" in raw else (raw, False)
        credentials_present |= secret
        values.append(
            {
                "protocol": protocol_for(value),
                "endpoint": value,
                "confidence": "inferred",
                "credentials_present": secret,
            }
        )
    return build_result(
        "agenttesla",
        data,
        {
            "source_name": name,
            "config_endpoints": values,
            "credentials_present": credentials_present,
        },
        [
            {
                "kind": "exfiltration.endpoint",
                "value": item["endpoint"],
                "role": item["protocol"],
                "confidence": item["confidence"],
                "source": "static_string",
            }
            for item in values
        ],
        [
            "Recovered .NET #US ordering is needed to promote inferred string candidates to confirmed config."
        ],
    )
