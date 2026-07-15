"""Shared filtering and configuration primitives for information stealers."""

from __future__ import annotations

from pathlib import Path
import re
from urllib.parse import urlsplit

from extractors.common import (
    build_result,
    extract_strings,
    url_candidates,
)

BENIGN_SUFFIXES = (
    "apple.com",
    "digicert.com",
    "globalsign.com",
    "microsoft.com",
    "microsoftonline.com",
    "go.dev",
    "nsis.sf.net",
    "w3.org",
    "certum.pl",
    "ocsp-certum.com",
    "thawte.com",
    "usertrust.com",
    "adobe.com",
    "purl.org",
    "curl.se",
    "docs.rs",
    "github.com",
    "ip-api.com",
    "ipinfo.io",
    "ipify.org",
    "icanhazip.com",
    "checkip.amazonaws.com",
    "cloudflare-dns.com",
    "dns.google",
    "freegeoip.app",
    "freegeip.app",
    "winimage.com",
    "1.1.1.1",
)


def clean_url(value: str) -> str | None:
    """Normalize a literal URL and reject malformed or known reference-only hosts."""
    value = value.rstrip(".,;)'\"]}>")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https", "ftp"} or not host or "." not in host:
        return None
    for suffix in BENIGN_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return None
        if re.fullmatch(rf".*{re.escape(suffix)}[0-9a-z]{{1,16}}", host):
            return None
    return value


def infrastructure_urls(strings: list[str]) -> list[str]:
    """Return normalized non-reference infrastructure URL candidates."""
    return sorted(
        {cleaned for value in url_candidates(strings) if (cleaned := clean_url(value))}
    )


def url_role(value: str) -> str:
    """Classify an embedded URL by conservative infrastructure role."""
    lowered = value.lower()
    if (
        "discord.com/api/webhooks/" in lowered
        or "discordapp.com/api/webhooks/" in lowered
    ):
        return "webhook_exfil_candidate"
    if "api.telegram.org/bot" in lowered:
        return "telegram_exfil_candidate"
    if any(
        token in lowered
        for token in ("/ledger/", "/upload", "/submit", "/gate", "/join", "/api/")
    ):
        return "c2_or_exfil_candidate"
    if any(token in lowered for token in (".zip", ".dll", ".exe", ".ps1", ".js")):
        return "payload_or_dependency_url"
    return "candidate_infrastructure"


def campaign_shape(name: str, data: bytes) -> str:
    """Describe the delivery/container shape without asserting operator identity."""
    suffix = Path(name).suffix.lower()
    if data.startswith(b"MZ"):
        return "direct_pe_or_pe_loader"
    if data[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe"}:
        return "direct_macho"
    if data.startswith(b"7z\xbc\xaf'\x1c"):
        return "encrypted_7z_delivery"
    if suffix in {".js", ".vbs", ".ps1", ".osascript", ".applescript", ".vba", ".sh"}:
        return f"{suffix.lstrip('.')}_script_delivery"
    if suffix in {".xlsm", ".docm"}:
        return "macro_office_delivery"
    return "unknown_or_nested_delivery"


def feature_hits(
    strings: list[str], features: dict[str, tuple[str, ...]]
) -> dict[str, bool]:
    """Match reviewed case-insensitive feature groups against extracted strings."""
    text = "\n".join(strings).lower()
    return {
        name: any(token.lower() in text for token in tokens)
        for name, tokens in features.items()
    }


def extract_stealer(
    family: str,
    data: bytes,
    name: str,
    markers: tuple[str, ...],
    features: dict[str, tuple[str, ...]],
    limitations: list[str],
) -> dict:
    """Build one conservative stealer configuration result from static literals."""
    strings = extract_strings(data)
    lowered = "\n".join(strings).lower()
    marker_hits = sorted(marker for marker in markers if marker.lower() in lowered)
    urls = infrastructure_urls(strings)
    endpoints: list[str] = []
    findings = [
        {
            "kind": "network.url",
            "value": value,
            "role": url_role(value),
            "confidence": "probable"
            if url_role(value) == "c2_or_exfil_candidate"
            else "candidate",
            "source": "embedded_literal",
        }
        for value in urls
    ]
    findings.extend(
        {
            "kind": "network.endpoint",
            "value": value,
            "role": "candidate_infrastructure",
            "confidence": "candidate",
            "source": "embedded_literal",
        }
        for value in endpoints
    )
    config = {
        "source_name": name,
        "campaign_shape": campaign_shape(name, data),
        "family_markers": marker_hits,
        "features": feature_hits(strings, features),
        "urls": urls,
        "endpoints": endpoints,
        "static_config_recovered": bool(urls or endpoints),
    }
    return build_result(family, data, config, findings, limitations)
