"""Shared bounded static extractor for profile-defined Windows malware families.

The module intentionally separates conservative literal recovery from family-
specific cryptographic decoders.  Findings are candidates unless a complete
family-specific config structure is available; no endpoint is contacted.
"""

from __future__ import annotations

import ipaddress
import json
from functools import lru_cache
from pathlib import Path
import re
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from extractors.common import build_result, endpoint_candidates, url_candidates

PROFILE_PATH = Path(__file__).with_name("profiles") / "windows_family_profiles.json"
ASCII = re.compile(rb"[\x20-\x7e]{4,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
FULL_SCAN_LIMIT = 8 * 1024 * 1024
SAMPLE_WINDOW = 2 * 1024 * 1024
MAX_STRINGS = 50_000
MAX_FINDINGS = 64
BENIGN_HOSTS = {
    "api.ipify.org", "freegeoip.net", "ip-api.com", "schemas.microsoft.com",
    "nsis.sf.net", "www.google.com", "www.microsoft.com", "support.microsoft.com",
    "aka.ms", "www.w3.org", "schemas.xmlsoap.org", "www.flexerasoftware.com",
    "logo.verisign.com", "docs.microsoft.com", "learn.microsoft.com", "go.microsoft.com",
    "www.youtube.com", "youtube.com", "google.com", "www.jrsoftware.org",
    "www.gendigital.com",
}
BENIGN_HOST_PARTS = (
    "cacerts.digicert.com", "crl.digicert.com", "crl3.digicert.com",
    "crl4.digicert.com", "ocsp.digicert.com", "crl.microsoft.com",
    "ocsp.sectigo.com", "crl.sectigo.com", "ocsp.usertrust.com",
    "comodoca.com", "usertrust.com", "sectigo.com", "digicert.com",
    "symcb.com", "verisign.com", "globalsign.com", "symauth.com", "contoso.com",
)
DISCOVERY_HOSTS = {"api.my-ip.io", "geolocation-db.com", "ipinfo.io", "ipwhois.app"}
DELIVERY_HOSTS = {
    "onedrive.live.com", "github.com", "raw.githubusercontent.com", "bitbucket.org",
    "dropbox.com", "www.dropbox.com",
}
COMMON_PUBLIC_TLDS = {
    "app", "at", "biz", "cc", "cfd", "ch", "cloud", "club", "co", "com", "de",
    "dev", "eu", "fr", "fun", "info", "io", "jp", "live", "me", "net", "nl",
    "online", "org", "pro", "ru", "site", "store", "tech", "top", "tv", "uk",
    "us", "website", "win", "xyz",
}
STAGE_SUFFIXES = (
    ".bat", ".cab", ".dll", ".exe", ".hta", ".img", ".iso", ".js", ".msi",
    ".png", ".ps1", ".rar", ".vbs", ".zip",
)



@lru_cache(maxsize=16)
def load_profiles(path: Path = PROFILE_PATH) -> dict[str, dict]:
    """Load and validate the profile map used by extractors and detectors."""
    value = json.loads(path.read_text(encoding="utf-8"))
    profiles = value.get("profiles")
    if value.get("schema_version") != 1 or not isinstance(profiles, dict):
        raise ValueError("invalid family profile document")
    return profiles


def normalize_family(value: str, profiles: dict[str, dict] | None = None) -> str:
    """Normalize a family ID or declared alias to one profile key."""
    profiles = profiles or load_profiles()
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    for family, profile in profiles.items():
        names = [family, profile.get("display_name", ""), *(profile.get("aliases") or [])]
        if any(re.sub(r"[^a-z0-9]", "", name.lower()) == normalized for name in names):
            return family
    raise ValueError(f"unsupported profiled family: {value}")


def profile_for(family: str) -> dict:
    """Return one normalized immutable-by-convention profile copy."""
    profiles = load_profiles()
    normalized = normalize_family(family, profiles)
    return {"family": normalized, **profiles[normalized]}


def bounded_strings(data: bytes, limit: int = MAX_STRINGS) -> list[str]:
    """Extract ordered unique ASCII/UTF-16LE strings from deterministic windows."""
    if limit <= 0:
        return []
    if len(data) <= FULL_SCAN_LIMIT:
        sample = data
    else:
        middle = max(0, (len(data) - SAMPLE_WINDOW) // 2)
        sample = data[:SAMPLE_WINDOW] + data[middle : middle + SAMPLE_WINDOW] + data[-SAMPLE_WINDOW:]
    values: list[str] = []
    seen: set[str] = set()
    for pattern, encoding in ((ASCII, "ascii"), (WIDE, "utf-16le")):
        for match in pattern.finditer(sample):
            value = match.group().decode(encoding, errors="ignore")
            if value and value not in seen:
                seen.add(value)
                values.append(value)
                if len(values) >= limit:
                    return values
    return values


def sanitize_network_url(value: str) -> str | None:
    """Remove URL secrets and reject local, malformed, certificate, and documentation hosts."""
    try:
        parsed = urlsplit(value.rstrip(".,;)]}"))
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme.lower() not in {"http", "https", "ftp"} or not host:
            return None
        if host in {"localhost", "example.com", "www.example.com"} or host.endswith((".local", ".invalid", ".example", ".test")):
            return None
        if host in BENIGN_HOSTS or any(host == item or host.endswith("." + item) for item in BENIGN_HOST_PARTS):
            return None
        try:
            address = ipaddress.ip_address(host)
            if not address.is_global:
                return None
        except ValueError:
            labels = host.split(".")
            label = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)
            if len(labels) < 2 or not re.fullmatch(r"[a-z]{2,63}", labels[-1], re.I):
                return None
            if not all(label.fullmatch(part) for part in labels) or (len(labels) == 2 and labels[0] == "www"):
                return None
        netloc = f"[{host}]" if ":" in host else host
        if parsed.port:
            netloc += f":{parsed.port}"
        path = parsed.path or "/"
        lowered = path.lower()
        parts = path.split("/")
        if host in {"discord.com", "discordapp.com"} and "/api/webhooks/" in lowered:
            index = next((i for i, part in enumerate(parts) if part.lower() == "webhooks"), None)
            if index is not None and len(parts) > index + 2:
                path = "/".join(parts[: index + 2])
        elif host == "hooks.slack.com" and lowered.startswith("/services/") and len(parts) > 4:
            path = "/".join(parts[:4])
        elif host == "api.telegram.org":
            path = re.sub(r"/bot[^/]{8,}", "/bot-REDACTED", path, flags=re.I)
        elif host == "t.me" and path.lower().rstrip("/") in {"/example", "/test"}:
            return None
        return urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
    except ValueError:
        return None


def url_role(default_role: str, value: str) -> str:
    """Classify sanitized URLs as discovery, delivery-stage, or profile-default roles."""
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    if host in DISCOVERY_HOSTS:
        return "host_discovery_service"
    if host in DELIVERY_HOSTS or parsed.path.lower().endswith(STAGE_SUFFIXES):
        return "stage_url_candidate"
    return default_role


def _publishable_endpoint(value: str) -> bool:
    host = value.rsplit(":", 1)[0].strip("[]").lower()
    if host in {"localhost", "example.com"} or host.endswith((".local", ".invalid", ".example", ".test")):
        return False
    try:
        return ipaddress.ip_address(host).is_global
    except ValueError:
        labels = host.split(".")
        label = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)
        return len(labels) >= 2 and labels[-1] in COMMON_PUBLIC_TLDS and all(label.fullmatch(part) for part in labels)


def extract_family(family: str, data: bytes, source_name: str = "sample.bin") -> dict:
    """Extract bounded candidate config and network indicators for one profile."""
    profile = profile_for(family)
    strings = bounded_strings(data)
    lowered = [value.lower() for value in strings]
    joined = "\n".join(lowered)
    marker_hits = [marker for marker in profile["markers"] if marker.lower() in joined]
    key_hits = [key for key in profile["config_keys"] if key.lower() in joined]
    enough_markers = len(marker_hits) >= int(profile["minimum_markers"])
    urls = []
    for raw in url_candidates(strings):
        value = sanitize_network_url(raw)
        if value and value not in urls:
            urls.append(value)
    endpoints = [value for value in endpoint_candidates(strings) if _publishable_endpoint(value)]
    role = profile["endpoint_role"]
    confidence = "probable" if enough_markers else "candidate"
    findings = [
        {
            "kind": "network.url",
            "value": value,
            "role": url_role(role, value),
            "confidence": confidence,
            "source": "bounded_static_strings",
        }
        for value in urls[:MAX_FINDINGS]
    ]
    remaining = max(0, MAX_FINDINGS - len(findings))
    findings.extend(
        {
            "kind": "network.endpoint",
            "value": value,
            "role": role,
            "confidence": confidence,
            "source": "bounded_static_strings",
        }
        for value in endpoints[:remaining]
    )
    config = {
        "source_name": source_name,
        "profile": profile["family"],
        "display_name": profile["display_name"],
        "category": profile["category"],
        "transport": profile["transport"],
        "marker_hits": marker_hits,
        "minimum_markers": profile["minimum_markers"],
        "observed_config_keys": key_hits,
        "network_candidates": [item["value"] for item in findings],
        "static_config_recovered": bool(enough_markers and findings),
        "scan_scope": "complete_input" if len(data) <= FULL_SCAN_LIMIT else "deterministic_three_window_sample",
    }
    return build_result(
        profile["family"],
        data,
        config,
        findings,
        [
            "Profile-driven static extraction; encrypted or packed config fields may require a family-specific decoder or recovered inner payload.",
            profile["confirmation"],
            "Candidate infrastructure was not contacted and liveness was not inferred.",
            "Credentials, tokens, URL queries, and URL fragments are not published.",
        ],
    )


def extractor_for(family: str) -> Callable[[bytes, str], dict]:
    """Return a two-argument extractor callable bound to one profile."""
    normalized = profile_for(family)["family"]

    def extract(data: bytes, source_name: str = "sample.bin") -> dict:
        """Run the bound family profile without executing the sample."""
        return extract_family(normalized, data, source_name)

    extract.__name__ = f"extract_{normalized}"
    return extract
