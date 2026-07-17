"""Shared, non-executing primitives for family configuration extractors."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from typing import Any

ASCII = re.compile(rb"[\x20-\x7e]{4,}")
WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
ENDPOINT = re.compile(
    r"(?<![\w.-])((?:[a-z0-9-]+\.)+[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})(?!\d)",
    re.I,
)
URL = re.compile(r"(?:https?|ftp)://[^\s\"'<>]{4,500}", re.I)


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def extract_strings(data: bytes, minimum: int = 4) -> list[str]:
    """Extract unique ordered ASCII and UTF-16LE strings."""
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    wide_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % minimum)
    values = [
        match.group().decode("ascii", errors="ignore")
        for match in ascii_re.finditer(data)
    ]
    values += [
        match.group().decode("utf-16le", errors="ignore")
        for match in wide_re.finditer(data)
    ]
    return list(dict.fromkeys(value for value in values if value))


def valid_host(host: str) -> bool:
    """Reject malformed IP literals while allowing syntactically valid domains."""
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False
    labels = host.lower().rstrip(".").split(".")
    if len(labels) < 2 or not re.fullmatch(r"[a-z]{2,63}", labels[-1]):
        return False
    label = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.I)
    return all(bool(label.fullmatch(part)) for part in labels)


def endpoint_candidates(strings: list[str]) -> list[str]:
    """Extract validated host:port candidates from static strings."""
    values = set()
    for value in strings:
        for host, raw_port in ENDPOINT.findall(value):
            port = int(raw_port)
            if valid_host(host) and 0 < port <= 65535:
                values.add(f"{host.lower().rstrip('.')}:{port}")
    return sorted(values)


def ipv4_candidates(strings: list[str]) -> list[str]:
    """Extract validated standalone IPv4 literals from static strings."""
    values = set()
    for value in strings:
        for raw in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", value):
            if valid_host(raw):
                values.add(raw)
    return sorted(values)


def url_candidates(strings: list[str]) -> list[str]:
    """Extract unique HTTP(S) URL candidates."""
    return sorted(
        {item.rstrip(".,;)") for value in strings for item in URL.findall(value)}
    )


def build_result(
    family: str,
    data: bytes,
    config: dict[str, Any],
    findings: list[dict],
    limitations: list[str],
) -> dict:
    """Build the common publish-safe extractor result."""
    return {
        "schema_version": 1,
        "family": family,
        "sample_sha256": sha256_bytes(data),
        "config": config,
        "findings": findings,
        "limitations": limitations,
        "credentials_published": False,
        "executed": False,
        "network_contacted": False,
    }
