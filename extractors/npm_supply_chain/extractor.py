"""Statically decode the 2026 axios/plain-crypto-js malicious postinstall."""

from __future__ import annotations

import ast
import base64
import re

from extractors.common import build_result, url_candidates

ARRAY_RE = re.compile(r"\bstq\s*=\s*(\[.*?\])\s*,\s*ord\s*=", re.DOTALL)
ORDER_RE = re.compile(r"\bord\s*=\s*[\"']([^\"']+)[\"']")
ENTRY_RE = re.compile(r"_entry\s*\(\s*[\"']([^\"']+)[\"']\s*\)")


def javascript_number_key(order: str) -> list[int]:
    """Model JavaScript ``Number(character)`` for the decimal key schedule."""
    return [int(character) if character.isdigit() else 0 for character in order]


def decode_value(value: str, order: str) -> str:
    """Decode one reversed-Base64 and XOR-obfuscated string without JavaScript."""
    transformed = value[::-1].replace("_", "=")
    raw = base64.b64decode(transformed, validate=True).decode("utf-8")
    key = javascript_number_key(order)
    if not key:
        raise ValueError("empty order key")
    return "".join(
        chr(ord(character) ^ key[(7 * index * index) % len(key)] ^ 333)
        for index, character in enumerate(raw)
    )


def parse_string_table(source: str) -> tuple[list[str], str]:
    """Parse the literal string table and order key without evaluating code."""
    array_match = ARRAY_RE.search(source)
    order_match = ORDER_RE.search(source)
    if not array_match or not order_match:
        raise ValueError("npm postinstall string table not found")
    try:
        values = ast.literal_eval(array_match.group(1))
    except (SyntaxError, ValueError) as exc:
        raise ValueError("invalid literal string table") from exc
    if not isinstance(values, list) or not all(isinstance(item, str) for item in values):
        raise ValueError("string table must contain only strings")
    return values, order_match.group(1)


def decode_script(source: str) -> dict:
    """Return decoded imports, templates, endpoints, and the campaign identifier."""
    table, order = parse_string_table(source)
    decoded = [decode_value(value, order) if value else "" for value in table]
    entry = ENTRY_RE.search(source)
    urls = url_candidates(decoded)
    return {
        "order_key": order,
        "entry_id": entry.group(1) if entry else None,
        "decoded_strings": decoded,
        "urls": urls,
        "platforms": sorted(
            platform for platform in ("win32", "darwin") if platform in decoded
        )
        + (["linux"] if any("/tmp/ld.py" in value for value in decoded) else []),
    }


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract publish-safe configuration from a malicious npm setup script."""
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("npm postinstall is not UTF-8 text") from exc
    decoded = decode_script(source)
    base_urls = decoded["urls"]
    campaign_id = decoded["entry_id"]
    urls = [
        f"{base.rstrip('/')}/{campaign_id}" if campaign_id else base
        for base in base_urls
    ]
    config = {
        "source_name": name,
        "campaign_id": campaign_id,
        "order_key": decoded["order_key"],
        "c2_base_urls": base_urls,
        "c2_urls": urls,
        "platforms": decoded["platforms"],
        "decoded_templates": decoded["decoded_strings"],
    }
    findings = [
        {
            "kind": "network.c2_url",
            "value": value,
            "role": "payload_dispatch",
            "confidence": "confirmed",
            "source": "decoded_postinstall_string",
        }
        for value in urls
    ]
    if campaign_id:
        findings.append(
            {
                "kind": "campaign.identifier",
                "value": campaign_id,
                "role": "request_path_and_filename",
                "confidence": "confirmed",
                "source": "postinstall_entry_argument",
            }
        )
    return build_result(
        "npm_supply_chain",
        data,
        config,
        findings,
        [
            "The downloaded platform payloads are not embedded in setup.js.",
            "A decoded URL is configuration evidence, not proof that infrastructure remains active.",
        ],
    )
