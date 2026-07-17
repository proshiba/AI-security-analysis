"""Static Vidar configuration and infrastructure candidate extractor."""

from __future__ import annotations

import itertools
import re

from extractors.common import build_result, extract_strings
from extractors.stealer_common import extract_stealer, feature_hits, infrastructure_urls, url_role
from unpackers.container_recovery import recover_inflated_pe

KEY_LENGTH = 16
MAX_CONFIG_SCAN = 64 * 1024 * 1024
VERSION_OFFSET = 0x010
VERSION_LENGTH_OFFSET = 0x030
BUILD_OFFSET = 0x031
BUILD_LENGTH_OFFSET = 0x071
RECORDS_OFFSET = 0x072
URL_LENGTH_OFFSET = 0x100
TAG_OFFSET = 0x101
TAG_LENGTH_OFFSET = 0x141
USER_AGENT_OFFSET = 0x142
USER_AGENT_LENGTH_OFFSET = 0x242
RECORD_STRIDE = 0x243
MAX_RECORDS = 32
VERSION_PATTERN = re.compile(rb"^[0-9]{1,3}(?:\.[0-9]{1,3}){1,3}$")


def _decrypt_field(data: bytes, base: int, value_offset: int, length_offset: int, key: bytes) -> bytes | None:
    """Decrypt one bounded repeated-XOR Vidar configuration field."""
    if base + length_offset >= len(data):
        return None
    length = data[base + length_offset]
    if not length:
        return b""
    if base + value_offset + length > len(data):
        return None
    encrypted = data[base + value_offset : base + value_offset + length]
    return bytes(left ^ right for left, right in zip(encrypted, itertools.cycle(key)))


def _printable(value: bytes) -> bool:
    """Return whether a non-empty field contains printable ASCII only."""
    return bool(value) and all(0x20 <= byte <= 0x7E for byte in value)


def _try_config(data: bytes, offset: int) -> dict | None:
    """Validate and decode one candidate Vidar XOR configuration blob."""
    if offset < 0 or offset + RECORDS_OFFSET + RECORD_STRIDE > len(data):
        return None
    key = data[offset : offset + KEY_LENGTH]
    version = _decrypt_field(data, offset, VERSION_OFFSET, VERSION_LENGTH_OFFSET, key)
    if not version or not VERSION_PATTERN.fullmatch(version):
        return None
    first_url = _decrypt_field(data, offset + RECORDS_OFFSET, 0, URL_LENGTH_OFFSET, key)
    if not first_url or not first_url.startswith(b"http") or not _printable(first_url):
        return None
    build = _decrypt_field(data, offset, BUILD_OFFSET, BUILD_LENGTH_OFFSET, key) or b""
    if build and not _printable(build):
        return None
    records: list[dict] = []
    for index in range(MAX_RECORDS):
        base = offset + RECORDS_OFFSET + index * RECORD_STRIDE
        url = _decrypt_field(data, base, 0, URL_LENGTH_OFFSET, key)
        if not url or not url.startswith(b"http") or not _printable(url):
            break
        tag = _decrypt_field(data, base, TAG_OFFSET, TAG_LENGTH_OFFSET, key) or b""
        agent = _decrypt_field(data, base, USER_AGENT_OFFSET, USER_AGENT_LENGTH_OFFSET, key) or b""
        if (tag and not _printable(tag)) or (agent and not _printable(agent)):
            return None
        records.append({"url": url.decode("ascii"), "tag": tag.decode("ascii"), "user_agent": agent.decode("ascii")})
    return {
        "version": version.decode("ascii"),
        "build_id": build.decode("ascii"),
        "records": records,
        "c2_urls": [item["url"] for item in records],
        "xor_key_hex": key.hex(),
        "profile": "vidar_repeated_xor_v1_5_plus",
    }


def _bounded_config_source(data: bytes) -> tuple[bytes, str]:
    """Select a bounded view and compact inflated PE certificate gaps."""
    if len(data) <= MAX_CONFIG_SCAN:
        return data, "complete_input"
    if data.startswith(b"MZ"):
        _, compact = recover_inflated_pe(data)
        if compact is not None:
            return compact, "inflated_pe_compacted"
    return data[:MAX_CONFIG_SCAN], "bounded_prefix"


def recover_xor_config(data: bytes) -> dict:
    """Locate Vidar's repeated-XOR config without NumPy or sample execution."""
    minimum = RECORDS_OFFSET + RECORD_STRIDE
    source, scan_source = _bounded_config_source(data)
    if len(source) < minimum:
        return {}
    for match in re.finditer(rb"[\x03-\x0f]", source[VERSION_LENGTH_OFFSET:]):
        offset = match.start()
        if offset + minimum > len(source):
            break
        key = source[offset : offset + KEY_LENGTH]
        if len(key) != KEY_LENGTH:
            continue
        if any(
            source[offset + RECORDS_OFFSET + index] ^ key[index] != expected
            for index, expected in enumerate(b"http")
        ):
            continue
        recovered = _try_config(source, offset)
        if recovered:
            recovered["config_offset"] = offset
            recovered["scan_source"] = scan_source
            recovered["original_size"] = len(data)
            return recovered
    return {}


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract decrypted Vidar config first, then conservative literals."""
    recovered = recover_xor_config(data)
    string_source, scan_source = _bounded_config_source(data)
    features = {
        "browser_collection": ("Login Data", "Web Data", "History", "Cookies"),
        "wallet_collection": ("wallet.dat", "Electrum", "Exodus", "Atomic"),
        "telegram_dead_drop": ("t.me/", "telegram.me/", "api.telegram.org"),
        "dependency_download": ("sqlite3.dll", "freebl3.dll", "nss3.dll"),
    }
    if not recovered:
        result = extract_stealer(
            "vidar",
            data,
            name,
            ("Vidar", "information.txt", "passwords.txt", "Autofill", "wallets"),
            features,
            [
                "Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.",
                "Packed or loader-stage samples require recursive recovery before a final config can be asserted.",
            ],
            analysis_data=string_source,
        )
        result["config"]["scan_source"] = scan_source
        result["config"]["original_size"] = len(data)
        return result
    strings = extract_strings(string_source)
    urls = sorted(set(recovered["c2_urls"]) | set(infrastructure_urls(strings)))
    findings = [
        {
            "kind": "network.url",
            "value": value,
            "role": "c2" if value in recovered["c2_urls"] else url_role(value),
            "confidence": "confirmed" if value in recovered["c2_urls"] else "candidate",
            "source": "vidar_xor_config" if value in recovered["c2_urls"] else "embedded_literal",
        }
        for value in urls
    ]
    config = {
        "source_name": name,
        **recovered,
        "static_config_recovered": True,
        "features": feature_hits(strings, features),
    }
    return build_result(
        "vidar",
        data,
        config,
        findings,
        [
            "XOR config validation requires a version and at least one printable HTTP record.",
            "Dead-drop URLs can resolve infrastructure indirectly and are reported separately from decoded server records.",
            "No recovered endpoint or social profile was contacted.",
        ],
    )
