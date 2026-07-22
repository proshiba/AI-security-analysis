"""Static Latrodectus configuration and encrypted-string extractor."""

from __future__ import annotations

from contextlib import suppress
import re

import pefile

from extractors.common import build_result, extract_strings
from extractors.stealer_common import feature_hits, infrastructure_urls

VERSION_PATTERN = re.compile(
    rb"\xc7\x44[\x20-\x2f].(.{4})"
    rb"\xc7\x44[\x20-\x2f].(.{4})"
    rb"\xc7\x44[\x20-\x2f].(.{4})\x8b\x05.{4}\x89",
    re.DOTALL,
)


def fnv1a_32(data: bytes) -> int:
    """Return the unsigned 32-bit FNV-1a value used for group IDs."""
    value = 0x811C9DC5
    for byte in data:
        value = 0x1000193 * (value ^ byte) & 0xFFFFFFFF
    return value


def prng_seed(seed: int) -> int:
    """Advance the reviewed Latrodectus encrypted-string PRNG."""
    sub = ((seed + 11865) << 31) | ((seed + 11865) >> 1)
    expr1 = (((sub << 31) | (sub >> 1)) << 30) & 0xFFFFFFFFFFFFFFFF
    sub = (expr1 & 0xFFFFFFFF) | (expr1 >> 32)
    expr2 = ((sub ^ 0x151D) >> 30) | (4 * (sub ^ 0x151D)) & 0xFFFFFFFF
    return ((expr2 >> 31) | (2 * expr2)) & 0xFFFFFFFF


def decrypt_string(data: bytes, mode: int) -> bytes:
    """Decrypt one bounded legacy Latrodectus string record."""
    if len(data) < 6 or mode not in {1, 2}:
        raise ValueError("invalid encrypted string")
    seed = int.from_bytes(data[:4], "little") & 0xFFFFFFFF
    length = int.from_bytes(data[4:6], "little") ^ int.from_bytes(data[:2], "little")
    if length > 4096 or 6 + length > len(data):
        raise ValueError("invalid encrypted string length")
    output = bytearray()
    for byte in data[6 : 6 + length]:
        seed = (seed + 1) & 0xFFFFFFFF if mode == 1 else prng_seed(seed)
        output.append((seed ^ byte) & 0xFF)
    return bytes(output)


def _version(data: bytes) -> str | None:
    """Recover a three-part version from the reviewed stack-write pattern."""
    match = VERSION_PATTERN.search(data)
    if not match:
        return None
    release, minor, major = (chunk[0] for chunk in match.groups())
    return f"{major}.{minor}.{release}"


def _data_section(data: bytes) -> bytes:
    """Return the first PE data section or an empty value on parse failure."""
    try:
        image = pefile.PE(data=data, fast_load=True)
        section = next(
            item for item in image.sections if b".data" in item.Name.rstrip(b"\0")
        )
        return section.get_data()
    except (StopIteration, AttributeError, pefile.PEFormatError, ValueError):
        return b""


def decrypt_legacy_strings(section: bytes) -> list[str]:
    """Recover and deduplicate printable strings from a legacy data section."""
    if len(section) < 10:
        return []
    marker = section[:4]
    offsets: list[int] = []
    cursor = 0
    while len(offsets) < 4096:
        offset = section.find(marker, cursor)
        if offset < 0:
            break
        offsets.append(offset)
        cursor = offset + 1
    values: list[str] = []
    for offset in offsets:
        for mode in (1, 2):
            with suppress(ValueError, UnicodeDecodeError):
                value = decrypt_string(section[offset:], mode).decode("ascii").replace("\0", "")
                if len(value) > 2 and value.isprintable() and value not in values:
                    values.append(value)
                    break
    return values


def recover_config(data: bytes) -> dict:
    """Recover a validated legacy Latrodectus config from one PE image."""
    values = decrypt_legacy_strings(_data_section(data))
    if not values:
        return {}
    urls = sorted({value for value in values if value.startswith(("http://", "https://"))})
    group = key = ""
    for index, value in enumerate(values[:-1]):
        if value == "/files/":
            group = values[index + 1]
        elif value == "ERROR":
            key = values[index + 1]
    characteristic = any("counter=%d&type=%d&guid=" in value for value in values)
    if not urls or not characteristic:
        return {}
    return {
        "c2_urls": urls,
        "version": _version(data),
        "group_name": group or None,
        "group_id": fnv1a_32(group.encode()) if group else None,
        "rc4_key": key or None,
        "decoded_strings": values[:256],
        "profile": "latrodectus_legacy_prng_strings",
    }


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract Latrodectus configuration and behavior evidence offline."""
    strings = extract_strings(data)
    recovered = recover_config(data)
    urls = recovered.get("c2_urls", []) or infrastructure_urls(strings)
    findings = [
        {
            "kind": "network.url",
            "value": value,
            "role": "c2" if recovered else "candidate_infrastructure",
            "confidence": "confirmed" if recovered else "candidate",
            "source": "latrodectus_string_decryption" if recovered else "embedded_literal",
        }
        for value in urls
    ]
    combined_strings = strings + recovered.get("decoded_strings", [])
    config = {
        "source_name": name,
        **recovered,
        "static_config_recovered": bool(recovered),
        "features": feature_hits(
            combined_strings,
            {
                "host_discovery": ("ipconfig /all", "systeminfo", "whoami /groups"),
                "domain_discovery": ("nltest /domain_trusts", "net group \"Domain Admins\""),
                "security_discovery": ("SecurityCenter2", "AntiVirusProduct"),
                "scheduled_task_persistence": ("LogonTrigger", "TimeTrigger"),
                "payload_download": ("/files/", "update_data.dat", "URLS|"),
                "rundll32_execution": ("rundll32.exe",),
            },
        ),
    }
    return build_result(
        "latrodectus",
        data,
        config,
        findings,
        [
            "Confirmed values require the characteristic decrypted registration format and at least one URL.",
            "AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.",
            "No check-in or infrastructure contact was performed.",
        ],
    )
