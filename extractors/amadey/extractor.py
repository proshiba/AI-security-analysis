"""Static Amadey configuration extractor for reviewed x86 and x64 layouts.

The implementation mirrors the documented/CAPE string layout but performs
all work in memory.  It never executes a sample or contacts recovered hosts.
"""

from __future__ import annotations

import base64
import re
import struct

import pefile

from extractors.common import build_result, extract_strings
from extractors.stealer_common import clean_url, feature_hits, infrastructure_urls

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
X86_CALL = re.compile(
    rb"\x6a(.)\x68(.{4})\xb9.{4}\xe8.{4}\x68.{4}\xe8.{4}\x59\xc3",
    re.DOTALL,
)
X64_CALL = re.compile(
    rb"\x48\x83\xec.\x41\xb8(.{4})\x48\x8d\x15(.{4})"
    rb"\x48\x8d\x0d.{4}\xe8.{4}",
    re.DOTALL,
)


def decode_amadey_string(key: str, encoded: str) -> bytes:
    """Decode one Amadey custom-alphabet value followed by Base64."""
    if not key or any(character not in ALPHABET + "=" for character in encoded):
        raise ValueError("invalid Amadey alphabet input")
    translated = []
    for index, character in enumerate(encoded):
        if character == "=":
            translated.append(character)
            continue
        left = ALPHABET.index(character)
        right = ALPHABET.index(key[index % len(key)])
        translated.append(ALPHABET[(left + (0x3F - right) + 0x3F) % 0x3F])
    return base64.b64decode("".join(translated), validate=True)


def _file_offset(pe: pefile.PE, virtual_address: int) -> int:
    """Convert one image virtual address into a bounded file offset."""
    return int(pe.get_offset_from_rva(virtual_address - pe.OPTIONAL_HEADER.ImageBase))


def _read_c_string(data: bytes, offset: int, limit: int = 4096) -> str:
    """Read a bounded ASCII C string from a verified file offset."""
    if not 0 <= offset < len(data):
        raise ValueError("string offset outside image")
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        raise ValueError("unterminated string")
    return data[offset:end].decode("ascii")


def _encoded_values(data: bytes, pe: pefile.PE) -> list[tuple[int, str]]:
    """Locate reviewed Amadey encoded-string call-site records."""
    values: list[tuple[int, str]] = []
    is_x64 = pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
    pattern = X64_CALL if is_x64 else X86_CALL
    for match in pattern.finditer(data):
        try:
            if is_x64:
                size = struct.unpack("<I", match.group(1))[0]
                instruction = match.start() + 10
                displacement = struct.unpack("<i", match.group(2))[0]
                target_rva = pe.get_rva_from_offset(instruction + 7) + displacement
                offset = int(pe.get_offset_from_rva(target_rva))
            else:
                size = match.group(1)[0]
                offset = _file_offset(pe, struct.unpack("<I", match.group(2))[0])
            value = _read_c_string(data, offset)
            if len(value) == size:
                values.append((size, value))
        except (UnicodeDecodeError, ValueError, struct.error, pefile.PEFormatError):
            continue
    return values


def recover_config(data: bytes) -> dict:
    """Recover validated Amadey configuration fields from one PE image."""
    try:
        pe = pefile.PE(data=data, fast_load=True)
        values = _encoded_values(data, pe)
    except (AttributeError, pefile.PEFormatError, ValueError):
        return {}
    keys = [value for size, value in values if size == 0x20 and "=" not in value]
    if len(keys) < 2:
        return {}
    decode_key, rc4_key = keys[:2]
    decoded: list[str] = []
    for _, value in values:
        try:
            plain = decode_amadey_string(decode_key, value)
            text = plain.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            continue
        if text.isprintable() and text not in decoded:
            decoded.append(text)
    c2s: list[str] = []
    version = install_dir = install_file = ""
    for index, value in enumerate(decoded[:64]):
        if value.endswith(".php") and index:
            candidate = clean_url(f"http://{decoded[index - 1]}{value}")
            if candidate:
                c2s.append(candidate)
        elif re.fullmatch(r"\d+\.\d{1,2}", value):
            version = value
        elif re.fullmatch(r"[0-9a-f]{10}", value):
            install_dir = value
        elif value.lower().endswith(".exe"):
            install_file = value
    campaign = re.search(rb"\x00\x00\x00([0-9a-f]{6})\x00\x00", data)
    if not c2s:
        return {}
    return {
        "c2_urls": sorted(set(c2s)),
        "version": version or None,
        "campaign_id": campaign.group(1).decode() if campaign else None,
        "install_directory": install_dir or None,
        "install_filename": install_file or None,
        "rc4_key": rc4_key,
        "decoded_strings": decoded[:64],
        "profile": "amadey_custom_alphabet_base64",
    }


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract Amadey config, behavior markers, and evidence-qualified C2s."""
    strings = extract_strings(data)
    recovered = recover_config(data)
    urls = recovered.get("c2_urls", []) or infrastructure_urls(strings)
    findings = [
        {
            "kind": "network.url",
            "value": value,
            "role": "c2" if recovered else "candidate_infrastructure",
            "confidence": "confirmed" if recovered else "candidate",
            "source": "amadey_config_decryption" if recovered else "embedded_literal",
        }
        for value in urls
    ]
    config = {
        "source_name": name,
        **recovered,
        "static_config_recovered": bool(recovered),
        "features": feature_hits(
            strings + recovered.get("decoded_strings", []),
            {
                "persistence": ("CurrentVersion\\Run", "Startup"),
                "plugin_download": ("/plugins/", "index.php", ".dll"),
                "system_discovery": ("ComputerName", "UserName", "os="),
                "rc4_protected_traffic": ("RC4", "crypt"),
            },
        ),
    }
    return build_result(
        "amadey",
        data,
        config,
        findings,
        [
            "Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.",
            "Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.",
            "No recovered endpoint was contacted.",
        ],
    )
