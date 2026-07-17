"""Decode the AtlasCross/Atlas RAT configuration layouts reported in 2026."""

from __future__ import annotations

import re
import struct

from extractors.common import build_result

CONFIG_SIZE = 324
CONFIG_MARKER = b"By@V<"
INI_FIELD_RE = re.compile(rb"(?im)^\s*(LoginAddress|LoginPort|REMARK|GROUPS|Time|SIGN)\s*=\s*([0-9a-f]+)\s*$")


def decrypt_config(data: bytes) -> bytes:
    """Apply the three-branch per-index XOR transform to a 324-byte config."""
    if len(data) != CONFIG_SIZE:
        raise ValueError(f"AtlasCross config must be {CONFIG_SIZE} bytes")
    output = bytearray(CONFIG_SIZE)
    for index, value in enumerate(data):
        if index <= 9:
            key = (0x67 - index) & 0xFF
        elif index <= 20:
            key = (index + 0x61) & 0xFF
        else:
            key = ((index * 7) & 0xFF) ^ ((index + 0x61) & 0xFF)
        output[index] = value ^ key
    return bytes(output)


def encrypt_config(data: bytes) -> bytes:
    """Encode a clear configuration for deterministic, non-malicious test fixtures."""
    return decrypt_config(data)


def decode_c_string(data: bytes) -> str:
    """Decode a bounded NUL-terminated UTF-8 field."""
    return data.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def parse_config(data: bytes) -> dict:
    """Parse domain, little-endian port, remark, and group from an encrypted blob."""
    clear = decrypt_config(data)
    return {
        "format": "encrypted_324_byte_blob",
        "c2_host": decode_c_string(clear[0x00:0x40]),
        "c2_port": struct.unpack_from("<H", clear, 0x40)[0],
        "remark": decode_c_string(clear[0x44:0xC4]),
        "group": decode_c_string(clear[0xC4:0x144]),
    }


def decode_ini_hex(value: bytes) -> str:
    """Decode one even-length hexadecimal UTF-16LE INI value."""
    if len(value) % 4:
        raise ValueError("AtlasCross INI value is not complete UTF-16LE hex")
    try:
        return bytes.fromhex(value.decode("ascii")).decode("utf-16le").rstrip("\0")
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError("invalid AtlasCross INI hex value") from exc


def parse_ini_config(data: bytes) -> dict:
    """Parse the dropped hex-UTF-16LE AtlasPro-style INI without exposing SIGN."""
    fields = {name.decode("ascii"): decode_ini_hex(value) for name, value in INI_FIELD_RE.findall(data)}
    if not {"LoginAddress", "LoginPort"} <= fields.keys():
        raise ValueError("AtlasCross INI endpoint fields not found")
    try:
        port = int(fields["LoginPort"])
    except ValueError as exc:
        raise ValueError("AtlasCross INI port is not decimal") from exc
    if not 0 < port <= 65535:
        raise ValueError("AtlasCross INI port is out of range")
    return {
        "format": "hex_utf16le_ini",
        "c2_host": fields["LoginAddress"],
        "c2_port": port,
        "remark": fields.get("REMARK", ""),
        "group": fields.get("GROUPS", ""),
        "timestamp": fields.get("Time"),
        "victim_identifier_present": bool(fields.get("SIGN")),
    }


def locate_config(data: bytes) -> tuple[int, bytes]:
    """Locate a config after the published marker or accept a raw config blob."""
    if len(data) == CONFIG_SIZE:
        return 0, data
    marker = data.find(CONFIG_MARKER)
    if marker < 0:
        raise ValueError("AtlasCross config marker not found")
    start = marker + len(CONFIG_MARKER)
    if len(data) < start + CONFIG_SIZE:
        raise ValueError("truncated AtlasCross configuration")
    return start, data[start : start + CONFIG_SIZE]


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract binary or dropped-INI AtlasCross configuration without execution."""
    if b"LoginAddress" in data and b"LoginPort" in data:
        offset, parsed = 0, parse_ini_config(data)
    else:
        offset, encrypted = locate_config(data)
        parsed = parse_config(encrypted)
    endpoint = f"{parsed['c2_host']}:{parsed['c2_port']}"
    return build_result(
        "atlascross",
        data,
        {"source_name": name, "config_offset": offset, **parsed},
        [
            {
                "kind": "network.c2_endpoint",
                "value": endpoint,
                "role": "primary_c2",
                "confidence": "confirmed",
                "source": "decrypted_config",
            }
        ],
        [
            "The binary algorithm is validated with a synthetic fixture because the published sample was unavailable from MalwareBazaar.",
            "SIGN presence is recorded but its victim identifier value is not published.",
            "Static configuration does not establish current C2 availability.",
        ],
    )
