"""Offline and loopback-only helpers for the documented SpyGlace protocol."""

from __future__ import annotations

import base64
import hashlib
import urllib.parse

from emulators.common import require_loopback as validate_loopback
from emulators.common import LoopbackCollector

DEFAULT_RC4_KEY = bytes.fromhex("90b149c69b149c4b99c04d1dc9b940b9")


def custom_rc4(key: bytes, data: bytes) -> bytes:
    """Apply SpyGlace's three-round KSA and modified PRGA symmetrically."""
    if not key:
        raise ValueError("key must be non-empty")
    state = list(range(256))
    for _round in range(3):
        j = 0
        for i in range(256):
            j = (j + state[i] + key[i % len(key)]) & 255
            state[i], state[j] = state[j], state[i]
    i = j = 0
    output = bytearray()
    for value in data:
        i = (i + 1) & 255
        j = (j + state[i]) & 255
        first = state[(state[i] + j) & 255]
        state[i], state[j] = state[j], state[i]
        index = (
            (
                state[((i >> 3) ^ (0x20 * j)) & 255]
                + state[((0x20 * i) ^ (j >> 3)) & 255]
            )
            ^ 0xAA
        ) & 255
        second = state[index] + state[(state[j] + state[i]) & 255]
        output.append((value ^ first ^ second) & 255)
    return bytes(output)


def encode_a004(system_profile: str, key: bytes = DEFAULT_RC4_KEY) -> str:
    """Encode one semicolon-delimited system profile for a local fixture."""
    return base64.b64encode(custom_rc4(key, system_profile.encode("utf-8"))).decode(
        "ascii"
    )


def decode_a004(value: str, key: bytes = DEFAULT_RC4_KEY) -> str:
    """Decode one Base64/custom-RC4 system-profile fixture."""
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise ValueError("a004 is not strict Base64") from exc
    return custom_rc4(key, raw).decode("utf-8")


def build_initial_form(
    userid: str,
    system_info: str,
    mode: str,
    system_profile: str,
    key: bytes = DEFAULT_RC4_KEY,
) -> bytes:
    """Build the documented four-field initial request body without sending it."""
    if mode not in {"uid", "info"}:
        raise ValueError("mode must be uid or info")
    fields = {
        "a001": hashlib.md5(userid.encode("utf-8"), usedforsecurity=False).hexdigest(),
        "a002": hashlib.md5(
            system_info.encode("utf-8"), usedforsecurity=False
        ).hexdigest(),
        "a003": mode,
        "a004": encode_a004(system_profile, key),
    }
    return urllib.parse.urlencode(fields).encode("ascii")


def parse_initial_form(body: bytes, key: bytes = DEFAULT_RC4_KEY) -> dict[str, str]:
    """Parse and decode a local four-field SpyGlace request fixture."""
    parsed = urllib.parse.parse_qs(body.decode("ascii"), strict_parsing=True)
    if set(parsed) != {"a001", "a002", "a003", "a004"} or any(
        len(value) != 1 for value in parsed.values()
    ):
        raise ValueError("unexpected SpyGlace form structure")
    result = {name: value[0] for name, value in parsed.items()}
    result["profile"] = decode_a004(result["a004"], key)
    return result


def require_loopback(host: str) -> str:
    """Resolve and require an IPv4/IPv6 loopback address."""
    return validate_loopback(host, "SpyGlace lab")
