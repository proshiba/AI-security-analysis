"""Tests for bounded Electron ASAR recovery."""

from __future__ import annotations

import hashlib
import json
import struct

import pytest

from unpackers.asar_unpacker import asar_header, is_asar, recover_asar, safe_asar_name


def fixture_asar(
    name: str = "src/main.js", blob: bytes = b"console.log('fixture')"
) -> bytes:
    """Build a minimal Chromium-pickle ASAR fixture."""
    digest = hashlib.sha256(blob).hexdigest()
    parts = name.split("/")
    node = {"size": len(blob), "offset": "0", "integrity": {"hash": digest}}
    tree = node
    for part in reversed(parts[1:]):
        tree = {"files": {part: tree}}
    header = {"files": {parts[0]: tree}}
    raw = json.dumps(header, separators=(",", ":")).encode()
    return struct.pack("<IIII", 4, len(raw) + 8, len(raw) + 4, len(raw)) + raw + blob


def test_recover_asar_script_with_integrity() -> None:
    """Recover one verified script and expose deterministic metadata."""
    data = fixture_asar()
    assert is_asar(data)
    header, offset = asar_header(data)
    assert "files" in header and offset < len(data)
    report, artifacts = recover_asar(data)
    assert report["member_count"] == 1
    assert report["inventory"][0]["integrity"] == "verified"
    assert artifacts == [("asar-script", b"console.log('fixture')")]


def test_accepts_bounded_nul_alignment_after_json_header() -> None:
    """実在Electron ASARのJSON終端NUL・alignment paddingを有界に受理する。"""

    data = fixture_asar()
    _word0, _word1, pickle_size, json_size = struct.unpack_from("<IIII", data)
    payload = data[16 + json_size :]
    padded = (
        struct.pack("<IIII", 4, pickle_size + 6, pickle_size + 2, json_size)
        + data[16 : 16 + json_size]
        + b"\x00\x00"
        + payload
    )
    header, offset = asar_header(padded)
    assert "files" in header
    assert offset == 16 + json_size + 2
    report, artifacts = recover_asar(padded)
    assert report["member_count"] == 1
    assert artifacts == [("asar-script", b"console.log('fixture')")]

    corrupted = bytearray(padded)
    corrupted[16 + json_size] = 1
    assert not is_asar(bytes(corrupted))


def test_rejects_traversal_and_bad_lengths() -> None:
    """Reject unsafe names and malformed pickle length relationships."""
    with pytest.raises(ValueError):
        safe_asar_name("../payload.js")
    malformed = bytearray(fixture_asar())
    malformed[4:8] = struct.pack("<I", 1)
    assert not is_asar(bytes(malformed))
