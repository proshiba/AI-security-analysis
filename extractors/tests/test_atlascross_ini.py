"""Dropped AtlasCross INI configuration tests."""

from __future__ import annotations

import pytest

from extractors.atlascross.extractor import decode_ini_hex, extract, parse_ini_config


def encode(value: str) -> str:
    """Encode one synthetic UTF-16LE fixture value as hexadecimal text."""
    return value.encode("utf-16le").hex()


def test_hex_utf16le_ini_extraction_and_sign_redaction() -> None:
    """Normalize a dropped INI while withholding its victim identifier value."""
    data = (
        "[Setting]\n"
        f"LoginAddress={encode('206.238.115.58')}\n"
        f"LoginPort={encode('886')}\n"
        f"REMARK={encode('campaign')}\n"
        f"GROUPS={encode('operator')}\n"
        f"Time={encode('2026-3-6 12:28')}\n"
        f"SIGN={encode('fixture-victim-id')}\n"
    ).encode()
    parsed = parse_ini_config(data)
    assert parsed["c2_host"] == "206.238.115.58"
    assert parsed["c2_port"] == 886
    assert parsed["victim_identifier_present"] is True
    assert "fixture-victim-id" not in str(parsed)
    result = extract(data, "AtlasPro.ini")
    assert result["findings"][0]["value"] == "206.238.115.58:886"
    assert result["network_contacted"] is False


def test_ini_decoder_rejects_invalid_values() -> None:
    """Reject incomplete UTF-16LE hex and non-decimal ports."""
    with pytest.raises(ValueError):
        decode_ini_hex(b"123")
    bad = f"LoginAddress={encode('host.example')}\nLoginPort={encode('nope')}\n".encode()
    with pytest.raises(ValueError):
        parse_ini_config(bad)
