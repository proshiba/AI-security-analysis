"""Regression tests for 2026-04-01 news campaign extractors."""

from __future__ import annotations

import struct

import pytest

from extractors.atlascross.extractor import CONFIG_MARKER, CONFIG_SIZE, encrypt_config, extract as extract_atlascross
from extractors.npm_supply_chain.extractor import decode_script, decode_value, extract as extract_npm, parse_string_table


def test_npm_decoder_and_extractor() -> None:
    """Decode a minimal table and retain the campaign URL and identifier."""
    order = "OrDeR_7077"
    clear = "http://sfrclak.com:8000/"
    key = [int(character) if character.isdigit() else 0 for character in order]
    transformed = "".join(chr(ord(character) ^ key[(7 * index * index) % 10] ^ 333) for index, character in enumerate(clear))
    import base64

    encoded = base64.b64encode(transformed.encode("utf-8")).decode()[::-1].replace("=", "_")
    source = f'const stq=["{encoded}"],ord="{order}"; _entry("6202033");'
    assert decode_value(encoded, order) == clear
    assert decode_script(source)["urls"] == [clear]
    result = extract_npm(source.encode(), "setup.js")
    assert result["config"]["campaign_id"] == "6202033"
    assert result["findings"][0]["confidence"] == "confirmed"
    assert result["network_contacted"] is False


def test_npm_parser_rejects_non_literal_code() -> None:
    """Reject a non-literal table instead of evaluating JavaScript."""
    with pytest.raises(ValueError):
        parse_string_table('stq=[run_code()],ord="x"')
    with pytest.raises(ValueError):
        decode_value("%%%", "x")


def test_atlascross_synthetic_config_round_trip() -> None:
    """Exercise every field against a deterministic synthetic config."""
    clear = bytearray(CONFIG_SIZE)
    clear[: len(b"bifa668.com")] = b"bifa668.com"
    struct.pack_into("<H", clear, 0x40, 9899)
    clear[0x44 : 0x44 + 7] = b"fixture"
    clear[0xC4 : 0xC4 + 6] = b"silver"
    encrypted = encrypt_config(bytes(clear))
    sample = b"header" + CONFIG_MARKER + encrypted + b"tail"
    result = extract_atlascross(sample, "config.bin")
    assert result["config"]["c2_host"] == "bifa668.com"
    assert result["config"]["c2_port"] == 9899
    assert result["config"]["remark"] == "fixture"
    assert result["findings"][0]["value"] == "bifa668.com:9899"
    assert result["executed"] is False


def test_atlascross_rejects_bad_layout() -> None:
    """Reject missing, truncated, and incorrectly sized configuration data."""
    with pytest.raises(ValueError):
        extract_atlascross(b"nothing")
    with pytest.raises(ValueError):
        extract_atlascross(CONFIG_MARKER + b"short")
