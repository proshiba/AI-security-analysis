"""Unit tests for SpyGlace static configuration extraction."""

from __future__ import annotations

import unittest

from extractors.spyglace.extractor import (
    AES_IV,
    AES_KEY,
    _first_userid,
    _first_valid_ip,
    _mutex,
    _rc4_key,
    _request_paths,
    decode_add_xor_sub,
    decoded_strings,
    extract,
    extract_config,
    printable_strings,
)


def encode(value: str, key: int) -> bytes:
    """Encode a fixture with SpyGlace's forward one-byte transform."""
    return bytes((((ord(char) + 1) ^ key) & 255) for char in value)


def fixture() -> bytes:
    """Build a compact config fixture with both transform domains."""
    config = [
        encode("ipaddr$$$$185.18.222.241", 2),
        encode("userid$$$$SAPPHIRE", 2),
        encode("1l8kad.asp", 2),
        encode("api.ipify.org", 2),
        encode("90b149c69b149c4b99c04d1dc9b940b9", 2),
    ]
    commands = [encode("procspawn", 3), encode("WinHttpOpen", 3)]
    wide = b"K31610KIO9834PG79A471".decode().encode("utf-16le")
    return b"\0".join(config + commands) + b"\0\0" + wide + b"\0\0" + AES_KEY + AES_IV


class SpyGlaceExtractorTests(unittest.TestCase):
    """Exercise transform, parsing, and result construction functions."""

    def test_transform_and_strings(self) -> None:
        encoded = encode("procspawn", 3).decode("latin1")
        self.assertEqual(decode_add_xor_sub(encoded, 3), "procspawn")
        with self.assertRaises(ValueError):
            decode_add_xor_sub("x", 999)
        rows = printable_strings(fixture())
        self.assertTrue(rows)
        self.assertIn("procspawn", decoded_strings(fixture(), 3))
        with self.assertRaises(ValueError):
            printable_strings(b"x", 1)

    def test_private_value_parsers(self) -> None:
        values = ["ipaddr$$$$999.1.1.1", "ipaddr$$$$31.58.136.207", "userid$$$$EVE", "x66hjl.asp", "90b149c69b149c4b99c04d1dc9b940b9"]
        self.assertEqual(_first_valid_ip(values), "31.58.136.207")
        self.assertEqual(_first_userid(values), "EVE")
        self.assertEqual(_request_paths(values), ["x66hjl.asp"])
        self.assertEqual(_rc4_key(values), "90b149c69b149c4b99c04d1dc9b940b9")
        self.assertEqual(_mutex(["K31610KIO9834PG79A471"]), "K31610KIO9834PG79A471")

    def test_config_and_common_result(self) -> None:
        config = extract_config(fixture())
        self.assertEqual(config["variant"], "spyglace")
        self.assertEqual(config["c2_ip"], "185.18.222.241")
        self.assertEqual(config["userid"], "SAPPHIRE")
        self.assertEqual(config["download_aes_key_hex"], AES_KEY.hex().upper())
        result = extract(fixture(), "fixture.bin")
        self.assertEqual(result["family"], "spyglace")
        self.assertFalse(result["executed"])


if __name__ == "__main__":
    unittest.main()
