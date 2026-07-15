"""Unit tests for SpyGlace repository-envelope recovery."""

from __future__ import annotations

import struct
import unittest

from unpackers.spyglace_unpacker import (
    REPOSITORY_XOR_KEY,
    build_parser,
    classify_payload,
    recover_payload,
    repeating_xor,
    sha256_bytes,
    valid_pe,
)


def minimal_pe(extra: bytes = b"") -> bytes:
    """Build a small structurally valid PE fixture with optional markers."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xE0)
    return bytes(data) + extra


class SpyGlaceUnpackerTests(unittest.TestCase):
    """Exercise each public recovery primitive."""

    def test_hash_and_xor(self) -> None:
        self.assertEqual(len(sha256_bytes(b"x")), 64)
        encoded = repeating_xor(b"payload", b"key")
        self.assertEqual(repeating_xor(encoded, b"key"), b"payload")
        with self.assertRaises(ValueError):
            repeating_xor(b"x", b"")

    def test_validation_classification_and_recovery(self) -> None:
        payload = minimal_pe(b"rpsgwra{l\0[ilJvvrSrel\0")
        self.assertTrue(valid_pe(payload))
        self.assertFalse(valid_pe(b"MZbad"))
        self.assertEqual(classify_payload(payload), "spyglace")
        encoded = repeating_xor(payload, REPOSITORY_XOR_KEY)
        result = recover_payload(encoded)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.data, payload)
        self.assertEqual(result.role, "spyglace")
        self.assertIsNone(recover_payload(b"not a pe"))

    def test_other_roles_and_parser(self) -> None:
        self.assertEqual(classify_payload(b"AadDDRTaSPtyAG57er#$ad!lDKTOPLTEL78pE"), "downloader2")
        self.assertEqual(classify_payload(b"sgznqhtgnghvmzxponum"), "downloader1")
        loader = b"{7849596A-48EA-486E-8937-A2A3009F31A9} CachedImage_2355_1481_POS4.dat"
        self.assertEqual(classify_payload(loader), "spyglace_loader")
        self.assertEqual(classify_payload(b"other"), "unknown_pe")
        args = build_parser().parse_args(["--input", "sample.bin"])
        self.assertEqual(args.input.name, "sample.bin")


if __name__ == "__main__":
    unittest.main()
