"""Unit tests for the loopback-only SpyGlace protocol laboratory."""

from __future__ import annotations

import socket
import unittest

from emulators.spyglace.lab import (
    LoopbackCollector,
    build_initial_form,
    custom_rc4,
    decode_a004,
    encode_a004,
    parse_initial_form,
    require_loopback,
)


class SpyGlaceLabTests(unittest.TestCase):
    """Exercise protocol codecs and strict loopback collection."""

    def test_rc4_and_a004_round_trip(self) -> None:
        key = b"key"
        clear = b"HOST;USER;CPU;OS;3.1.15"
        self.assertEqual(custom_rc4(key, custom_rc4(key, clear)), clear)
        encoded = encode_a004(clear.decode())
        self.assertEqual(decode_a004(encoded), clear.decode())
        with self.assertRaises(ValueError):
            custom_rc4(b"", b"x")
        with self.assertRaises(ValueError):
            decode_a004("not base64!")

    def test_form_round_trip(self) -> None:
        body = build_initial_form("SAPPHIRE", "systeminfo", "uid", "HOST;USER;CPU;OS;3.1.15")
        parsed = parse_initial_form(body)
        self.assertEqual(parsed["a003"], "uid")
        self.assertEqual(parsed["profile"], "HOST;USER;CPU;OS;3.1.15")
        with self.assertRaises(ValueError):
            build_initial_form("x", "y", "bad", "z")
        with self.assertRaises(ValueError):
            parse_initial_form(b"a001=x")

    def test_loopback_guard_and_collector(self) -> None:
        self.assertEqual(require_loopback("127.0.0.1"), "127.0.0.1")
        with self.assertRaises(ValueError):
            require_loopback("192.0.2.1")
        collector = LoopbackCollector()
        port = collector.start()
        with socket.create_connection(("127.0.0.1", port), timeout=1.0) as client:
            client.sendall(b"fixture")
        collector.stop()
        self.assertEqual(collector.received, [b"fixture"])


if __name__ == "__main__":
    unittest.main()
