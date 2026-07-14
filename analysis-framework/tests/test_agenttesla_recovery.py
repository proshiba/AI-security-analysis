from __future__ import annotations

import base64
import importlib.util
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAMILY = ROOT / "malware" / "agenttesla"
COMMON = ROOT / "common"
for value in (str(FAMILY), str(COMMON)):
    if value not in sys.path:
        sys.path.insert(0, value)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse:
    def __init__(self, data: bytes):
        self.status = 200
        self.headers = {
            "Content-Length": str(len(data)),
            "Content-Type": "application/octet-stream",
        }
        self._stream = io.BytesIO(data)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    def __init__(self, data: bytes):
        self.data = data

    def open(self, _request, timeout: float):
        assert timeout > 0
        return FakeResponse(self.data)


class AgentTeslaRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = load_module(
            "agenttesla_config_extractor", FAMILY / "agenttesla_config_extractor.py"
        )
        cls.fetch = load_module(
            "agenttesla_payload_fetch", FAMILY / "agenttesla_payload_fetch.py"
        )
        cls.recover = load_module(
            "agenttesla_recover", FAMILY / "agenttesla_recover.py"
        )

    def test_ftp_config_is_redacted(self):
        strings = [
            "Mozilla/5.0",
            "ftp://operator:secret@ftp.example.test",
            "operator",
            "secret",
        ]
        result = self.config.extract_config_from_strings(strings)
        self.assertEqual(
            result["config_endpoints"][0]["endpoint"], "ftp.example.test:21"
        )
        self.assertTrue(result["credentials_present"])
        self.assertNotIn("secret", str(result))
        self.assertFalse(result["credentials_published"])

    def test_smtp_config_is_redacted(self):
        strings = [
            "Mozilla/5.0",
            "587",
            "smtp.example.test",
            "operator@example.test",
            "secret",
        ]
        result = self.config.extract_config_from_strings(strings)
        self.assertEqual(
            result["config_endpoints"][0]["endpoint"], "smtp.example.test:587"
        )
        self.assertNotIn("operator@example.test", str(result))
        self.assertNotIn("secret", str(result))

    def test_http_config_after_baseboard_marker(self):
        strings = [
            "Mozilla/5.0",
            "other",
            "Win32_BaseBoard",
            "skip",
            "https://panel.example.test/gate",
        ]
        result = self.config.extract_config_from_strings(strings)
        self.assertEqual(result["config_endpoints"][0]["protocol"], "HTTP(S)")
        self.assertEqual(
            result["config_endpoints"][0]["endpoint"], "https://panel.example.test/gate"
        )

    def test_telegram_token_is_redacted(self):
        secret = "123456:ABCDEF"
        strings = [
            "Mozilla/5.0",
            f"https://api.telegram.org/bot{secret}/sendMessage",
        ]
        result = self.config.extract_config_from_strings(strings)
        endpoint = result["config_endpoints"][0]["endpoint"]
        self.assertEqual(endpoint, "https://api.telegram.org/<redacted>")
        self.assertNotIn(secret, str(result))
        self.assertTrue(result["credentials_present"])

    def test_marker_reverse_base64_transform(self):
        payload = b"MZ-synthetic-dotnet-candidate-with-enough-bytes-for-layer-detection"
        encoded_reversed = base64.b64encode(payload)[::-1]
        stage = b"prefixIN-" + encoded_reversed + b"-in1suffix"
        blobs = [blob for _source, blob in self.recover.transformed_blobs(stage)]
        self.assertIn(payload, blobs)

    def test_marker_hash_padding_is_restored_before_reverse(self):
        payload = b"MZ-synthetic-dotnet-candidate-with-null-padding-" + b"\0" * 24
        encoded_reversed = base64.b64encode(payload)[::-1].replace(b"A", b"#")
        stage = b"imageIN-" + encoded_reversed + b"-in1"
        blobs = [blob for _source, blob in self.recover.transformed_blobs(stage)]
        self.assertIn(payload, blobs)

    def test_discovers_url_in_base64_layer(self):
        url = "https://stage.example.test/payload.png"
        wrapped = base64.b64encode(url.encode())
        self.assertIn(url, self.recover.discover_urls(wrapped))

    def test_bounded_fetch_uses_reviewed_url_without_real_network(self):
        body = b"bounded-stage"
        resolver = lambda *_args, **_kwargs: [  # noqa: E731
            (2, 1, 6, "", ("93.184.216.34", 443))
        ]
        data, metadata = self.fetch.fetch_payload(
            "https://example.com/stage",
            max_bytes=1024,
            opener=FakeOpener(body),
            resolver=resolver,
        )
        self.assertEqual(data, body)
        self.assertEqual(metadata["size"], len(body))
        self.assertFalse(metadata["redirects_followed"])
        self.assertTrue(metadata["network_contacted"])

    def test_private_stage_address_is_refused(self):
        resolver = lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 80))]  # noqa: E731
        with self.assertRaisesRegex(ValueError, "non-public"):
            self.fetch.resolve_public_addresses("localhost", 80, resolver)


if __name__ == "__main__":
    unittest.main()
