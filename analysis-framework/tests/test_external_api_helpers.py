"""外部API helperを実通信なしで検証する。"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from datetime import date
from pathlib import Path
from unittest.mock import Mock, patch

import pyzipper

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import external_api_helpers as api


def json_response(value: object, status: int = 200) -> api.HttpResponse:
    """JSON用の上限内HTTP応答fixtureを返す。"""

    return api.HttpResponse(status, {}, json.dumps(value).encode("utf-8"))


def encrypted_zip_fixture() -> bytes:
    """展開不要で暗号化flagだけを検証できる最小ZIP fixtureを返す。"""

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("sample.bin", b"benign-test-fixture")
    data = bytearray(stream.getvalue())
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    if local < 0 or central < 0:
        raise AssertionError("ZIP fixture headerがありません")
    local_flags = int.from_bytes(data[local + 6 : local + 8], "little") | 1
    central_flags = int.from_bytes(data[central + 8 : central + 10], "little") | 1
    data[local + 6 : local + 8] = local_flags.to_bytes(2, "little")
    data[central + 8 : central + 10] = central_flags.to_bytes(2, "little")
    return bytes(data)


class FakeUrlResponse:
    """``urllib``応答の最小context manager。"""

    def __init__(self, body: bytes, status: int = 200) -> None:
        self.body = body
        self.status = status
        self.headers: dict[str, str] = {"Content-Type": "application/json"}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit: int) -> bytes:
        return self.body

    def getcode(self) -> int:
        return self.status


class HttpLayerTests(unittest.TestCase):
    """共有HTTP層とlimiterの再試行契約を検証する。"""

    def test_http_client_retries_429_without_exposing_secret(self) -> None:
        """429のRetry-Afterを尊重し、secretをerrorへ含めない。"""

        opener = Mock()
        opener.open.side_effect = [
            urllib.error.HTTPError(
                "https://example.invalid/?token=top-secret",
                429,
                "limited",
                {"Retry-After": "3"},
                None,
            ),
            FakeUrlResponse(b'{"ok": true}'),
        ]
        sleeper = Mock()
        client = api.HttpClient(opener=opener, sleeper=sleeper, attempts=2)

        response = client.request(
            "GET",
            "https://example.invalid/?token=top-secret",
            headers={"Authorization": "Bearer top-secret"},
        )

        self.assertEqual(response.json(), {"ok": True})
        sleeper.assert_called_once_with(3.0)
        self.assertEqual(opener.open.call_count, 2)

        opener.open.side_effect = urllib.error.HTTPError(
            "https://example.invalid/?token=top-secret", 401, "denied", {}, None
        )
        with self.assertRaises(api.ExternalServiceError) as caught:
            client.request(
                "GET",
                "https://example.invalid/?token=top-secret",
                headers={"Authorization": "Bearer top-secret"},
            )
        self.assertNotIn("top-secret", str(caught.exception))

    def test_rate_limiter_enforces_daily_limit(self) -> None:
        """設定した日次上限を超えるrequestを送信前に拒否する。"""

        limiter = api.RateLimiter(
            requests_per_minute=60,
            requests_per_day=1,
            clock=lambda: 0.0,
            day_provider=lambda: date(2026, 8, 9),
            sleeper=Mock(),
        )
        limiter.acquire()
        with self.assertRaises(api.RateLimitError):
            limiter.acquire()


class MalwareBazaarTests(unittest.TestCase):
    """MalwareBazaar helperの照会と暗号化archive保存を検証する。"""

    def test_query_and_download_success(self) -> None:
        """family照会を正規化し、暗号化ZIPのまま保存する。"""

        http = Mock()
        http.request.side_effect = [
            json_response(
                {
                    "query_status": "ok",
                    "data": [
                        {
                            "sha256_hash": "a" * 64,
                            "signature": "FixtureFamily",
                            "tags": ["exe", "fixture"],
                        }
                    ],
                }
            ),
            api.HttpResponse(200, {}, encrypted_zip_fixture()),
        ]
        client = api.MalwareBazaarClient(http=http)
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"MALWAREBAZAAR_AUTH_KEY": "test-key"}, clear=True
        ):
            rows = client.query_by_family("FixtureFamily", limit=1)
            result = client.download_sample("a" * 64, downloads_dir=Path(temporary))
            saved_archive = Path(result["archive_path"]).read_bytes()

        self.assertEqual(rows[0]["query_kind"], "family")
        self.assertEqual(rows[0]["sha256"], "a" * 64)
        self.assertTrue(result["archive_encrypted"])
        self.assertFalse(result["archive_extracted"])
        self.assertEqual(saved_archive, encrypted_zip_fixture())

    def test_missing_key_is_lazy(self) -> None:
        """client生成時は失敗せず、実操作時だけmissing keyを報告する。"""

        client = api.MalwareBazaarClient(http=Mock())
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(api.CredentialError, "MALWAREBAZAAR_AUTH_KEY"),
        ):
            client.query_by_hash("a" * 64)
        client.http.request.assert_not_called()


class MaxMindTests(unittest.TestCase):
    """MaxMindのoffline優先とoptional web serviceを検証する。"""

    def test_offline_lookup_does_not_require_license_key(self) -> None:
        """local MMDB指定時は環境資格情報なしで正規化する。"""

        city_record = {
            "country": {"iso_code": "JP", "names": {"ja": "日本"}},
            "city": {"names": {"ja": "東京"}},
            "location": {"latitude": 35.0, "longitude": 139.0},
        }
        asn_record = {
            "autonomous_system_number": 64500,
            "autonomous_system_organization": "Example Network",
        }

        class Reader:
            def __init__(self, value: dict) -> None:
                self.value = value

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def get(self, _ip: str) -> dict:
                return self.value

        fake_maxminddb = Mock()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            city_path = root / "GeoLite2-City.mmdb"
            asn_path = root / "GeoLite2-ASN.mmdb"
            city_path.touch()
            asn_path.touch()
            fake_maxminddb.open_database.side_effect = lambda path: Reader(
                city_record if "City" in path else asn_record
            )
            client = api.MaxMindClient(city_path, asn_path, http=Mock())
            with patch.dict(os.environ, {}, clear=True), patch.dict(
                sys.modules, {"maxminddb": fake_maxminddb}
            ):
                result = client.enrich_ip("8.8.8.8")

        self.assertEqual(result["country_code"], "JP")
        self.assertEqual(result["city"], "東京")
        self.assertEqual(result["asn"], 64500)
        self.assertEqual(result["organization"], "Example Network")
        client.http.request.assert_not_called()

    def test_web_lookup_success_and_missing_key(self) -> None:
        """web serviceは明示時だけ資格情報を要求し、共通dictを返す。"""

        http = Mock()
        http.request.return_value = json_response(
            {
                "country": {"iso_code": "US", "names": {"en": "United States"}},
                "city": {"names": {"en": "Mountain View"}},
                "traits": {
                    "autonomous_system_number": 15169,
                    "autonomous_system_organization": "Google LLC",
                },
            }
        )
        client = api.MaxMindClient(http=http)
        with patch.dict(
            os.environ,
            {"MAXMIND_ACCOUNT_ID": "123", "MAXMIND_LICENSE_KEY": "test-key"},
            clear=True,
        ):
            result = client.enrich_ip("8.8.8.8", use_web_service=True)
        self.assertEqual(result["asn"], 15169)
        self.assertEqual(result["organization"], "Google LLC")

        with (
            patch.dict(os.environ, {"MAXMIND_ACCOUNT_ID": "123"}, clear=True),
            self.assertRaisesRegex(api.CredentialError, "MAXMIND_LICENSE_KEY"),
        ):
            client.enrich_ip("8.8.8.8", use_web_service=True)


class VirusTotalTests(unittest.TestCase):
    """VirusTotal v3補強とlimiter連携を検証する。"""

    def test_enrichment_and_behavior_success(self) -> None:
        """file、IP、domain、behaviorをraw応答なしで正規化する。"""

        http = Mock()
        http.request.side_effect = [
            json_response(
                {
                    "data": {
                        "id": "a" * 64,
                        "attributes": {
                            "sha256": "a" * 64,
                            "size": 123,
                            "last_analysis_stats": {"malicious": 10, "undetected": 2},
                        },
                    }
                }
            ),
            json_response(
                {
                    "data": {
                        "id": "8.8.8.8",
                        "attributes": {"country": "US", "asn": 15169, "as_owner": "Google LLC"},
                    }
                }
            ),
            json_response(
                {
                    "data": {
                        "id": "example.com",
                        "attributes": {
                            "registrar": "Example Registrar",
                            "last_dns_records": [{"type": "A", "value": "8.8.8.8", "ttl": 60}],
                        },
                    }
                }
            ),
            json_response(
                {
                    "data": [
                        {
                            "id": "sandbox-1",
                            "attributes": {
                                "sandbox_name": "fixture-box",
                                "verdict": "malicious",
                                "contacted_domains": ["Example.COM"],
                                "ip_traffic": [{"destination_ip": "8.8.8.8"}],
                                "processes_tree": [{"name": "fixture.exe"}],
                            },
                        }
                    ]
                }
            ),
        ]
        limiter = Mock()
        client = api.VirusTotalClient(http=http, limiter=limiter)
        with patch.dict(os.environ, {"VT_API_KEY": "test-key"}, clear=True):
            file_result = client.enrich_file_hash("a" * 64)
            ip_result = client.enrich_ip("8.8.8.8")
            domain_result = client.enrich_domain("Example.COM")
            behavior = client.fetch_behavior_reports("a" * 64)

        self.assertEqual(file_result["last_analysis_stats"]["malicious"], 10)
        self.assertEqual(ip_result["organization"], "Google LLC")
        self.assertEqual(domain_result["last_dns_records"][0]["value"], "8.8.8.8")
        self.assertEqual(behavior["process_names"], ["fixture.exe"])
        self.assertTrue(behavior["network_context_only"])
        self.assertEqual(http.request.call_count, 4)

    def test_missing_key_does_not_consume_rate_limit(self) -> None:
        """VT keyがない場合はlimiterとnetworkの手前で明確に失敗する。"""

        http = Mock()
        limiter = Mock()
        client = api.VirusTotalClient(http=http, limiter=limiter)
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(api.CredentialError, "VT_API_KEY"):
            client.enrich_domain("example.com")
        http.request.assert_not_called()
        limiter.acquire.assert_not_called()


class TriageTests(unittest.TestCase):
    """Triageのsubmit、poll、report、artifact取得をmockで検証する。"""

    SAMPLE_ID = "260809-abcdefghij"

    @staticmethod
    def _safe_http() -> Mock:
        """redirect拒否capabilityを宣言したHTTP mockを返す。"""

        http = Mock()
        http.redirects_denied = True
        return http

    def test_submit_status_report_and_artifact_success(self) -> None:
        """主要操作がraw commandを公開せず、downloadを自動展開しない。"""

        http = self._safe_http()
        encrypted_sample = encrypted_zip_fixture()
        http.request.side_effect = [
            json_response({"id": self.SAMPLE_ID, "status": "submitted"}),
            json_response({"status": "completed"}),
            json_response(
                {
                    "processes": [
                        {"image": "C:/fixture/fixture.exe", "cmd": "fixture.exe --test"}
                    ],
                    "dumped": [{"path": "C:/fixture/dump.bin", "sha256": "b" * 64}],
                    "network": {"requests": [{"url": "https://example.com/path?token=secret"}]},
                }
            ),
            json_response(
                {
                    "extracted": [
                        {"resource": "behavioral1/memory/process-memory.dmp"}
                    ]
                }
            ),
            api.HttpResponse(200, {}, b"memory-fixture"),
            api.HttpResponse(200, {}, encrypted_sample),
        ]
        client = api.TriageClient(http=http, sleeper=Mock())
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"TRIAGE_API_KEY": "test-key"}, clear=True
        ):
            root = Path(temporary)
            sample = root / "fixture.bin"
            sample.write_bytes(b"benign-submit-fixture")
            submitted = client.submit_sample(sample, profiles=["win10"], tags=["fixture"])
            status = client.poll_analysis_status(self.SAMPLE_ID)
            report = client.retrieve_behavioral_report(self.SAMPLE_ID, "behavioral1")
            artifacts = client.list_memory_dump_artifacts(self.SAMPLE_ID)
            memory = client.retrieve_memory_dump(
                self.SAMPLE_ID,
                "behavioral1",
                "process-memory.dmp",
                root / "memory.dmp",
            )
            downloaded = client.fetch_sample(self.SAMPLE_ID, downloads_dir=root / "downloads")

            self.assertEqual(Path(memory["artifact_path"]).read_bytes(), b"memory-fixture")
            self.assertEqual(Path(downloaded["archive_path"]).read_bytes(), encrypted_sample)

        self.assertEqual(submitted["sample_id"], self.SAMPLE_ID)
        self.assertEqual(status["status"], "completed")
        self.assertEqual(report["process_names"], ["fixture.exe"])
        self.assertEqual(len(report["command_sha256"]), 1)
        self.assertEqual(report["network_context"], ["example.com"])
        self.assertFalse(report["raw_commands_included"])
        self.assertEqual(artifacts, [{"task_id": "behavioral1", "name": "process-memory.dmp", "kind": "memory_dump"}])
        self.assertFalse(downloaded["archive_extracted"])

    def test_fetch_sample_preserves_server_encrypted_zip(self) -> None:
        """server提供の暗号化ZIPはbyteを変更せず保存する。"""

        body = encrypted_zip_fixture()
        http = self._safe_http()
        http.request.return_value = api.HttpResponse(200, {}, body)
        client = api.TriageClient(http=http)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"TRIAGE_API_KEY": "test-key"}, clear=True),
        ):
            result = client.fetch_sample(
                self.SAMPLE_ID,
                downloads_dir=Path(temporary),
            )
            saved = Path(result["archive_path"]).read_bytes()

        self.assertEqual(saved, body)
        self.assertTrue(result["server_response_encrypted_zip"])
        self.assertEqual(result["source_sha256"], hashlib.sha256(body).hexdigest())
        self.assertEqual(result["source_size"], len(body))
        self.assertFalse(result["plaintext_written"])

    def test_fetch_sample_wraps_matching_raw_response_in_aes256(self) -> None:
        """完全SHA-256一致のraw応答だけをmemory上でAES-256へ包む。"""

        payload = b"MZ" + b"benign-raw-fixture" * 32
        expected = hashlib.sha256(payload).hexdigest()
        http = self._safe_http()
        http.request.return_value = api.HttpResponse(200, {}, payload)
        client = api.TriageClient(http=http)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"TRIAGE_API_KEY": "test-key"}, clear=True),
        ):
            root = Path(temporary)
            result = client.fetch_sample(
                self.SAMPLE_ID,
                downloads_dir=root,
                expected_sha256=expected,
                member_name="fixture.exe",
            )
            archive_path = Path(result["archive_path"])
            with pyzipper.AESZipFile(archive_path) as archive:
                archive.setpassword(b"infected")
                restored = archive.read("fixture.exe")
                encryption_strength = archive.getinfo("fixture.exe").wz_aes_strength
            plaintext_paths = [path for path in root.rglob("*") if path.is_file() and path != archive_path]

        self.assertEqual(restored, payload)
        self.assertEqual(encryption_strength, 3)
        self.assertEqual(plaintext_paths, [])
        self.assertFalse(result["server_response_encrypted_zip"])
        self.assertEqual(result["archive_encryption"], "WinZip AES-256")
        self.assertEqual(result["source_sha256"], expected)
        self.assertEqual(result["source_size"], len(payload))
        self.assertEqual(
            result["archive_size_limit"],
            api.DEFAULT_MAX_SAMPLE_BYTES,
        )
        self.assertFalse(result["plaintext_written"])

    def test_fetch_sample_rejects_archive_growth_beyond_limit(self) -> None:
        """AES archiveがsourceより増えて上限超過する場合は保存前に拒否する。"""

        payload = b"MZ"
        expected = hashlib.sha256(payload).hexdigest()
        http = self._safe_http()
        http.request.return_value = api.HttpResponse(200, {}, payload)
        client = api.TriageClient(http=http)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"TRIAGE_API_KEY": "test-key"}, clear=True),
        ):
            root = Path(temporary)
            with self.assertRaises(api.ExternalServiceError) as captured:
                client.fetch_sample(
                    self.SAMPLE_ID,
                    downloads_dir=root,
                    expected_sha256=expected,
                    max_bytes=len(payload),
                )
            self.assertEqual(list(root.rglob("*")), [])

        self.assertEqual(captured.exception.code, "archive_size_limit_exceeded")
        self.assertEqual(http.request.call_args.kwargs["max_bytes"], len(payload))

    def test_fetch_sample_rejects_invalid_max_before_request(self) -> None:
        """不正な応答上限は資格情報・network処理より先に拒否する。"""

        http = self._safe_http()
        client = api.TriageClient(http=http)
        for invalid in (0, True, api.DEFAULT_MAX_SAMPLE_BYTES + 1):
            with self.subTest(max_bytes=invalid), self.assertRaises(ValueError):
                client.fetch_sample(self.SAMPLE_ID, max_bytes=invalid)
        http.request.assert_not_called()

    def test_fetch_sample_rejects_raw_without_expected_sha256(self) -> None:
        """raw応答でexpected SHA-256がない場合は保存前に拒否する。"""

        http = self._safe_http()
        http.request.return_value = api.HttpResponse(200, {}, b"MZraw-fixture")
        client = api.TriageClient(http=http)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"TRIAGE_API_KEY": "test-key"}, clear=True),
        ):
            root = Path(temporary)
            with self.assertRaisesRegex(api.ExternalServiceError, "expected_sha256"):
                client.fetch_sample(self.SAMPLE_ID, downloads_dir=root)
            self.assertEqual(list(root.rglob("*")), [])

    def test_fetch_sample_rejects_raw_sha256_mismatch(self) -> None:
        """raw応答のSHA-256不一致ではarchiveを作らない。"""

        http = self._safe_http()
        http.request.return_value = api.HttpResponse(200, {}, b"MZraw-fixture")
        client = api.TriageClient(http=http)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"TRIAGE_API_KEY": "test-key"}, clear=True),
        ):
            root = Path(temporary)
            with self.assertRaisesRegex(api.ExternalServiceError, "一致しません"):
                client.fetch_sample(
                    self.SAMPLE_ID,
                    downloads_dir=root,
                    expected_sha256="0" * 64,
                )
            self.assertEqual(list(root.rglob("*")), [])

    def test_fetch_sample_never_overwrites_existing_destination(self) -> None:
        """既存archiveがある場合はraw一致後も内容を変更しない。"""

        payload = b"MZ" + b"raw-fixture" * 16
        expected = hashlib.sha256(payload).hexdigest()
        http = self._safe_http()
        http.request.return_value = api.HttpResponse(200, {}, payload)
        client = api.TriageClient(http=http)
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"TRIAGE_API_KEY": "test-key"}, clear=True),
        ):
            destination = Path(temporary) / "existing.zip"
            destination.write_bytes(b"preserve-existing")
            with self.assertRaises(FileExistsError):
                client.fetch_sample(
                    self.SAMPLE_ID,
                    output_path=destination,
                    expected_sha256=expected,
                )
            self.assertEqual(destination.read_bytes(), b"preserve-existing")
            self.assertEqual(list(destination.parent.glob(".*.part")), [])

    def test_missing_key_is_lazy(self) -> None:
        """Triage helperも操作時だけ環境資格情報を要求する。"""

        http = self._safe_http()
        client = api.TriageClient(http=http)
        with (
            patch.dict(os.environ, {}, clear=True),
            self.assertRaisesRegex(api.CredentialError, "TRIAGE_API_KEY"),
        ):
            client.get_analysis_status(self.SAMPLE_ID)
        http.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
