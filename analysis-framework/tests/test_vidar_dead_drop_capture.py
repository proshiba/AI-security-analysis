"""Vidar dead-drop限定取得器のoffline計画と安全境界を検証する。"""

from __future__ import annotations

import importlib
import ipaddress
import itertools
import json
import os
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

VIDAR = Path(__file__).parents[1] / "malware" / "vidar"
if str(VIDAR) not in sys.path:
    sys.path.insert(0, str(VIDAR))

CAPTURE = importlib.import_module("dead_drop_capture")
SNAPSHOT = importlib.import_module("dead_drop_snapshot")

SAMPLE_SHA256 = "a" * 64
EPIC_BASE_URL = "https://dev.epicgames.com/community/api/user_profiles/profile.json"
EPIC_URL = f"{EPIC_BASE_URL}?hash_id=EMqJL"


def _document() -> dict[str, Any]:
    return {
        "sha256": SAMPLE_SHA256,
        "endpoint_semantics": [
            {
                "url": "https://t.me/nag0a",
                "role": "dead_drop.telegram",
                "confidence": "confirmed_static_config",
            },
            {
                "url": EPIC_URL,
                "role": "dead_drop.epic_community_profile_candidate",
                "confidence": "confirmed_static_config",
            },
            {
                "url": "https://unsupported.example/profile",
                "role": "dead_drop.unknown",
                "confidence": "confirmed_static_config",
            },
        ],
        "records": [
            {"url": "https://t.me/nag0a", "tag": "o0oi1", "user_agent": "fixture"},
            {"url": EPIC_URL, "tag": "o0oi1", "user_agent": "fixture"},
        ],
    }


def _synthetic_vidar_blob() -> bytes:
    key = b"0123456789abcdef"
    urls = (b"https://t.me/nag0a", EPIC_URL.encode("ascii"))
    blob = bytearray(0x072 + 0x243 * (len(urls) + 1))
    blob[:16] = key

    def store(base: int, value_offset: int, length_offset: int, value: bytes) -> None:
        blob[base + length_offset] = len(value)
        blob[base + value_offset : base + value_offset + len(value)] = bytes(
            left ^ right for left, right in zip(value, itertools.cycle(key))
        )

    store(0, 0x010, 0x030, b"3.2")
    store(0, 0x031, 0x071, b"fixture")
    for index, url in enumerate(urls):
        base = 0x072 + 0x243 * index
        store(base, 0, 0x100, url)
        store(base, 0x101, 0x141, b"o0oi1")
        store(base, 0x142, 0x242, b"FixtureAgent/1")
    return bytes(blob)


def _epic_source() -> dict[str, Any]:
    plan = CAPTURE.build_capture_plan(_document())
    return next(item for item in plan["sources"] if item["service"] == "epic_games")


class _Headers:
    def __init__(self, pairs: list[tuple[str, str]]) -> None:
        self.pairs = pairs

    def get_all(self, name: str) -> list[str] | None:
        values = [value for key, value in self.pairs if key.casefold() == name.casefold()]
        return values or None

    def get(self, name: str, default: Any = None) -> Any:
        values = self.get_all(name)
        return values[-1] if values else default


class _Response:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        headers: Any = None,
    ) -> None:
        self.status = status
        self.headers = headers if headers is not None else {
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body)),
        }
        self.body = body
        self.closed = False
        self.maximum_read: int | None = None

    def read(self, maximum: int) -> bytes:
        self.maximum_read = maximum
        return self.body

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.request_data: tuple[Any, ...] | None = None
        self.closed = False

    def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
        self.request_data = (method, target, headers)

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


def _public_resolver(host: str, port: int, **kwargs: Any) -> list[tuple[Any, ...]]:
    assert host == "dev.epicgames.com"
    assert port == 443
    assert kwargs == {"type": socket.SOCK_STREAM, "proto": socket.IPPROTO_TCP}
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]


def _fixture_fetcher_for(body: bytes) -> Any:
    def fixture_fetcher(
        source: dict[str, Any],
        **kwargs: Any,
    ) -> tuple[bytes, dict[str, Any]]:
        assert kwargs["allow_network"] is True
        digest = __import__("hashlib").sha256(body).hexdigest()
        return body, {
            "service": source["service"],
            "source_url": source["source_url"],
            "http_status": 200,
            "content_type": "application/json",
            "body_size": len(body),
            "body_sha256": digest,
            "resolved_addresses": ["8.8.8.8"],
            "pinned_address": "8.8.8.8",
            "redirects_followed": False,
            "request_count": 1,
            "sample_executed": False,
            "network_contacted": True,
        }

    return fixture_fetcher


def _bounded_fixture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, Any],
) -> tuple[Path, dict[str, Any]]:
    monkeypatch.setattr(
        CAPTURE,
        "_bounded_builtin_fetch",
        _fixture_fetcher_for(b'{"profile":"8.8.8.8:443"}'),
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(document), encoding="utf-8")
    outcome = CAPTURE.capture_sources(
        document,
        services=["telegram", "epic_games"],
        private_output_directory=tmp_path / "private-bounded",
        allow_network=True,
        captured_at=lambda: datetime(2026, 9, 2, tzinfo=UTC),
    )
    return config_path, outcome


def test_capture_plan_normalizes_epic_candidate_without_confirming_it() -> None:
    plan = CAPTURE.build_capture_plan(_document())
    by_service = {item["service"]: item for item in plan["sources"]}

    assert by_service["telegram"]["confirmed_dead_drop"] is True
    assert by_service["epic_games"] == {
        "service": "epic_games",
        "source_url": EPIC_URL,
        "role": "dead_drop.epic_community_profile_candidate",
        "static_binding_status": "candidate_requires_response_corroboration",
        "eligible_for_capture": True,
        "confirmed_dead_drop": False,
    }
    assert by_service["unsupported"]["eligible_for_capture"] is False
    assert by_service["unsupported"]["confirmed_dead_drop"] is False
    assert plan["network_contacted"] is False
    assert plan["publication_policy"]["raw_response_publication_allowed"] is False


def test_sample_builder_hash_checks_and_recovers_exact_private_locator(tmp_path: Path) -> None:
    sample = tmp_path / "fixture.bin"
    raw = _synthetic_vidar_blob()
    sample.write_bytes(raw)
    digest = __import__("hashlib").sha256(raw).hexdigest()

    document = CAPTURE.build_capture_document_from_sample(sample, digest)
    plan = CAPTURE.build_capture_plan(document)

    assert document["safety"]["sample_executed"] is False
    assert document["config"]["records"][1]["url"] == EPIC_URL
    assert plan["eligible_service_count"] == 2
    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="SHA-256"):
        CAPTURE.build_capture_document_from_sample(sample, "b" * 64)


def test_publicly_redacted_epic_locator_is_not_capture_eligible() -> None:
    value = _document()
    locator_hash = __import__("hashlib").sha256(b"EMqJL").hexdigest()
    epic = value["endpoint_semantics"][1]
    epic["url"] = EPIC_BASE_URL
    epic["locator_query_present"] = True
    epic["locator_query_parameter"] = "hash_id"
    epic["locator_query_value_sha256"] = locator_hash
    value["records"][1]["url"] = EPIC_BASE_URL

    plan = CAPTURE.build_capture_plan(value)
    source = next(item for item in plan["sources"] if item["service"] == "epic_games")
    rendered = json.dumps(source, ensure_ascii=False)

    assert source["eligible_for_capture"] is False
    assert source["static_binding_status"] == "required_hash_id_redacted_or_missing"
    assert source["locator_query_value_sha256"] == locator_hash
    assert "EMqJL" not in rendered


@pytest.mark.parametrize(
    "url",
    (
        "http://dev.epicgames.com/community/api/user_profiles/profile.json",
        "https://dev.epicgames.com.evil.example/community/api/user_profiles/profile.json",
        EPIC_BASE_URL,
        "https://dev.epicgames.com/community/api/user_profiles/profile.json?user=1",
        "https://dev.epicgames.com/community/api/user_profiles/profile.json?hash_id=x",
        "https://dev.epicgames.com/community/api/user_profiles/profile.json?hash_id=EMqJL&x=1",
        "https://dev.epicgames.com/other/profile.json",
        "https://@dev.epicgames.com/community/api/user_profiles/profile.json",
        "https://:@dev.epicgames.com/community/api/user_profiles/profile.json",
        "https://dev.epicgames.com:/community/api/user_profiles/profile.json",
        " https://dev.epicgames.com/community/api/user_profiles/profile.json",
        "https://dev.epicgames.com/community/api/user_profiles/profile.json\t",
        "https://dev.epicgames.com/community/api/user_profiles/profile.json\r\nignored",
    ),
)
def test_epic_capture_requires_exact_https_service_route(url: str) -> None:
    value = _document()
    value["endpoint_semantics"][1]["url"] = url
    source = CAPTURE.build_capture_plan(value)["sources"][1]
    assert source["eligible_for_capture"] is False
    assert source["confirmed_dead_drop"] is False


def test_plan_omits_unsupported_url_credentials_and_query_tokens() -> None:
    secret = "do-not-publish-this-token"
    value = _document()
    value["endpoint_semantics"].append(
        {
            "url": f"https://user:{secret}@unsupported.example/path?token={secret}",
            "role": f"dead_drop.unknown.{secret}",
            "confidence": "confirmed_static_config",
        }
    )
    rendered = json.dumps(CAPTURE.build_capture_plan(value), ensure_ascii=False)
    assert secret not in rendered
    unsupported = json.loads(rendered)["sources"][-1]
    assert unsupported["source_url"] is None
    assert unsupported["raw_source_omitted"] is True


@pytest.mark.parametrize(
    ("service_index", "url", "role"),
    (
        (0, "https://t.me/nag0a?token=secret", "dead_drop.telegram"),
        (0, "https://t.me/nag0a", "dead_drop.telegram.typo"),
        (0, "https://www.pinterest.com/example/", "dead_drop.pinterest_extra"),
        (0, "https://steamcommunity.com/id/example", "dead_drop.steam_profile_extra"),
    ),
)
def test_query_and_unknown_role_suffix_are_not_capture_eligible(
    service_index: int,
    url: str,
    role: str,
) -> None:
    value = _document()
    value["endpoint_semantics"][service_index]["url"] = url
    value["endpoint_semantics"][service_index]["role"] = role
    source = CAPTURE.build_capture_plan(value)["sources"][service_index]
    assert source["eligible_for_capture"] is False


def test_fetch_is_off_by_default_before_dns_or_connection() -> None:
    def forbidden_resolver(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        raise AssertionError("DNS must not run")

    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="allow_network"):
        CAPTURE._fetch_static_source_in_process(
            _epic_source(), resolver=forbidden_resolver
        )


def test_epic_fixture_is_fetched_once_with_dns_pin_and_strict_get() -> None:
    body = b'{"bio":"8.8.8.8:443"}'
    response = _Response(body)
    connection = _Connection(response)
    observed: list[tuple[str, int, str, float]] = []

    def factory(host: str, port: int, address: str, timeout: float) -> _Connection:
        observed.append((host, port, address, timeout))
        return connection

    source = _epic_source()
    source["request_user_agent"] = "FixtureAgent/1"
    captured, metadata = CAPTURE._fetch_static_source_in_process(
        source,
        allow_network=True,
        resolver=_public_resolver,
        connection_factory=factory,
    )

    assert captured == body
    assert len(observed) == 1
    host, port, address, remaining_timeout = observed[0]
    assert (host, port, address) == ("dev.epicgames.com", 443, "8.8.8.8")
    assert 0 < remaining_timeout <= 10.0
    assert connection.request_data is not None
    assert connection.request_data[0:2] == (
        "GET",
        "/community/api/user_profiles/profile.json?hash_id=EMqJL",
    )
    assert connection.request_data[2]["Accept-Encoding"] == "identity"
    assert connection.request_data[2]["User-Agent"] == "FixtureAgent/1"
    assert response.maximum_read == CAPTURE.MAXIMUM_SNAPSHOT_BYTES + 1
    assert response.closed is True
    assert connection.closed is True
    assert metadata["request_count"] == 1
    assert metadata["redirects_followed"] is False
    assert metadata["pinned_address"] == "8.8.8.8"


def test_static_user_agent_rejects_header_injection_before_dns() -> None:
    source = _epic_source()
    source["request_user_agent"] = "Fixture\r\nX-Injected: yes"
    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="User-Agent"):
        CAPTURE._fetch_static_source_in_process(
            source,
            allow_network=True,
            resolver=lambda *args, **kwargs: pytest.fail("DNS must not run"),
        )


def test_mixed_public_and_private_dns_answers_are_rejected_before_connect() -> None:
    def resolver(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]

    def forbidden_factory(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("connection must not run")

    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="非global"):
        CAPTURE._fetch_static_source_in_process(
            _epic_source(),
            allow_network=True,
            resolver=resolver,
            connection_factory=forbidden_factory,
        )


@pytest.mark.parametrize(
    ("family", "address"),
    (
        (socket.AF_INET, "224.0.0.1"),
        (socket.AF_INET6, "ff0e::1"),
        (socket.AF_INET6, "fec0::1"),
        (socket.AF_INET6, "2002:0a00:0001::1"),
    ),
)
def test_multicast_dns_answer_is_rejected_before_connect(
    family: int,
    address: str,
) -> None:
    def resolver(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        return [(family, socket.SOCK_STREAM, 6, "", (address, 443))]

    def forbidden_factory(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("connection must not run")

    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="非global unicast"):
        CAPTURE._fetch_static_source_in_process(
            _epic_source(),
            allow_network=True,
            resolver=resolver,
            connection_factory=forbidden_factory,
        )


def test_multicast_endpoint_is_not_promoted_to_c2_candidate() -> None:
    assert SNAPSHOT._extract_endpoints("224.0.0.1:443 ff0e::1:443") == set()


def test_global_unicast_policy_rejects_site_local_and_keeps_public_ipv4() -> None:
    assert SNAPSHOT.is_global_unicast(ipaddress.ip_address("fec0::1")) is False
    assert SNAPSHOT.is_global_unicast(ipaddress.ip_address("::ffff:8.8.8.8")) is False
    assert SNAPSHOT.is_global_unicast(ipaddress.ip_address("2002:0808:0808::1")) is False
    assert SNAPSHOT.is_global_unicast(
        ipaddress.ip_address("2001:0000:4136:e378:8000:63bf:3fff:fdd2")
    ) is False
    assert SNAPSHOT.is_global_unicast(ipaddress.ip_address("8.8.8.8")) is True


@pytest.mark.parametrize(
    ("response", "message"),
    (
        (_Response(b"", status=302, headers={"Location": "https://example.com"}), "HTTP status"),
        (
            _Response(
                b"x",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(CAPTURE.MAXIMUM_SNAPSHOT_BYTES + 1),
                },
            ),
            "Content-Length",
        ),
        (
            _Response(
                b"x",
                headers={"Content-Type": "application/json", "Content-Encoding": "gzip"},
            ),
            "圧縮",
        ),
        (_Response(b"x", headers={"Content-Length": "1"}), "Content-Type"),
        (
            _Response(b"\xff", headers={"Content-Type": "text/plain"}),
            "UTF-8",
        ),
    ),
)
def test_redirect_oversize_and_compression_are_rejected(
    response: _Response,
    message: str,
) -> None:
    connection = _Connection(response)
    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match=message):
        CAPTURE._fetch_static_source_in_process(
            _epic_source(),
            allow_network=True,
            resolver=_public_resolver,
            connection_factory=lambda *args: connection,
        )
    assert connection.closed is True


@pytest.mark.parametrize(
    ("headers", "body", "message"),
    (
        (
            _Headers(
                [
                    ("Content-Type", "text/plain"),
                    ("Content-Length", "1"),
                    ("Content-Length", "1"),
                ]
            ),
            b"x",
            "Content-Lengthの重複",
        ),
        (
            {"Content-Type": "text/plain", "Content-Length": "2"},
            b"x",
            "受信byte数",
        ),
        (
            {"Content-Type": "text/plain", "Content-Range": "bytes 0-0/1"},
            b"x",
            "Content-Range",
        ),
        (
            {"Content-Type": "text/plain", "Transfer-Encoding": "gzip"},
            b"x",
            "未対応のTransfer-Encoding",
        ),
        (
            {
                "Content-Type": "text/plain",
                "Transfer-Encoding": "chunked",
                "Content-Length": "1",
            },
            b"x",
            "併用",
        ),
        ({"Content-Type": "text/plain", "Content-Length": "0"}, b"", "空のHTTP body"),
    ),
)
def test_http_framing_ambiguity_and_empty_body_are_rejected(
    headers: Any,
    body: bytes,
    message: str,
) -> None:
    connection = _Connection(_Response(body, headers=headers))
    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match=message):
        CAPTURE._fetch_static_source_in_process(
            _epic_source(),
            allow_network=True,
            resolver=_public_resolver,
            connection_factory=lambda *args: connection,
        )


def test_absolute_deadline_includes_dns_without_real_sleep() -> None:
    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()

    def resolver(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        clock.now = 11.0
        return _public_resolver(*args, **kwargs)

    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="DNS解決"):
        CAPTURE._fetch_static_source_in_process(
            _epic_source(),
            allow_network=True,
            timeout=10.0,
            resolver=resolver,
            connection_factory=lambda *args: pytest.fail("connection must not run"),
            monotonic=clock,
        )


def test_private_capture_manifest_can_be_correlated_without_publishing_raw(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    endpoint = b'{"profile":"8.8.8.8:443"}'

    def fixture_fetcher(
        source: dict[str, Any],
        **kwargs: Any,
    ) -> tuple[bytes, dict[str, Any]]:
        assert kwargs["allow_network"] is True
        digest = __import__("hashlib").sha256(endpoint).hexdigest()
        return endpoint, {
            "service": source["service"],
            "source_url": source["source_url"],
            "http_status": 200,
            "content_type": "application/json",
            "body_size": len(endpoint),
            "body_sha256": digest,
            "resolved_addresses": ["8.8.8.8"],
            "pinned_address": "8.8.8.8",
            "redirects_followed": False,
            "request_count": 1,
            "sample_executed": False,
            "network_contacted": True,
        }

    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_document()), encoding="utf-8")
    private = tmp_path / "private-capture"
    monkeypatch.setattr(CAPTURE, "_bounded_builtin_fetch", fixture_fetcher)
    outcome = CAPTURE.capture_sources(
        _document(),
        sample_sha256=SAMPLE_SHA256,
        services=["telegram", "epic_games"],
        private_output_directory=private,
        allow_network=True,
        captured_at=lambda: datetime(2026, 9, 2, tzinfo=UTC),
    )

    manifest_path = Path(outcome["manifest_path"])
    metadata = json.loads(Path(outcome["private_metadata_path"]).read_text(encoding="utf-8"))
    result = SNAPSHOT.analyze_snapshot_set(config_path, manifest_path)

    assert result["final_c2_candidate"] == "8.8.8.8:443"
    assert result["c2_confirmed"] is False
    assert result["snapshot_provenance"] == {
        "capture_mode": "bounded_opt_in_network_capture",
        "network_contacted_during_capture": True,
        "receipt_validation": "internally_verified_private_capture_receipt",
        "external_authenticity_established": False,
    }
    assert result["safety"] == {
        "network_contacted": False,
        "sample_executed": False,
        "tool_published_raw_response": False,
        "tool_managed_output_repository_publication": False,
        "shared_service_is_c2": False,
        "active_probe_required": False,
    }
    assert "body_path" not in json.dumps(result)
    assert metadata["publication_policy"]["raw_response_publication_allowed"] is False
    assert len(list(private.glob("*.body"))) == 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["capture_receipt"]["profile"] == CAPTURE.BOUNDED_CAPTURE_RECEIPT_PROFILE
    assert outcome["tool_published_raw_response"] is False
    assert outcome["tool_managed_output_repository_publication"] is False


def test_same_tag_bound_enc_value_from_two_services_recovers_candidate_without_protocol_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    encrypted = "4b93f7ebab5c2ac9bc31feaed1b9383b"
    body = f'{{"profile":"o0oi1 ENC:{encrypted}"}}'.encode("ascii")
    monkeypatch.setattr(CAPTURE, "_bounded_builtin_fetch", _fixture_fetcher_for(body))
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_document()), encoding="utf-8")
    outcome = CAPTURE.capture_sources(
        _document(),
        sample_sha256=SAMPLE_SHA256,
        services=["telegram", "epic_games"],
        private_output_directory=tmp_path / "private-enc",
        allow_network=True,
        captured_at=lambda: datetime(2026, 9, 2, tzinfo=UTC),
    )

    result = SNAPSHOT.analyze_snapshot_set(config_path, Path(outcome["manifest_path"]))
    rendered = json.dumps(result, ensure_ascii=False)

    assert result["status"] == "decoded_correlated_final_c2_candidate"
    assert result["final_c2_candidate"] == "fpw.13balien.org"
    assert result["corroborating_service_count"] == 2
    assert result["confidence"] == 0.95
    assert result["endpoint_resolution"] == {
        "method": "tag_bound_enc_decoder_two_service_correlation",
        "shared_service_response_decoded": True,
        "protocol_recovered": False,
        "protocol_status": "unresolved_static_protocol",
    }
    assert result["decoder"]["raw_key_published"] is False
    assert result["decoder"]["raw_ciphertext_published"] is False
    assert result["uncorroborated_final_c2_candidates"] == []
    assert encrypted not in rendered
    assert "Glasikprostik" not in rendered


def test_unbound_enc_tag_and_single_service_do_not_promote_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'{"profile":"wrong-tag ENC:4b93f7ebab5c2ac9bc31feaed1b9383b"}'
    monkeypatch.setattr(CAPTURE, "_bounded_builtin_fetch", _fixture_fetcher_for(body))
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_document()), encoding="utf-8")
    outcome = CAPTURE.capture_sources(
        _document(),
        sample_sha256=SAMPLE_SHA256,
        services=["telegram"],
        private_output_directory=tmp_path / "private-unbound",
        allow_network=True,
        captured_at=lambda: datetime(2026, 9, 2, tzinfo=UTC),
    )

    result = SNAPSHOT.analyze_snapshot_set(config_path, Path(outcome["manifest_path"]))

    assert result["status"] == "inconclusive_snapshot_set"
    assert result["final_c2_candidate"] is None
    assert result["observations"][0]["encoded_marker_count"] == 1
    assert result["observations"][0]["tag_bound_marker_count"] == 0


def test_one_tag_bound_enc_source_is_reported_but_not_promoted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b'{"profile":"o0oi1 ENC:4b93f7ebab5c2ac9bc31feaed1b9383b"}'
    monkeypatch.setattr(CAPTURE, "_bounded_builtin_fetch", _fixture_fetcher_for(body))
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_document()), encoding="utf-8")
    outcome = CAPTURE.capture_sources(
        _document(),
        sample_sha256=SAMPLE_SHA256,
        services=["telegram"],
        private_output_directory=tmp_path / "private-single-bound",
        allow_network=True,
        captured_at=lambda: datetime(2026, 9, 2, tzinfo=UTC),
    )

    result = SNAPSHOT.analyze_snapshot_set(config_path, Path(outcome["manifest_path"]))

    assert result["final_c2_candidate_recovered"] is False
    assert result["uncorroborated_final_c2_candidates"] == [
        {
            "endpoint": "fpw.13balien.org",
            "service_count": 1,
            "status": "tag_bound_decoded_requires_second_service",
        }
    ]


def test_handler_shaped_document_can_plan_capture_and_analyze(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nested_config = _document().copy()
    nested_config.pop("sha256")
    handler_document = {
        "result": {
            "sample_sha256": SAMPLE_SHA256,
            "config": nested_config,
        }
    }
    assert CAPTURE.build_capture_plan(handler_document)["eligible_service_count"] == 2
    config_path, outcome = _bounded_fixture(tmp_path, monkeypatch, handler_document)
    result = SNAPSHOT.analyze_snapshot_set(config_path, Path(outcome["manifest_path"]))
    assert result["sample_sha256"] == SAMPLE_SHA256
    assert result["snapshot_provenance"]["receipt_validation"] == (
        "internally_verified_private_capture_receipt"
    )


@pytest.mark.parametrize("mutation", ("metadata", "missing_receipt"))
def test_bounded_receipt_missing_or_tampered_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    config_path, outcome = _bounded_fixture(tmp_path, monkeypatch, _document())
    manifest_path = Path(outcome["manifest_path"])
    if mutation == "metadata":
        metadata_path = Path(outcome["private_metadata_path"])
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["captures"][0]["http_status"] = 201
        metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        message = "receipt SHA-256"
    else:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest.pop("capture_receipt")
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        message = "manifest key集合"
    with pytest.raises(SNAPSHOT.VidarDeadDropError, match=message):
        SNAPSHOT.analyze_snapshot_set(config_path, manifest_path)


def test_injected_test_transport_never_receives_bounded_provenance(
    tmp_path: Path,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_document()), encoding="utf-8")
    outcome = CAPTURE._capture_sources_for_test(
        _document(),
        sample_sha256=SAMPLE_SHA256,
        services=["telegram", "epic_games"],
        private_output_directory=tmp_path / "private-untrusted",
        fetcher=_fixture_fetcher_for(b'{"profile":"8.8.8.8:443"}'),
        captured_at=lambda: datetime(2026, 9, 2, tzinfo=UTC),
    )
    result = SNAPSHOT.analyze_snapshot_set(config_path, Path(outcome["manifest_path"]))
    assert result["snapshot_provenance"]["capture_mode"] == (
        "analyst_supplied_offline_snapshot"
    )
    assert result["snapshot_provenance"]["receipt_validation"] == "not_applicable"
    assert result["safety"]["tool_managed_output_repository_publication"] == (
        "not_assessed"
    )


def test_parent_recomputes_body_sha_and_rejects_transport_metadata(
    tmp_path: Path,
) -> None:
    fixture = _fixture_fetcher_for(b'{"profile":"8.8.8.8:443"}')

    def forged_fetcher(*args: Any, **kwargs: Any) -> tuple[bytes, dict[str, Any]]:
        body, metadata = fixture(*args, **kwargs)
        metadata["body_sha256"] = "0" * 64
        return body, metadata

    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="取得結果と不一致"):
        CAPTURE._capture_sources_for_test(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=tmp_path / "private-forged",
            fetcher=forged_fetcher,
            captured_at=lambda: datetime(2026, 9, 2, tzinfo=UTC),
        )


def test_snapshot_symlink_is_rejected_without_following_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, outcome = _bounded_fixture(tmp_path, monkeypatch, _document())
    manifest_path = Path(outcome["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    body_path = manifest_path.parent / manifest["snapshots"][0]["body_path"]
    saved = body_path.with_suffix(".saved")
    body_path.rename(saved)
    try:
        body_path.symlink_to(saved.name)
    except OSError:
        saved.rename(body_path)
        pytest.skip("この環境ではsymlinkを作成できません")
    with pytest.raises(SNAPSHOT.VidarDeadDropError, match="symlink|reparse"):
        SNAPSHOT.analyze_snapshot_set(config_path, manifest_path)


def test_snapshot_growth_during_single_handle_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, outcome = _bounded_fixture(tmp_path, monkeypatch, _document())
    manifest_path = Path(outcome["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    body_path = manifest_path.parent / manifest["snapshots"][0]["body_path"]
    body_identity = (body_path.stat().st_dev, body_path.stat().st_ino)
    original_read = SNAPSHOT.os.read
    changed = False

    def growing_read(descriptor: int, amount: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, amount)
        metadata = os.fstat(descriptor)
        if not changed and (metadata.st_dev, metadata.st_ino) == body_identity:
            try:
                with body_path.open("ab") as stream:
                    stream.write(b"x")
            except OSError:
                pytest.skip("この環境ではopen中fileを変更できません")
            changed = True
        return chunk

    monkeypatch.setattr(SNAPSHOT.os, "read", growing_read)
    with pytest.raises(SNAPSHOT.VidarDeadDropError, match="読取り中変更"):
        SNAPSHOT.analyze_snapshot_set(config_path, manifest_path)
    assert changed is True


@pytest.mark.parametrize(
    "captured_at",
    ("2026-02-30T00:00:00Z", "2099-01-01T00:00:00Z"),
)
def test_invalid_or_future_capture_time_is_rejected(
    tmp_path: Path,
    captured_at: str,
) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_document()), encoding="utf-8")
    outcome = CAPTURE._capture_sources_for_test(
        _document(),
        sample_sha256=SAMPLE_SHA256,
        services=["telegram", "epic_games"],
        private_output_directory=tmp_path / "private-time",
        fetcher=_fixture_fetcher_for(b'{"profile":"8.8.8.8:443"}'),
        captured_at=lambda: datetime(2026, 9, 2, tzinfo=UTC),
    )
    manifest_path = Path(outcome["manifest_path"])
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["snapshots"][0]["captured_at"] = captured_at
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(SNAPSHOT.VidarDeadDropError, match="実在|未来"):
        SNAPSHOT.analyze_snapshot_set(config_path, manifest_path)


def test_normalizer_rejects_conflicting_wrapper_hash_family_and_non_string_sha() -> None:
    nested = _document().copy()
    nested.pop("sha256")
    conflict = {
        "sample_sha256": SAMPLE_SHA256,
        "config": nested,
        "result": {
            "sample_sha256": "b" * 64,
            "config": {**nested, "family": "not-vidar"},
        },
    }
    with pytest.raises(SNAPSHOT.VidarDeadDropError, match="Vidarではありません"):
        SNAPSHOT.normalize_analysis_document(conflict)
    conflict["result"]["config"].pop("family")
    with pytest.raises(SNAPSHOT.VidarDeadDropError, match="sample SHA-256が不一致"):
        SNAPSHOT.normalize_analysis_document(conflict)
    conflict["result"]["sample_sha256"] = int("1" * 64)
    conflict["sample_sha256"] = int("1" * 64)
    with pytest.raises(SNAPSHOT.VidarDeadDropError, match="文字列"):
        SNAPSHOT.normalize_analysis_document(conflict)


@pytest.mark.parametrize(
    ("document", "message"),
    (
        ({**_document(), "config": []}, "config wrapper"),
        ({**_document(), "result": []}, "result wrapper"),
        (
            {
                "result": {
                    "sample_sha256": SAMPLE_SHA256,
                    "config": "not-an-object",
                }
            },
            "result.config wrapper",
        ),
    ),
)
def test_present_non_object_wrapper_is_rejected(
    document: dict[str, Any],
    message: str,
) -> None:
    with pytest.raises(SNAPSHOT.VidarDeadDropError, match=message):
        SNAPSHOT.normalize_analysis_document(document)


def test_public_artifact_directory_is_rejected_before_fetch(tmp_path: Path) -> None:
    called = False

    def forbidden_fetcher(*args: Any, **kwargs: Any) -> Any:
        nonlocal called
        called = True
        raise AssertionError("fetch must not run")

    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="analysis-results"):
        CAPTURE.capture_sources(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=tmp_path / "analysis-results" / "raw",
            allow_network=True,
        )
    assert called is False


def test_any_git_worktree_is_rejected_as_private_output(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".git").write_text("gitdir: elsewhere\n", encoding="utf-8")

    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="Git repository"):
        CAPTURE.capture_sources(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=repository / "private",
            allow_network=True,
        )


def test_preexisting_empty_private_directory_is_rejected(tmp_path: Path) -> None:
    private = tmp_path / "already-exists"
    private.mkdir()
    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="存在しない新規path"):
        CAPTURE.capture_sources(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=private,
            allow_network=True,
        )


@pytest.mark.skipif(os.name != "nt", reason="UNCはWindows固有")
def test_unc_private_output_is_rejected_before_network() -> None:
    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="UNC"):
        CAPTURE.capture_sources(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=Path(r"\\server\share\private"),
            allow_network=True,
        )


def test_mapped_remote_drive_type_is_rejected_before_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(CAPTURE, "_windows_drive_type", lambda path: 4)
    private = tmp_path / "remote-drive-output"
    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="mapped network drive"):
        CAPTURE.capture_sources(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=private,
            allow_network=True,
        )
    assert private.exists() is False


@pytest.mark.skipif(os.name != "nt", reason="Windows DACL固有")
def test_windows_dacl_is_applied_to_directory_and_every_placeholder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = CAPTURE._windows_apply_and_verify_private_dacl
    observed: list[tuple[str, bool, bool]] = []

    def recording(
        path: Path,
        *,
        directory: bool,
        create_directory: bool = False,
    ) -> None:
        original(
            path,
            directory=directory,
            create_directory=create_directory,
        )
        observed.append((path.name, directory, create_directory))

    monkeypatch.setattr(CAPTURE, "_windows_apply_and_verify_private_dacl", recording)
    with pytest.raises(RuntimeError, match="stop after ACL verification"):
        CAPTURE._capture_sources_for_test(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=tmp_path / "private-dacl",
            fetcher=lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError("stop after ACL verification")
            ),
        )
    assert observed == [
        ("private-dacl", True, True),
        ("snapshot-01-epic_games.body", False, False),
        ("capture-metadata.private.json", False, False),
        ("snapshot-manifest.private.json", False, False),
    ]


def test_timeout_cleanup_terminates_before_any_grace_join() -> None:
    class Process:
        pid = 1

        def __init__(self) -> None:
            self.alive = True
            self.calls: list[str] = []

        def is_alive(self) -> bool:
            return self.alive

        def terminate(self) -> None:
            self.calls.append("terminate")
            self.alive = False

        def kill(self) -> None:
            self.calls.append("kill")
            self.alive = False

        def join(self, timeout: float) -> None:
            self.calls.append(f"join:{timeout}")

    process = Process()
    CAPTURE._stop_process_bounded(process, terminate_first=True)
    assert process.calls[0] == "terminate"


@pytest.mark.skipif(os.name == "nt", reason="Windows ACLはst_modeでは検証しない")
def test_new_private_directory_uses_mode_0700(tmp_path: Path) -> None:
    private = tmp_path / "private-mode"

    def failing_fetcher(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("stop after preparation")

    with pytest.raises(RuntimeError, match="stop after preparation"):
        CAPTURE._capture_sources_for_test(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=private,
            fetcher=failing_fetcher,
        )
    assert private.stat().st_mode & 0o777 == 0o700


def test_private_directory_replacement_during_fetch_is_rejected(tmp_path: Path) -> None:
    private = tmp_path / "private-capture"
    moved = tmp_path / "private-capture-original"
    endpoint = b'{"profile":"8.8.8.8:443"}'

    def replacing_fetcher(
        source: dict[str, Any],
        **kwargs: Any,
    ) -> tuple[bytes, dict[str, Any]]:
        try:
            private.rename(moved)
        except OSError as exc:
            raise CAPTURE.VidarDeadDropCaptureError(
                "directory差し替えをOSが拒否しました"
            ) from exc
        private.mkdir()
        digest = __import__("hashlib").sha256(endpoint).hexdigest()
        return endpoint, {
            "service": source["service"],
            "source_url": source["source_url"],
            "body_sha256": digest,
        }

    with pytest.raises(CAPTURE.VidarDeadDropCaptureError, match="差し替え"):
        CAPTURE._capture_sources_for_test(
            _document(),
            sample_sha256=SAMPLE_SHA256,
            services=["epic_games"],
            private_output_directory=private,
            fetcher=replacing_fetcher,
        )
    placeholder_root = moved if moved.exists() else private
    if moved.exists():
        assert list(private.iterdir()) == []
    placeholders = list(placeholder_root.iterdir())
    assert {path.name for path in placeholders} == {
        "snapshot-01-epic_games.body",
        "capture-metadata.private.json",
        "snapshot-manifest.private.json",
    }
    assert all(path.stat().st_size == 0 for path in placeholders)


def test_cli_without_allow_network_only_prints_plan(tmp_path: Path, capsys: Any) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps(_document()), encoding="utf-8")

    assert CAPTURE.main(["--config", str(config)]) == 0
    rendered = json.loads(capsys.readouterr().out)
    assert rendered["network_contacted"] is False
    assert not (tmp_path / "private").exists()

    assert CAPTURE.main(["--config", str(config), "--service", "epic_games"]) == 2
    error = json.loads(capsys.readouterr().out)
    assert "--allow-network" in error["error"]
