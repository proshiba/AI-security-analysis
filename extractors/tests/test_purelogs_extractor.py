"""PureLogs静的extractorの回帰テスト。"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from extractors.purelogs import extract
from extractors.purelogs import extractor as purelogs_extractor
from extractors.purelogs.extractor import endpoint_candidates
from extractors.purelogs.managed_resource import PureLogsManagedResource


def test_extracts_corroborated_http_profile() -> None:
    """複数の固有pathで裏付けたC2だけを採用する。"""
    data = (
        b"https://logs.example.test:8443/ping\n"
        b"/plugin\n/userinfo\n/browser\n/filesearch/req\n/finish\n"
        b"protobuf-net\n"
    )
    result = extract(data, "decrypted-http.txt")
    assert result["config"]["variant"] == "purelogs_http_api"
    assert result["config"]["endpoints"] == ["logs.example.test:8443"]
    assert result["findings"][0]["confidence"] == "confirmed"
    assert result["network_contacted"] is False


def test_rejects_generic_browser_url() -> None:
    """一般的なbrowser文字列や単独URLをPureLogs C2に昇格させない。"""
    result = extract(b"https://example.test/browser", "generic.txt")
    assert result["config"]["variant"] == "unresolved_variant"
    assert result["config"]["endpoints"] == []
    assert result["findings"] == []


def test_endpoint_candidates_validate_ports() -> None:
    """不正portを除外し、URLの既定HTTPS portを補う。"""
    assert endpoint_candidates(
        "https://one.example/path two.example:56001 bad.example:70000"
    ) == ["one.example:443", "two.example:56001"]


def test_endpoint_candidates_reject_invalid_url_hostname_labels() -> None:
    """URL parserが受理してもDNS labelとして不正なhostは公開しない。"""

    assert endpoint_candidates(
        "https://bad_label.example/plugin https://good.example/plugin"
    ) == ["good.example:443"]


def test_structured_evidence_excludes_secondary_purerat_channel() -> None:
    """役割付き観測ではPureRAT channelをPureLogs C2へ混入させない。"""
    payload = {
        "channels": [
            {
                "role": "PureLogs HTTP API over TLS",
                "endpoint": "logs.example.test:8443",
            },
            {
                "role": "PureRAT/PureHVNC candidate binary channel over TLS",
                "endpoint": "rat.example.test:56001",
            },
        ],
        "observed_requests": ["/plugin", "/userinfo", "/filesearch/req", "/finish"],
    }
    result = extract(json.dumps(payload).encode(), "network-validation.json")
    assert result["config"]["variant"] == "purelogs_http_api"
    assert result["config"]["endpoints"] == ["logs.example.test:8443"]
    assert [item["value"] for item in result["findings"]] == ["logs.example.test:8443"]


def _varint(value: int) -> bytes:
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def _bytes_field(number: int, value: bytes) -> bytes:
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def test_recovers_base64_protobuf_config_without_publishing_aes_key() -> None:
    """PureLogs protobufからC2を回収し、AES鍵はhashだけを公開する。"""

    key = bytes(range(32))
    message = b"".join(
        (
            _bytes_field(1, b"https://logs.example.test:8443"),
            _bytes_field(2, key),
            _bytes_field(3, b"campaign-a"),
            _bytes_field(4, b"mutex-a"),
        )
    )
    encoded = base64.b64encode(message)
    data = b"purelogs\x00/plugin\x00" + encoded

    result = extract(data, "purelogs-config.bin")

    assert result["config"]["variant"] == "purelogs_protobuf_config"
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["decoded_config_recovered"] is True
    assert result["config"]["status"] == "purelogs_protobuf_config_recovered"
    assert result["config"]["endpoints"] == ["logs.example.test:8443"]
    assert result["config"]["protobuf"]["aes_key_sha256"] == [
        hashlib.sha256(key).hexdigest()
    ]
    assert key.hex() not in json.dumps(result)
    assert result["c2"][0]["confidence"] == "confirmed_static_configuration"


def test_rejects_protobuf_config_with_ambiguous_32_byte_keys() -> None:
    """通信鍵を一意に選べないprotobufを設定回収済みへ昇格させない。"""

    message = b"".join(
        (
            _bytes_field(1, b"https://logs.example.test:8443"),
            _bytes_field(2, b"A" * 32),
            _bytes_field(3, b"B" * 32),
            _bytes_field(4, b"campaign-a"),
            _bytes_field(5, b"mutex-a"),
        )
    )

    with pytest.raises(
        ValueError,
        match="PureLogs Base64/protobuf configuration was not found",
    ):
        purelogs_extractor.decode_config_blob(base64.b64encode(message).decode())


def test_configured_and_observed_endpoints_keep_distinct_provenance() -> None:
    """HTTP観測先をprotobuf設定由来の標準C2 recordへ昇格させない。"""

    key = bytes(range(32))
    message = b"".join(
        (
            _bytes_field(1, b"https://configured.example:8443"),
            _bytes_field(2, key),
            _bytes_field(3, b"campaign-a"),
            _bytes_field(4, b"mutex-a"),
        )
    )
    data = b"purelogs\x00https://observed.example:9443/plugin\x00" + base64.b64encode(
        message
    )

    result = extract(data, "mixed-evidence.bin")

    assert result["config"]["endpoints"] == [
        "configured.example:8443",
        "observed.example:9443",
    ]
    assert result["config"]["configured_endpoints"] == ["configured.example:8443"]
    assert result["config"]["observed_protocol_endpoints"] == ["observed.example:9443"]
    assert [item["host"] for item in result["c2"]] == ["configured.example"]
    findings = {item["value"]: item for item in result["findings"]}
    assert findings["configured.example:8443"]["role"] == "configured_c2"
    assert findings["configured.example:8443"]["source"] == ("base64_protobuf_config")
    assert findings["observed.example:9443"]["role"] == "observed_c2"


def test_protobuf_candidate_without_family_markers_does_not_confirm_family() -> None:
    """構造設定だけではPureLogs帰属や標準C2確証へ昇格させない。"""

    message = b"".join(
        (
            _bytes_field(1, b"https://unknown.example:443"),
            _bytes_field(2, b"K" * 32),
            _bytes_field(3, b"build"),
            _bytes_field(4, b"mutex"),
        )
    )
    result = extract(base64.b64encode(message), "unknown.bin")

    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["decoded_config_recovered"] is True
    assert result["config"]["status"] == (
        "protobuf_config_candidate_requires_family_evidence"
    )
    assert result["config"]["family_attribution_confirmed"] is False
    assert result["config"]["endpoints"] == []
    assert result["c2"] == []


@pytest.mark.parametrize("marker", [b"protobuf-net", b"/plugin"])
def test_single_generic_marker_does_not_promote_protobuf_candidate(
    marker: bytes,
) -> None:
    """設定shapeに一般markerを1個加えただけではfamily/C2確定にしない。"""

    message = b"".join(
        (
            _bytes_field(1, b"https://unknown.example:443"),
            _bytes_field(2, b"K" * 32),
            _bytes_field(3, b"build"),
            _bytes_field(4, b"mutex"),
        )
    )
    result = extract(marker + b"\x00" + base64.b64encode(message), "unknown.bin")

    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["decoded_config_recovered"] is True
    assert result["config"]["family_attribution_confirmed"] is False
    assert result["config"]["endpoints"] == []
    assert result["c2"] == []


def test_protobuf_net_and_one_path_do_not_promote_config_or_family() -> None:
    """共通library名と固有path 1個を設定・family確証へ昇格させない。"""

    message = b"".join(
        (
            _bytes_field(1, b"https://unknown.example:443"),
            _bytes_field(2, b"K" * 32),
            _bytes_field(3, b"build"),
            _bytes_field(4, b"mutex"),
        )
    )
    result = extract(
        b"protobuf-net\x00/plugin\x00" + base64.b64encode(message),
        "unknown.bin",
    )

    assert result["supports_family_attribution"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["supports_family_attribution"] is False
    assert result["config"]["endpoints"] == []
    assert result["c2"] == []


def test_weak_route_endpoint_finding_is_explicitly_unattributed() -> None:
    """弱いrouteのendpointをobserved C2と表現せず未帰属候補へ留める。"""

    result = extract(
        b"protobuf-net\x00https://candidate.example:8443/plugin",
        "weak-route.bin",
    )

    assert result["supports_family_attribution"] is False
    assert result["config"]["endpoints"] == ["candidate.example:8443"]
    assert result["c2"] == []
    assert result["findings"] == [
        {
            "kind": "network.endpoint",
            "value": "candidate.example:8443",
            "role": "family_unresolved_endpoint_candidate",
            "confidence": "unverified",
            "source": "static_or_decrypted_protocol_evidence",
            "family_attribution_confirmed": False,
            "c2_confirmation_allowed": False,
        }
    ]


def test_bounded_text_stops_before_unbounded_string_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """巨大な単一文字列は公開text上限で切り、全matchを複製しない。"""

    monkeypatch.setattr(purelogs_extractor, "MAX_SCAN_BYTES", 64)
    monkeypatch.setattr(purelogs_extractor, "MAX_TEXT_CHARS", 16)

    text, truncated = purelogs_extractor._bounded_text(b"A" * 64)

    assert text == "A" * 16
    assert truncated is True


def test_bounded_text_limits_short_string_object_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """短い断片を大量に与えてもlist／setのobject数を上限で止める。"""

    monkeypatch.setattr(purelogs_extractor, "MAX_TEXT_STRINGS", 2)

    text, truncated = purelogs_extractor._bounded_text(b"AAAA\x01BBBB\x01CCCC")

    assert text == "AAAA\nBBBB"
    assert truncated is True


def test_structured_metadata_size_limit_falls_back_to_text_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """JSON専用上限は通常入力のtext endpoint走査まで抑止しない。"""

    monkeypatch.setattr(purelogs_extractor, "MAX_STRUCTURED_METADATA_BYTES", 8)
    data = (
        b"https://logs.example.test:8443/plugin\n/userinfo\n/filesearch/req\n/finish\n"
    )

    assert purelogs_extractor._structured_channel_endpoints(data) is None
    result = extract(data, "large-static-input.bin")
    assert result["config"]["endpoints"] == ["logs.example.test:8443"]
    assert not any("endpoint候補数" in item for item in result["limitations"])


def test_multiple_unbound_protobuf_ports_fail_closed() -> None:
    """複数の整数候補をhostへcross productしてC2確定しない。"""

    key = bytes(range(32))
    message = b"".join(
        (
            _bytes_field(1, b"logs.example.test"),
            _bytes_field(2, key),
            _varint((3 << 3) | 0) + _varint(8443),
            _varint((4 << 3) | 0) + _varint(12345),
            _bytes_field(5, b"fixture-build"),
        )
    )

    result = extract(
        b"purelogs\x00/plugin\x00" + base64.b64encode(message),
        "ambiguous-ports.bin",
    )

    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["configured_endpoints"] == []
    assert result["c2"] == []


def test_endpoint_candidate_limit_suppresses_incomplete_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """URL列挙上限を超えた場合、部分的なC2集合を公開しない。"""

    monkeypatch.setattr(purelogs_extractor, "MAX_ENDPOINT_CANDIDATES", 1)
    data = (
        b"https://one.example/plugin\n"
        b"https://two.example/userinfo\n/filesearch/req\n/finish\n"
    )

    result = extract(data, "many-urls.txt")

    assert result["config"]["endpoints"] == []
    assert result["findings"] == []
    assert any("endpoint候補数" in item for item in result["limitations"])


def test_unrelated_url_is_not_mixed_into_corroborated_http_profile() -> None:
    """既知pathと無関係なURLをPureLogs C2へ混入させない。"""

    data = (
        b"https://logs.example.test:8443/plugin\n"
        b"https://download.example.test/payload.bin\n"
        b"/userinfo\n/filesearch/req\n/finish\n"
    )
    result = extract(data, "observed-http.txt")

    assert result["config"]["endpoints"] == ["logs.example.test:8443"]


def test_managed_resource_table_recovers_nested_url_and_separate_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """復元tableを優先し、URLと別fieldのportをC2設定へ結合する。"""

    key = bytes(range(32))
    nested = b"".join(
        (
            _bytes_field(1, b"https://192.0.2.16"),
            _varint((2 << 3) | 0) + _varint(8443),
            _varint((4 << 3) | 0) + _varint(1),
            _bytes_field(5, b"build"),
            _bytes_field(6, b"Default"),
            _bytes_field(7, key),
        )
    )
    wrapper = _bytes_field(7, nested)
    recovered_text = "\n".join(
        (
            "/plugin",
            "/userinfo",
            "/filesearch/req",
            "/finish",
            base64.b64encode(wrapper).decode("ascii"),
        )
    )

    recovered = PureLogsManagedResource(
        records=tuple(recovered_text.splitlines()),
        resource_sha256="0" * 64,
        decrypted_sha256="1" * 64,
        inflated_sha256="2" * 64,
        protector_key_sha256="3" * 64,
        header_identifier_sha256="4" * 64,
    )

    monkeypatch.setattr(
        purelogs_extractor,
        "recover_purelogs_managed_strings",
        lambda _data: recovered,
    )

    result = extract(b"MZ synthetic managed fixture", "terminal.exe")

    assert result["config"]["variant"] == "purelogs_protobuf_config"
    assert result["config"]["configured_endpoints"] == ["192.0.2.16:8443"]
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["managed_resource_recovery"]["record_count"] == 5
    assert result["c2"] == [
        {
            "host": "192.0.2.16",
            "port": 8443,
            "role": "c2",
            "confidence": "confirmed_static_configuration",
            "evidence": {
                "kind": "base64_protobuf_config",
                "aes_key_length_validated": True,
                "family_markers_correlated": True,
            },
        }
    ]
