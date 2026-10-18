"""PureLogs静的extractorの回帰テスト。"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from extractors.purehvnc import extractor as purehvnc_extractor
from extractors.purelogs import extract
from extractors.purelogs import extractor as purelogs_extractor
from extractors.purelogs.extractor import endpoint_candidates
from extractors.purelogs.managed_resource import (
    PureLogsManagedResource,
    PureLogsResourceConflictError,
    PureLogsResourceLimitError,
    PureLogsResourceScanIncomplete,
)


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


def test_endpoint_candidates_reject_invalid_numeric_dotted_quad() -> None:
    """IPv4として不正なnumeric dotted-quadをdomain扱いしない。"""

    assert endpoint_candidates(
        "999.999.999.999:443 https://01.02.03.04/plugin good.example:56001"
    ) == ["good.example:56001"]


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


def _encoded_config(endpoint: str, key: bytes) -> bytes:
    """一意なPureLogs設定fixtureをBase64で返す。"""

    message = b"".join(
        (
            _bytes_field(1, endpoint.encode("ascii")),
            _bytes_field(2, key),
            _bytes_field(3, b"campaign-a"),
            _bytes_field(4, b"mutex-a"),
        )
    )
    return base64.b64encode(message)


def _managed_resource(records: tuple[str, ...]) -> PureLogsManagedResource:
    """公開証拠を持つ合成managed resourceを生成する。"""

    return PureLogsManagedResource(
        records=records,
        resource_sha256="0" * 64,
        decrypted_sha256="1" * 64,
        inflated_sha256="2" * 64,
        protector_key_sha256="3" * 64,
        header_identifier_sha256="4" * 64,
    )


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


def test_bounded_text_keeps_utf16le_visible_after_ascii_decoy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """先行ASCII decoyがあってもUTF-16LE文字列へ走査枠を残す。"""

    monkeypatch.setattr(purelogs_extractor, "MAX_TEXT_CHARS", 16)
    data = b"A" * 64 + b"\x01BBBB\x01" + "/plugin".encode("utf-16le")

    text, truncated = purelogs_extractor._bounded_text(data)

    assert "/plugin" in text
    assert len(text) <= 16
    assert truncated is True


def test_bounded_text_reserves_quota_for_ascii_and_utf16le_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ASCII断片が件数上限を先取りしてもUTF-16LE走査を枯渇させない。"""

    monkeypatch.setattr(purelogs_extractor, "MAX_TEXT_STRINGS", 4)
    data = b"AAAA\x01BBBB\x01CCCC\x01DDDD\x01" + "/plugin".encode("utf-16le")

    text, truncated = purelogs_extractor._bounded_text(data)

    assert "/plugin" in text.splitlines()
    assert len(text.splitlines()) <= 4
    assert truncated is True


def test_bounded_text_duplicate_at_quota_boundary_keeps_scanning() -> None:
    """他encodingの既出値がquotaと同長でも後続値を捨てない。"""

    original_chars = purelogs_extractor.MAX_TEXT_CHARS
    try:
        purelogs_extractor.MAX_TEXT_CHARS = 9
        data = (
            b"ABCD\x01"
            + "ABCD".encode("utf-16le")
            + b"\x01"
            + "WXYZ".encode("utf-16le")
        )

        text, truncated = purelogs_extractor._bounded_text(data)
    finally:
        purelogs_extractor.MAX_TEXT_CHARS = original_chars

    assert text.splitlines() == ["ABCD", "WXYZ"]
    assert truncated is False


def test_bounded_text_marks_unscanned_match_after_exact_quota() -> None:
    """quota到達後に後続matchがある場合は未完了として返す。"""

    original_chars = purelogs_extractor.MAX_TEXT_CHARS
    try:
        purelogs_extractor.MAX_TEXT_CHARS = 9
        data = (
            b"ABCD\x01"
            + "ABCD".encode("utf-16le")
            + b"\x01"
            + "WXYZ".encode("utf-16le")
            + b"\x01"
            + "QRST".encode("utf-16le")
        )

        text, truncated = purelogs_extractor._bounded_text(data)
    finally:
        purelogs_extractor.MAX_TEXT_CHARS = original_chars

    assert text.splitlines() == ["ABCD", "WXYZ"]
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


def test_raw_config_is_searched_when_managed_resource_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """managed復元時もraw文字列にだけある設定を独立して回収する。"""

    encoded = _encoded_config("https://raw.example:8443", b"R" * 32)
    recovered = _managed_resource(
        ("/plugin", "/userinfo", "/filesearch/req", "/finish")
    )
    monkeypatch.setattr(
        purelogs_extractor,
        "recover_purelogs_managed_strings",
        lambda _data: recovered,
    )

    result = extract(b"purelogs\x00" + encoded, "raw-config.bin")

    assert result["config"]["configured_endpoints"] == ["raw.example:8443"]
    assert result["config"]["static_config_recovered"] is True


@pytest.mark.parametrize(
    ("error_type", "expected_status"),
    (
        (
            PureLogsResourceScanIncomplete,
            "managed_resource_candidate_set_incomplete",
        ),
        (PureLogsResourceLimitError, "managed_resource_scan_limit_exceeded"),
        (
            PureLogsResourceConflictError,
            "conflicting_managed_resource_candidates",
        ),
    ),
)
def test_managed_resource_scan_failure_blocks_valid_raw_config(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[PureLogsResourceScanIncomplete],
    expected_status: str,
) -> None:
    """resource走査未完了時はraw側の先行設定も公開しない。"""

    encoded = _encoded_config("https://raw.example:8443", b"R" * 32)
    monkeypatch.setattr(
        purelogs_extractor,
        "recover_purelogs_managed_strings",
        lambda _data: (_ for _ in ()).throw(error_type("fixture")),
    )

    result = extract(
        b"PureLogs /plugin /userinfo /filesearch/req /finish " + encoded,
        "raw-config-resource-failure.bin",
    )

    assert result["config"]["status"] == expected_status
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["configured_endpoints"] == []
    assert result["config"]["managed_resource_recovery"]["status"] == (expected_status)
    assert (
        result["config"]["managed_resource_recovery"]["candidate_set_complete"] is False
    )
    assert result["c2"] == []


def test_raw_and_managed_sources_share_base64_work_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """rawとresourceを別々の総work上限で二重に走査しない。"""

    valid = _encoded_config("https://raw.example:8443", b"R" * 32)
    noise = base64.b64encode(b"N" * 48)
    recovered = _managed_resource(
        (
            "/plugin",
            "/userinfo",
            "/filesearch/req",
            "/finish",
            noise.decode("ascii"),
        )
    )
    monkeypatch.setattr(
        purelogs_extractor,
        "recover_purelogs_managed_strings",
        lambda _data: recovered,
    )
    monkeypatch.setattr(
        purelogs_extractor,
        "MAX_CONFIG_BASE64_WORK_CHARS",
        len(valid) + len(noise) - 1,
    )

    result = extract(
        b"PureLogs /plugin /userinfo /filesearch/req /finish " + valid,
        "shared-work-budget.bin",
    )

    assert result["config"]["status"] == "configuration_candidate_scan_incomplete"
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["configured_endpoints"] == []
    assert result["c2"] == []


def test_same_config_in_raw_and_managed_sources_is_deduplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じidentityの設定は複数の文字列源にあっても競合扱いしない。"""

    encoded = _encoded_config("https://same.example:8443", b"S" * 32)
    recovered = _managed_resource(
        (
            "/plugin",
            "/userinfo",
            "/filesearch/req",
            "/finish",
            encoded.decode("ascii"),
        )
    )
    monkeypatch.setattr(
        purelogs_extractor,
        "recover_purelogs_managed_strings",
        lambda _data: recovered,
    )

    result = extract(b"purelogs\x00" + encoded, "duplicate-config.bin")

    assert result["config"]["status"] == "purelogs_protobuf_config_recovered"
    assert result["config"]["configured_endpoints"] == ["same.example:8443"]


def test_conflicting_raw_and_managed_configs_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """rawとmanagedの設定identityが異なる場合はC2を公開しない。"""

    raw_encoded = _encoded_config("https://raw.example:8443", b"R" * 32)
    managed_encoded = _encoded_config("https://managed.example:9443", b"M" * 32)
    recovered = _managed_resource(
        (
            "/plugin",
            "/userinfo",
            "/filesearch/req",
            "/finish",
            managed_encoded.decode("ascii"),
        )
    )
    monkeypatch.setattr(
        purelogs_extractor,
        "recover_purelogs_managed_strings",
        lambda _data: recovered,
    )

    result = extract(b"purelogs\x00" + raw_encoded, "conflicting-config.bin")

    assert result["config"]["status"] == "conflicting_configuration_candidates"
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["configured_endpoints"] == []
    assert result["c2"] == []


def test_truncated_raw_scan_does_not_publish_an_early_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未走査領域に相反設定があり得る場合は先行候補を採用しない。"""

    encoded = _encoded_config("https://early.example:8443", b"E" * 32)
    prefix = b"PureLogs /plugin /userinfo /filesearch/req /finish " + encoded + b"\x00"
    monkeypatch.setattr(purelogs_extractor, "MAX_SCAN_BYTES", len(prefix))

    result = extract(prefix + b"A" * 128, "truncated-config.bin")

    assert result["config"]["status"] == "configuration_candidate_scan_incomplete"
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["configured_endpoints"] == []
    assert result["c2"] == []


def test_protobuf_message_limit_does_not_hide_behind_a_valid_config() -> None:
    """未完了の入れ子候補と正常設定が併存してもC2を公開しない。"""

    valid = _encoded_config("https://good.example:8443", b"G" * 32)
    oversized_nested = b"".join(
        _bytes_field(12, _bytes_field(1, index.to_bytes(2, "little")))
        for index in range(purelogs_extractor.MAX_CONFIG_MESSAGES + 1)
    )
    encoded_nested = base64.b64encode(oversized_nested)
    data = (
        b"PureLogs /plugin /userinfo /filesearch/req /finish "
        + valid
        + b" "
        + encoded_nested
    )

    result = extract(data, "candidate-limit.bin")

    assert result["config"]["status"] == "configuration_candidate_scan_incomplete"
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["configured_endpoints"] == []
    assert result["c2"] == []


def test_many_bounded_base64_noise_candidates_do_not_hide_valid_config() -> None:
    """短いprotector metadataが64件を超えても総work内なら設定を回収する。"""

    noise = [base64.b64encode(index.to_bytes(16, "little")) for index in range(96)]
    valid = _encoded_config("https://many.example:8443", b"M" * 32)
    data = b"PureLogs /plugin /userinfo /filesearch/req /finish " + b" ".join(
        (*noise, valid)
    )

    result = extract(data, "many-bounded-candidates.bin")

    assert result["config"]["status"] == "purelogs_protobuf_config_recovered"
    assert result["config"]["configured_endpoints"] == ["many.example:8443"]


def test_base64_total_work_limit_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """候補件数を許容しても総decode work上限到達は成功へ降格しない。"""

    valid = _encoded_config("https://good.example:8443", b"G" * 32)
    monkeypatch.setattr(
        purelogs_extractor,
        "MAX_CONFIG_BASE64_WORK_CHARS",
        len(valid) + 63,
    )
    data = (
        b"PureLogs /plugin /userinfo /filesearch/req /finish "
        + valid
        + b" "
        + base64.b64encode(b"A" * 48)
    )

    result = extract(data, "base64-work-limit.bin")

    assert result["config"]["status"] == "configuration_candidate_scan_incomplete"
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["configured_endpoints"] == []
    assert result["c2"] == []


def test_shared_protobuf_field_limit_does_not_hide_behind_a_valid_config() -> None:
    """共有parserのfield上限到達も通常のno-matchとして無視しない。"""

    valid = _encoded_config("https://good.example:8443", b"G" * 32)
    oversized_fields = b"".join(
        _varint(1 << 3) + _varint(index)
        for index in range(purehvnc_extractor.MAX_CONFIG_PROTOBUF_FIELDS + 1)
    )
    data = (
        b"PureLogs /plugin /userinfo /filesearch/req /finish "
        + valid
        + b" "
        + base64.b64encode(oversized_fields)
    )

    result = extract(data, "field-limit.bin")

    assert result["config"]["status"] == "configuration_candidate_scan_incomplete"
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["configured_endpoints"] == []
    assert result["c2"] == []
