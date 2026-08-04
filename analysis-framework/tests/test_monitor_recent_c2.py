from __future__ import annotations

import sys
from pathlib import Path

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import monitor_recent_c2  # noqa: E402


def plan() -> dict:
    return {
        "schema_version": 1,
        "analysis_window": {
            "start": "2026-07-26T00:00:00+09:00",
            "end": "2026-08-02T23:59:59+09:00",
        },
        "targets": [
            {
                "target_id": "fixture-443",
                "family": "fixture",
                "host": "c2.example",
                "port": 443,
                "protocol": "tls",
                "method": "tls_handshake",
                "transport": "direct",
                "sample_sha256s": ["a" * 64],
                "sources": ["fixture/config.json:c2"],
            }
        ],
    }


def test_tls_success_separates_reachability_from_c2_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe(args):
        assert args.allow_network is True
        assert args.send_hex is None
        assert args.n520_checkin is False
        return {
            "timestamp_utc": "2026-08-02T00:00:00+00:00",
            "status": "tls_connected",
            "tcp_status": "open",
            "alive": True,
            "c2_confirmed": False,
            "target_contact_attempted": True,
            "target_connection_established": True,
            "tls": {"version": "TLSv1.3"},
        }

    monkeypatch.setattr(monitor_recent_c2, "probe", fake_probe)
    result = monitor_recent_c2.monitor(plan(), allow_network=True)
    assessment = result["results"][0]["assessment"]
    assert assessment["state"] == "tls_endpoint_reachable_c2_not_confirmed"
    assert assessment["reachability_confidence"] == 0.95
    assert assessment["c2_operational_confidence"] == 0.40
    assert result["policy"]["malware_checkin_sent"] is False


def test_banner_body_and_sensitive_http_headers_are_not_published() -> None:
    sanitized = monitor_recent_c2._sanitize_observation(
        {
            "banner": {
                "length": 12,
                "sha256": "b" * 64,
                "prefix_base64": "MjIwIGZpeHR1cmUNCg==",
            },
            "http": {
                "status": 200,
                "headers": {
                    "server": "fixture",
                    "set-cookie": "secret=value",
                    "location": "/token/secret",
                },
            },
        }
    )
    assert "prefix_base64" not in sanitized["banner"]
    assert sanitized["banner"]["ftp_220_marker"] is True
    assert sanitized["http"]["headers"] == {"server": "fixture"}


@pytest.mark.parametrize(
    "target_patch",
    [
        {"host": "10.0.0.0/8"},
        {"host": "*.example"},
        {"ports": [80, 443]},
        {"send_hex": "00"},
        {"checkin": True},
        {"timeout_seconds": 5.1},
        {"maximum_response_bytes": 257},
        {"host": "exampleexampleexampleexampleexampleexampleexampleexample.onion"},
    ],
)
def test_rejects_ranges_payloads_and_unsafe_tor(target_patch: dict) -> None:
    value = plan()
    value["targets"][0].update(target_patch)
    with pytest.raises(monitor_recent_c2.PlanError):
        monitor_recent_c2.validate_plan(value)


def test_onion_requires_loopback_tor_and_tcp_connect() -> None:
    value = plan()
    value["targets"][0].update(
        {
            "host": "exampleexampleexampleexampleexampleexampleexampleexample.onion",
            "port": 80,
            "protocol": "tcp",
            "method": "tcp_connect",
            "transport": "tor-socks5",
        }
    )
    checked = monitor_recent_c2.validate_plan(value)
    args = monitor_recent_c2._probe_args(checked["targets"][0], False)
    assert args.proxy_host == "127.0.0.1"
    assert args.proxy_port == 9050
    assert args.connect_only is True


def test_markdown_is_japanese_and_states_confidence_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        monitor_recent_c2,
        "probe",
        lambda _args: {
            "timestamp_utc": "2026-08-02T00:00:00+00:00",
            "status": "tcp_connect_only",
            "tcp_status": "open",
            "alive": True,
            "target_contact_attempted": True,
            "target_connection_established": True,
        },
    )
    value = plan()
    value["targets"][0].update(
        {
            "port": 80,
            "protocol": "tcp",
            "method": "tcp_connect",
        }
    )
    rendered = monitor_recent_c2.render_markdown(
        monitor_recent_c2.monitor(value, allow_network=False),
    )
    assert "C2稼働状況" in rendered
    assert "TCP接続だけなら最大0.25" in rendered
    assert "malware check-in" in rendered


def test_markdown_renders_old_to_new_ip_with_as_geo_and_tags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        monitor_recent_c2,
        "probe",
        lambda _args: {
            "timestamp_utc": "2026-08-02T00:00:00+00:00",
            "status": "tcp_connect_only",
            "tcp_status": "open",
            "alive": True,
            "target_contact_attempted": True,
            "target_connection_established": True,
        },
    )
    result = monitor_recent_c2.monitor(plan(), allow_network=False)
    old_detail = {
        "ip": "193.26.115.118",
        "as": {"asn": 210558, "organization": "1337 Services GmbH"},
        "geo": {"country_name": "ドイツ", "subdivision_name": None, "city_name": None},
        "infrastructure": {
            "tags": [{"label": "防弾ホスティング"}, {"label": "ホスティング"}],
            "bulletproof_hosting": {"label": "防弾ホスティング"},
        },
    }
    new_detail = {
        "ip": "185.139.214.102",
        "as": {"asn": 200019, "organization": "Alexhost Srl"},
        "geo": {"country_name": "アメリカ", "subdivision_name": "ネバダ州", "city_name": "ラスベガス"},
        "infrastructure": {
            "tags": [{"label": "防弾ホスティング"}, {"label": "ホスティング"}],
            "bulletproof_hosting": {"label": "防弾ホスティング"},
        },
    }
    transition = {
        "observed_at_utc": "2026-08-02T00:00:00+00:00",
        "from": [old_detail],
        "to": [new_detail],
        "removed": [old_detail],
        "added": [new_detail],
        "classification": "infrastructure_ip_change",
    }
    result["results"][0]["dns_tracking"] = {
        "history": [{"ip_details": [new_detail]}],
        "transitions": [transition],
        "raw_ip_change_count": 1,
        "infrastructure_ip_change_count": 1,
        "shared_cdn_rotation_ignored_count": 0,
    }
    rendered = monitor_recent_c2.render_markdown(result)
    assert "旧IPから新IPへの遷移" in rendered
    assert "193[.]26[.]115[.]118" in rendered
    assert "AS210558 / 1337 Services GmbH" in rendered
    assert "185[.]139[.]214[.]102" in rendered
    assert "AS200019 / Alexhost Srl" in rendered
    assert "ネバダ州 / ラスベガス" in rendered
    assert "防弾ホスティング" in rendered


def test_dns_resolve_does_not_connect_to_c2_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = plan()
    value["targets"][0].update(
        {
            "port": 0,
            "protocol": "dns",
            "method": "dns_resolve",
        }
    )
    monkeypatch.setattr(
        monitor_recent_c2.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("203.0.113.10", 0))],
    )
    monkeypatch.setattr(
        monitor_recent_c2,
        "probe",
        lambda _args: pytest.fail("DNS-only観測でC2 serviceへ接続してはいけない"),
    )
    result = monitor_recent_c2.monitor(value, allow_network=True)
    entry = result["results"][0]
    assert entry["observation"]["resolved_ips"] == ["203.0.113.10"]
    assert entry["observation"]["target_contact_attempted"] is False
    assert entry["assessment"]["state"] == "dns_resolved_c2_service_not_confirmed"
    assert entry["assessment"]["c2_operational_confidence"] == 0.0
    assert "（DNSのみ）" in monitor_recent_c2.render_markdown(result)


def reviewed_target(profile_id: str, host: str, port: int, protocol: str, method: str) -> dict:
    return {
        "schema_version": 1,
        "analysis_window": {
            "start": "リポジトリ収録開始",
            "end": "2026-08-02T23:59:59+09:00",
        },
        "targets": [
            {
                "target_id": profile_id,
                "family": "valleyrat",
                "host": host,
                "port": port,
                "protocol": protocol,
                "method": method,
                "protocol_profile_id": profile_id,
                "transport": "direct",
                "sample_sha256s": ["e" * 64],
                "sources": ["fixture:reviewed"],
                "timeout_seconds": 3.0,
                "maximum_response_bytes": 64 if protocol != "n520" else 44,
            }
        ],
    }


def test_winos_heartbeat_confirms_only_reviewed_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = reviewed_target(
        "valleyrat-winos-heartbeat-20260727",
        "haochisadnka.cc",
        6685,
        "winos",
        "winos_heartbeat",
    )
    monkeypatch.setattr(
        monitor_recent_c2,
        "_probe_winos_reviewed",
        lambda profile, allow: {
            "connected": True,
            "sent_bytes": 15,
            "received_bytes": 15,
            "dns_answers": ["134.122.185.201"],
            "pinned_ip": "134.122.185.201",
            "response": {
                "declared_length": 15,
                "command": 0xC9,
                "role": "heartbeat_or_status",
                "complete": True,
            },
        },
    )
    result = monitor_recent_c2.monitor(value, allow_network=True)
    entry = result["results"][0]
    assert entry["assessment"]["state"] == "c2_protocol_confirmed"
    assert entry["observation"]["winos_response"]["command"] == 0xC9
    assert result["policy"]["malware_checkin_sent"] is True
    assert result["policy"]["stage_requested"] is False


def test_vvas_uses_registry_payload_without_stage_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = reviewed_target(
        "valleyrat-vvas-8bf54-6666",
        "202.95.8.27",
        6666,
        "vvas",
        "vvas_checkin",
    )

    def fake_probe(args):
        assert args.send_hex == "333200"
        assert args.expected_stage_size == 307214
        assert args.expected_header_size == 14
        assert args.max_bytes == 64
        assert args.artifact_zip is None
        return {
            "timestamp_utc": "2026-08-02T00:00:00+00:00",
            "status": "confirmed_vvas_c2",
            "alive": True,
            "c2_confirmed": True,
            "target_contact_attempted": True,
            "target_connection_established": True,
            "application_data_sent": True,
            "sent_hex": "333200",
            "resolved_ips": ["202.95.8.27"],
        }

    monkeypatch.setattr(monitor_recent_c2, "probe", fake_probe)
    result = monitor_recent_c2.monitor(value, allow_network=True)
    assert "sent_hex" not in result["results"][0]["observation"]
    assert result["results"][0]["assessment"]["state"] == "c2_protocol_confirmed"
    assert result["policy"]["reviewed_heartbeat_or_checkin_sent_count"] == 1


def test_n520_is_server_first_and_never_sends_checkin() -> None:
    value = reviewed_target(
        "valleyrat-n520-d11e793-9999",
        "118.107.21.88",
        9999,
        "n520",
        "n520_server_first",
    )
    target = monitor_recent_c2.validate_plan(value)["targets"][0]
    args = monitor_recent_c2._probe_args(target, True)
    assert args.sni == "update.microsoft.com"
    assert args.n520_checkin is False
    assert args.max_bytes == 44


def test_active_protocol_rejects_unknown_profile_and_plan_payload() -> None:
    value = reviewed_target(
        "valleyrat-winos-heartbeat-20260727",
        "haochisadnka.cc",
        6685,
        "winos",
        "winos_heartbeat",
    )
    value["targets"][0]["protocol_profile_id"] = "unreviewed"
    with pytest.raises(monitor_recent_c2.PlanError):
        monitor_recent_c2.validate_plan(value)
    value["targets"][0]["protocol_profile_id"] = "valleyrat-winos-heartbeat-20260727"
    value["targets"][0]["send_hex"] = "00"
    with pytest.raises(monitor_recent_c2.PlanError):
        monitor_recent_c2.validate_plan(value)

def test_markdown_uses_limited_scope_title(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        monitor_recent_c2,
        "probe",
        lambda _args: {
            "timestamp_utc": "2026-08-04T00:00:00+00:00",
            "status": "tcp_connect_only",
            "tcp_status": "open",
            "alive": True,
            "target_contact_attempted": True,
            "target_connection_established": True,
        },
    )
    value = plan()
    value["collection_scope"] = "valleyrat_pdfcore8_three_cases"
    rendered = monitor_recent_c2.render_markdown(
        monitor_recent_c2.monitor(value, allow_network=False),
    )
    assert rendered.startswith("# 対象限定のC2稼働状況")
    assert "監視scopeは `valleyrat_pdfcore8_three_cases`" in rendered
    assert "全履歴IOCから自動抽出" not in rendered
