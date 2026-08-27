from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_protocol_probe_profiles  # noqa: E402
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


def test_monitoring_plan_accepts_512_targets_and_rejects_513() -> None:
    value = plan()
    template = value["targets"][0]
    value["targets"] = [
        {
            **template,
            "target_id": f"fixture-{index}",
            "host": f"c2-{index}.example",
        }
        for index in range(monitor_recent_c2.MAX_MONITORING_TARGETS)
    ]
    monitor_recent_c2.validate_plan(value)
    value["targets"].append(
        {
            **template,
            "target_id": "fixture-over-limit",
            "host": "c2-over-limit.example",
        }
    )
    with pytest.raises(monitor_recent_c2.PlanError, match="512 endpoint"):
        monitor_recent_c2.validate_plan(value)


def test_tls_success_separates_reachability_from_c2_confidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_probe(_target, **kwargs):
        assert kwargs["allow_network"] is True
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

    monkeypatch.setattr(monitor_recent_c2, "probe_target_with_nmap", fake_probe)
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
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
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
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
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
        monitor_recent_c2,
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
            "execution_engine": "nmap_nse",
            "status": "dns_resolved",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": False,
            "target_connection_established": False,
            "application_data_sent": False,
            "resolved_ips": ["203.0.113.10"],
        },
    )
    result = monitor_recent_c2.monitor(value, allow_network=True)
    entry = result["results"][0]
    assert entry["observation"]["resolved_ips"] == ["203.0.113.10"]
    assert entry["observation"]["target_contact_attempted"] is False
    assert entry["assessment"]["state"] == "dns_resolved_c2_service_not_confirmed"
    assert entry["assessment"]["c2_operational_confidence"] == 0.0
    assert "（DNSのみ）" in monitor_recent_c2.render_markdown(result)


def reviewed_target(profile_id: str, host: str, port: int, protocol: str, method: str) -> dict:
    registry_pin = c2_protocol_probe_profiles.profile_registry_metadata()
    profile = c2_protocol_probe_profiles.resolve_profile(
        profile_id,
        host,
        port,
        expected_registry_sha256=registry_pin["sha256"],
    )
    return {
        "schema_version": 1,
        "analysis_window": {
            "start": "リポジトリ収録開始",
            "end": "2026-08-02T23:59:59+09:00",
        },
        "protocol_profile_registry": registry_pin,
        "targets": [
            {
                "target_id": profile_id,
                "family": profile["family"],
                "host": host,
                "port": port,
                "protocol": protocol,
                "method": method,
                "protocol_profile_id": profile_id,
                "protocol_profile_registry_source": registry_pin["source"],
                "protocol_profile_registry_sha256": registry_pin["sha256"],
                "transport": "direct",
                "sample_sha256s": profile["sample_sha256s"],
                "sources": ["fixture:reviewed"],
                "timeout_seconds": profile["timeout_seconds"],
                "maximum_request_bytes": profile.get("maximum_request_bytes"),
                "maximum_response_bytes": profile["maximum_response_bytes"],
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
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
            "execution_engine": "nmap_nse",
            "status": "winos_control_response",
            "alive": True,
            "c2_confirmed": True,
            "confidence": 0.95,
            "target_contact_attempted": True,
            "target_connection_established": True,
            "application_data_sent": True,
            "sent_bytes": 15,
            "received_bytes": 15,
            "resolved_ips": ["134.122.185.201"],
            "pinned_ip": "134.122.185.201",
            "channel_role": "control",
            "winos_response": {
                "declared_length": 15,
                "command": 0xC9,
            },
        },
    )
    result = monitor_recent_c2.monitor(value, allow_network=True)
    entry = result["results"][0]
    assert entry["assessment"]["state"] == "c2_protocol_confirmed"
    assert entry["observation"]["winos_response"]["command"] == 0xC9
    assert entry["observation"]["channel_role"] == "control"
    assert result["policy"]["malware_checkin_sent"] is True
    assert result["policy"]["stage_requested"] is False


def test_winos_ip_literal_dispatch_keeps_exact_profile_and_registry_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_id = "valleyrat-winos-heartbeat-20260810-64-81-30-192-6666"
    value = reviewed_target(
        profile_id,
        "64.81.30.192",
        6666,
        "winos",
        "winos_heartbeat",
    )
    expected_pin = value["protocol_profile_registry"]["sha256"]

    def fake_probe(target, **kwargs):
        assert kwargs["allow_network"] is True
        assert target["protocol_profile_registry_sha256"] == expected_pin
        profile = c2_protocol_probe_profiles.resolve_profile(profile_id, target["host"], target["port"])
        assert profile["profile_id"] == profile_id
        assert profile["host"] == profile["pinned_ips"][0] == "64.81.30.192"
        assert profile["channel_role"] == "stage_and_control"
        return {
            "execution_engine": "nmap_nse", "status": "winos_control_response",
            "alive": True, "c2_confirmed": True, "confidence": 0.95,
            "target_contact_attempted": True, "target_connection_established": True,
            "application_data_sent": True,
            "sent_bytes": 15,
            "received_bytes": 15,
            "dns_answers": ["64.81.30.192"],
            "pinned_ip": "64.81.30.192",
            "channel_role": "stage_and_control",
            "winos_response": {"declared_length": 15, "command": 0xC9},
            "stage_requested": False,
            "victim_metadata_sent": False,
            "operation_command_sent": False,
        }

    monkeypatch.setattr(monitor_recent_c2, "probe_target_with_nmap", fake_probe)
    result = monitor_recent_c2.monitor(value, allow_network=True)
    entry = result["results"][0]

    assert entry["assessment"]["state"] == "c2_protocol_confirmed"
    assert entry["observation"]["channel_role"] == "stage_and_control"
    assert entry["observation"]["pinned_ip"] == "64.81.30.192"
    assert result["policy"]["malware_checkin_sent"] is True
    assert result["policy"]["stage_requested"] is False
    assert result["policy"]["victim_metadata_sent"] is False
    assert entry["observation"]["operation_command_sent"] is False



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

    def fake_probe(target, **kwargs):
        assert target["protocol_profile_id"] == "valleyrat-vvas-8bf54-6666"
        assert kwargs["allow_network"] is True
        return {
            "execution_engine": "nmap_nse",
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

    monkeypatch.setattr(monitor_recent_c2, "probe_target_with_nmap", fake_probe)
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
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
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


def test_asyncrat_certificate_mismatch_does_not_exclude_c2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = reviewed_target(
        "asyncrat-058-20f21565-191-96-78-221-7788",
        "191.96.78.221",
        7788,
        "asyncrat",
        "asyncrat_tls_messagepack",
    )

    def fake_probe(_target, **kwargs):
        assert kwargs["allow_network"] is True
        assert kwargs["allow_application_probes"] is False
        return {
            "timestamp_utc": "2026-08-04T00:00:00+00:00",
            "status": "tls_handshake_only_application_probe_disabled",
            "alive": True,
            "c2_confirmed": False,
            "target_contact_attempted": True,
            "target_connection_established": True,
            "application_data_sent": False,
            "protocol_response_received": False,
            "resolved_ips": ["191.96.78.221"],
            "tls": {
                "handshake": True,
                "certificate": {
                    "state": "mismatch_inconclusive",
                    "exact_match": False,
                    "certificate_mismatch_excludes_c2": False,
                },
            },
            "certificate_mismatch_excludes_c2": False,
        }

    monkeypatch.setattr(monitor_recent_c2, "probe_target_with_nmap", fake_probe)
    result = monitor_recent_c2.monitor(value, allow_network=True)
    observation = result["results"][0]["observation"]
    assert observation["tls"]["certificate"]["state"] == "mismatch_inconclusive"
    assert observation["certificate_mismatch_excludes_c2"] is False
    assert result["policy"]["certificate_mismatch_excludes_c2"] is False
    assert result["results"][0]["assessment"]["state"] == "tls_endpoint_reachable_c2_not_confirmed"


def test_venomrat_application_probe_requires_separate_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = reviewed_target(
        "venomrat-603-6a24ba25-localto-6377",
        "s2gj9tonn.localto.net",
        6377,
        "venomrat",
        "venomrat_tls_messagepack",
    )

    def fake_probe(_target, **kwargs):
        assert kwargs["allow_application_probes"] is True
        return {
            "timestamp_utc": "2026-08-04T00:00:00+00:00",
            "status": "confirmed_tls_messagepack_c2",
            "alive": True,
            "c2_confirmed": True,
            "target_contact_attempted": True,
            "target_connection_established": True,
            "application_data_sent": True,
            "protocol_response_received": True,
            "request_count": 1,
            "request_budget_used": 1,
            "sent_bytes": 48,
            "received_bytes": 42,
            "response_packet": "Po_ng",
            "response_field_count": 1,
            "response_frame_size": 42,
            "response_frame_sha256": "a" * 64,
            "response_decoded_size": 15,
            "response_decoded_sha256": "b" * 64,
            "detector_status": "confirmed_tls_messagepack_c2",
            "tls_version_exact": True,
            "tls": {
                "handshake": True,
                "observed_version": "TLSv1.2",
                "expected_version": "TLSv1.2",
                "version_exact": True,
                "certificate": {
                    "state": "exact_match",
                    "exact_match": True,
                    "observed_sha256": (
                        "4370b606ee51b67ab75611600406eb74762f5c134309358d042d696d789c5e22"
                    ),
                    "expected_sha256": (
                        "4370b606ee51b67ab75611600406eb74762f5c134309358d042d696d789c5e22"
                    ),
                    "certificate_mismatch_excludes_c2": False,
                },
            },
            "certificate_mismatch_excludes_c2": False,
            "victim_metadata_sent": False,
            "stage_requested": False,
            "operation_command_sent": False,
            "command_polling_performed": False,
            "raw_request_published": False,
            "raw_response_published": False,
            "raw_response_retained": False,
            "synthetic_result_sent": False,
            "resolved_ips": ["93.184.216.34"],
        }

    monkeypatch.setattr(monitor_recent_c2, "probe_target_with_nmap", fake_probe)
    result = monitor_recent_c2.monitor(
        value,
        allow_network=True,
        allow_application_probes=True,
    )
    assert result["results"][0]["assessment"]["state"] == "c2_protocol_confirmed"
    assert result["policy"]["malware_checkin_sent"] is True
    assert result["policy"]["victim_metadata_sent"] is False


def test_agenttesla_authentication_is_fail_closed_without_vault() -> None:
    value = reviewed_target(
        "agenttesla-ftp-auth-3f091457-vilimorin",
        "ftp.vilimorin.com",
        21,
        "ftp",
        "ftp_authenticated",
    )
    result = monitor_recent_c2.monitor(
        value,
        allow_network=True,
        allow_authentication=True,
    )
    observation = result["results"][0]["observation"]
    assert observation["status"] == "private_credential_vault_missing"
    assert observation["target_contact_attempted"] is False
    assert observation["authentication_attempted"] is False


def test_agenttesla_accepted_credential_confirms_protocol(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    value = reviewed_target(
        "agenttesla-ftp-auth-3f091457-vilimorin",
        "ftp.vilimorin.com",
        21,
        "ftp",
        "ftp_authenticated",
    )
    vault = tmp_path / "private.json"
    vault.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        monitor_recent_c2,
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
            "execution_engine": "nmap_nse", "status": "sample_credential_ftp_login_succeeded",
            "alive": True, "c2_confirmed": True, "confidence": 0.95,
            "target_contact_attempted": True, "target_connection_established": True,
            "application_data_sent": True, "authentication_attempted": True,
            "authentication_accepted": True, "commands_sent": ["USER", "PASS", "QUIT"],
            "banner": {"code": "220", "raw_text_published": False},
            "user_reply_code": 331, "pass_reply_code": 230, "quit_reply_code": 221,
            "resolved_ips": ["93.184.216.34"], "file_transfer_attempted": False,
            "credential_material_published": False,
        },
    )
    result = monitor_recent_c2.monitor(
        value,
        allow_network=True,
        allow_authentication=True,
        private_credential_vault=vault,
    )
    entry = result["results"][0]
    assert entry["assessment"]["state"] == "c2_protocol_confirmed"
    assert entry["observation"]["authentication_accepted"] is True
    assert entry["observation"]["commands_sent"] == ["USER", "PASS", "QUIT"]
    assert entry["observation"]["credential_material_published"] is False
    assert entry["observation"]["file_transfer_attempted"] is False
    assert result["policy"]["malware_checkin_sent"] is False
    assert result["policy"]["authentication_attempted_count"] == 1
    assert result["policy"]["maximum_response_bytes"] == 1024
    rendered = monitor_recent_c2.render_markdown(result)
    assert "USER／必要時のPASS／QUIT" in rendered
    assert "認証情報は使用していません" not in rendered
    assert "応答最大1024 byte" in rendered
    serialized = json.dumps(result)
    assert "fixture-user" not in serialized
    assert "fixture-password" not in serialized


def test_agenttesla_invalid_private_vault_is_not_a_negative_c2_observation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    value = reviewed_target(
        "agenttesla-ftp-auth-3f091457-vilimorin",
        "ftp.vilimorin.com",
        21,
        "ftp",
        "ftp_authenticated",
    )
    vault = tmp_path / "invalid.json"
    vault.write_text("{}", encoding="utf-8")

    monkeypatch.setattr(
        monitor_recent_c2,
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
            "execution_engine": "nmap_nse",
            "status": "private_credential_vault_error",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": False,
            "target_connection_established": False,
            "application_data_sent": False,
        },
    )
    result = monitor_recent_c2.monitor(
        value,
        allow_network=True,
        allow_authentication=True,
        private_credential_vault=vault,
    )
    entry = result["results"][0]
    assert entry["observation"]["status"] == "private_credential_vault_error"
    assert entry["observation"]["target_contact_attempted"] is False
    assert entry["assessment"]["state"] == "not_observed_safety_gate"
    assert entry["assessment"]["negative_observation_confidence"] == 0.0


def test_stealc_registration_and_tasking_require_separate_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = reviewed_target(
        "stealc-v2-1backs-31-77-228-62-80",
        "31.77.228.62",
        80,
        "stealc",
        "stealc_v2_registration_task",
    )
    disabled = monitor_recent_c2.monitor(value, allow_network=True)
    assert disabled["results"][0]["observation"]["status"] == ("malware_registration_tasking_disabled")
    assert disabled["results"][0]["assessment"]["state"] == "not_observed_safety_gate"

    calls = []

    def fake_probe(target, **kwargs):
        calls.append((target["protocol_profile_id"], kwargs))
        return {
            "execution_engine": "nmap_nse",
            "status": "confirmed_stealc_registration_task",
            "alive": True,
            "c2_confirmed": True,
            "target_contact_attempted": True,
            "target_connection_established": True,
            "application_data_sent": True,
            "protocol_response_received": True,
            "registration_attempted": True,
            "registration_accepted": True,
            "task_poll_attempted": False,
            "task_response_received": False,
            "task_available": False,
            "task_content_published": False,
            "task_executed": False,
            "payload_download_attempted": False,
            "victim_metadata_sent": False,
            "synthetic_identity_sent": True,
            "resolved_ips": ["31.77.228.62"],
            "request_count": 1,
        }

    monkeypatch.setattr(monitor_recent_c2, "probe_target_with_nmap", fake_probe)
    enabled = monitor_recent_c2.monitor(value, allow_network=True, allow_malware_registration=True)
    assert calls[0][1]["allow_network"] is True
    assert calls[0][1]["allow_malware_registration"] is True
    assert enabled["results"][0]["assessment"]["state"] == "c2_protocol_confirmed"
    assert enabled["policy"]["registration_attempted_count"] == 1
    assert enabled["policy"]["maximum_response_bytes"] == 16384
    assert enabled["policy"]["maximum_application_requests_per_target"] == 3
    assert enabled["policy"]["task_poll_attempted_count"] == 0
    assert enabled["policy"]["task_content_published"] is False
    assert enabled["policy"]["task_executed"] is False
    assert enabled["policy"]["payload_download_attempted"] is False
    assert enabled["policy"]["command_polling_performed"] is False


def test_profile_required_performs_dns_only_and_keeps_c2_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = plan()
    value["targets"][0].update(
        {
            "host": "fallback.example",
            "port": 5776,
            "protocol": "tcp",
            "method": "protocol_profile_required",
            "protocol_hints": ["remusstealer"],
            "protocol_profile_required": True,
            "protocol_profile_status": "reviewed_exact_profile_missing",
        }
    )
    monkeypatch.setattr(
        monitor_recent_c2,
        "probe_target_with_nmap",
        lambda _target, **_kwargs: {
            "execution_engine": "nmap_nse",
            "status": "dns_resolved",
            "alive": False,
            "c2_confirmed": False,
            "target_contact_attempted": False,
            "target_connection_established": False,
            "application_data_sent": False,
            "resolved_ips": ["203.0.113.20"],
        },
    )

    result = monitor_recent_c2.monitor(value, allow_network=True)
    entry = result["results"][0]
    assert entry["observation"]["resolved_ips"] == ["203.0.113.20"]
    assert entry["observation"]["target_contact_attempted"] is False
    assert entry["assessment"]["state"] == "protocol_profile_required_c2_unverified"
    assert entry["assessment"]["c2_operational_confidence"] == 0.0
    assert entry["assessment"]["method_confidence_ceiling"] == 0.05
    assert entry["protocol_hints"] == ["remusstealer"]


def test_profile_required_rejects_missing_or_conflicting_fail_closed_metadata() -> None:
    value = plan()
    value["targets"][0].update(
        {
            "port": 5776,
            "protocol": "tcp",
            "method": "protocol_profile_required",
            "protocol_profile_required": True,
            "protocol_profile_status": "reviewed_exact_profile_missing",
        }
    )
    with pytest.raises(monitor_recent_c2.PlanError):
        monitor_recent_c2.validate_plan(value)
    value["targets"][0]["protocol_hints"] = ["remusstealer", "asyncrat"]
    with pytest.raises(monitor_recent_c2.PlanError):
        monitor_recent_c2.validate_plan(value)


def test_active_plan_rejects_cross_sample_overlay() -> None:
    value = reviewed_target(
        "valleyrat-winos-heartbeat-20260727",
        "haochisadnka.cc",
        6685,
        "winos",
        "winos_heartbeat",
    )
    value["targets"][0]["sample_sha256s"] = ["f" * 64]

    with pytest.raises(
        monitor_recent_c2.PlanError,
        match="sample",
    ):
        monitor_recent_c2.validate_plan(value)


def test_remus_unverified_task_schema_has_zero_c2_confidence() -> None:
    assessment = monitor_recent_c2.assess_observation(
        {"method": "remus_registration_task"},
        {
            "status": "remus_task_schema_unverified",
            "tcp_status": "open",
            "target_connection_established": True,
            "c2_confirmed": False,
        },
    )

    assert assessment["state"] == "remus_task_schema_unverified_c2_not_confirmed"
    assert assessment["reachability_confidence"] == 0.98
    assert assessment["c2_operational_confidence"] == 0.0
    assert assessment["negative_observation_confidence"] == 0.0
