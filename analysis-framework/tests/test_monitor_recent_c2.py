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
    sanitized = monitor_recent_c2._sanitize_observation({
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
    })
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
    value["targets"][0].update({
        "host": "exampleexampleexampleexampleexampleexampleexampleexample.onion",
        "port": 80,
        "protocol": "tcp",
        "method": "tcp_connect",
        "transport": "tor-socks5",
    })
    checked = monitor_recent_c2.validate_plan(value)
    args = monitor_recent_c2._probe_args(checked["targets"][0], False)
    assert args.proxy_host == "127.0.0.1"
    assert args.proxy_port == 9050
    assert args.connect_only is True


def test_markdown_is_japanese_and_states_confidence_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(monitor_recent_c2, "probe", lambda _args: {
        "timestamp_utc": "2026-08-02T00:00:00+00:00",
        "status": "tcp_connect_only",
        "tcp_status": "open",
        "alive": True,
        "target_contact_attempted": True,
        "target_connection_established": True,
    })
    value = plan()
    value["targets"][0].update({
        "port": 80,
        "protocol": "tcp",
        "method": "tcp_connect",
    })
    rendered = monitor_recent_c2.render_markdown(
        monitor_recent_c2.monitor(value, allow_network=False),
    )
    assert "C2稼働状況" in rendered
    assert "TCP接続だけなら最大0.25" in rendered
    assert "malware check-in" in rendered
