from __future__ import annotations

import json
import sys
from pathlib import Path


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_infrastructure_tags as tags  # noqa: E402
import c2_monitoring_history as history  # noqa: E402


def record(
    ip: str,
    asn: int,
    organization: str,
    *,
    country: str = "ドイツ",
    country_code: str = "DE",
    city: str = "フランクフルト",
) -> dict:
    return {
        "ip": ip,
        "as": {
            "autonomous_system_number": asn,
            "autonomous_system_organization": organization,
        },
        "geo": {
            "country_iso_code": country_code,
            "country_name": country,
            "subdivision_iso_code": None,
            "subdivision_name": None,
            "city_name": city,
            "latitude": 50.11,
            "longitude": 8.68,
            "accuracy_radius_km": 50,
            "time_zone": "Europe/Berlin",
        },
    }


def tag_ids(detail: dict) -> set[str]:
    return {item["id"] for item in detail["infrastructure"]["tags"]}


def test_registry_distinguishes_confirmed_suspected_and_cdn() -> None:
    registry = tags.load_registry()
    confirmed = tags.build_ip_detail(
        record("193.26.115.118", 210558, "1337 Services GmbH"),
        host="logs.example",
        shared_cdn_provider=None,
        registry=registry,
    )
    suspected = tags.build_ip_detail(
        record("134.122.185.201", 152194, "CTG Server Limited"),
        host="c2.example",
        shared_cdn_provider=None,
        registry=registry,
    )
    cdn = tags.build_ip_detail(
        record("104.21.1.1", 13335, "Cloudflare, Inc."),
        host="edge.example",
        shared_cdn_provider="Cloudflare",
        registry=registry,
    )

    assert confirmed["infrastructure"]["bulletproof_hosting"]["classification"] == "confirmed"
    assert "bulletproof_hosting" in tag_ids(confirmed)
    assert suspected["infrastructure"]["bulletproof_hosting"]["classification"] == "suspected"
    assert "bulletproof_hosting_suspected" in tag_ids(suspected)
    assert cdn["infrastructure"]["bulletproof_hosting"]["classification"] == "not_indicated"
    assert {"cdn", "anycast_shared_edge", "dns_resolution"} <= tag_ids(cdn)
    assert "bulletproof_hosting" not in tag_ids(cdn)


def test_generic_vpn_and_hosting_markers_are_tagged_without_bulletproof_claim() -> None:
    detail = tags.build_ip_detail(
        record("192.0.2.5", 64500, "Example VPN Hosting LLC"),
        host="vpn.example",
        shared_cdn_provider=None,
        registry=tags.load_registry(),
    )

    assert {"vpn_proxy", "hosting", "dns_resolution"} <= tag_ids(detail)
    assert detail["infrastructure"]["bulletproof_hosting"]["classification"] == "unknown"


def monitoring_entry(timestamp: str, detail: dict) -> dict:
    return {
        "target_id": "transition-fixture",
        "family": "fixture",
        "host": "transition.example",
        "port": 443,
        "protocol": "tcp",
        "transport": "direct",
        "method": "tcp_connect",
        "observation": {
            "timestamp_utc": timestamp,
            "resolved_ips": [detail["ip"]],
            "alive": True,
            "target_contact_attempted": True,
        },
        "assessment": {"state": "transport_reachable_c2_not_confirmed"},
        "maxmind": {"records": [detail]},
    }


def test_transition_contains_from_to_geo_as_and_infrastructure_tags(tmp_path: Path) -> None:
    previous = tmp_path / "2026-08-01"
    previous.mkdir()
    old_record = record("193.26.115.118", 210558, "1337 Services GmbH")
    (previous / "monitoring-results.json").write_text(
        json.dumps(
            {
                "policy": {"network_enabled": True},
                "results": [monitoring_entry("2026-08-01T00:00:00+00:00", old_record)],
            }
        ),
        encoding="utf-8",
    )
    new_record = record(
        "185.139.214.102",
        200019,
        "Alexhost Srl",
        country="アメリカ",
        country_code="US",
        city="ラスベガス",
    )
    current = {
        "policy": {"network_enabled": True},
        "results": [monitoring_entry("2026-08-02T00:00:00+00:00", new_record)],
    }
    plan = {
        "schema_version": 1,
        "targets": [
            {
                "target_id": "transition-fixture",
                "host": "transition.example",
                "port": 443,
                "protocol": "tcp",
                "transport": "direct",
            }
        ],
    }

    enriched, _monitoring, _active = history.apply_monitoring_history(
        current,
        plan,
        history_root=tmp_path,
        current_run_name="2026-08-02",
    )

    dns = enriched["results"][0]["dns_tracking"]
    transition = dns["transitions"][0]
    assert transition["from"][0]["ip"] == "193.26.115.118"
    assert transition["from"][0]["as"]["asn"] == 210558
    assert transition["from"][0]["geo"]["country_iso_code"] == "DE"
    assert transition["to"][0]["ip"] == "185.139.214.102"
    assert transition["to"][0]["as"]["asn"] == 200019
    assert transition["to"][0]["geo"]["country_iso_code"] == "US"
    assert "bulletproof_hosting" in tag_ids(transition["from"][0])
    assert "bulletproof_hosting" in tag_ids(transition["to"][0])
    assert transition["classification"] == "infrastructure_ip_change"
