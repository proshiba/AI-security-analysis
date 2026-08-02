from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import enrich_c2_geo  # noqa: E402


def results() -> dict:
    return {
        "results": [
            {
                "host": "c2.example",
                "observation": {"host": "c2.example", "resolved_ips": ["45.66.228.114"]},
            },
            {
                "host": "alias.example",
                "observation": {"host": "alias.example", "resolved_ips": ["45.66.228.114"]},
            },
            {
                "host": "internal.example",
                "observation": {"host": "internal.example", "resolved_ips": ["10.0.0.5", "127.0.0.1"]},
            },
            {
                "host": "hidden.onion",
                "observation": {"host": "hidden.onion", "resolved_ips": []},
            },
        ]
    }


def api_response(address: str) -> dict:
    return {
        "ip": address,
        "success": True,
        "continent": "Asia",
        "continent_code": "AS",
        "country": "Japan",
        "country_code": "JP",
        "region": "Tokyo",
        "city": "Chiyoda",
        "latitude": 35.68944412,
        "longitude": 139.69166565,
        "postal": "100-0001",
        "connection": {"asn": 64500, "org": "Example Org", "isp": "Example ISP", "domain": "example.net"},
        "timezone": {"id": "Asia/Tokyo", "offset": 32400},
    }


def test_private_reserved_and_onion_addresses_are_not_queried() -> None:
    targets = enrich_c2_geo.resolved_ips(results())
    assert list(targets) == ["45.66.228.114"]
    assert targets["45.66.228.114"] == ["alias.example", "c2.example"]


def test_public_ip_predicate_rejects_non_routable() -> None:
    assert enrich_c2_geo.is_public_ip("45.66.228.114")
    for address in (
        "10.0.0.5",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "203.0.113.10",  # ドキュメント用レンジもPythonはprivate扱い
        "not-an-ip",
    ):
        assert not enrich_c2_geo.is_public_ip(address)


def test_without_allow_network_no_request_is_made(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> dict:
        raise AssertionError("--allow-network なしで通信してはならない")

    monkeypatch.setattr(enrich_c2_geo, "fetch", fail)
    payload = enrich_c2_geo.build(results(), allow_network=False, timeout=1.0, pause=0.0)
    assert payload["network_enabled"] is False
    assert payload["target_c2_contacted"] is False
    assert payload["resolved_count"] == 0
    assert payload["ips"][0]["geo_resolved"] is False


def test_summary_keeps_only_declared_fields_and_rounds_coordinates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(enrich_c2_geo, "fetch", lambda address, timeout: api_response(address))
    payload = enrich_c2_geo.build(results(), allow_network=True, timeout=1.0, pause=0.0)
    entry = payload["ips"][0]
    assert payload["resolved_count"] == 1
    assert entry["geo_resolved"] is True
    assert entry["country_code"] == "JP"
    assert entry["latitude"] == 35.6894
    assert entry["longitude"] == 139.6917
    assert entry["asn"] == 64500
    assert entry["organization"] == "Example Org"
    # postal など宣言していない項目は保持しない
    assert "postal" not in entry


def test_failed_lookup_is_recorded_without_aborting(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(address: str, timeout: float) -> dict:
        raise OSError("network down")

    monkeypatch.setattr(enrich_c2_geo, "fetch", boom)
    payload = enrich_c2_geo.build(results(), allow_network=True, timeout=1.0, pause=0.0)
    assert payload["resolved_count"] == 0
    assert payload["errors"] == [{"ip": "45.66.228.114", "error": "OSError", "http_status": None}]
    assert payload["ips"][0]["geo_resolved"] is False


def test_unsuccessful_api_payload_is_treated_as_unresolved(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(enrich_c2_geo, "fetch", lambda address, timeout: {"success": False})
    payload = enrich_c2_geo.build(results(), allow_network=True, timeout=1.0, pause=0.0)
    assert payload["resolved_count"] == 0
    assert payload["ips"][0]["geo_resolved"] is False


def test_check_mode_reports_uncovered_ips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    directory = tmp_path / "2026-08-02"
    directory.mkdir()
    (directory / enrich_c2_geo.RESULTS_NAME).write_text(
        json.dumps(results()), encoding="utf-8"
    )
    (directory / enrich_c2_geo.OUTPUT_NAME).write_text(
        json.dumps({"ips": []}), encoding="utf-8"
    )
    assert enrich_c2_geo.main(["--results", str(directory), "--check"]) == 1

    (directory / enrich_c2_geo.OUTPUT_NAME).write_text(
        json.dumps({"ips": [{"ip": "45.66.228.114", "geo_resolved": True}]}), encoding="utf-8"
    )
    assert enrich_c2_geo.main(["--results", str(directory), "--check"]) == 0
