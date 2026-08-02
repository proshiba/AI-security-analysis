from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "analysis-framework" / "common" / "maxmind_c2_enrichment.py"
SPEC = importlib.util.spec_from_file_location("maxmind_c2_enrichment", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class FakeReader:
    def __init__(self, values):
        self.values = values

    def get(self, ip):
        return self.values.get(ip)


def test_current_download_request_keeps_key_out_of_url() -> None:
    request, mode = MODULE.download_request(
        "GeoLite2-City", "tar.gz", account_id="12345", license_key="secret-value"
    )
    assert "secret-value" not in request.full_url
    assert request.headers["Authorization"].startswith("Basic ")
    assert mode == "basic_auth_current"


def test_projection_keeps_geo_and_as_fields() -> None:
    city = MODULE.project_city({
        "continent": {"code": "AS", "names": {"ja": "アジア"}},
        "country": {"iso_code": "JP", "names": {"ja": "日本"}},
        "registered_country": {"iso_code": "US"},
        "subdivisions": [{"iso_code": "13", "names": {"ja": "東京都"}}],
        "city": {"names": {"ja": "東京"}},
        "postal": {"code": "100-0001"},
        "location": {"latitude": 35.0, "longitude": 139.0, "accuracy_radius": 100, "time_zone": "Asia/Tokyo"},
    })
    asn = MODULE.project_asn({
        "autonomous_system_number": 64500,
        "autonomous_system_organization": "Example ASN",
    })
    assert city["country_iso_code"] == "JP"
    assert city["city_name"] == "東京"
    assert asn["autonomous_system_number"] == 64500


def test_enrichment_uses_only_observed_global_ips() -> None:
    monitoring = {"results": [{"target_id": "fixture", "observation": {"resolved_ips": ["203.0.113.10", "8.8.8.8", "127.0.0.1"]}}]}
    city = FakeReader({"8.8.8.8": {"country": {"iso_code": "US"}}})
    asn = FakeReader({"8.8.8.8": {"autonomous_system_number": 15169}})
    enriched = MODULE.enrich_monitoring(monitoring, city, asn, city_metadata={}, asn_metadata={})
    records = enriched["results"][0]["maxmind"]["records"]
    assert [item["ip"] for item in records] == ["8.8.8.8"]
    assert enriched["maxmind"]["lookup_count"] == 1
    assert enriched["maxmind"]["license_key_published"] is False
