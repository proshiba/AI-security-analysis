from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "analysis-framework" / "common" / "render_c2_maxmind_section.py"
SPEC = importlib.util.spec_from_file_location("render_c2_maxmind_section", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_render_and_idempotent_insert() -> None:
    result = {
        "maxmind": {
            "matched_count": 1, "lookup_count": 1,
            "city_database": {"build_time_utc": "2026-08-01T00:00:00+00:00", "official_checksum_verified": True},
            "asn_database": {"build_time_utc": "2026-08-01T00:00:00+00:00", "official_checksum_verified": True},
            "attribution": "GeoLite2 Data created by MaxMind",
        },
        "results": [{
            "host": "c2.example", "port": 443,
            "maxmind": {"records": [{
                "ip": "8.8.8.8", "geo": {"country_name": "米国", "city_name": "Mountain View"},
                "as": {"autonomous_system_number": 15169, "autonomous_system_organization": "Google LLC"},
            }]},
        }],
    }
    section = MODULE.render_maxmind_section(result)
    once = MODULE.insert_section("# report\n\n## 安全境界\n", section)
    twice = MODULE.insert_section(once, section)
    assert "AS15169 / Google LLC" in twice
    assert "GeoLite2 City DB構築時刻" in twice
    assert "MaxMind帰属表記（原文）" in twice
    assert twice.count("<!-- maxmind-enrichment:start -->") == 1
    assert twice.index("## MaxMind Geo/ASエンリッチ") < twice.index("## 安全境界")
