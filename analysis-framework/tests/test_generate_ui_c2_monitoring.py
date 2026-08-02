from __future__ import annotations

import importlib.util
import json
from pathlib import Path


MODULE_PATH = Path(__file__).parents[2] / "ui" / "generate_ui_data.py"
SPEC = importlib.util.spec_from_file_location("generate_ui_data_under_test", MODULE_PATH)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(target)


def test_c2_ui_keeps_raw_cdn_rotation_but_excludes_infrastructure_change(
    tmp_path: Path,
    monkeypatch,
) -> None:
    results = tmp_path / "analysis-results"
    run = results / "research" / "c2-monitoring" / "2026-08-02"
    run.mkdir(parents=True)
    old_detail = {
        "ip": "104.21.1.1",
        "as": {"asn": 13335, "organization": "Cloudflare, Inc."},
        "geo": {"country_iso_code": "US", "country_name": "アメリカ"},
        "infrastructure": {
            "tags": [{"id": "cdn", "label": "CDN"}],
            "bulletproof_hosting": {"classification": "not_indicated"},
        },
    }
    new_detail = {**old_detail, "ip": "172.67.1.1"}
    transition = {
        "from": [old_detail],
        "to": [new_detail],
        "removed": [old_detail],
        "added": [new_detail],
        "classification": "shared_cdn_rotation_ignored",
    }
    payload = {
        "generated_at_utc": "2026-08-02T00:00:00+00:00",
        "target_count": 1,
        "monitoring_history_summary": {
            "active_target_count": 1,
            "retired_target_count": 0,
        },
        "results": [
            {
                "target_id": "fixture",
                "host": "cdn.example",
                "port": 443,
                "protocol": "tcp",
                "transport": "direct",
                "availability_status": "on",
                "observation": {
                    "timestamp_utc": "2026-08-02T00:00:00+00:00",
                    "resolved_ips": ["172.67.1.1"],
                    "alive": True,
                },
                "assessment": {
                    "state": "transport_reachable_c2_not_confirmed",
                    "reachability_confidence": 0.9,
                    "c2_operational_confidence": 0.25,
                },
                "monitoring_lifecycle": {"status": "active_on", "active": True},
                "dns_tracking": {
                    "history": [
                        {
                            "date": "2026-08-01",
                            "observed_at_utc": "2026-08-01T00:00:00+00:00",
                            "ips": ["104.21.1.1"],
                            "ip_details": [old_detail],
                            "transition": None,
                            "raw_ip_changed": False,
                            "infrastructure_ip_change": False,
                            "change_classification": "initial_observation",
                            "shared_cdn_provider": "Cloudflare",
                        },
                        {
                            "date": "2026-08-02",
                            "observed_at_utc": "2026-08-02T00:00:00+00:00",
                            "ips": ["172.67.1.1"],
                            "ip_details": [new_detail],
                            "transition": transition,
                            "raw_ip_changed": True,
                            "infrastructure_ip_change": False,
                            "change_classification": "shared_cdn_rotation_ignored",
                            "shared_cdn_provider": "Cloudflare",
                        },
                    ],
                    "transitions": [transition],
                },
            }
        ],
    }
    (run / "monitoring-results.json").write_text(
        json.dumps(payload, ensure_ascii=False),
        encoding="utf-8",
    )
    monkeypatch.setattr(target, "RESULTS", results)
    monkeypatch.setattr(target, "REPO_ROOT", tmp_path)

    generated = target.load_c2_monitoring(set())

    assert generated["runs"][0]["monitoring_history"]["active_target_count"] == 1
    assert generated["endpoints"][0]["active"] is True
    timeline = generated["ip_history"][0]
    assert timeline["raw_changes"] == 1
    assert timeline["changes"] == 0
    assert timeline["ignored_cdn_rotations"] == 1
    assert timeline["points"][-1]["change_classification"] == "shared_cdn_rotation_ignored"
    assert timeline["points"][-1]["ip_details"][0]["as"]["asn"] == 13335
    assert timeline["points"][-1]["transition"]["from"][0]["ip"] == "104.21.1.1"
    assert timeline["points"][-1]["transition"]["to"][0]["ip"] == "172.67.1.1"
    assert set(generated["geo"]) == {"104.21.1.1", "172.67.1.1"}
    assert generated["geo"]["172.67.1.1"]["source"] == "GeoLite2 City/ASN"
