from __future__ import annotations

import json
import sys
from pathlib import Path

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from build_all_c2_monitoring_targets import build_inventory


def _write_case(root: Path, family: str, sample: str, payload: dict, *, name: str = "iocs.json") -> None:
    path = root / family / "versions" / "unknown" / "cases" / sample / name
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_builds_all_ordinary_targets_and_audits_exclusions(tmp_path: Path) -> None:
    sample = "a" * 64
    malware_root = tmp_path / "malware"
    _write_case(
        malware_root,
        "fixture",
        sample,
        {
            "network": [
                {"host": "c2.example", "port": 4444, "role": "primary_c2"},
                {"host": "c2.example", "role": "fallback_c2"},
                {"host": "portless.example", "role": "dns_fallback_exfiltration"},
                {"value": "hiddenserviceexample.onion:80", "role": "c2_onion"},
                {"url": "https://download.example/payload", "role": "distribution"},
                {"host": "10.0.0.1", "port": 443, "role": "c2"},
                {"host": "kill.example", "port": 80, "role": "kill_switch_not_c2"},
            ],
            "configured_or_observed_c2": [
                {
                    "value": "logs.example:8443",
                    "ip": "8.8.8.8",
                    "role": "PureLogs C2",
                }
            ],
            "configured_c2": [{"host": "configured.example", "port": 62050, "role": ""}],
        },
    )

    plan, inventory = build_inventory(malware_root, generated_date="2026-08-02")
    endpoints = {(target["host"], target["port"], target["method"]) for target in plan["targets"]}
    assert ("c2.example", 4444, "tcp_connect") in endpoints
    assert ("portless.example", 0, "dns_resolve") in endpoints
    assert ("logs.example", 8443, "tcp_connect") in endpoints
    assert ("configured.example", 62050, "tcp_connect") in endpoints
    assert not any(host == "8.8.8.8" for host, _, _ in endpoints)
    assert not any(host.endswith(".onion") for host, _, _ in endpoints)
    assert inventory["ordinary_candidate_host_count"] == 4
    assert inventory["planned_ordinary_host_count"] == 4
    assert inventory["ordinary_host_coverage_percent"] == 100.0
    assert inventory["exclusion_reason_counts"]["onion_excluded_by_policy"] == 1
    assert inventory["exclusion_reason_counts"]["distribution_only"] == 1
    assert inventory["exclusion_reason_counts"]["non_global_ip_excluded"] == 1
    assert inventory["exclusion_reason_counts"]["explicit_non_c2_role"] == 1


def test_url_without_explicit_port_uses_protocol_default(tmp_path: Path) -> None:
    malware_root = tmp_path / "malware"
    _write_case(
        malware_root,
        "fixture",
        "b" * 64,
        {
            "network": [
                {"url": "https://secure.example/api", "role": "http_c2"},
                {"url": "ftp://ftp.example/out", "role": "credential_exfiltration"},
            ]
        },
    )
    plan, _ = build_inventory(malware_root, generated_date="2026-08-02")
    assert {(target["host"], target["port"]) for target in plan["targets"]} == {
        ("secure.example", 443),
        ("ftp.example", 21),
    }


def test_scans_research_c2_schemas_without_clickfix_delivery(tmp_path: Path) -> None:
    results = tmp_path / "analysis-results"
    atlas = results / "research" / "campaigns" / "atlas" / "iocs.json"
    atlas.parent.mkdir(parents=True)
    atlas.write_text(json.dumps({"network": {"c2": ["atlas.example:9899", "8.8.8.8:9899"]}}), encoding="utf-8")
    supply = results / "research" / "supply-chain" / "npm" / "iocs.json"
    supply.parent.mkdir(parents=True)
    supply.write_text(
        json.dumps(
            {
                "network": [
                    {"value": "npm-c2.example", "role": "c2_domain"},
                    {"value": "8000/tcp", "role": "c2_port"},
                ]
            }
        ),
        encoding="utf-8",
    )
    campaign = results / "research" / "campaigns" / "correlated" / "iocs.json"
    campaign.parent.mkdir(parents=True)
    campaign.write_text(
        json.dumps(
            {"indicators": [{"type": "endpoint", "value": "campaign.example:2404", "role": "shared_campaign_evidence"}]}
        ),
        encoding="utf-8",
    )
    clickfix = results / "clickfix" / "landing.example" / "cases" / "one" / "iocs.json"
    clickfix.parent.mkdir(parents=True)
    clickfix.write_text(
        json.dumps(
            {
                "indicators": [
                    {"type": "domain", "value": "landing.example", "role": "clickfix_landing_or_payload_delivery"}
                ]
            }
        ),
        encoding="utf-8",
    )

    plan, inventory = build_inventory(results, generated_date="2026-08-02")
    endpoints = {(target["host"], target["port"]) for target in plan["targets"]}
    assert endpoints == {
        ("atlas.example", 9899),
        ("8.8.8.8", 9899),
        ("npm-c2.example", 8000),
        ("campaign.example", 2404),
    }
    assert inventory["scanned_ioc_file_count"] == 4
    assert inventory["ordinary_host_coverage_percent"] == 100.0
    assert inventory["exclusion_reason_counts"]["role_not_c2"] == 1


def test_explicit_malware_protocol_hint_fails_closed_without_exact_profile(
    tmp_path: Path,
) -> None:
    sample = "c" * 64
    malware_root = tmp_path / "malware"
    without_hint = {"network": [{"host": "fallback.example", "port": 5776, "role": "fallback_c2"}]}
    _write_case(malware_root, "remusstealer", sample, without_hint)
    baseline_plan, _ = build_inventory(malware_root, generated_date="2026-08-09")
    baseline = next(target for target in baseline_plan["targets"] if target["host"] == "fallback.example")
    assert baseline["method"] == "tcp_connect"

    with_hint = json.loads(json.dumps(without_hint))
    with_hint["network"][0]["protocol"] = "remusstealer"
    case_path = malware_root / "remusstealer" / "versions" / "unknown" / "cases" / sample / "iocs.json"
    case_path.write_text(json.dumps(with_hint), encoding="utf-8")
    hinted_plan, _ = build_inventory(malware_root, generated_date="2026-08-09")
    hinted = next(target for target in hinted_plan["targets"] if target["host"] == "fallback.example")

    assert hinted["target_id"] == baseline["target_id"]
    assert hinted["protocol"] == "tcp"
    assert hinted["protocol_hints"] == ["remusstealer"]
    assert hinted["method"] == "protocol_profile_required"
    assert hinted["protocol_profile_required"] is True
    assert hinted["protocol_profile_status"] == "reviewed_exact_profile_missing"


def test_conflicting_explicit_protocol_hints_do_not_select_first_value(tmp_path: Path) -> None:
    malware_root = tmp_path / "malware"
    _write_case(
        malware_root,
        "fixture",
        "d" * 64,
        {
            "network": [
                {"host": "conflict.example", "port": 443, "role": "c2", "protocol": "asyncrat"},
                {"host": "conflict.example", "port": 443, "role": "c2", "protocol": "remusstealer"},
            ]
        },
    )
    plan, _ = build_inventory(malware_root, generated_date="2026-08-09")
    target = next(target for target in plan["targets"] if target["host"] == "conflict.example")
    assert target["protocol"] == "tcp"
    assert target["protocol_hints"] == ["asyncrat", "remusstealer"]
    assert target["method"] == "protocol_profile_required"
    assert target["protocol_profile_status"] == "conflicting_explicit_protocol_hints"
