from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from build_all_c2_monitoring_targets import build_inventory  # noqa: E402


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


def test_daily_ioc_summary_is_bound_to_effective_targets_without_phishing(tmp_path: Path) -> None:
    results = tmp_path / "analysis-results"
    source_date = "2026-08-24"
    summary = results / "research" / "daily-news-malware" / source_date / "ioc-summary.json"
    summary.parent.mkdir(parents=True)
    summary.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_date": source_date,
                "items": [
                    {
                        "ioc_type": "domain",
                        "ioc_value": "daily-c2.example",
                        "category": "c2",
                        "malware": "Fixture",
                        "valid": True,
                    },
                    {
                        "ioc_type": "url",
                        "ioc_value": "https://daily-secure.example/drop",
                        "category": "c2",
                        "malware": "Fixture",
                        "valid": True,
                    },
                    {
                        "ioc_type": "url",
                        "ioc_value": "https://phishing.example/login",
                        "category": "phishing-site",
                        "malware": "Fixture",
                        "valid": True,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    plan, inventory = build_inventory(
        results,
        generated_date=source_date,
        daily_source_date=source_date,
    )

    daily_targets = [target for target in plan["targets"] if target.get("daily_source_dates")]
    assert {(target["host"], target["port"]) for target in daily_targets} == {
        ("daily-c2.example", 0),
        ("daily-secure.example", 443),
    }
    assert all(target["daily_source_dates"] == [source_date] for target in daily_targets)
    assert not any(target["host"] == "phishing.example" for target in plan["targets"])
    assert len(plan["daily_source_handoffs"]) == 1
    handoff = plan["daily_source_handoffs"][0]
    assert handoff["source_date"] == source_date
    assert handoff["source_target_count"] == 2
    assert handoff["effective_target_count"] == 2
    assert len(handoff["source_target_commitment_sha256"]) == 64
    assert len(handoff["effective_target_commitment_sha256"]) == 64
    assert inventory["scanned_daily_ioc_summary_file_count"] == 1


def _write_daily_summary(results: Path, source_date: str, items: list[dict]) -> Path:
    summary = results / "research" / "daily-news-malware" / source_date / "ioc-summary.json"
    summary.parent.mkdir(parents=True)
    summary.write_text(
        json.dumps({"schema_version": 1, "source_date": source_date, "items": items}),
        encoding="utf-8",
    )
    return summary


def _daily_c2_item(value: str, *, ioc_type: str = "domain") -> dict:
    return {
        "ioc_type": ioc_type,
        "ioc_value": value,
        "category": "c2",
        "malware": "Fixture",
        "valid": True,
    }


def test_only_explicit_daily_summary_is_added_to_historical_monitoring(tmp_path: Path) -> None:
    results = tmp_path / "analysis-results"
    historical_date = "2026-07-29"
    source_date = "2026-08-23"
    _write_daily_summary(
        results,
        historical_date,
        [
            _daily_c2_item("historical-c2.example"),
            _daily_c2_item("historical-wallet.eth"),
        ],
    )
    _write_daily_summary(results, source_date, [_daily_c2_item("current-c2.example")])

    plan, inventory = build_inventory(
        results,
        generated_date="2026-08-24",
        daily_source_date=source_date,
    )

    by_host = {target["host"]: target for target in plan["targets"]}
    assert "historical-c2.example" not in by_host
    assert by_host["current-c2.example"]["daily_source_dates"] == [source_date]
    assert "historical-wallet.eth" not in by_host
    assert [record["source_date"] for record in plan["daily_source_handoffs"]] == [source_date]
    assert inventory["scanned_daily_ioc_summary_file_count"] == 1
    assert "non_dns_name_excluded" not in inventory["exclusion_reason_counts"]


def test_explicit_daily_source_rejects_policy_excluded_current_target(tmp_path: Path) -> None:
    results = tmp_path / "analysis-results"
    source_date = "2026-08-24"
    _write_daily_summary(results, source_date, [_daily_c2_item("current-wallet.eth")])

    with pytest.raises(ValueError, match="完全に結合されていません"):
        build_inventory(
            results,
            generated_date=source_date,
            daily_source_date=source_date,
        )


def test_explicit_daily_source_must_be_canonical_and_present(tmp_path: Path) -> None:
    results = tmp_path / "analysis-results"

    with pytest.raises(ValueError, match="canonical YYYY-MM-DD"):
        build_inventory(
            results,
            generated_date="2026-08-24",
            daily_source_date="2026-8-24",
        )
    with pytest.raises(ValueError, match="一意に見つかりません"):
        build_inventory(
            results,
            generated_date="2026-08-24",
            daily_source_date="2026-08-24",
        )


def test_explicit_daily_source_rejects_duplicate_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = tmp_path / "analysis-results"
    source_date = "2026-08-24"
    first = _write_daily_summary(results, source_date, [_daily_c2_item("first.example")])
    second = (
        results
        / "duplicate"
        / "daily-news-malware"
        / source_date
        / "ioc-summary.json"
    )
    second.parent.mkdir(parents=True)
    second.write_text(first.read_text(encoding="utf-8"), encoding="utf-8")
    original_glob = Path.glob

    def duplicate_daily_glob(path: Path, pattern: str):
        if path == results and pattern == "research/daily-news-malware/*/ioc-summary.json":
            return iter((first, second))
        return original_glob(path, pattern)

    monkeypatch.setattr(Path, "glob", duplicate_daily_glob)
    with pytest.raises(ValueError, match="重複しています"):
        build_inventory(
            results,
            generated_date=source_date,
            daily_source_date=source_date,
        )


def test_shared_services_are_excluded_but_per_tenant_hostnames_are_kept(tmp_path: Path) -> None:
    """利用者の区別がpath側にある正規サービスを能動監視の対象から外す。

    IOCは `https://webhook.site/<token>` のような個別URLでも、対象生成は
    ホストとportへ正規化するのでtokenが落ちる。残った `webhook.site` を
    叩いても分かるのは「サービスが動いている」ことだけで、C2稼働とは無関係。
    しかも無関係な第三者の正規サービスへ接続することになる。

    一方 Cloudflare Workers のようにホスト名が利用者ごとに割り当てられる
    サービスは、ホスト名そのものが攻撃者固有なので対象に残す。
    """
    sample = "b" * 64
    malware_root = tmp_path / "malware"
    _write_case(
        malware_root,
        "fixture",
        sample,
        {
            "network": [
                # 共有ホスト。tokenが落ちるので除外する。
                {"url": "https://webhook.site/1f0d4d1a-0000-4000-8000-000000000000", "role": "c2"},
                {"url": "http://telegra.ph/some-article-01-01", "role": "c2_exfiltration"},
                # 利用者ごとのホスト名。これは残す。
                {"url": "https://gentle-pond-2294.example-account.workers.dev/a", "role": "c2"},
                # 通常のC2。対照。
                {"host": "c2.example", "port": 4444, "role": "primary_c2"},
            ]
        },
    )

    plan, inventory = build_inventory(malware_root, generated_date="2026-09-01")
    hosts = {target["host"] for target in plan["targets"]}

    assert "webhook.site" not in hosts
    assert "telegra.ph" not in hosts
    # 完全一致で判定しているので、利用者ごとのサブドメインは巻き込まない
    assert "gentle-pond-2294.example-account.workers.dev" in hosts
    assert "c2.example" in hosts

    reasons = {
        item["host"]: item["reason"]
        for item in inventory["exclusions"]
        if item.get("host")
    }
    assert reasons["webhook.site"] == "shared_service_tenant_in_path_excluded"
    assert reasons["telegra.ph"] == "shared_service_tenant_in_path_excluded"

    # 何を外したかが成果物から追えること
    assert inventory["policy"]["shared_service_tenant_in_path_excluded"] == [
        "telegra.ph",
        "webhook.site",
    ]
    assert inventory["exclusion_reason_counts"]["shared_service_tenant_in_path_excluded"] == 2
