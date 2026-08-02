#!/usr/bin/env python3
"""daily解析の4系統が揃い、安全条件を満たすことを検証する。"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
from typing import Any

EXPECTED_CASES = 50
NEWS_FILES = {
    "DETECTION.md",
    "README.md",
    "STATIC-ANALYSIS.md",
    "THREAT-ANALYSIS.md",
    "infrastructure-summary.json",
    "ioc-summary.json",
    "provider-summary.json",
    "sample-static-summary.json",
}
CLICKFIX_FILES = {
    "FEATURES.md",
    "INFRASTRUCTURE.md",
    "IOC-LIST.md",
    "OVERALL-LOGIC.md",
    "README.md",
    "TRIAGE.md",
    "analysis.json",
    "infrastructure.json",
    "iocs.json",
    "live-observation.json",
    "triage-evidence.json",
    "rules/sigma.yml",
}


def _finding(findings: list[dict[str, str]], code: str, path: Path, message: str) -> None:
    findings.append({"code": code, "path": path.as_posix(), "message": message})


def _json(path: Path, findings: list[dict[str, str]]) -> dict[str, Any]:
    if not path.is_file():
        _finding(findings, "missing_file", path, "必須JSONがありません。")
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        _finding(findings, "invalid_json", path, f"JSONを読めません: {type(error).__name__}")
        return {}
    if not isinstance(value, dict):
        _finding(findings, "invalid_json_root", path, "JSON rootはobjectである必要があります。")
        return {}
    return value


def _files(root: Path, names: set[str], findings: list[dict[str, str]]) -> None:
    for name in sorted(names):
        if not (root / name).is_file():
            _finding(findings, "missing_file", root / name, "必須成果物がありません。")


def _window_date(value: object) -> str | None:
    """日付またはtimezone付きISO日時をdaily比較用の日付へ正規化する。"""

    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


def validate_news(repository: Path, source_date: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    root = repository / "analysis-results" / "research" / "daily-news-malware" / source_date
    _files(root, NEWS_FILES, findings)
    names = (
        "infrastructure-summary.json",
        "ioc-summary.json",
        "provider-summary.json",
        "sample-static-summary.json",
    )
    values = {name: _json(root / name, findings) for name in names}
    for name, value in values.items():
        if value and value.get("source_date") != source_date:
            _finding(findings, "source_date_mismatch", root / name, "source_dateが解析対象日と一致しません。")
    provider = values["provider-summary.json"]
    if provider.get("virustotal_submission_performed") is not False:
        _finding(
            findings,
            "virustotal_submission_not_false",
            root / "provider-summary.json",
            "VirusTotalへの新規submitはdaily解析で許可しません。",
        )
    safety = values["sample-static-summary.json"].get("safety") or {}
    for key in (
        "sample_executed",
        "network_contacted_by_sample",
        "raw_sample_published",
        "raw_decompilation_published",
    ):
        if safety.get(key) is not False:
            _finding(
                findings,
                f"unsafe_{key}",
                root / "sample-static-summary.json",
                f"safety.{key}がfalseではありません。",
            )
    return {"name": "daily_news", "root": root.as_posix(), "complete": not findings, "findings": findings}


def _pending_count(value: Any) -> int:
    if isinstance(value, list):
        return len(value)
    return value if isinstance(value, int) else 0


def validate_malwarebazaar(
    repository: Path,
    analysis_date: str,
    expected_cases: int = EXPECTED_CASES,
) -> dict[str, Any]:
    if expected_cases <= 0:
        raise ValueError("MalwareBazaar件数は正の整数である必要があります")
    findings: list[dict[str, str]] = []
    compact = analysis_date.replace("-", "")
    root = (
        repository
        / "analysis-results"
        / "collections"
        / f"malwarebazaar-windows-{compact}-{expected_cases:04d}"
    )
    _files(root, {"README.md", "manifest.json", "publication-summary.json"}, findings)
    manifest_path = root / "manifest.json"
    manifest = _json(manifest_path, findings)
    cases = manifest.get("cases") or []
    acquisitions = manifest.get("acquisition_items") or []
    checks = {
        "requested": manifest.get("requested"),
        "downloaded": manifest.get("downloaded"),
        "cases": len(cases) if isinstance(cases, list) else -1,
        "acquisition_items": len(acquisitions) if isinstance(acquisitions, list) else -1,
    }
    for field, actual in checks.items():
        if actual != expected_cases:
            _finding(
                findings,
                f"malwarebazaar_{field}_count",
                manifest_path,
                f"{field}は{expected_cases}である必要があります: actual={actual}",
            )
    for field in ("acquisition_complete", "analysis_complete", "complete"):
        if manifest.get(field) is not True:
            _finding(findings, f"malwarebazaar_{field}_not_true", manifest_path, f"{field}がtrueではありません。")
    if _pending_count(manifest.get("pending")):
        _finding(findings, "malwarebazaar_pending", manifest_path, "未完了queueが残っています。")
    for field in ("samples_executed", "network_contacted"):
        if manifest.get(field) is not False:
            _finding(findings, f"malwarebazaar_unsafe_{field}", manifest_path, f"{field}がfalseではありません。")
    if manifest.get("archives_stored_in_repository") is not False:
        _finding(
            findings,
            "malwarebazaar_archives_in_repository",
            manifest_path,
            "検体archiveをrepositoryへ保存してはいけません。",
        )
    publication_path = root / "publication-summary.json"
    publication = _json(publication_path, findings)
    if publication.get("analysis_complete") is not True:
        _finding(
            findings,
            "malwarebazaar_publication_incomplete",
            publication_path,
            "publication-summaryのanalysis_completeがtrueではありません。",
        )
    return {
        "name": f"malwarebazaar_{expected_cases}",
        "root": root.as_posix(),
        "expected_cases": expected_cases,
        "actual_cases": len(cases) if isinstance(cases, list) else 0,
        "complete": not findings,
        "findings": findings,
    }


def _case_root(clickfix_root: Path, relative: str) -> Path | None:
    candidate = (clickfix_root / relative).resolve()
    try:
        candidate.relative_to(clickfix_root.resolve())
    except ValueError:
        return None
    return candidate


def validate_clickfix(repository: Path, analysis_date: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    compact = analysis_date.replace("-", "")
    root = repository / "analysis-results" / "clickfix"
    collection = root / "collections" / f"clickfix-daily-{compact}"
    _files(
        collection,
        {"INFRASTRUCTURE-SUMMARY.md", "README.md", "TRIAGE-SUMMARY.md", "manifest.json"},
        findings,
    )
    manifest_path = collection / "manifest.json"
    manifest = _json(manifest_path, findings)
    cases = manifest.get("cases") or []
    if manifest.get("analysis_date") != analysis_date:
        _finding(findings, "clickfix_analysis_date_mismatch", manifest_path, "analysis_dateが一致しません。")
    if manifest.get("case_count") != EXPECTED_CASES or len(cases) != EXPECTED_CASES:
        _finding(findings, "clickfix_case_count", manifest_path, f"ClickFix caseは{EXPECTED_CASES}件必要です。")
    domains: set[str] = set()
    case_ids: set[str] = set()
    for item in cases if isinstance(cases, list) else []:
        domain = str(item.get("domain") or "")
        case_id = str(item.get("case_id") or "")
        relative = str(item.get("relative_path") or "")
        if not domain or domain in domains:
            _finding(
                findings,
                "clickfix_duplicate_or_empty_domain",
                manifest_path,
                f"domainが空または重複しています: {domain}",
            )
        if not case_id or case_id in case_ids:
            _finding(
                findings,
                "clickfix_duplicate_or_empty_case_id",
                manifest_path,
                f"case_idが空または重複しています: {case_id}",
            )
        domains.add(domain)
        case_ids.add(case_id)
        case_root = _case_root(root, relative)
        if case_root is None:
            _finding(findings, "clickfix_case_path_escape", manifest_path, f"case pathがroot外です: {relative}")
            continue
        _files(case_root, CLICKFIX_FILES, findings)
        infrastructure = _json(case_root / "infrastructure.json", findings)
        if infrastructure.get("case_id") != case_id or not infrastructure.get("investigated_at_utc"):
            _finding(
                findings,
                "clickfix_infrastructure_incomplete",
                case_root / "infrastructure.json",
                "case_idまたはインフラ調査日時が不完全です。",
            )
        triage = _json(case_root / "triage-evidence.json", findings)
        if triage.get("case_id") != case_id or not triage.get("queried_at_utc"):
            _finding(
                findings,
                "clickfix_triage_incomplete",
                case_root / "triage-evidence.json",
                "case_idまたはTriage照合日時が不完全です。",
            )
        safety = triage.get("safety") or {}
        for key in (
            "sample_submitted",
            "sample_downloaded",
            "artifact_downloaded",
            "pcap_downloaded",
            "sample_executed_locally",
        ):
            if safety.get(key) is not False:
                _finding(
                    findings,
                    f"clickfix_unsafe_{key}",
                    case_root / "triage-evidence.json",
                    f"safety.{key}がfalseではありません。",
                )
    return {
        "name": "clickfix_50",
        "root": collection.as_posix(),
        "expected_cases": EXPECTED_CASES,
        "actual_cases": len(cases) if isinstance(cases, list) else 0,
        "complete": not findings,
        "findings": findings,
    }


def validate_c2_live_check(repository: Path, analysis_date: str) -> dict[str, Any]:
    """dailyのC2限定ライブチェックとMaxMind鮮度更新を検証する。"""
    findings: list[dict[str, str]] = []
    root = repository / "analysis-results" / "research" / "c2-monitoring" / analysis_date
    required_files = {
        "README.md",
        "monitoring-results.json",
        "targets.json",
        "effective-targets.json",
        "active-targets.json",
        "monitoring-history.json",
    }
    _files(root, required_files, findings)
    results_path = root / "monitoring-results.json"
    result = _json(results_path, findings)
    policy = result.get("policy") if isinstance(result.get("policy"), dict) else {}
    if policy.get("network_enabled") is not True:
        _finding(
            findings,
            "c2_live_check_not_enabled",
            results_path,
            "dailyではC2ライブチェックを有効にする必要があります。",
        )
    if policy.get("one_bounded_probe_per_target") is not True:
        _finding(
            findings,
            "c2_live_check_not_bounded",
            results_path,
            "対象ごとの限定probeが確認できません。",
        )
    target_count = result.get("target_count")
    observations = result.get("results") if isinstance(result.get("results"), list) else []
    if not isinstance(target_count, int) or target_count <= 0 or len(observations) != target_count:
        _finding(
            findings,
            "c2_live_check_target_count",
            results_path,
            "C2ライブチェック対象と結果件数が一致する正数である必要があります。",
        )
    window = result.get("analysis_window") if isinstance(result.get("analysis_window"), dict) else {}
    if _window_date(window.get("end")) != analysis_date:
        _finding(
            findings,
            "c2_live_check_date_mismatch",
            results_path,
            "analysis_window.endがdaily解析日と一致しません。",
        )
    for item in observations:
        observation = item.get("observation") if isinstance(item, dict) else {}
        if not isinstance(observation, dict) or not observation.get("timestamp_utc"):
            _finding(
                findings,
                "c2_live_check_missing_timestamp",
                results_path,
                "全C2結果にライブ観測時刻が必要です。",
            )
            break
        availability = item.get("availability_status")
        dns_tracking = item.get("dns_tracking") if isinstance(item, dict) else {}
        lifecycle = item.get("monitoring_lifecycle") if isinstance(item, dict) else {}
        if availability not in {"on", "off", "not_observed"}:
            _finding(
                findings,
                "c2_monitoring_availability_missing",
                results_path,
                "全C2結果にON／OFF／未観測の正規化状態が必要です。",
            )
            break
        if not isinstance(dns_tracking, dict) or not isinstance(
            dns_tracking.get("history"), list
        ):
            _finding(
                findings,
                "c2_dns_history_missing",
                results_path,
                "全C2結果にDNS/IP遷移履歴が必要です。",
            )
            break
        dns_history = dns_tracking.get("history")
        dns_transitions = dns_tracking.get("transitions")
        if not isinstance(dns_transitions, list):
            _finding(
                findings,
                "c2_dns_transitions_missing",
                results_path,
                "全C2結果に旧IPから新IPへの遷移event listが必要です。",
            )
            break
        invalid_detail = False
        for point in dns_history:
            if not isinstance(point, dict):
                invalid_detail = True
                break
            ips = point.get("ips") if isinstance(point.get("ips"), list) else []
            ip_details = (
                point.get("ip_details")
                if isinstance(point.get("ip_details"), list)
                else []
            )
            if len(ip_details) != len(ips):
                invalid_detail = True
                break
            for detail in ip_details:
                infrastructure = (
                    detail.get("infrastructure")
                    if isinstance(detail, dict)
                    and isinstance(detail.get("infrastructure"), dict)
                    else {}
                )
                bulletproof = (
                    infrastructure.get("bulletproof_hosting")
                    if isinstance(infrastructure.get("bulletproof_hosting"), dict)
                    else {}
                )
                if (
                    not isinstance(detail, dict)
                    or not isinstance(detail.get("as"), dict)
                    or not isinstance(detail.get("geo"), dict)
                    or not isinstance(infrastructure.get("tags"), list)
                    or bulletproof.get("classification")
                    not in {"confirmed", "suspected", "not_indicated", "unknown"}
                ):
                    invalid_detail = True
                    break
            if invalid_detail:
                break
        if invalid_detail:
            _finding(
                findings,
                "c2_dns_ip_enrichment_incomplete",
                results_path,
                "DNS履歴の全IPにAS、Geo、インフラタグ、防弾ホスティング評価が必要です。",
            )
            break
        if any(
            not isinstance(transition, dict)
            or not isinstance(transition.get("from"), list)
            or not isinstance(transition.get("to"), list)
            or not isinstance(transition.get("added"), list)
            or not isinstance(transition.get("removed"), list)
            for transition in dns_transitions
        ):
            _finding(
                findings,
                "c2_dns_transition_enrichment_incomplete",
                results_path,
                "全DNS遷移eventに旧側、新側、追加、消失のIP詳細が必要です。",
            )
            break
        if not isinstance(lifecycle, dict) or lifecycle.get("status") not in {
            "active_on",
            "active_grace",
            "active_unobserved",
            "retired_stopped",
        }:
            _finding(
                findings,
                "c2_monitoring_lifecycle_missing",
                results_path,
                "全C2結果に継続監視または停止のライフサイクル状態が必要です。",
            )
            break

    history_summary = (
        result.get("monitoring_history_summary")
        if isinstance(result.get("monitoring_history_summary"), dict)
        else {}
    )
    if history_summary.get("retirement_after_days_without_on") != 7:
        _finding(
            findings,
            "c2_retirement_threshold_not_seven_days",
            results_path,
            "C2監視停止閾値はONなし7日である必要があります。",
        )
    minimum_off = history_summary.get("minimum_off_observations")
    if not isinstance(minimum_off, int) or isinstance(minimum_off, bool) or minimum_off < 2:
        _finding(
            findings,
            "c2_retirement_off_observations_too_low",
            results_path,
            "停止判定には2回以上のOFF実観測が必要です。",
        )
    if history_summary.get("shared_cdn_rotation_counts_as_infrastructure_change") is not False:
        _finding(
            findings,
            "c2_shared_cdn_rotation_not_excluded",
            results_path,
            "共有CDN内のIPローテーションはインフラIP変化件数から除外する必要があります。",
        )

    active_path = root / "active-targets.json"
    active_plan = _json(active_path, findings)
    active_targets = active_plan.get("targets") if isinstance(active_plan.get("targets"), list) else []
    expected_active = history_summary.get("active_target_count")
    if not isinstance(expected_active, int) or len(active_targets) != expected_active:
        _finding(
            findings,
            "c2_active_target_count_mismatch",
            active_path,
            "次回active監視対象件数が履歴要約と一致しません。",
        )
    active_keys = {
        (
            str(item.get("host") or "").casefold().rstrip("."),
            item.get("port"),
            str(item.get("protocol") or "tcp").casefold(),
            str(item.get("transport") or "direct").casefold(),
            str(item.get("http_path") or ""),
        )
        for item in active_targets
        if isinstance(item, dict)
    }
    for item in observations:
        if not isinstance(item, dict):
            continue
        lifecycle = item.get("monitoring_lifecycle")
        if not isinstance(lifecycle, dict) or lifecycle.get("status") != "retired_stopped":
            continue
        key = (
            str(item.get("host") or "").casefold().rstrip("."),
            item.get("port"),
            str(item.get("protocol") or "tcp").casefold(),
            str(item.get("transport") or "direct").casefold(),
            str(item.get("http_path") or ""),
        )
        if key in active_keys:
            _finding(
                findings,
                "c2_retired_target_still_active",
                active_path,
                "停止履歴へ移したC2が次回active監視対象に残っています。",
            )
            break
    effective_path = root / "effective-targets.json"
    effective_plan = _json(effective_path, findings)
    effective_targets = (
        effective_plan.get("targets")
        if isinstance(effective_plan.get("targets"), list)
        else []
    )
    if len(effective_targets) != target_count:
        _finding(
            findings,
            "c2_effective_target_count_mismatch",
            effective_path,
            "今回の実効監視対象件数がライブ観測結果件数と一致しません。",
        )

    history_path = root / "monitoring-history.json"
    monitoring_history = _json(history_path, findings)
    history_endpoints = (
        monitoring_history.get("endpoints")
        if isinstance(monitoring_history.get("endpoints"), list)
        else []
    )
    if monitoring_history.get("current_run") != analysis_date:
        _finding(
            findings,
            "c2_monitoring_history_date_mismatch",
            history_path,
            "監視履歴のcurrent_runがdaily解析日と一致しません。",
        )
    if len(history_endpoints) < len(observations):
        _finding(
            findings,
            "c2_monitoring_history_endpoint_count",
            history_path,
            "停止済みを含む監視履歴endpoint数が今回の観測件数を下回っています。",
        )
    for endpoint in history_endpoints:
        if not isinstance(endpoint, dict):
            _finding(
                findings,
                "c2_monitoring_history_invalid_endpoint",
                history_path,
                "監視履歴endpointはobjectである必要があります。",
            )
            break
        dns_tracking = endpoint.get("dns_tracking")
        lifecycle = endpoint.get("monitoring_lifecycle")
        events = endpoint.get("events")
        if (
            not isinstance(dns_tracking, dict)
            or not isinstance(dns_tracking.get("history"), list)
            or not isinstance(lifecycle, dict)
            or not isinstance(events, list)
        ):
            _finding(
                findings,
                "c2_monitoring_history_incomplete_endpoint",
                history_path,
                "全監視履歴endpointにDNS履歴、ライフサイクル、状態遷移eventが必要です。",
            )
            break
        if lifecycle.get("status") == "retired_stopped" and not any(
            isinstance(event, dict)
            and event.get("event") == "monitoring_stopped_after_7d_without_on"
            for event in events
        ):
            _finding(
                findings,
                "c2_retirement_event_missing",
                history_path,
                "停止済みC2には監視停止eventが必要です。",
            )
            break
    maxmind = result.get("maxmind") if isinstance(result.get("maxmind"), dict) else {}
    freshness = (
        maxmind.get("freshness_policy")
        if isinstance(maxmind.get("freshness_policy"), dict)
        else {}
    )
    if freshness.get("checked_before_live_check") is not True:
        _finding(
            findings,
            "maxmind_freshness_not_checked_before_live",
            results_path,
            "ライブチェック前のMaxMind DB鮮度確認がありません。",
        )
    maximum_age = freshness.get("maximum_build_age_hours")
    if not isinstance(maximum_age, (int, float)) or isinstance(maximum_age, bool) or maximum_age > 24:
        _finding(
            findings,
            "maxmind_maximum_age_over_24_hours",
            results_path,
            "MaxMind DB build age上限は24時間以下である必要があります。",
        )
    expected_editions = ("GeoLite2-City", "GeoLite2-ASN")
    stale_before = freshness.get("stale_before_refresh")
    if not isinstance(stale_before, dict) or any(
        not isinstance(stale_before.get(edition), bool) for edition in expected_editions
    ):
        _finding(
            findings,
            "maxmind_stale_before_incomplete",
            results_path,
            "City/ASN双方の更新前鮮度判定が必要です。",
        )
        stale_before = {}
    build_epoch_before = freshness.get("build_epoch_before_refresh")
    if not isinstance(build_epoch_before, dict) or any(
        not isinstance(build_epoch_before.get(edition), int)
        or isinstance(build_epoch_before.get(edition), bool)
        or build_epoch_before.get(edition, 0) <= 0
        for edition in expected_editions
    ):
        _finding(
            findings,
            "maxmind_build_epoch_before_incomplete",
            results_path,
            "City/ASN双方の更新前build epochが必要です。",
        )
    if any(stale_before.values()):
        if freshness.get("refresh_performed") is not True:
            _finding(
                findings,
                "maxmind_stale_database_not_refreshed",
                results_path,
                "24時間以上前のMaxMind DBを更新していません。",
            )
        stale_after = freshness.get("stale_after_refresh")
        if not isinstance(stale_after, dict) or any(
            not isinstance(stale_after.get(edition), bool) for edition in expected_editions
        ):
            _finding(
                findings,
                "maxmind_stale_after_incomplete",
                results_path,
                "更新後のCity/ASN双方の鮮度判定が必要です。",
            )
        elif (
            any(stale_after.values())
            and freshness.get("latest_available_still_stale") is not True
        ):
            _finding(
                findings,
                "maxmind_latest_stale_not_recorded",
                results_path,
                "最新版自体が24時間超の場合は、その事実を明示する必要があります。",
            )
    for database_key in ("city_database", "asn_database"):
        database = maxmind.get(database_key) if isinstance(maxmind.get(database_key), dict) else {}
        if database.get("official_checksum_verified") is not True:
            _finding(
                findings,
                f"maxmind_{database_key}_checksum_unverified",
                results_path,
                "MaxMind DBの公式checksum検証がありません。",
            )
    for flag in ("license_key_published", "download_url_published", "mmdb_published"):
        if maxmind.get(flag) is not False:
            _finding(findings, f"maxmind_unsafe_{flag}", results_path, f"{flag}がfalseではありません。")
    return {
        "name": "c2_live_check",
        "root": root.as_posix(),
        "expected_cases": target_count if isinstance(target_count, int) else 0,
        "actual_cases": len(observations),
        "complete": not findings,
        "findings": findings,
    }


def validate_daily_analysis(
    repository: Path,
    analysis_date: str,
    news_source_date: str | None = None,
    malwarebazaar_count: int = EXPECTED_CASES,
) -> dict[str, Any]:
    if malwarebazaar_count <= 0:
        raise ValueError("MalwareBazaar件数は正の整数である必要があります")
    effective_news_date = news_source_date or analysis_date
    lanes = [
        validate_news(repository, effective_news_date),
        validate_malwarebazaar(repository, analysis_date, malwarebazaar_count),
        validate_clickfix(repository, analysis_date),
        validate_c2_live_check(repository, analysis_date),
    ]
    return {
        "schema_version": 1,
        "analysis_date": analysis_date,
        "news_source_date": effective_news_date,
        "required_lanes": [
            "daily_news",
            f"malwarebazaar_{malwarebazaar_count}",
            "clickfix_50",
            "c2_live_check",
        ],
        "complete": all(lane["complete"] for lane in lanes),
        "finding_count": sum(len(lane["findings"]) for lane in lanes),
        "lanes": lanes,
        "safety": {
            "validator_network_contacted": False,
            "samples_opened": False,
            "samples_executed": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--analysis-date", required=True)
    parser.add_argument(
        "--news-source-date",
        help="tech-memo最新公開日。省略時はanalysis-dateと同じ日付を使う。",
    )
    parser.add_argument(
        "--malwarebazaar-count",
        type=int,
        default=EXPECTED_CASES,
        help="検証対象のMalwareBazaar日次解析件数。既定値は50。",
    )
    arguments = parser.parse_args(argv)
    if arguments.malwarebazaar_count <= 0:
        parser.error("--malwarebazaar-countは正の整数で指定してください")
    analysis_date = datetime.strptime(arguments.analysis_date, "%Y-%m-%d").date().isoformat()
    news_source_date = None
    if arguments.news_source_date:
        news_source_date = datetime.strptime(arguments.news_source_date, "%Y-%m-%d").date().isoformat()
    result = validate_daily_analysis(
        arguments.repository.resolve(),
        analysis_date,
        news_source_date,
        arguments.malwarebazaar_count,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
