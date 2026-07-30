#!/usr/bin/env python3
"""daily解析の3系統が揃い、安全条件を満たすことを検証する。"""

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


def validate_malwarebazaar(repository: Path, analysis_date: str) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    compact = analysis_date.replace("-", "")
    root = repository / "analysis-results" / "collections" / f"malwarebazaar-windows-{compact}-0050"
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
        if actual != EXPECTED_CASES:
            _finding(
                findings,
                f"malwarebazaar_{field}_count",
                manifest_path,
                f"{field}は{EXPECTED_CASES}である必要があります: actual={actual}",
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
        "name": "malwarebazaar_50",
        "root": root.as_posix(),
        "expected_cases": EXPECTED_CASES,
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


def validate_daily_analysis(
    repository: Path,
    analysis_date: str,
    news_source_date: str | None = None,
) -> dict[str, Any]:
    effective_news_date = news_source_date or analysis_date
    lanes = [
        validate_news(repository, effective_news_date),
        validate_malwarebazaar(repository, analysis_date),
        validate_clickfix(repository, analysis_date),
    ]
    return {
        "schema_version": 1,
        "analysis_date": analysis_date,
        "news_source_date": effective_news_date,
        "required_lanes": ["daily_news", "malwarebazaar_50", "clickfix_50"],
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
    arguments = parser.parse_args(argv)
    analysis_date = datetime.strptime(arguments.analysis_date, "%Y-%m-%d").date().isoformat()
    news_source_date = None
    if arguments.news_source_date:
        news_source_date = datetime.strptime(arguments.news_source_date, "%Y-%m-%d").date().isoformat()
    result = validate_daily_analysis(
        arguments.repository.resolve(),
        analysis_date,
        news_source_date,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
