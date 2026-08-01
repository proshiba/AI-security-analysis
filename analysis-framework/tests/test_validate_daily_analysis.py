from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys


MODULE_PATH = Path(__file__).resolve().parents[1] / "common" / "validate_daily_analysis.py"
SPEC = importlib.util.spec_from_file_location("validate_daily_analysis", MODULE_PATH)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = target
SPEC.loader.exec_module(target)


ANALYSIS_DATE = "2026-07-30"


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False),
        encoding="utf-8",
    )


def _complete_repository(root: Path, malwarebazaar_count: int = 50) -> Path:
    news = root / "analysis-results" / "research" / "daily-news-malware" / ANALYSIS_DATE
    news.mkdir(parents=True)
    for name in target.NEWS_FILES:
        path = news / name
        if path.suffix == ".md":
            path.write_text("# 日次解析\n", encoding="utf-8")
    _write_json(
        news / "ioc-summary.json",
        {"source_date": ANALYSIS_DATE},
    )
    _write_json(
        news / "infrastructure-summary.json",
        {"source_date": ANALYSIS_DATE},
    )
    _write_json(
        news / "provider-summary.json",
        {
            "source_date": ANALYSIS_DATE,
            "virustotal_submission_performed": False,
        },
    )
    _write_json(
        news / "sample-static-summary.json",
        {
            "source_date": ANALYSIS_DATE,
            "safety": {
                "sample_executed": False,
                "network_contacted_by_sample": False,
                "raw_sample_published": False,
                "raw_decompilation_published": False,
            },
        },
    )

    compact = ANALYSIS_DATE.replace("-", "")
    malwarebazaar = (
        root
        / "analysis-results"
        / "collections"
        / f"malwarebazaar-windows-{compact}-{malwarebazaar_count:04d}"
    )
    malwarebazaar.mkdir(parents=True)
    (malwarebazaar / "README.md").write_text(
        "# MalwareBazaar解析\n",
        encoding="utf-8",
    )
    _write_json(
        malwarebazaar / "manifest.json",
        {
            "requested": malwarebazaar_count,
            "downloaded": malwarebazaar_count,
            "cases": [
                {"sha256": f"{index:064x}"}
                for index in range(malwarebazaar_count)
            ],
            "acquisition_items": [
                {"sha256": f"{index:064x}"}
                for index in range(malwarebazaar_count)
            ],
            "acquisition_complete": True,
            "analysis_complete": True,
            "complete": True,
            "pending": 0,
            "samples_executed": False,
            "network_contacted": False,
            "archives_stored_in_repository": False,
        },
    )
    _write_json(
        malwarebazaar / "publication-summary.json",
        {"analysis_complete": True},
    )

    clickfix = root / "analysis-results" / "clickfix"
    collection = clickfix / "collections" / f"clickfix-daily-{compact}"
    collection.mkdir(parents=True)
    for name in (
        "README.md",
        "INFRASTRUCTURE-SUMMARY.md",
        "TRIAGE-SUMMARY.md",
    ):
        (collection / name).write_text("# ClickFix解析\n", encoding="utf-8")
    cases = []
    for index in range(50):
        domain = f"case{index}.example"
        case_id = f"20260730-threatfox-{index}"
        relative = f"{domain}/cases/{case_id}"
        case_root = clickfix / relative
        for name in target.CLICKFIX_FILES:
            path = case_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.suffix == ".json":
                _write_json(path, {})
            else:
                path.write_text("# 成果物\n", encoding="utf-8")
        _write_json(
            case_root / "infrastructure.json",
            {
                "case_id": case_id,
                "investigated_at_utc": "2026-07-30T00:00:00Z",
            },
        )
        _write_json(
            case_root / "triage-evidence.json",
            {
                "case_id": case_id,
                "queried_at_utc": "2026-07-30T00:00:00Z",
                "safety": {
                    "sample_submitted": False,
                    "sample_downloaded": False,
                    "artifact_downloaded": False,
                    "pcap_downloaded": False,
                    "sample_executed_locally": False,
                },
            },
        )
        cases.append(
            {
                "domain": domain,
                "case_id": case_id,
                "relative_path": relative,
            }
        )
    _write_json(
        collection / "manifest.json",
        {
            "analysis_date": ANALYSIS_DATE,
            "case_count": 50,
            "cases": cases,
        },
    )
    return root


def test_complete_three_lane_daily_analysis_passes(tmp_path: Path) -> None:
    repository = _complete_repository(tmp_path)

    result = target.validate_daily_analysis(repository, ANALYSIS_DATE)

    assert result["complete"] is True
    assert result["finding_count"] == 0
    assert [lane["name"] for lane in result["lanes"]] == [
        "daily_news",
        "malwarebazaar_50",
        "clickfix_50",
    ]


def test_missing_clickfix_case_fails_daily_completion(tmp_path: Path) -> None:
    repository = _complete_repository(tmp_path)
    manifest_path = (
        repository / "analysis-results" / "clickfix" / "collections" / "clickfix-daily-20260730" / "manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["cases"].pop()
    manifest["case_count"] = 49
    _write_json(manifest_path, manifest)

    result = target.validate_daily_analysis(repository, ANALYSIS_DATE)

    assert result["complete"] is False
    assert any(finding["code"] == "clickfix_case_count" for finding in result["lanes"][2]["findings"])


def test_complete_daily_analysis_supports_100_malwarebazaar_cases(tmp_path: Path) -> None:
    repository = _complete_repository(tmp_path, malwarebazaar_count=100)

    result = target.validate_daily_analysis(
        repository,
        ANALYSIS_DATE,
        malwarebazaar_count=100,
    )

    assert result["complete"] is True
    assert result["required_lanes"] == [
        "daily_news",
        "malwarebazaar_100",
        "clickfix_50",
    ]
    assert result["lanes"][1]["expected_cases"] == 100
    assert result["lanes"][1]["actual_cases"] == 100


def test_partial_malwarebazaar_fails_daily_completion(tmp_path: Path) -> None:
    repository = _complete_repository(tmp_path)
    manifest_path = (
        repository / "analysis-results" / "collections" / "malwarebazaar-windows-20260730-0050" / "manifest.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["analysis_complete"] = False
    manifest["complete"] = False
    manifest["pending"] = 1
    _write_json(manifest_path, manifest)

    result = target.validate_daily_analysis(repository, ANALYSIS_DATE)

    assert result["complete"] is False
    codes = {item["code"] for item in result["lanes"][1]["findings"]}
    assert "malwarebazaar_analysis_complete_not_true" in codes
    assert "malwarebazaar_pending" in codes


def test_unsafe_triage_artifact_download_fails(tmp_path: Path) -> None:
    repository = _complete_repository(tmp_path)
    evidence_path = next((repository / "analysis-results" / "clickfix").rglob("triage-evidence.json"))
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    evidence["safety"]["artifact_downloaded"] = True
    _write_json(evidence_path, evidence)

    result = target.validate_daily_analysis(repository, ANALYSIS_DATE)

    assert result["complete"] is False
    assert any(finding["code"] == "clickfix_unsafe_artifact_downloaded" for finding in result["lanes"][2]["findings"])


def test_news_source_date_can_differ_from_execution_date(tmp_path: Path) -> None:
    repository = _complete_repository(tmp_path)
    original = repository / "analysis-results" / "research" / "daily-news-malware" / ANALYSIS_DATE
    source_date = "2026-07-29"
    renamed = original.with_name(source_date)
    original.rename(renamed)
    for path in renamed.glob("*.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        value["source_date"] = source_date
        _write_json(path, value)

    result = target.validate_daily_analysis(
        repository,
        ANALYSIS_DATE,
        news_source_date=source_date,
    )

    assert result["complete"] is True
    assert result["analysis_date"] == ANALYSIS_DATE
    assert result["news_source_date"] == source_date
