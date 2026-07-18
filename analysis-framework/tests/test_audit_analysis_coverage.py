"""Tests for the repository-only analysis coverage audit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

import audit_analysis_coverage as audit


SHA = "a" * 64


def _repository(tmp_path: Path) -> Path:
    results = tmp_path / "analysis-results"
    case = results / "family" / "cases" / SHA
    case.mkdir(parents=True)
    (case / "README.md").write_text("# case\n", encoding="utf-8")
    (case / "IOC-LIST.md").write_text(
        "# IOC 一覧\n\n"
        "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |\n"
        "|---|---|---|---|---|\n"
        f"| sha256 | {SHA} | submitted_sample | confirmed | test |\n",
        encoding="utf-8",
    )
    (case / "analysis.json").write_text(
        json.dumps(
            {
                "status": "needs_review",
                "static_config_recovered": False,
                "limitation": "terminal not_recovered",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "analysis_history.yaml").write_text(
        yaml.safe_dump({"analyses": [{"sample_sha256": SHA}]}), encoding="utf-8"
    )
    definitions = tmp_path / "analysis-framework" / "definitions"
    (definitions / "malware").mkdir(parents=True)
    (definitions / "workflows").mkdir()
    (definitions / "malware" / "family.yaml").write_text("{}\n", encoding="utf-8")
    registry = tmp_path / "analysis-framework" / "registry"
    registry.mkdir(parents=True)
    (registry / "malware_types.json").write_text(
        json.dumps({"malware_types": [{"id": "family"}]}), encoding="utf-8"
    )
    return tmp_path


def test_audit_reports_status_unresolved_and_schema_gap(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    report = audit.audit_repository(repository)
    assert report["counts"]["case_directories"] == 1
    assert report["analysis_statuses"] == {"needs_review": 1}
    assert report["counts"]["decoded_or_static_config_not_recovered_cases"] == 1
    assert report["findings"]["decoded_or_static_config_not_recovered_cases"] == [
        {
            "sha256": SHA,
            "paths": [f"analysis-results/family/cases/{SHA}/analysis.json"],
        }
    ]
    assert report["unresolved_case_hashes"]["not_recovered"] == [SHA]
    assert report["finding_counts"]["analysis_json_without_schema_version"] == 1
    assert report["finding_counts"]["case_hashes_missing_from_history"] == 0
    assert report["safety"]["samples_opened"] is False


def test_case_recovery_state_overrides_unselected_child_failures(tmp_path: Path) -> None:
    """Do not count a recovered case merely because another child was unrecovered."""
    repository = _repository(tmp_path)
    case = repository / "analysis-results" / "family" / "cases" / SHA
    (case / "analysis.json").write_text(
        json.dumps(
            {
                "case": {"static_config_recovered": True},
                "config": {
                    "config": {"static_config_recovered": True},
                    "selected_layer_config": {
                        "config": {"static_config_recovered": True}
                    },
                },
                "layers": [
                    {"config": {"static_config_recovered": False}}
                ],
            }
        ),
        encoding="utf-8",
    )
    report = audit.audit_repository(repository)
    assert report["counts"]["decoded_or_static_config_not_recovered_cases"] == 0
    assert report["findings"]["decoded_or_static_config_not_recovered_cases"] == []

    (case / "analysis.json").write_text(
        json.dumps(
            {
                "case": {},
                "config": {
                    "config": {"static_config_recovered": False},
                    "selected_layer_config": {
                        "config": {"static_config_recovered": True}
                    },
                },
                "layers": [
                    {"config": {"static_config_recovered": False}}
                ],
            }
        ),
        encoding="utf-8",
    )
    selected_report = audit.audit_repository(repository)
    assert selected_report["counts"]["decoded_or_static_config_not_recovered_cases"] == 0


def test_readme_only_unresolved_marker_is_counted(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    case = repository / "analysis-results" / "family" / "cases" / SHA
    (case / "README.md").write_text("Terminal: none recovered.\n", encoding="utf-8")
    report = audit.audit_repository(repository)
    assert report["unresolved_case_hashes"]["none_recovered"] == [SHA]


def test_ioc_provider_and_output_boundary_checks(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    case = repository / "analysis-results" / "family" / "cases" / SHA
    (case / "IOC-LIST.md").write_text("# old format\n", encoding="utf-8")
    (case / "malwarebazaar-info.json").write_text(
        json.dumps({"reporter": "should-not-be-public"}), encoding="utf-8"
    )
    report = audit.audit_repository(repository)
    assert report["finding_counts"]["nonstandard_ioc_lists"] == 1
    assert report["finding_counts"]["provider_boundary_violations"] == 1
    with pytest.raises(ValueError, match="within the repository"):
        audit._validate_output_paths(repository, (repository.parent / "outside.json",))


def test_hard_case_summary_uses_canonical_research_path(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    report_path = (
        repository
        / "analysis-results"
        / "research"
        / "audits"
        / "static-hard-cases"
        / "deep-static-triage.json"
    )
    report_path.parent.mkdir(parents=True)
    report_path.write_text(
        json.dumps({"summary": {"total": 3, "analyzed": 2, "partial": 1}}),
        encoding="utf-8",
    )

    report = audit.audit_repository(repository)

    assert report["hard_case_summary"]["total"] == 3
    assert report["hard_case_summary"]["analyzed"] == 2


def test_cli_writes_distinct_reports(tmp_path: Path) -> None:
    repository = _repository(tmp_path)
    output_json = repository / "audit.json"
    output_markdown = repository / "audit.md"
    assert (
        audit.main(
            [
                "--repository",
                str(repository),
                "--output-json",
                str(output_json),
                "--output-markdown",
                str(output_markdown),
            ]
        )
        == 0
    )
    assert json.loads(output_json.read_text(encoding="utf-8"))["schema_version"] == 1
    assert "静的解析カバレッジ監査" in output_markdown.read_text(encoding="utf-8")
