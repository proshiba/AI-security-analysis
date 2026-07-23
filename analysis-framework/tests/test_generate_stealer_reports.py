"""Tests for stealer report generation."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import pytest


COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import generate_stealer_reports as reports  # noqa: E402
import audit_japanese_docs as japanese_audit  # noqa: E402


def fixture_case(root: Path, sha256: str) -> None:
    """Create one normalized report-input fixture."""
    root.mkdir(parents=True)
    config = {
        "config": {
            "features": {"browser_collection": True},
            "version": "1.2.3",
            "decoded_strings": ["large evidence omitted from README"],
            "static_config_recovered": True,
        },
        "findings": [
            {
                "kind": "network.url",
                "value": "https://evil.example/api/",
                "role": "c2_or_exfil_candidate",
                "confidence": "probable",
                "source": "embedded_literal",
            }
        ],
        "limitations": ["fixture limitation from the parser"],
        "layers_analyzed": 0,
    }
    (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (root / "c2-candidates.json").write_text(json.dumps({"targets": []}), encoding="utf-8")
    unpack = {
        "size": 4096,
        "entropy": 7.0,
        "format": "pe",
        "pe": {
            "machine": "0x8664",
            "is_dotnet": False,
            "is_go": False,
            "imports": 12,
            "import_libraries": ["kernel32.dll"],
            "entrypoint_section": ".text",
            "sections": [{"name": ".text"}],
            "classification": "not_packed",
            "overlay_size": 0,
            "resource_count": 1,
        },
    }
    (root / "unpack.json").write_text(json.dumps(unpack), encoding="utf-8")
    (root / "layers.json").write_text(json.dumps({"layers": []}), encoding="utf-8")


def test_load_summarize_render_generate_and_cli(tmp_path: Path) -> None:
    """Exercise every public report-generation function."""
    sha256 = "a" * 64
    pipeline = tmp_path / "pipeline"
    fixture_case(pipeline / sha256, sha256)
    item = {
        "sha256": sha256,
        "name": "x.exe",
        "family": "fixture",
        "campaign": "direct_pe_or_pe_loader",
        "format": "pe",
        "packing_suspected": True,
        "recovered_artifacts": 0,
        "config_findings": 1,
    }
    summary = {
        "family": "fixture",
        "signature": "Fixture",
        "source": "vx-underground",
        "counts": {"errors": 0, "with_static_config": 1},
        "cases": [item],
    }
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    case = reports.load_case(pipeline / sha256)
    value = reports.summarize_family(summary, pipeline)
    case_text = reports.render_case(item, case)
    assert "設定とC2の証拠" in case_text
    assert "large evidence omitted from README" not in case_text
    family_text = reports.render_family(value)
    assert "検知時の考慮事項" in family_text
    assert "## 静的実行ロジック（根拠別）" in case_text
    assert "x86-64のネイティブPE" in case_text
    assert "提供元ラベルだけからC2や実機能を断定" not in case_text
    assert "現在の到達性や所有者は未確認" in case_text
    assert "`vx-underground`" in family_text
    empty_family = {
        **value,
        "features": {},
        "findings": [],
        "config_values": {},
    }
    empty_path = tmp_path / "empty-family.md"
    empty_path.write_text(reports.render_family(empty_family), encoding="utf-8")
    assert japanese_audit.analyze_markdown(empty_path, tmp_path)["english_only_prose"] == []
    assert value["config_values"]["version"] == {"1.2.3": 1}
    destination = tmp_path / "results"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"items": [{"sha256": sha256, "zip_path": "local.zip"}]}), encoding="utf-8")
    assert reports.generate(summary_path, pipeline, destination, manifest_path)["case_count"] == 1
    public = json.loads((destination / "malwarebazaar-manifest.json").read_text())
    assert public["items"] == [{"sha256": sha256}]
    audit = japanese_audit.audit_repository(tmp_path, [destination])
    assert audit["counts"]["documents"] == 2
    assert audit["documents_without_japanese"] == []
    assert audit["counts"]["english_only_prose_lines"] == 0
    args = ["--summary", str(summary_path), "--pipeline-root", str(pipeline), "--destination", str(destination)]
    assert reports.build_parser().parse_args(args).summary == summary_path
    assert reports.main(args) == 0


def test_append_report_generation_rejects_duplicates(tmp_path: Path) -> None:
    """既存集計へ別ケースだけを追記し、同一SHAの再追記を拒否する。"""
    first_sha = "1" * 64
    second_sha = "2" * 64
    first_pipeline = tmp_path / "first"
    second_pipeline = tmp_path / "second"
    fixture_case(first_pipeline / first_sha, first_sha)
    fixture_case(second_pipeline / second_sha, second_sha)

    def write_summary(path: Path, sha256: str) -> Path:
        item = {
            "sha256": sha256,
            "name": f"{sha256}.exe",
            "family": "fixture",
            "campaign": "direct_pe",
            "format": "pe",
            "packing_suspected": False,
            "recovered_artifacts": 0,
            "config_findings": 1,
        }
        value = {
            "family": "fixture",
            "signature": "Fixture",
            "source": "MalwareBazaar",
            "counts": {"total": 1, "errors": 0, "with_static_config": 1},
            "cases": [item],
        }
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    first_summary = write_summary(tmp_path / "first-summary.json", first_sha)
    second_summary = write_summary(tmp_path / "second-summary.json", second_sha)
    first_manifest = tmp_path / "first-manifest.json"
    second_manifest = tmp_path / "second-manifest.json"
    first_manifest.write_text(
        json.dumps({"complete": True, "items": [{"sha256": first_sha, "zip_path": "a.zip"}]}),
        encoding="utf-8",
    )
    second_manifest.write_text(
        json.dumps({"complete": True, "items": [{"sha256": second_sha, "zip_path": "b.zip"}]}),
        encoding="utf-8",
    )
    destination = tmp_path / "combined"
    reports.generate(first_summary, first_pipeline, destination, first_manifest)
    combined = reports.generate(
        second_summary, second_pipeline, destination, second_manifest, append=True
    )
    assert combined["case_count"] == 2
    assert combined["counts"]["total"] == 2
    assert (destination / "cases" / first_sha / "README.md").is_file()
    assert (destination / "cases" / second_sha / "README.md").is_file()
    public = json.loads(
        (destination / "malwarebazaar-manifest.json").read_text(encoding="utf-8")
    )
    assert [item["sha256"] for item in public["items"]] == [first_sha, second_sha]
    assert all("zip_path" not in item for item in public["items"])
    with pytest.raises(ValueError, match="duplicate cases"):
        reports.generate(
            second_summary, second_pipeline, destination, second_manifest, append=True
        )


def test_canonical_collection_destination_separates_cases_and_updates_indexes(
    short_tmp: Path,
) -> None:
    """collection集約とcanonical caseを分離し、indexを同期する。"""
    sha256 = "c" * 64
    tmp_path = short_tmp
    pipeline = tmp_path / "pipeline"
    fixture_case(pipeline / sha256, sha256)
    summary = {
        "family": "AgentTesla",
        "signature": "AgentTesla",
        "source": "MalwareBazaar",
        "counts": {"errors": 0, "with_static_config": 1},
        "cases": [
            {
                "sha256": sha256,
                "name": "x.exe",
                "family": "agenttesla",
                "campaign": "direct_pe",
                "format": "pe",
                "packing_suspected": False,
                "recovered_artifacts": 0,
                "config_findings": 1,
            }
        ],
    }
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    destination = (
        tmp_path
        / "analysis-results"
        / "collections"
        / "refresh-20260718"
        / "sources"
        / "agenttesla"
    )

    reports.generate(summary_path, pipeline, destination)

    canonical = (
        tmp_path
        / "analysis-results"
        / "malware"
        / "agenttesla"
        / "versions"
        / "unknown"
        / "cases"
        / sha256
    )
    assert (canonical / "README.md").is_file()
    assert not (destination / "cases").exists()
    analysis = json.loads((canonical / "analysis.json").read_text(encoding="utf-8"))
    assert analysis["schema_version"] == 1
    assert "../" in (destination / "README.md").read_text(encoding="utf-8")
    catalog = json.loads(
        (
            tmp_path / "analysis-results" / "catalog" / "cases.json"
        ).read_text(encoding="utf-8")
    )
    assert catalog["cases"][sha256]["family"] == "agenttesla"
    collection = json.loads(
        (
            tmp_path
            / "analysis-results"
            / "collections"
            / "refresh-20260718"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert collection["cases"] == [{"case_id": f"sha256:{sha256}"}]
