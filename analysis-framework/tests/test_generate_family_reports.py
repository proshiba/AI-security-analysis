"""AgentTesla／RemcosRATレポート生成器の日本語出力を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import audit_japanese_docs as japanese_audit  # noqa: E402
import generate_family_reports as reports  # noqa: E402


def reviewed_case(family: str) -> dict:
    """両ファミリーの分岐を通る公開可能なケースfixtureを返す。"""
    return {
        "sha256": "b" * 64,
        "artifact": "javascript_loader",
        "campaign": "rar_wrapped_javascript",
        "c2": ["203.0.113.5:443"],
        "stage_urls": ["https://stage.example.invalid/payload"],
        "notes": ["loader chain recovered from static structure"],
        "protocol": "smtp" if family == "AgentTesla" else "tcp",
        "version": "4.6",
    }


@pytest.mark.parametrize("family", ["AgentTesla", "RemcosRAT"])
def test_templates_emit_japanese_markdown_without_english_prose(tmp_path: Path, family: str) -> None:
    """両ファミリーのケース／索引に英語だけの説明行を生成しない。"""
    case = reviewed_case(family)
    documents = {
        f"{family}-case.md": reports.case_report(family, case),
        f"{family}-index.md": reports.family_index({"family": family, "cases": [case]}),
    }
    for name, content in documents.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        result = japanese_audit.analyze_markdown(path, tmp_path)
        assert result["has_japanese"] is True
        assert result["english_only_prose"] == []
        assert "`rar_wrapped_javascript`" in content


def test_main_regenerates_only_japanese_markdown(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLIで再生成した索引とケース文書も日本語監査を通過する。"""
    data = {"family": "AgentTesla", "cases": [reviewed_case("AgentTesla")]}
    source = tmp_path / "cases.json"
    source.write_text(json.dumps(data), encoding="utf-8")
    output = tmp_path / "results"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate_family_reports.py",
            "--cases",
            str(source),
            "--output",
            str(output),
        ],
    )
    assert reports.main() == 0
    audit = japanese_audit.audit_repository(tmp_path, [output])
    assert audit["counts"]["documents"] == 2
    assert audit["documents_without_japanese"] == []
    assert audit["counts"]["english_only_prose_lines"] == 0
    indicators = json.loads((output / "cases" / ("b" * 64) / "indicators.json").read_text(encoding="utf-8"))
    assert indicators["executed_locally"] is False
    assert indicators["network_contacted"] is False
    assert indicators["credentials_published"] is False


def test_main_separates_canonical_cases_from_collection_source(
    short_tmp: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """canonical collection出力ではcaseを固定レイアウトへ分離する。"""
    tmp_path = short_tmp
    case = reviewed_case("AgentTesla")
    source = tmp_path / "cases.json"
    source.write_text(
        json.dumps({"family": "AgentTesla", "cases": [case]}),
        encoding="utf-8",
    )
    output = (
        tmp_path
        / "analysis-results"
        / "collections"
        / "refresh-20260718"
        / "sources"
        / "agenttesla"
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "generate_family_reports.py",
            "--cases",
            str(source),
            "--output",
            str(output),
        ],
    )

    assert reports.main() == 0

    canonical = (
        tmp_path
        / "analysis-results"
        / "malware"
        / "agenttesla"
        / "versions"
        / "unknown"
        / "cases"
        / case["sha256"]
    )
    assert (canonical / "README.md").is_file()
    assert not (output / "cases").exists()
    indicators = json.loads(
        (canonical / "indicators.json").read_text(encoding="utf-8")
    )
    assert indicators["schema_version"] == 1
    catalog = json.loads(
        (
            tmp_path / "analysis-results" / "catalog" / "cases.json"
        ).read_text(encoding="utf-8")
    )
    assert catalog["cases"][case["sha256"]]["family"] == "agenttesla"
    collection = json.loads(
        (
            tmp_path
            / "analysis-results"
            / "collections"
            / "refresh-20260718"
            / "manifest.json"
        ).read_text(encoding="utf-8")
    )
    assert collection["cases"] == [
        {"case_id": f"sha256:{case['sha256']}"}
    ]
