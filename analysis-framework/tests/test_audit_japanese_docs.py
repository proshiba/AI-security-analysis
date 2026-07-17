"""文書日本語化監査の境界条件を検証する。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import audit_japanese_docs as audit


def test_audit_distinguishes_japanese_prose_from_code_and_english(tmp_path: Path) -> None:
    """コード内英語を無視し、英語だけの見出しと説明を列挙する。"""
    repository = tmp_path / "repo"
    repository.mkdir()
    japanese = repository / "ja.md"
    japanese.write_text(
        "# 解析概要\n\n検体は実行せず、静的に確認した。\n\n```text\nEnglish code only\n```\n",
        encoding="utf-8",
    )
    english = repository / "en.md"
    english.write_text(
        "# Overview\n\nThis document contains a fully English explanation.\n",
        encoding="utf-8",
    )
    report = audit.audit_repository(repository)
    assert report["counts"]["documents"] == 2
    assert report["documents_without_japanese"] == ["en.md"]
    assert report["counts"]["english_only_prose_lines"] == 2


def test_discovery_rejects_external_roots_and_ignores_work(tmp_path: Path) -> None:
    """監査範囲外パスを拒否し、ローカル作業文書を数えない。"""
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "README.md").write_text("# 日本語\n", encoding="utf-8")
    work = repository / ".work"
    work.mkdir()
    (work / "private.md").write_text("# English\n", encoding="utf-8")
    pytest_cache = repository / ".pytest_cache"
    pytest_cache.mkdir()
    (pytest_cache / "README.md").write_text("# Generated cache documentation\n", encoding="utf-8")
    assert audit.audit_repository(repository)["counts"]["documents"] == 1
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(ValueError, match="within the repository"):
        audit.discover_markdown(repository, [outside])


def test_audit_ignores_machine_value_rows_and_command_enumerations() -> None:
    """hash主体の表行と小文字command列挙を英語説明として誤検知しない。"""

    digest = "a" * 64
    table = (
        f"| {digest} | 185.18.222.241 | SAPPHIRE | "
        "one.asp, two.asp | K31610KIO9834PG79A471 |"
    )
    assert audit._english_prose_candidate(table) is False
    assert audit._english_prose_candidate(
        "- procspawn、prockill、proclist、diskinfo"
    ) is False
    assert audit._english_prose_candidate(
        "- This remains ordinary English prose and must be reported."
    ) is True
    assert audit._english_prose_candidate(
        "| circl_hashlookup | not_found | 93 |"
    ) is False
    assert audit._english_prose_candidate(
        "| `https://example.test/a.ps1` | stage_url_candidate | candidate | bounded_static_strings |"
    ) is False
    assert audit._english_prose_candidate("## v7.2.6-pro（7.2.6 Pro）") is False
    assert audit._english_prose_candidate(
        "| Assessment | This row remains ordinary English prose |"
    ) is True


def test_ioc_machine_rows_are_not_treated_as_human_prose(tmp_path: Path) -> None:
    """日本語見出しを持つIOC一覧では機械値を英語説明として数えない。"""

    repository = tmp_path / "repo"
    repository.mkdir()
    ioc = repository / "IOC-LIST.md"
    ioc.write_text(
        "# IOC一覧\n\n| 種別 | 値 | 役割 | 確度 | 根拠 |\n"
        "|---|---|---|---|---|\n"
        "| url | https://example.test/a.ps1 | stage_url_candidate | candidate | config.json |\n",
        encoding="utf-8",
    )

    report = audit.audit_repository(repository)
    assert report["counts"]["english_only_prose_lines"] == 0


def test_cli_writes_bounded_outputs_and_can_fail_on_findings(tmp_path: Path) -> None:
    """CLI の出力制約と findings 終了コードを検証する。"""
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "README.md").write_text("# Overview\n", encoding="utf-8")
    output_json = repository / "audit.json"
    output_md = repository / "audit.md"
    result = audit.main(
        [
            "--repository",
            str(repository),
            "--output-json",
            str(output_json),
            "--output-markdown",
            str(output_md),
            "--fail-on-findings",
        ]
    )
    assert result == 1
    assert json.loads(output_json.read_text(encoding="utf-8"))["schema_version"] == 1
    assert "# 文書日本語化監査" in output_md.read_text(encoding="utf-8")
    with pytest.raises(ValueError, match="within the repository"):
        audit.main(
            [
                "--repository",
                str(repository),
                "--output-json",
                str(tmp_path / "outside.json"),
            ]
        )
