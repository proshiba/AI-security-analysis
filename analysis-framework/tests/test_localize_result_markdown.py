"""解析結果 Markdown の安全な日本語化とトランザクション境界を検証する。"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import localize_result_markdown as localize


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repo"
    results = repository / "analysis-results"
    results.mkdir(parents=True)
    return repository, results


def test_preserves_fences_inline_code_urls_hashes_and_enum_values() -> None:
    digest = "a" * 64
    fenced = "```yaml\nOverview: analysis\nrule: NeverTranslate\n```"
    source = (
        f"# Demo case {digest}\r\n\r\n"
        "## Overview\r\n"
        "- Unpack status: `no_artifact_recovered`\r\n"
        "- YARA rule name: `Keep_This_Rule`\r\n"
        f"- Reference: [Overview](https://example.test/Overview) {digest}\r\n\r\n"
        + fenced
        + "\r\n"
    )
    result = localize.localize_markdown(source)
    assert f"# Demo ケース {digest}\r\n" in result
    assert "## 概要\r\n" in result
    assert "- アンパック状況: `no_artifact_recovered`\r\n" in result
    assert "`Keep_This_Rule`" in result
    assert "https://example.test/Overview" in result
    assert result.count(digest) == 2
    assert fenced in result
    prefix = result.split("```yaml", 1)[0]
    assert "\r\n" in prefix and "\n" not in prefix.replace("\r\n", "")


def test_translates_common_templates_and_ioc_header_without_changing_rows() -> None:
    source = (
        "# XWorm analysis results\n\n"
        "## Config and C2 evidence\n\n"
        "| Type | Value | Role | Confidence | Source |\n"
        "|---|---|---|---|---|\n"
        "| sha256 | abc | submitted_sample | confirmed | directory |\n\n"
        "An embedded value is not proof that the server is live or exclusively controlled by this family.\n\n"
        "## Limitations\n"
        "- Static extraction only; no payload execution or C2 contact was performed.\n"
    )
    result = localize.localize_markdown(source)
    assert "# XWorm 解析結果" in result
    assert "## 設定および C2 の根拠" in result
    assert (
        "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |"
        in result
    )
    assert "| sha256 | abc | submitted_sample | confirmed | directory |" in result
    assert "埋め込み値だけでは" in result
    assert "## 制約" in result
    assert "ペイロードの実行や C2 への接続は行っていない" in result
    assert localize.find_unresolved_english(result) == ()


def test_reports_exact_unresolved_english_and_does_not_hide_it() -> None:
    source = (
        "# Overview\n\n"
        "This custom sentence still requires a reviewed human translation.\n"
        "- Notes: This second custom explanation also remains unresolved.\n"
    )
    result = localize.localize_markdown(source)
    findings = localize.find_unresolved_english(result)
    assert result.startswith("# 概要\n")
    assert [item.line for item in findings] == [3, 4]
    assert findings[0].text == (
        "This custom sentence still requires a reviewed human translation."
    )
    assert findings[1].text == (
        "- Notes: This second custom explanation also remains unresolved."
    )


def test_japanese_citation_and_narrow_identifiers_are_not_false_positives() -> None:
    localized = (
        "- Blind Eagle：AsyncRATを使用した。"
        "（[出典：検証機関「AsyncRATの技術解析」]"
        "(<https://example.test/english/path>)）（信頼度：高）\n"
    )
    assert localize.find_unresolved_english(localized) == ()

    untranslated_title = (
        "- 出典を確認した。"
        "[出典：検証機関「This English Article Title Remains」]"
        "(<https://example.test/report>)\n"
    )
    assert localize.find_unresolved_english(untranslated_title)

    mixed_unknown = "説明：This custom English prose still remains unresolved.\n"
    assert localize.find_unresolved_english(mixed_unknown)


def test_abbreviated_hash_asp_and_boolean_machine_values_are_preserved() -> None:
    source = "- 検体 `add013bf...`：ファイル login.asp、設定値 false。\n"
    assert localize.find_unresolved_english(source) == ()
    assert localize._preserved_values(source) == (
        "code:`add013bf...`",
        "filename:login.asp",
    )
    technical_chain = (
        "| 復元チェーン | UTF-16スクリプト → PowerShell → "
        "Unicode値から19968減算 | x64 .NET／パッキングなし |\n"
    )
    assert localize.find_unresolved_english(technical_chain) == ()


def test_generic_ascii_h1_is_not_disguised_as_a_product_title() -> None:
    source = "# Public analysis publication rules\n"
    result = localize.localize_markdown(source)
    assert result == source
    assert localize.find_unresolved_english(result)[0].text == source.rstrip()


def test_existing_japanese_link_label_repository_identifier_is_unchanged() -> None:
    source = (
        "# XWorm 解析概要\n\n"
        "参照先: [AI-security-analysis](https://example.test/repository)\n"
    )
    assert localize.localize_markdown(source) == source


def test_reviewed_full_document_translation_is_bound_to_source_hash(
    tmp_path: Path,
) -> None:
    repository, results = _repository(tmp_path)
    source = "# Special report\n\nThis requires a document-specific translation.\n"
    document = results / "special.md"
    document.write_text(source, encoding="utf-8")
    digest = localize._digest(document.read_bytes())
    knowledge = (
        repository / "analysis-framework" / "knowledge" / "result_markdown_ja"
    )
    knowledge.mkdir(parents=True)
    (knowledge / f"{digest}.md").write_text(
        "# 特別報告\n\nこの文書には個別にレビューした翻訳を適用する。\n",
        encoding="utf-8",
    )
    plan = localize.build_plan(repository)
    assert plan.entries[0].translation_method == "reviewed_document"
    assert plan.entries[0].unresolved == ()
    assert localize.apply_plan(plan) == 1
    assert document.read_text(encoding="utf-8").startswith("# 特別報告")
    second_plan = localize.build_plan(repository)
    assert second_plan.entries[0].translation_method == "reviewed_document"
    assert second_plan.entries[0].unresolved == ()
    assert not second_plan.entries[0].changed


def test_reviewed_translation_inherits_uniform_source_newlines(tmp_path: Path) -> None:
    repository, results = _repository(tmp_path)
    document = results / "crlf.md"
    document.write_bytes(b"# XWorm analysis\r\n\r\n```text\r\nvalue\r\n```\r\n")
    digest = localize._digest(document.read_bytes())
    knowledge = repository / "analysis-framework/knowledge/result_markdown_ja"
    knowledge.mkdir(parents=True)
    (knowledge / f"{digest}.md").write_bytes(
        "# XWorm 解析\n\n```text\nvalue\n```\n".encode("utf-8")
    )
    plan = localize.build_plan(repository)
    target = plan.entries[0]._target_bytes
    assert b"\r\n" in target
    assert b"\n" not in target.replace(b"\r\n", b"")


def test_reviewed_translation_rejects_protected_value_reordering(
    tmp_path: Path,
) -> None:
    repository, results = _repository(tmp_path)
    document = results / "claims.md"
    document.write_text(
        "# Claims\n\nFirst: https://one.example/ `first_value`\n"
        "Second: https://two.example/ `second_value`\n",
        encoding="utf-8",
    )
    digest = localize._digest(document.read_bytes())
    knowledge = repository / "analysis-framework/knowledge/result_markdown_ja"
    knowledge.mkdir(parents=True)
    (knowledge / f"{digest}.md").write_text(
        "# 主張\n\n2番目: https://two.example/ `second_value`\n"
        "1番目: https://one.example/ `first_value`\n",
        encoding="utf-8",
    )
    with pytest.raises(localize.LocalizationError, match="changed protected values"):
        localize.build_plan(repository)


def test_reviewed_translation_may_format_an_existing_enum_as_inline_code(
    tmp_path: Path,
) -> None:
    repository, results = _repository(tmp_path)
    document = results / "status.md"
    document.write_bytes(b"# Status\n\n| skipped_size_limit | 1 |\n")
    digest = localize._digest(document.read_bytes())
    knowledge = repository / "analysis-framework/knowledge/result_markdown_ja"
    knowledge.mkdir(parents=True)
    (knowledge / f"{digest}.md").write_text(
        "# 状態\n\n| サイズ制限によるスキップ (`skipped_size_limit`) | 1 |\n",
        encoding="utf-8",
    )
    plan = localize.build_plan(repository)
    assert plan.entries[0].translation_method == "reviewed_document"
    assert plan.entries[0].unresolved == ()


def test_cli_defaults_to_dry_run_and_never_changes_source(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository, results = _repository(tmp_path)
    document = results / "family.md"
    original = "# XWorm analysis results\n\n## Overview\n"
    document.write_text(original, encoding="utf-8")
    assert localize.main(["--repository", str(repository)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["mode"] == "dry-run"
    assert report["counts"]["changed"] == 1
    assert report["counts"]["written_files"] == 0
    assert document.read_text(encoding="utf-8") == original


def test_write_is_explicit_and_second_plan_is_idempotent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository, results = _repository(tmp_path)
    document = results / "family.md"
    document.write_text("# XWorm analysis results\n\n## Overview\n", encoding="utf-8")
    assert localize.main(["--repository", str(repository), "--write"]) == 0
    first_report = json.loads(capsys.readouterr().out)
    assert first_report["counts"]["written_files"] == 1
    assert document.read_text(encoding="utf-8") == "# XWorm 解析結果\n\n## 概要\n"
    second = localize.build_plan(repository)
    assert sum(entry.changed for entry in second.entries) == 0
    assert localize.localize_markdown(
        document.read_text(encoding="utf-8")
    ) == document.read_text(encoding="utf-8")


def test_unresolved_english_fails_closed_before_any_write(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repository, results = _repository(tmp_path)
    document = results / "family.md"
    original = "# Overview\n\nThis unexplained custom prose must remain unchanged.\n"
    document.write_text(original, encoding="utf-8")
    assert localize.main(["--repository", str(repository), "--write"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["unresolved_lines"] == 1
    assert report["files"][0]["unresolved_english"][0]["text"] == (
        "This unexplained custom prose must remain unchanged."
    )
    assert document.read_text(encoding="utf-8") == original


def test_apply_rejects_a_stale_fingerprint_without_writing(tmp_path: Path) -> None:
    repository, results = _repository(tmp_path)
    document = results / "family.md"
    document.write_text("# XWorm analysis\n", encoding="utf-8")
    plan = localize.build_plan(repository)
    changed = "# XWorm analysis results\n"
    document.write_text(changed, encoding="utf-8")
    with pytest.raises(localize.StalePlanError, match="changed after dry-run"):
        localize.apply_plan(plan)
    assert document.read_text(encoding="utf-8") == changed
    assert not list(results.glob("*.localize-*.tmp"))


def test_mid_transaction_failure_rolls_back_all_replaced_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository, results = _repository(tmp_path)
    first = results / "a.md"
    second = results / "b.md"
    first_original = "# XWorm analysis\n"
    second_original = "# DCRat analysis\n"
    first.write_text(first_original, encoding="utf-8")
    second.write_text(second_original, encoding="utf-8")
    plan = localize.build_plan(repository)
    real_replace = localize._replace_path
    calls = 0

    def fail_once_on_second_replace(source: Path, target: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected replacement failure")
        real_replace(source, target)

    monkeypatch.setattr(localize, "_replace_path", fail_once_on_second_replace)
    with pytest.raises(localize.LocalizationApplyError, match="rolled back"):
        localize.apply_plan(plan)
    assert first.read_text(encoding="utf-8") == first_original
    assert second.read_text(encoding="utf-8") == second_original
    assert not list(results.glob("*.localize-*.tmp"))


def test_discovery_and_report_outputs_are_repository_bounded(
    tmp_path: Path,
) -> None:
    repository, results = _repository(tmp_path)
    (results / "family.md").write_text("# XWorm analysis\n", encoding="utf-8")
    outside = tmp_path / "outside.md"
    outside.write_text("# Outside\n", encoding="utf-8")
    with pytest.raises(localize.LocalizationError, match="within analysis-results"):
        localize.build_plan(repository, [outside])
    outside_directory = tmp_path / "must-not-be-created"
    assert localize.main(
        [
            "--repository", str(repository),
            "--report-json", str(outside_directory / "outside.json"),
        ]
    ) == 2
    assert not outside_directory.exists()


def test_root_readme_and_agents_are_owned_by_layout_docs_and_excluded(
    tmp_path: Path,
) -> None:
    repository, results = _repository(tmp_path)
    (results / "README.md").write_text("# Root documentation\n", encoding="utf-8")
    (results / "AGENTS.md").write_text("# Agent instructions\n", encoding="utf-8")
    (results / "family.md").write_text("# XWorm analysis\n", encoding="utf-8")
    plan = localize.build_plan(repository)
    assert [entry.path for entry in plan.entries] == ["analysis-results/family.md"]


def test_hard_case_machine_row_is_not_misclassified_as_english_prose() -> None:
    """固定schemaの技術値行は、日本語table header配下の説明文と区別する。"""
    digest = "a" * 64
    row = (
        f"| {digest} | redlinestealer | themida_protector | analyzed | "
        "1 | Themida | - |"
    )
    assert localize.find_unresolved_english(row + "\n") == ()
    assert localize.find_unresolved_english(
        "| digest | family | free form prose | analyzed | 1 | marker | - |\n"
    )
    layer = (
        f"- レイヤー {digest}: 形式=pe; マーカー=UPX; "
        "ネイティブルーティング=control_flow_flattening:confounded, "
        "indirect_branch_obfuscation:confounded; "
        "マネージドルーティング=-\n"
    )
    assert localize.find_unresolved_english(layer) == ()


def test_reviewed_research_headings_are_not_reported_as_unresolved() -> None:
    source = (
        "### VenomRAT の再評価\n"
        "### ValleyRAT 3件の再評価\n"
        "### RemcosRAT（`78b21599...`）の再評価\n"
    )
    assert localize.find_unresolved_english(source) == ()


def test_unclassified_post_translation_is_path_limited() -> None:
    source = "- None recovered from static evidence.\n"
    unclassified = (
        "analysis-results/malware/unclassified/sha256/README.md"
    )
    collection = (
        "analysis-results/collections/"
        "malwarebazaar-unknown-20260717/README.md"
    )
    outside = "analysis-results/malware/not-scoped/version/README.md"
    for relative_path in (unclassified, collection):
        translators = localize._line_translators_for_result_path(relative_path)
        assert len(translators) == 1
        assert localize.localize_markdown(
            source, post_line_translators=translators
        ) == "- 静的根拠から復元できた項目はありません。\n"
    assert localize._line_translators_for_result_path(outside) == ()
    assert localize.localize_markdown(source) == source


def test_other_family_post_translation_is_path_limited() -> None:
    source = "| none recovered | - | - | static extraction incomplete |\n"
    target = "analysis-results/malware/amadey/versions/unknown/cases/hash/README.md"
    outside = "analysis-results/malware/xworm/versions/unknown/cases/hash/README.md"
    translators = localize._line_translators_for_result_path(target)
    assert translators == (localize._translate_other_family_line,)
    assert localize.localize_markdown(
        source, post_line_translators=translators
    ) == "| 復元なし | - | - | 静的抽出未完了 |\n"
    assert localize._line_translators_for_result_path(outside) != translators


def test_research_post_translation_is_path_limited() -> None:
    source = "# Security news analysis: 2026-04-01\n"
    research = "analysis-results/research/news/20260401/README.md"
    outside = "analysis-results/malware/not-scoped/README.md"
    translators = localize._line_translators_for_result_path(research)
    assert len(translators) == 1
    assert localize.localize_markdown(
        source, post_line_translators=translators
    ) == "# 2026年4月1日のセキュリティニュース解析\n"
    assert localize._line_translators_for_result_path(outside) == ()
    assert localize.localize_markdown(source) == source


def test_collection_translation_is_path_limited() -> None:
    source = (
        "No active C2 check-in was performed. Use "
        "`analysis-framework/common/c2_candidate_detector.py` for "
        "offline assessment and passive-query generation.\n"
    )
    scoped = (
        "analysis-results/collections/refresh-20260715/"
        "sources/vidar/README.md"
    )
    outside = "analysis-results/collections/other/sources/vidar/README.md"
    translators = localize._line_translators_for_result_path(scoped)
    assert len(translators) == 1
    assert localize.localize_markdown(
        source, post_line_translators=translators
    ) != source
    assert localize._line_translators_for_result_path(outside) == ()


def test_legacy_family_post_translation_is_path_limited() -> None:
    source = "- Cases with validated static config: 0\n"
    scoped = (
        "analysis-results/malware/valleyrat/versions/unknown/README.md"
    )
    outside = "analysis-results/malware/not-scoped/versions/unknown/README.md"
    translators = localize._line_translators_for_result_path(scoped)
    assert translators[0] is localize._translate_legacy_family_line
    assert localize.localize_markdown(
        source, post_line_translators=translators
    ) != source
    heading = "## Collection/behavior features\n"
    assert localize.localize_markdown(
        heading, post_line_translators=translators
    ) == "## 収集・挙動の特徴\n"
    assert localize._line_translators_for_result_path(outside) == ()
    assert localize.localize_markdown(source) == source


@pytest.mark.parametrize(
    ("relative_path", "source"),
    [
        (
            "analysis-results/malware/unclassified/example/README.md",
            "- None recovered from static evidence.\n",
        ),
        (
            "analysis-results/malware/valleyrat/versions/unknown/README.md",
            "- Cases with validated static config: 0\n",
        ),
        (
            "analysis-results/research/news/20260401/README.md",
            "# Security news analysis: 2026-04-01\n",
        ),
        (
            "analysis-results/collections/malwarebazaar-20260717/sources/dcrat/README.md",
            "| 検体 | 形式 |\n| --- | --- |\n| `sample` | VBスクリプト |\n",
        ),
        (
            "analysis-results/malware/purehvnc/README.md",
            "PureCoder開発者ブランドの商用マルウェア群である。\n",
        ),
        (
            "analysis-results/malware/valleyrat/BEHAVIOR-C2.md",
            "- 暗号方式：AES-CBC方式。\n",
        ),
        (
            "analysis-results/malware/purehvnc/README.md",
            "# PureHVNC / PureRAT 解析概要\n",
        ),
        (
            "analysis-results/malware/valleyrat/OSINT.md",
            "# ValleyRAT / Winos4.0：公開情報の詳細\n",
        ),
        (
            "analysis-results/malware/remcosrat/VERSIONS.md",
            "## v6.0.0-pro（6.0.0 Pro）\n",
        ),
        (
            "analysis-results/malware/latrodectus/OSINT.md",
            "利用主体：TA577、TA578。Team Cymruの調査に基づく。\n",
        ),
    ],
)
def test_scoped_translation_chain_is_idempotent(
    relative_path: str, source: str
) -> None:
    translators = localize._line_translators_for_result_path(relative_path)
    first = localize.localize_markdown(
        source, post_line_translators=translators
    )
    second = localize.localize_markdown(
        first, post_line_translators=translators
    )
    assert first == second
