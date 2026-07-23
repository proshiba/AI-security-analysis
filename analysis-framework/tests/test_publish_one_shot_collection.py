"""MalwareBazaarワンショットcollection公開処理の試験。"""

from __future__ import annotations

from pathlib import Path
import sys

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import publish_one_shot_collection as publisher  # noqa: E402


def report(selected_family: str | None = None) -> dict:
    """最小のワンショット分類結果を返す。"""
    return {"classification": {"selected_family": selected_family}}


def test_choose_family_uses_internal_result_before_provider() -> None:
    """内部高確度判定を提供元ラベルより優先する。"""
    family, basis = publisher.choose_family(
        {"signature": "WannaCry", "tags": ["WannaCry"]},
        report("efimer"),
        {"efimer", "wannacry", "unclassified"},
    )
    assert (family, basis) == ("efimer", "one_shot_static_detector")


def test_choose_family_is_conservative_for_provider_labels() -> None:
    """対応済み直接ラベルだけを採用し、dropped-byを本体分類へ流用しない。"""
    known = {"efimer", "vidar", "unclassified"}
    assert publisher.choose_family(
        {"signature": "Efimer", "tags": []}, report(), known
    ) == ("efimer", "malwarebazaar_reported_signature")
    assert publisher.choose_family(
        {"signature": None, "tags": ["ClickFix", "Efimer", "exe"]},
        report(),
        known,
    ) == ("efimer", "malwarebazaar_direct_tag")
    assert publisher.choose_family(
        {"signature": None, "tags": ["dropped-by-Remus", "exe"]},
        report(),
        known,
    ) == ("unclassified", "no_supported_family_evidence")
    assert publisher.choose_family(
        {"signature": "NewFamily", "tags": ["Efimer"]}, report(), known
    ) == ("unclassified", "unsupported_reported_signature")


def test_capability_notes_require_exact_imports() -> None:
    """能力手掛かりは完全一致importだけから作り、実行を断定しない。"""
    notes = publisher.capability_notes(
        {"imports": {"KERNEL32.dll": ["CreateProcessW", "WriteProcessMemory"]}}
    )
    assert {item["capability"] for item in notes} == {
        "process_creation",
        "process_injection",
    }
    assert publisher.capability_notes(
        {"imports": {"KERNEL32.dll": ["NotCreateProcessWMarker"]}}
    ) == []


def test_render_iocs_contains_only_submitted_hash() -> None:
    """汎用候補domainをIOCへ昇格せず、提出SHA-256だけを描画する。"""
    digest = "a" * 64
    rendered = publisher.render_iocs(digest)
    assert digest in rendered
    assert "汎用文字列走査" in rendered
    assert "http://" not in rendered

def test_find_case_source_requires_exactly_one_completed_report(tmp_path: Path) -> None:
    """分割runの未完了directoryを無視し、重複完了caseを拒否する。"""
    digest = "b" * 64
    first = tmp_path / "first" / "cases" / digest
    second = tmp_path / "second" / "cases" / digest
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (first / "report.json").write_text("{}", encoding="utf-8")
    assert publisher.find_case_source([tmp_path / "first", tmp_path / "second"], digest) == first
    (second / "report.json").write_text("{}", encoding="utf-8")
    try:
        publisher.find_case_source([tmp_path / "first", tmp_path / "second"], digest)
    except ValueError as exc:
        assert "2件" in str(exc)
    else:
        raise AssertionError("重複完了caseを拒否しませんでした")

def test_find_case_source_prefers_explicit_family_followup(tmp_path: Path) -> None:
    """汎用runと明示family runが重なる場合は追加解析を優先する。"""
    digest = "c" * 64
    generic = tmp_path / "generic" / "cases" / digest
    forced = tmp_path / "forced" / "cases" / digest
    generic.mkdir(parents=True)
    forced.mkdir(parents=True)
    (generic / "report.json").write_text(
        '{"classification":{"selection_basis":"detector"}}', encoding="utf-8"
    )
    (forced / "report.json").write_text(
        '{"classification":{"selection_basis":"explicit_operator_selection"}}',
        encoding="utf-8",
    )
    assert publisher.find_case_source(
        [tmp_path / "generic", tmp_path / "forced"], digest
    ) == forced


def test_choose_family_does_not_mislabel_explicit_selection_as_detector() -> None:
    """明示family選択は提供元報告として記録する。"""
    value = report("wannacry")
    value["classification"]["selection_basis"] = "explicit_operator_selection"
    assert publisher.choose_family(
        {"signature": "WannaCry", "tags": []},
        value,
        {"wannacry", "unclassified"},
    ) == ("wannacry", "malwarebazaar_reported_signature")
