"""ケース知識監査の旧形式成果物フォールバックを検証する。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
sys.path.insert(0, str(COMMON))

import audit_case_knowledge


@pytest.mark.parametrize(
    "cached_profile",
    [
        {"schema_version": 1, "family": "legacy"},
        {
            "sha256": "1" * 64,
            "family": "legacy",
            "campaign_type": "unknown",
            "analysis_assessment": {"status": "partial", "unresolved": []},
        },
    ],
)
def test_incomplete_assessment_is_rebuilt_instead_of_aborting(
    monkeypatch,
    tmp_path,
    cached_profile,
) -> None:
    """旧形式features.jsonが1件あっても全体監査を停止しない。"""

    sha256 = "1" * 64
    case_dir = tmp_path / "analysis-results" / "malware" / "example" / "versions" / "unknown" / "cases" / sha256
    case_dir.mkdir(parents=True)
    (case_dir / "features.json").write_text(
        json.dumps(cached_profile),
        encoding="utf-8",
    )
    rebuilt = {
        "sha256": sha256,
        "family": "example",
        "campaign_type": "unknown",
        "analysis_assessment": {
            "status": "partial",
            "score": 1,
            "maximum_score": 2,
            "missing": ["behaviors"],
            "unresolved": ["behavior_not_documented"],
            "next_actions": ["静的な挙動を確認する。"],
        },
    }
    calls = []
    monkeypatch.setattr(audit_case_knowledge, "_history_by_sha", lambda _repository: {})
    monkeypatch.setattr(
        audit_case_knowledge,
        "discover_case_directories",
        lambda _results: [case_dir],
    )

    def rebuild(candidate, history):
        calls.append((candidate, history))
        return rebuilt

    monkeypatch.setattr(audit_case_knowledge, "build_case_profile", rebuild)

    report = audit_case_knowledge.audit(tmp_path)

    assert calls == [(case_dir, None)]
    assert report["counts"] == {
        "cases": 1,
        "complete": 0,
        "partial": 1,
        "insufficient": 0,
        "cases_with_unresolved_items": 1,
    }
    assert report["cases_requiring_follow_up"][0]["sha256"] == sha256


def _complete_profile(sha256: str) -> dict:
    return {
        "sha256": sha256,
        "family": "example",
        "campaign_type": "unknown",
        "analysis_assessment": {
            "status": "complete",
            "score": 2,
            "maximum_score": 2,
            "missing": [],
            "unresolved": [],
            "next_actions": [],
        },
    }


def _partial_profile(sha256: str) -> dict:
    profile = _complete_profile(sha256)
    profile["analysis_assessment"] = {
        "status": "partial",
        "score": 1,
        "maximum_score": 2,
        "missing": ["behaviors"],
        "unresolved": ["behavior_not_documented"],
        "next_actions": ["静的な挙動を確認する。"],
    }
    return profile


def _prepare_case(tmp_path: Path, sha256: str, cached_profile: object) -> Path:
    case_dir = tmp_path / "analysis-results" / "malware" / "example" / "versions" / "unknown" / "cases" / sha256
    case_dir.mkdir(parents=True)
    (case_dir / "features.json").write_text(json.dumps(cached_profile), encoding="utf-8")
    return case_dir


def test_semantically_valid_cached_assessment_is_retained(monkeypatch, tmp_path) -> None:
    """意味契約を満たす既存profileは再構築しない。"""

    sha256 = "1" * 64
    case_dir = _prepare_case(tmp_path, sha256, _complete_profile(sha256))
    monkeypatch.setattr(audit_case_knowledge, "_history_by_sha", lambda _repository: {})
    monkeypatch.setattr(audit_case_knowledge, "discover_case_directories", lambda _results: [case_dir])

    def unexpected_rebuild(_candidate, _history):
        pytest.fail("valid cached profile must be retained")

    monkeypatch.setattr(audit_case_knowledge, "build_case_profile", unexpected_rebuild)

    report = audit_case_knowledge.audit(tmp_path)

    assert report["counts"]["complete"] == 1
    assert report["counts"]["cases_with_unresolved_items"] == 0
    assert report["cases_requiring_follow_up"] == []


@pytest.mark.parametrize(
    ("profile_updates", "assessment_updates"),
    [
        ({"sha256": "2" * 64}, {}),
        ({}, {"score": -1}),
        ({}, {"score": 3}),
        ({}, {"score": 0, "maximum_score": 0}),
        ({}, {"status": "complete_with_documented_limits"}),
        ({}, {"status": {"unexpected": "mapping"}}),
        ({}, {"missing": [{"unexpected": "mapping"}]}),
        ({}, {"unresolved": [{"unexpected": "mapping"}]}),
        ({}, {"next_actions": [{"unexpected": "mapping"}]}),
    ],
    ids=[
        "different-sha256",
        "negative-score",
        "score-above-maximum",
        "zero-maximum-score",
        "invalid-status",
        "unhashable-status",
        "dict-in-missing",
        "dict-in-unresolved",
        "dict-in-next-actions",
    ],
)
def test_semantically_invalid_cached_assessment_is_rebuilt_without_counting_complete(
    monkeypatch,
    tmp_path,
    profile_updates,
    assessment_updates,
) -> None:
    """破損キャッシュをcompleteへ加算せず、公開case情報から再構築する。"""

    sha256 = "1" * 64
    cached_profile = _complete_profile(sha256)
    cached_profile.update(profile_updates)
    cached_profile["analysis_assessment"].update(assessment_updates)
    case_dir = _prepare_case(tmp_path, sha256, cached_profile)
    rebuilt = _partial_profile(sha256)
    calls = []
    monkeypatch.setattr(audit_case_knowledge, "_history_by_sha", lambda _repository: {})
    monkeypatch.setattr(audit_case_knowledge, "discover_case_directories", lambda _results: [case_dir])

    def rebuild(candidate, history):
        calls.append((candidate, history))
        return rebuilt

    monkeypatch.setattr(audit_case_knowledge, "build_case_profile", rebuild)

    report = audit_case_knowledge.audit(tmp_path)

    assert calls == [(case_dir, None)]
    assert report["counts"]["complete"] == 0
    assert report["counts"]["partial"] == 1
    assert report["status_counts"] == {"partial": 1}


def test_malformed_cached_json_is_rebuilt_instead_of_aborting(monkeypatch, tmp_path) -> None:
    """構文破損したfeatures.jsonでも監査全体を停止しない。"""

    sha256 = "1" * 64
    case_dir = _prepare_case(tmp_path, sha256, _complete_profile(sha256))
    (case_dir / "features.json").write_text("{", encoding="utf-8")
    monkeypatch.setattr(audit_case_knowledge, "_history_by_sha", lambda _repository: {})
    monkeypatch.setattr(audit_case_knowledge, "discover_case_directories", lambda _results: [case_dir])
    monkeypatch.setattr(
        audit_case_knowledge,
        "build_case_profile",
        lambda _candidate, _history: _partial_profile(sha256),
    )

    report = audit_case_knowledge.audit(tmp_path)

    assert report["counts"]["complete"] == 0
    assert report["counts"]["partial"] == 1
