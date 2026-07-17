"""Tests for strict public-result sanitation and auditing."""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import sanitize_public_results as public  # noqa: E402


SHA256 = "a" * 64


def raw_response(sha256: str = SHA256) -> dict[str, object]:
    """Return a minimal raw response containing fields that must not survive."""
    return {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": sha256,
                "first_seen": "2026-07-11 23:01:38",
                "last_seen": None,
                "file_size": 1234,
                "file_type": "exe",
                "file_type_mime": "application/x-dosexec",
                "signature": "ValleyRAT",
                "tags": ["exe", "ValleyRAT"],
                "reporter": "private-reporter",
                "comment": "private comment",
                "archive_pw": "private password",
                "vendor_intel": {"private": True},
            }
        ],
    }


def test_raw_response_becomes_an_exact_allowlisted_summary() -> None:
    summary = public.sanitize_malwarebazaar_document(raw_response(), SHA256)
    public.validate_malwarebazaar_summary(summary, SHA256)
    assert set(summary) == public.SUMMARY_KEYS
    assert set(summary["sample"]) == public.SAMPLE_KEYS
    assert summary["raw_provider_response_published"] is False
    serialized = json.dumps(summary)
    for forbidden in ("reporter", "comment", "archive_pw", "vendor_intel", "private"):
        assert forbidden not in serialized


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update({"unexpected": True}),
        lambda value: value.update({"schema_version": 1.0}),
        lambda value: value.update({"raw_provider_response_published": True}),
        lambda value: value["sample"].update({"unexpected": True}),
        lambda value: value["sample"].update({"sha256": "b" * 64}),
        lambda value: value["sample"].update({"tags": ["api_key=must-not-publish"]}),
    ],
)
def test_summary_validation_fails_closed(mutate) -> None:
    summary = public.sanitize_malwarebazaar_document(raw_response(), SHA256)
    mutate(summary)
    with pytest.raises(public.PublicArtifactError):
        public.validate_malwarebazaar_summary(summary, SHA256)


def test_parent_hash_mismatch_prevents_all_writes(tmp_path: Path) -> None:
    mismatched = tmp_path / ("b" * 64) / public.MALWAREBAZAAR_FILENAME
    mismatched.parent.mkdir()
    original = json.dumps(raw_response())
    mismatched.write_text(original, encoding="utf-8")
    other = tmp_path / "other.json"
    other.write_text(json.dumps({"test_email": "person@example.test"}), encoding="utf-8")

    with pytest.raises(public.PublicArtifactError, match="does not match"):
        public.process_public_tree(tmp_path, write=True)
    assert mismatched.read_text(encoding="utf-8") == original
    assert "person@example.test" in other.read_text(encoding="utf-8")


def test_tree_write_redacts_email_then_check_is_read_only(tmp_path: Path, capsys) -> None:
    case = tmp_path / SHA256
    case.mkdir()
    metadata = case / public.MALWAREBAZAAR_FILENAME
    metadata.write_text(json.dumps(raw_response()), encoding="utf-8")
    config = case / "static-analysis.json"
    config.write_text(
        json.dumps({"embedded_config": {"test_email": "person@example.test"}}),
        encoding="utf-8",
    )

    report = public.process_public_tree(tmp_path, write=True)
    assert report == {
        "json_files": 2,
        "malwarebazaar_files": 1,
        "changed_files": 2,
        "email_redactions": 1,
    }
    assert json.loads(config.read_text(encoding="utf-8"))["embedded_config"][
        "test_email"
    ] == public.REDACTED_EMAIL
    assert public.process_public_tree(tmp_path) == {
        "json_files": 2,
        "malwarebazaar_files": 1,
        "changed_files": 0,
        "email_redactions": 0,
    }
    assert public.main(["--root", str(tmp_path)]) == 0
    assert "person@example.test" not in capsys.readouterr().out


def test_repository_public_json_boundary() -> None:
    repository = Path(__file__).parents[2]
    report = public.process_public_tree(repository / "analysis-results")
    assert report["malwarebazaar_files"] >= 5
    digest = "462ae2f56a5f3a961be8bdee03497c65cad61ab04c2482ddcb14e6bf6cdd70fb"
    catalog = json.loads(
        (repository / "analysis-results" / "catalog" / "cases.json").read_text(
            encoding="utf-8"
        )
    )
    case = repository / catalog["cases"][digest]["canonical_path"]
    mx_go = json.loads(
        (case / "static-analysis.json").read_text(encoding="utf-8")
    )
    assert mx_go["embedded_config"]["test_email"] == public.REDACTED_EMAIL
