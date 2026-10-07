from __future__ import annotations

import json
import os
import sys
import urllib.request
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMON_ROOT = REPOSITORY_ROOT / "analysis-framework" / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import triage_family_search as search


def _safe_opener():
    return urllib.request.build_opener(search.retrieval.NoRedirect())


def _row(index: int, *, status: str = "reported", kind: str = "file") -> dict[str, str]:
    return {
        "id": f"261007-abcdefgh{index:02d}",
        "sha256": f"{index:064x}",
        "filename": f"sample-{index}.bin",
        "submitted": "2026-10-07T00:00:00Z",
        "completed": "2026-10-07T00:01:00Z",
        "status": status,
        "kind": kind,
    }


def test_search_pages_deduplicates_and_keeps_provider_hint_unconfirmed(monkeypatch) -> None:
    calls: list[str] = []

    def fake_api(path, api_key, *, opener, timeout):
        calls.append(path)
        if "offset=" not in path:
            return {"data": [_row(1), _row(2)], "next": "opaque|cursor"}
        return {"data": [_row(2), _row(3)]}

    monkeypatch.setattr(search.retrieval, "api_json", fake_api)
    document = search.search_public_families(
        ["FormBook"],
        api_key="secret",
        opener=_safe_opener(),
        excluded_hashes={f"{1:064x}"},
        maximum_results=10,
        maximum_pages=3,
    )

    assert document["selected_hashes"] == [f"{2:064x}", f"{3:064x}"]
    assert document["exclusion_counts"] == {
        "existing_sha256": 1,
        "duplicate_sha256": 1,
        "non_reported": 0,
        "non_file": 0,
    }
    assert all(
        item["provider_family_hint_is_confirmation"] is False
        for item in document["candidates"]
    )
    assert document["safety"]["sample_downloaded"] is False
    assert document["safety"]["candidate_public_page_verified"] is False
    assert document["candidate_set_complete"] is True
    assert document["stop_reason"] == "queries_exhausted"
    assert "filename" not in document["candidates"][0]
    assert document["candidates"][0]["public_page_verified"] is False
    assert "offset=opaque%7Ccursor" in calls[1]


def test_search_rejects_cyclic_cursor(monkeypatch) -> None:
    monkeypatch.setattr(
        search.retrieval,
        "api_json",
        lambda *args, **kwargs: {"data": [_row(1)], "next": "same"},
    )

    with pytest.raises(ValueError, match="cursorが循環"):
        search.search_public_families(
            ["formbook"],
            api_key="secret",
            opener=_safe_opener(),
            maximum_results=10,
            maximum_pages=3,
        )


@pytest.mark.parametrize(
    "family",
    ["", "family:formbook", "formbook OR family:xloader", "../formbook"],
)
def test_family_value_is_strict(family: str) -> None:
    with pytest.raises(ValueError):
        search.normalize_family(family)


def test_manifest_hashes_supports_selection_and_acquisition_shapes(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "selected_hashes": [f"{1:064x}"],
                "candidates": [{"sha256": f"{2:064x}"}],
                "downloads": [{"parent_sha256": f"{3:064x}"}],
                "root_sample_candidates": [
                    {
                        "parent_sha256": f"{4:064x}",
                        "expected_sha256": f"{4:064x}",
                    }
                ],
                "root_sample_downloads": [
                    {
                        "parent_sha256": f"{5:064x}",
                        "expected_sha256": f"{5:064x}",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert search.load_excluded_hashes([path]) == {
        f"{1:064x}",
        f"{2:064x}",
        f"{3:064x}",
        f"{4:064x}",
        f"{5:064x}",
    }


def test_manifest_hashes_rejects_conflicting_acquisition_digest(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "root_sample_downloads": [
                    {
                        "parent_sha256": f"{1:064x}",
                        "expected_sha256": f"{2:064x}",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="矛盾するSHA-256"):
        search.load_excluded_hashes([path])


def test_manifest_hashes_rejects_row_without_digest(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"downloads": [{"sample_id": "x"}]}), encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256がありません"):
        search.load_excluded_hashes([path])


def test_main_builds_no_redirect_opener(monkeypatch, tmp_path: Path) -> None:
    built_handlers: list[object] = []
    sentinel_opener = object()

    def fake_build_opener(*handlers):
        built_handlers.extend(handlers)
        return sentinel_opener

    def fake_search(*args, **kwargs):
        assert kwargs["opener"] is sentinel_opener
        return {
            "selected": 0,
            "selected_hashes": [],
            "candidates": [],
            "safety": {"sample_downloaded": False},
        }

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setattr(search, "search_public_families", fake_search)
    monkeypatch.setenv("TRIAGE_API_KEY", "secret")

    assert (
        search.main(
            [
                "--family",
                "formbook",
                "--output-manifest",
                str(tmp_path / "manifest.json"),
                "--allow-network",
            ]
        )
        == 0
    )
    assert len(built_handlers) == 1
    assert isinstance(built_handlers[0], search.retrieval.NoRedirect)


def test_page_limit_is_reported_as_truncated(monkeypatch) -> None:
    monkeypatch.setattr(
        search.retrieval,
        "api_json",
        lambda *args, **kwargs: {"data": [_row(1)], "next": "more"},
    )

    document = search.search_public_families(
        ["formbook"],
        api_key="secret",
        opener=_safe_opener(),
        maximum_results=10,
        maximum_pages=1,
    )

    assert document["candidate_set_complete"] is False
    assert document["candidate_set_truncated"] is True
    assert document["stop_reason"] == "one_or_more_queries_truncated"
    assert document["family_coverage"] == [
        {
            "family": "formbook",
            "complete": False,
            "stop_reason": "maximum_pages_reached",
        }
    ]


def test_private_output_path_rejects_repository() -> None:
    with pytest.raises(ValueError, match="repository外"):
        search.validate_private_output_path(
            search.REPOSITORY_ROOT / "analysis-results" / "triage.json"
        )


def test_search_rejects_opener_without_redirect_refusal() -> None:
    with pytest.raises(ValueError, match="NoRedirect"):
        search.search_public_families(
            ["formbook"],
            api_key="secret",
            opener=urllib.request.build_opener(),
        )


def test_page_rejects_empty_rows_with_next_cursor() -> None:
    with pytest.raises(ValueError, match="空ページ"):
        search._validated_page({"data": [], "next": "more"})


@pytest.mark.parametrize(
    "raw",
    [r"\\server\share\manifest.json", r"\\?\C:\manifest.json", r"C:\manifest.json:ads"],
)
def test_nonlocal_and_special_manifest_paths_are_rejected(raw: str) -> None:
    with pytest.raises(ValueError):
        search.validate_private_output_path(Path(raw))


def test_atomic_write_removes_temporary_file_when_fsync_fails(
    monkeypatch, tmp_path: Path
) -> None:
    target = tmp_path / "manifest.json"

    def fail_fsync(_descriptor):
        raise OSError("synthetic fsync failure")

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(OSError, match="synthetic"):
        search._atomic_write_json(target, {"schema_version": 1})

    assert not target.exists()
    assert list(tmp_path.glob(".manifest.json.*.tmp")) == []


def test_page_rejects_oversized_or_control_cursor() -> None:
    with pytest.raises(ValueError, match="1ページ上限"):
        search._validated_page({"data": [{}] * (search.PAGE_LIMIT + 1)})
    with pytest.raises(ValueError, match="制御文字"):
        search._validated_page({"data": [], "next": "bad\nvalue"})
