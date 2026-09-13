"""解析結果catalogの単調同期を検証する。"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
sys.path.insert(0, str(COMMON))

import sync_result_catalog as catalog


def _entry(digest: str) -> dict[str, str]:
    return {
        "case_id": f"sha256:{digest}",
        "family": "test",
        "case_kind": "malware",
        "version_key": "unknown",
        "canonical_path": f"analysis-results/malware/test/versions/unknown/cases/{digest}",
    }


def test_validate_monotonic_accepts_only_additions() -> None:
    first = "a" * 64
    second = "b" * 64
    existing = {"schema_version": 1, "cases": {first: _entry(first)}}
    desired = {
        "schema_version": 1,
        "cases": {first: _entry(first), second: _entry(second)},
    }
    assert catalog.validate_monotonic(existing, desired) == (second,)


def test_validate_monotonic_rejects_existing_entry_change() -> None:
    digest = "a" * 64
    existing = {"schema_version": 1, "cases": {digest: _entry(digest)}}
    changed = _entry(digest)
    changed["family"] = "changed"
    with pytest.raises(catalog.CatalogSyncError, match="would change"):
        catalog.validate_monotonic(
            existing, {"schema_version": 1, "cases": {digest: changed}}
        )


def test_validate_monotonic_accepts_safe_version_relocation() -> None:
    digest = "a" * 64
    existing = {"schema_version": 1, "cases": {digest: _entry(digest)}}
    relocated = _entry(digest)
    relocated["version_key"] = "v3"
    relocated["canonical_path"] = (
        f"analysis-results/malware/test/versions/v3/cases/{digest}"
    )

    assert catalog.validate_monotonic(
        existing, {"schema_version": 1, "cases": {digest: relocated}}
    ) == ()


def test_validate_monotonic_rejects_noncanonical_relocation() -> None:
    digest = "a" * 64
    existing = {"schema_version": 1, "cases": {digest: _entry(digest)}}
    relocated = _entry(digest)
    relocated["version_key"] = "v3"
    relocated["canonical_path"] = f"analysis-results/malware/test/{digest}"

    with pytest.raises(catalog.CatalogSyncError, match="would change"):
        catalog.validate_monotonic(
            existing, {"schema_version": 1, "cases": {digest: relocated}}
        )


def test_validate_monotonic_rejects_deletion() -> None:
    digest = "a" * 64
    existing = {"schema_version": 1, "cases": {digest: _entry(digest)}}
    with pytest.raises(catalog.CatalogSyncError, match="would disappear"):
        catalog.validate_monotonic(
            existing, {"schema_version": 1, "cases": {}}
        )


def test_validate_monotonic_accepts_exact_explicit_deletion() -> None:
    digest = "a" * 64
    existing = {"schema_version": 1, "cases": {digest: _entry(digest)}}

    additions = catalog.validate_monotonic(
        existing,
        {"schema_version": 1, "cases": {}},
        approved_case_removals={digest},
    )

    assert additions == ()


def test_validate_monotonic_rejects_unused_deletion_approval() -> None:
    digest = "a" * 64
    existing = {"schema_version": 1, "cases": {digest: _entry(digest)}}

    with pytest.raises(catalog.CatalogSyncError, match="does not exactly match"):
        catalog.validate_monotonic(
            existing,
            {"schema_version": 1, "cases": {digest: _entry(digest)}},
            approved_case_removals={"b" * 64},
        )


def test_normalize_approved_case_removals_rejects_invalid_or_duplicate() -> None:
    with pytest.raises(catalog.CatalogSyncError, match="lowercase SHA-256"):
        catalog.normalize_approved_case_removals(["not-a-hash"])
    with pytest.raises(catalog.CatalogSyncError, match="duplicate"):
        catalog.normalize_approved_case_removals(["a" * 64, "A" * 64])


def test_read_approved_case_removals_uses_stdin_and_rejects_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64
    monkeypatch.setattr(catalog.sys, "stdin", io.StringIO(digest.upper() + "\n"))
    assert catalog.read_approved_case_removals_from_stdin() == frozenset({digest})

    monkeypatch.setattr(catalog.sys, "stdin", io.StringIO(""))
    with pytest.raises(catalog.CatalogSyncError, match="stdin is empty"):
        catalog.read_approved_case_removals_from_stdin()


@pytest.mark.parametrize(
    "argv",
    [
        ["--allow-removed-case-stdin"],
        ["--bootstrap-missing-catalog"],
        ["--write", "--bootstrap-missing-catalog", "--allow-removed-case-stdin"],
    ],
)
def test_cli_rejects_nonwrite_or_conflicting_explicit_approval(argv: list[str]) -> None:
    with pytest.raises(catalog.CatalogSyncError):
        catalog.main(argv)


def test_cli_reads_deletion_approval_from_stdin_path_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    approved = frozenset({"a" * 64})
    captured = {}
    monkeypatch.setattr(
        catalog,
        "read_approved_case_removals_from_stdin",
        lambda: approved,
    )

    def sync(repository, **kwargs):
        captured.update(repository=repository, **kwargs)
        return {"write_performed": True}

    monkeypatch.setattr(catalog, "sync_catalog", sync)

    assert catalog.main(
        [
            "--repository",
            str(tmp_path),
            "--write",
            "--allow-removed-case-stdin",
        ]
    ) == 0
    assert captured == {
        "repository": tmp_path,
        "write": True,
        "approved_case_removals": approved,
        "bootstrap_missing_catalog": False,
    }


def test_validate_monotonic_rejects_mixed_approved_and_unapproved_deletions() -> None:
    approved = "a" * 64
    unapproved = "b" * 64
    existing = {
        "schema_version": 1,
        "cases": {
            approved: _entry(approved),
            unapproved: _entry(unapproved),
        },
    }

    with pytest.raises(catalog.CatalogSyncError, match="would disappear"):
        catalog.validate_monotonic(
            existing,
            {"schema_version": 1, "cases": {}},
            approved_case_removals={approved},
        )


def _catalog_plan(*digests: str) -> dict[str, object]:
    return {
        "errors": [],
        "catalog": {
            "path": "analysis-results/catalog/cases.json",
            "document": {
                "schema_version": 1,
                "cases": {digest: _entry(digest) for digest in digests},
            },
        },
    }


def test_sync_rejects_mismatch_before_catalog_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved = "a" * 64
    unapproved = "b" * 64
    catalog_path = tmp_path / "analysis-results" / "catalog" / "cases.json"
    catalog_path.parent.mkdir(parents=True)
    original = {
        "schema_version": 1,
        "cases": {
            approved: _entry(approved),
            unapproved: _entry(unapproved),
        },
    }
    catalog_path.write_text(json.dumps(original), encoding="utf-8")
    monkeypatch.setattr(
        catalog,
        "_atomic_write",
        lambda _path, _value: pytest.fail("承認不一致時にwriteしてはならない"),
    )

    with pytest.raises(catalog.CatalogSyncError, match="would disappear"):
        catalog.sync_catalog(
            tmp_path,
            write=True,
            plan=_catalog_plan(),
            approved_case_removals={approved},
        )
    assert json.loads(catalog_path.read_text(encoding="utf-8")) == original


def test_missing_catalog_requires_one_time_write_bootstrap(tmp_path: Path) -> None:
    digest = "a" * 64
    plan = _catalog_plan(digest)

    with pytest.raises(catalog.CatalogSyncError, match="catalog is missing"):
        catalog.sync_catalog(tmp_path, write=True, plan=plan)
    with pytest.raises(catalog.CatalogSyncError, match="requires write mode"):
        catalog.sync_catalog(
            tmp_path,
            plan=plan,
            bootstrap_missing_catalog=True,
        )

    result = catalog.sync_catalog(
        tmp_path,
        write=True,
        plan=plan,
        bootstrap_missing_catalog=True,
    )

    assert result["write_performed"] is True
    assert result["existing_cases"] == 0
    assert result["desired_cases"] == 1
    with pytest.raises(catalog.CatalogSyncError, match="approval is unused"):
        catalog.sync_catalog(
            tmp_path,
            write=True,
            plan=plan,
            bootstrap_missing_catalog=True,
        )


def test_catalog_bootstrap_rejects_deletion_approval(tmp_path: Path) -> None:
    with pytest.raises(catalog.CatalogSyncError, match="cannot be combined"):
        catalog.sync_catalog(
            tmp_path,
            write=True,
            plan=_catalog_plan(),
            approved_case_removals={"a" * 64},
            bootstrap_missing_catalog=True,
        )


def test_bootstrap_creates_catalog_even_when_desired_case_set_is_empty(
    tmp_path: Path,
) -> None:
    result = catalog.sync_catalog(
        tmp_path,
        write=True,
        plan=_catalog_plan(),
        bootstrap_missing_catalog=True,
    )

    catalog_path = tmp_path / "analysis-results" / "catalog" / "cases.json"
    assert result["write_performed"] is True
    assert json.loads(catalog_path.read_text(encoding="utf-8")) == {
        "schema_version": 1,
        "cases": {},
    }

def test_validate_monotonic_accepts_safe_unclassified_normalization() -> None:
    digest = "a" * 64
    old = _entry(digest)
    old["family"] = "unclassified"
    old["canonical_path"] = (
        f"analysis-results/malware/unclassified/versions/unknown/cases/{digest}"
    )
    new = dict(old)
    new["case_kind"] = "unclassified"
    new["attribution_status"] = "unresolved"

    assert catalog.validate_monotonic(
        {"schema_version": 1, "cases": {digest: old}},
        {"schema_version": 1, "cases": {digest: new}},
    ) == ()


def test_validate_monotonic_rejects_unclassified_normalization_with_path_change() -> None:
    digest = "a" * 64
    old = _entry(digest)
    old["family"] = "unclassified"
    old["canonical_path"] = (
        f"analysis-results/malware/unclassified/versions/unknown/cases/{digest}"
    )
    new = dict(old)
    new["case_kind"] = "unclassified"
    new["attribution_status"] = "unresolved"
    new["canonical_path"] = f"analysis-results/malware/unclassified/{digest}"

    with pytest.raises(catalog.CatalogSyncError, match="would change"):
        catalog.validate_monotonic(
            {"schema_version": 1, "cases": {digest: old}},
            {"schema_version": 1, "cases": {digest: new}},
        )
def test_sync_case_identity_metadata_preserves_equivalent_version_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = "a" * 64
    target = f"analysis-results/malware/unclassified/versions/unknown/cases/{digest}"
    metadata_path = tmp_path / target / "metadata.json"
    metadata_path.parent.mkdir(parents=True)
    metadata_path.write_text(
        json.dumps(
            {
                "family": "unclassified",
                "case_kind": "malware",
                "malware_version": {
                    "status": "unknown",
                    "normalized_key": "unknown",
                    "reason": "既存の詳細な版根拠",
                },
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    desired = {
        "schema_version": 1,
        "case_id": f"sha256:{digest}",
        "sha256": digest,
        "case_kind": "unclassified",
        "family": "unclassified",
        "canonical_path": target,
        "collections": [],
        "attribution_status": "unresolved",
        "malware_version": {
            "status": "unknown",
            "normalized_key": "unknown",
            "reason": "一般化した既定値",
        },
    }
    monkeypatch.setattr(
        catalog,
        "build_layout_plan",
        lambda _repository: {
            "errors": [],
            "cases": [{"sha256": digest, "target": target, "metadata": desired}],
        },
    )

    result = catalog.sync_case_identity_metadata(tmp_path, write=True)

    updated = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert result["updated_cases"] == [digest]
    assert updated["case_kind"] == "unclassified"
    assert updated["attribution_status"] == "unresolved"
    assert updated["malware_version"]["reason"] == "既存の詳細な版根拠"
