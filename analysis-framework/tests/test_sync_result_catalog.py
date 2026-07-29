"""解析結果catalogの単調同期を検証する。"""

from __future__ import annotations

from pathlib import Path
import json
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
sys.path.insert(0, str(COMMON))

import sync_result_catalog as catalog  # noqa: E402


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
