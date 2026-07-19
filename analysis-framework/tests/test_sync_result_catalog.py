"""解析結果catalogの単調同期を検証する。"""

from __future__ import annotations

from pathlib import Path
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


def test_validate_monotonic_rejects_deletion() -> None:
    digest = "a" * 64
    existing = {"schema_version": 1, "cases": {digest: _entry(digest)}}
    with pytest.raises(catalog.CatalogSyncError, match="would disappear"):
        catalog.validate_monotonic(
            existing, {"schema_version": 1, "cases": {}}
        )
