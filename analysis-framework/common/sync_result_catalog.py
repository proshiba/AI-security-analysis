#!/usr/bin/env python3
"""固定レイアウトのcaseを、単調追加だけ許可して全件catalogへ同期する。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from result_layout import LayoutPlanError, build_layout_plan


class CatalogSyncError(ValueError):
    """既存catalogの破壊的変更が必要な場合に送出する。"""


def _load_catalog(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema_version": 1, "cases": {}}
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict) or not isinstance(value.get("cases"), dict):
        raise CatalogSyncError("catalog must be an object with a cases mapping")
    if value.get("schema_version", 1) != 1:
        raise CatalogSyncError("unsupported catalog schema")
    value["schema_version"] = 1
    return value


def validate_monotonic(
    existing: dict[str, Any], desired: dict[str, Any]
) -> tuple[str, ...]:
    """既存entryが消失・変更しないことを検証し、新規SHA-256を返す。"""

    old_cases = existing.get("cases")
    new_cases = desired.get("cases")
    if not isinstance(old_cases, dict) or not isinstance(new_cases, dict):
        raise CatalogSyncError("catalog cases must be mappings")
    for digest, entry in old_cases.items():
        if digest not in new_cases:
            raise CatalogSyncError(f"existing case would disappear: {digest}")
        replacement = new_cases[digest]
        if replacement != entry and not _is_safe_version_relocation(
            digest, entry, replacement
        ):
            raise CatalogSyncError(f"existing case would change: {digest}")
    return tuple(sorted(set(new_cases) - set(old_cases)))


def _is_safe_version_relocation(
    digest: str, existing: Any, desired: Any
) -> bool:
    """同一caseを正規のversion階層へ直す変更だけを許可する。"""

    if not isinstance(existing, dict) or not isinstance(desired, dict):
        return False
    stable_keys = {
        "case_id", "family", "case_kind", "attribution_status", "provisional_cluster_id"
    }
    if any(existing.get(key) != desired.get(key) for key in stable_keys):
        return False
    family = desired.get("family")
    version_key = desired.get("version_key")
    canonical_path = desired.get("canonical_path")
    if not all(
        isinstance(value, str) for value in (family, version_key, canonical_path)
    ):
        return False
    expected = f"analysis-results/malware/{family}/versions/{version_key}/cases/{digest}"
    return desired.get("case_kind") == "malware" and canonical_path == expected


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    handle = tempfile.NamedTemporaryFile(
        prefix=".catalog-", suffix=".tmp", dir=path.parent, delete=False
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def sync_catalog(repository: Path, *, write: bool = False) -> dict[str, Any]:
    """レイアウト計画からcatalogを再構成し、単調追加だけを任意で反映する。"""

    root = repository.resolve()
    plan = build_layout_plan(root)
    errors = plan.get("errors") or []
    if errors:
        raise LayoutPlanError(f"layout preflight failed: {errors[0]}")
    path = root / plan["catalog"]["path"]
    existing = _load_catalog(path)
    desired = plan["catalog"]["document"]
    additions = validate_monotonic(existing, desired)
    changed = desired != existing
    if write and changed:
        _atomic_write(path, desired)
    return {
        "catalog": path.relative_to(root).as_posix(),
        "existing_cases": len(existing["cases"]),
        "desired_cases": len(desired["cases"]),
        "added_cases": list(additions),
        "updated_cases": sorted(
            digest
            for digest in set(existing["cases"]) & set(desired["cases"])
            if existing["cases"][digest] != desired["cases"][digest]
        ),
        "write_performed": bool(write and changed),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--write",
        action="store_true",
        help="単調追加の検証に成功した場合だけcatalogを置換する",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = sync_catalog(args.repository, write=args.write)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
