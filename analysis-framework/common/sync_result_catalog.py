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
        if replacement != entry and not (
            _is_safe_version_relocation(digest, entry, replacement)
            or _is_safe_unclassified_normalization(digest, entry, replacement)
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


def _is_safe_unclassified_normalization(
    digest: str, existing: Any, desired: Any
) -> bool:
    """旧式の未分類case表現を正規の帰属未解決表現へだけ補正する。"""

    if not isinstance(existing, dict) or not isinstance(desired, dict):
        return False
    mutable_keys = {"case_kind", "attribution_status", "provisional_cluster_id"}
    if any(
        existing.get(key) != desired.get(key)
        for key in set(existing) | set(desired)
        if key not in mutable_keys
    ):
        return False
    if (
        existing.get("family") != "unclassified"
        or desired.get("family") != "unclassified"
        or existing.get("case_kind") != "malware"
        or desired.get("case_kind") != "unclassified"
        or desired.get("attribution_status") not in {"unresolved", "provisional"}
    ):
        return False
    if existing.get("attribution_status") not in {
        None,
        desired.get("attribution_status"),
    }:
        return False
    if existing.get("provisional_cluster_id") not in {
        None,
        desired.get("provisional_cluster_id"),
    }:
        return False
    version_key = desired.get("version_key")
    canonical_path = desired.get("canonical_path")
    if not isinstance(version_key, str) or not isinstance(canonical_path, str):
        return False
    expected = (
        "analysis-results/malware/unclassified/versions/"
        f"{version_key}/cases/{digest}"
    )
    return canonical_path == expected


def _metadata_document(path: Path) -> tuple[dict[str, Any], bool]:
    """case metadataを厳格に読み、存在有無とともに返す。"""

    if not path.exists():
        return {}, False
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise CatalogSyncError(f"metadata must be an object: {path}")
    return value, True


def sync_case_identity_metadata(
    repository: Path, *, write: bool = False, plan: dict[str, Any] | None = None
) -> dict[str, Any]:
    """固定レイアウトからcase identity metadataを補完し、安全な分類補正だけを行う。

    `plan` を渡すと、同じレイアウト計画を使い回して再構築を省く。計画の構築は
    全成果物の走査を伴い1回あたり数十秒かかるため、同一ツリーに対して何度も
    作り直さないための入口。呼び出し側は、計画の入力(metadata.jsonを含む)が
    その後に書き換わっていないことを保証する責任を持つ。
    """

    root = repository.resolve()
    plan = build_layout_plan(root) if plan is None else plan
    errors = plan.get("errors") or []
    if errors:
        raise LayoutPlanError(f"layout preflight failed: {errors[0]}")
    updates: dict[Path, dict[str, Any]] = {}
    updated_cases: list[str] = []
    for case in plan["cases"]:
        digest = case["sha256"]
        path = root / case["target"] / "metadata.json"
        current, _exists = _metadata_document(path)
        desired = case["metadata"]
        merged = dict(current)
        for key, expected in desired.items():
            if key not in current or current[key] == expected:
                merged[key] = expected
                continue
            if (
                key == "case_kind"
                and current[key] == "malware"
                and expected == "unclassified"
                and desired.get("family") == "unclassified"
            ):
                merged[key] = expected
                continue
            if (
                key == "malware_version"
                and isinstance(current[key], dict)
                and isinstance(expected, dict)
                and current[key].get("status") == expected.get("status")
                and current[key].get("normalized_key") == expected.get("normalized_key")
            ):
                continue
            raise CatalogSyncError(
                f"unsafe metadata identity change for {digest}: {key}"
            )
        if merged != current:
            updates[path] = merged
            updated_cases.append(digest)
    if write:
        for path, document in sorted(updates.items()):
            _atomic_write(path, document)
    return {
        "case_directories": len(plan["cases"]),
        "updated_cases": sorted(updated_cases),
        "write_performed": bool(write and updates),
    }


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


def sync_catalog(
    repository: Path, *, write: bool = False, plan: dict[str, Any] | None = None
) -> dict[str, Any]:
    """レイアウト計画からcatalogを再構成し、単調追加だけを任意で反映する。

    `plan` の意味は sync_case_identity_metadata と同じ。
    """

    root = repository.resolve()
    plan = build_layout_plan(root) if plan is None else plan
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
    """catalog同期CLIの引数parserを返す。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--write",
        action="store_true",
        help="単調追加の検証に成功した場合だけcatalogを置換する",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、同期計画または書込み結果を出力する。"""

    args = build_parser().parse_args(argv)
    result = sync_catalog(args.repository, write=args.write)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
