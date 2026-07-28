#!/usr/bin/env python3
"""collection内の既存caseへ全体ロジックの静的Mermaid図を反映する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from overall_logic_diagrams import (
    load_static_layers,
    render_overall_logic_markdown,
)


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise TypeError(f"{path}のrootはobjectである必要があります")
    return value


def _collection_hashes(collection_dir: Path) -> list[str]:
    manifest = _load_object(collection_dir / "manifest.json")
    output: set[str] = set()
    for field in ("acquisition_items", "cases", "items"):
        values = manifest.get(field, [])
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, dict):
                continue
            digest = str(item.get("sha256") or item.get("sha256_hash") or "")
            if len(digest) == 64:
                output.add(digest.casefold())
    for digest in manifest.get("requested_sha256", []):
        rendered = str(digest)
        if len(rendered) == 64:
            output.add(rendered.casefold())
    if not output:
        raise ValueError(f"collectionのSHA-256一覧を取得できません: {collection_dir}")
    return sorted(output)


def _case_index(repository: Path, targets: set[str]) -> dict[str, Path]:
    root = repository / "analysis-results" / "malware"
    output: dict[str, Path] = {}
    for path in root.glob("*/*/*/*/*/static-logic.json"):
        digest = path.parent.name.casefold()
        if digest in targets:
            output[digest] = path.parent
    return output


def refresh_collection(
    repository: Path,
    collection_dir: Path,
    *,
    write: bool,
) -> dict[str, Any]:
    """対象collectionの全体ロジック文書を再描画し、差分を集計する。"""

    repository = repository.resolve()
    collection_dir = collection_dir.resolve()
    digests = _collection_hashes(collection_dir)
    index = _case_index(repository, set(digests))
    missing = [digest for digest in digests if digest not in index]
    changed: list[str] = []
    unchanged: list[str] = []
    for digest in digests:
        case_dir = index.get(digest)
        if case_dir is None:
            continue
        report = _load_object(case_dir / "static-logic.json")
        rendered = render_overall_logic_markdown(
            report,
            load_static_layers(case_dir),
        )
        target = case_dir / "OVERALL-LOGIC.md"
        current = (
            target.read_text(encoding="utf-8-sig")
            if target.is_file()
            else ""
        )
        if current == rendered:
            unchanged.append(digest)
            continue
        changed.append(digest)
        if write:
            target.write_text(rendered, encoding="utf-8")
    return {
        "schema_version": 1,
        "collection": collection_dir.name,
        "requested_cases": len(digests),
        "resolved_cases": len(index),
        "changed_cases": len(changed),
        "unchanged_cases": len(unchanged),
        "missing_cases": missing,
        "changed_sha256": changed,
        "write": write,
    }


def main() -> int:
    """CLI引数を解釈し、再描画または差分検査の終了状態を返す。"""

    parser = argparse.ArgumentParser(
        description="既存caseのOVERALL-LOGIC.mdへ静的Mermaid図を反映します"
    )
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--collection", type=Path, required=True)
    parser.add_argument(
        "--write",
        action="store_true",
        help="差分を実際に書き込みます。省略時はcheckだけを行います。",
    )
    args = parser.parse_args()
    report = refresh_collection(
        args.repository,
        args.collection,
        write=args.write,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["missing_cases"]:
        return 2
    if not args.write and report["changed_cases"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
